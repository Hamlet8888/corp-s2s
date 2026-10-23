"""
Route lookups for troubleshooting: longest-prefix match over connected and static routes.

The table comes from the config (connected networks of each virtual router's interfaces plus
static routes, for legacy virtual routers and Advanced Routing logical routers), or from a live
``show routing route``, which also contains BGP/OSPF routes.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from common.parser import _entries, _first_child_tag, _int, _members, _text

from .objects import Interval, interval_str, try_target


@dataclass
class Route:
    vr: str
    destination: Interval
    prefixlen: int
    interface: Optional[str]
    nexthop_type: Optional[str]       # connected | ip-address | next-vr | discard | fqdn | None
    nexthop: Optional[str]
    metric: int = 10
    origin: str = "static"            # connected | static | live
    name: str = ""

    def describe(self) -> str:
        via = {"connected": "connected", "discard": "DISCARD (blackhole)"}.get(self.nexthop_type or "")
        if via is None:
            via = (f"next-vr {self.nexthop}" if self.nexthop_type == "next-vr"
                   else f"via {self.nexthop}" if self.nexthop else "interface route")
        label = f" '{self.name}'" if self.name else ""
        return (f"{interval_str(self.destination)} {via}" + (f" dev {self.interface}" if self.interface else "")
                + f" [{self.origin}{label}, metric {self.metric}]")


@dataclass
class RouteResult:
    vr_path: List[str]
    route: Optional[Route] = None
    interface: Optional[str] = None
    discard: bool = False
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.route is not None and not self.discard and self.interface is not None


def _prefixlen(iv: Interval) -> int:
    v, lo, hi = iv
    bits = 32 if v == 4 else 128
    return bits - (hi - lo + 1).bit_length() + 1


@dataclass
class RouteTable:
    routes: Dict[str, List[Route]] = field(default_factory=dict)          # vr -> routes
    vr_interfaces: Dict[str, List[str]] = field(default_factory=dict)     # vr -> interfaces
    live: bool = False
    logical: Dict[str, tuple] = field(default_factory=dict)               # name -> (logical-router, vrf)

    def add(self, route: Route) -> None:
        self.routes.setdefault(route.vr, []).append(route)

    @property
    def vrs(self) -> List[str]:
        return sorted(set(self.routes) | set(self.vr_interfaces))

    def vr_of(self, interface: Optional[str]) -> Optional[str]:
        return next((vr for vr, ifs in self.vr_interfaces.items() if interface in ifs), None)

    def lookup(self, vr: str, iv: Interval) -> Optional[Route]:
        """Longest-prefix match for the first address of *iv*; ties go to the lowest metric."""
        v, addr = iv[0], iv[1]
        best: Optional[Route] = None
        for r in self.routes.get(vr, []):
            dv, lo, hi = r.destination
            if dv != v or not lo <= addr <= hi:
                continue
            if best is None or (r.prefixlen, -r.metric) > (best.prefixlen, -best.metric):
                best = r
        return best

    def resolve(self, vr: str, iv: Interval, _depth: int = 0) -> RouteResult:
        """Follow next-vr hops and recursive next-hops to the egress interface."""
        res = RouteResult(vr_path=[vr])
        r = self.lookup(vr, iv)
        if r is None:
            res.error = f"no route to {interval_str(iv)} in virtual router '{vr}'"
            return res
        res.route = r
        if r.nexthop_type == "discard":
            res.discard = True
            res.error = f"route {r.describe()} discards the traffic"
            return res
        if r.nexthop_type == "next-vr" and r.nexthop:
            if _depth >= 4 or r.nexthop == vr:
                res.error = f"next-vr loop at '{vr}'"
                return res
            sub = self.resolve(r.nexthop, iv, _depth + 1)
            sub.vr_path = [vr] + sub.vr_path
            return sub
        res.interface = r.interface
        if not res.interface and r.nexthop:
            nh = try_target(r.nexthop)
            nr = self.lookup(vr, nh) if nh else None
            if nr is not None and nr is not r:
                res.interface = nr.interface
        if not res.interface:
            res.error = f"route {r.describe()} has no resolvable egress interface"
        return res

    def ingress_vr(self, iv: Interval) -> Optional[str]:
        """The VR with the most specific route back to *iv*: where traffic from *iv* most likely enters."""
        best, best_key = None, None
        for vr in self.vrs:
            r = self.lookup(vr, iv)
            if r is None or r.nexthop_type in ("next-vr", "discard"):
                continue
            key = (r.prefixlen, r.nexthop_type == "connected", -r.metric)
            if best_key is None or key > best_key:
                best, best_key = vr, key
        return best


# ---------------------------------------------------------------------------
# Building the table
# ---------------------------------------------------------------------------

def _connected(table: RouteTable, vr: str, interfaces, store) -> None:
    by_name = {i.name: i for i in interfaces}
    for ifname in table.vr_interfaces.get(vr, []):
        i = by_name.get(ifname)
        for ip in (i.ips if i else []):
            try:
                net = ipaddress.ip_interface(ip).network
            except ValueError:
                kind_val = store.addresses.get(ip) if store else None
                try:
                    net = ipaddress.ip_interface(kind_val[1]).network if kind_val else None
                except ValueError:
                    net = None
                if net is None:
                    continue
            iv = (net.version, int(net.network_address), int(net.broadcast_address))
            table.add(Route(vr, iv, net.prefixlen, ifname, "connected", None, 0, "connected"))


def _static(table: RouteTable, vr: str, entries, store) -> None:
    for r in entries:
        dest = _text(r, "destination")
        iv = store.address_value(dest) if store else try_target(dest)
        if iv is None:
            continue
        nh = r.find("nexthop")
        nht = _first_child_tag(nh)
        nhv = _text(nh, nht) if nht in ("ip-address", "next-vr", "fqdn", "ipv6-address", "next-lr") else None
        if nht == "ipv6-address":
            nht = "ip-address"
        if nht == "next-lr":
            nht = "next-vr"
        table.add(Route(vr, iv, _prefixlen(iv), _text(r, "interface"), nht, nhv,
                        _int(_text(r, "metric")) or 10, "static", r.get("name", "")))


def routes_from_config(net: ET.Element, vrs, interfaces, store=None) -> RouteTable:
    """Build a table from legacy virtual routers (``vrs`` from :mod:`common.parser`) and logical routers."""
    table = RouteTable()
    for v in vrs:
        table.vr_interfaces[v.name] = list(v.interfaces)
    for v in net.findall("virtual-router/entry"):
        name = v.get("name", "")
        _static(table, name, _entries(v, "routing-table/ip/static-route"), store)
        _static(table, name, _entries(v, "routing-table/ipv6/static-route"), store)
    for lr in _entries(net, "logical-router"):
        for vrf in _entries(lr, "vrf"):
            name = lr.get("name", "") if vrf.get("name") == "default" else f"{lr.get('name')}/{vrf.get('name')}"
            table.vr_interfaces[name] = _members(vrf, "interface")
            table.logical[name] = (lr.get("name", ""), vrf.get("name", ""))
            _static(table, name, _entries(vrf, "routing-table/ip/static-route"), store)
    for vr in list(table.vr_interfaces):
        _connected(table, vr, interfaces, store)
    return table


def routes_from_live(root: ET.Element, vr_interfaces: Dict[str, List[str]], logical=None) -> RouteTable:
    """Parse ``<show><routing><route/></routing></show>`` output (active routes only)."""
    table = RouteTable(vr_interfaces=dict(vr_interfaces), live=True, logical=dict(logical or {}))
    for e in root.iter("entry"):
        dest = (e.findtext("destination") or "").strip()
        flags = (e.findtext("flags") or "").split()
        iv = try_target(dest)
        if iv is None or "A" not in flags:
            continue
        nh = (e.findtext("nexthop") or "").strip()
        if "C" in flags or "H" in flags:
            nht = "connected"
        elif nh == "discard":
            nht = "discard"
        elif try_target(nh):
            nht = "ip-address"
        else:
            nht = "next-vr" if nh else None
        metric = _int((e.findtext("metric") or "").strip()) or 0
        vr = (e.findtext("virtual-router") or "default").strip()
        table.add(Route(vr, iv, _prefixlen(iv), (e.findtext("interface") or "").strip() or None, nht,
                        nh or None, metric, "live", " ".join(flags)))
    return table
