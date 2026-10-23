"""
Desired-state planner and diff engine for PAN-OS site-to-site tunnels.

Each inventory link is defined **once** (``a``, ``b``, plus ``paths`` of
primary/failover WAN pairs). For every path, the planner renders **both
ends** from the same data, so the peer IPs, IKE identities, crypto profiles,
proxy-IDs (mirrored) and the tunnel /30 always agree:

    tunnel interface  ->  zone membership  ->  VR membership
    ->  IKE gateway  ->  IPsec tunnel (+ proxy-IDs, monitor)  ->  static routes

That list is also the apply order, so references always resolve.

The desired objects are then diffed against each firewall's current state
(:class:`DeviceState`, built from a parsed export or from the demo
inventory's ``observed:`` section):

* ``create``: the object doesn't exist. Sent with ``action=set`` on the entry xpath.
* ``update``: it exists but differs. Sent with ``action=edit`` (full replacement),
  with a field-by-field explanation.
* unchanged objects are counted but not emitted.

The planner **never deletes**. Objects on a device that the inventory doesn't
describe are listed as *unmanaged* for a human to decide on.

Pre-shared keys are never known to the planner. Gateway elements carry a
placeholder (``__PSK:<link-id>__``) that ``apply`` replaces at push time
with a key from the environment or Secret Server. Rendered plans pass through
:func:`common.parser.strip_secrets`, so even the placeholder prints as ``<redacted>``.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from common import miniyaml
from common.parser import FirewallConfig, parse_directory, strip_secrets
from common.xpath import FW_NETWORK, child, fw_vsys

logger = logging.getLogger("corp_s2s.planner")

DEMO_INVENTORY = Path(__file__).resolve().parent / "examples" / "mock_inventory.yaml"
PAN_NAME_MAX = 63           # PAN-OS object name limit for gateways/tunnels/routes (10.x+)
PSK_PLACEHOLDER = "__PSK:{link_id}__"

# Apply order: dependencies first.
KIND_ORDER = ("tunnel-interface", "zone-member", "vr-member", "ike-gateway", "ipsec-tunnel", "static-route")


# ---------------------------------------------------------------------------
# Plan model
# ---------------------------------------------------------------------------

@dataclass
class PlanAction:
    device: str
    op: str                       # create | update
    kind: str                     # one of KIND_ORDER
    name: str
    api_action: str               # set | edit
    xpath: str
    element: str                  # XML text; may contain a PSK placeholder, never a real key
    link: str                     # "A <-> B (role)"
    changes: List[str] = field(default_factory=list)

    def as_tuple(self) -> Tuple[str, str, str]:
        """Return ``(api_action, xpath, element)``, the shape :class:`common.api.PanosApiClient` consumes."""
        return self.api_action, self.xpath, self.element

    def redacted_element(self) -> str:
        return redact(self.element)


@dataclass
class DevicePlan:
    device: str
    site: str
    actions: List[PlanAction] = field(default_factory=list)
    unchanged: int = 0
    unmanaged: List[str] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)      # reasons apply must refuse this device
    notes: List[str] = field(default_factory=list)


def redact(element_xml: str) -> str:
    """Return *element_xml* with secret leaves (PSKs) replaced by ``<redacted>``."""
    root = ET.fromstring(f"<r>{element_xml}</r>")
    strip_secrets(root)
    for el in root.iter():
        if el.get("redacted"):
            el.text = "<redacted>"
            del el.attrib["redacted"]
    return "".join(ET.tostring(c, encoding="unicode") for c in root)


# ---------------------------------------------------------------------------
# Current device state (what is already configured)
# ---------------------------------------------------------------------------

@dataclass
class DeviceState:
    """The comparable view of one firewall's VPN objects.

    Field dicts only hold what the source knows. A field absent from the
    current state is *unknown* and is not diffed. ``known_kinds`` lists the
    object kinds the source fully describes. For other kinds, the planner
    assumes they already exist for tunnels that already exist (the demo
    ``observed:`` data has no routes or zones).
    """
    hostname: str
    gateways: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tunnels: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tunnel_ifs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    routes: List[Dict[str, Any]] = field(default_factory=list)   # {name, vr, destination, interface, metric}
    zone_members: Dict[str, Set[str]] = field(default_factory=dict)
    vr_members: Dict[str, Set[str]] = field(default_factory=dict)
    known_kinds: Set[str] = field(default_factory=set)

    def used_units(self) -> Set[int]:
        out = set()
        for n in self.tunnel_ifs:
            m = re.match(r"^tunnel\.(\d+)$", n)
            if m:
                out.add(int(m.group(1)))
        return out

    def find_gateway(self, name: str, local_id: str, peer_id: str) -> Optional[str]:
        """Find an existing gateway by name, falling back to a match on both IKE identities."""
        if name in self.gateways:
            return name
        for n, g in self.gateways.items():
            if g.get("local_id") == local_id and g.get("peer_id") == peer_id:
                return n
        return None

    @classmethod
    def from_firewall(cls, fw: FirewallConfig) -> "DeviceState":
        st = cls(hostname=fw.hostname or Path(fw.source_file).stem,
                 known_kinds=set(KIND_ORDER))
        for g in fw.ike_gateways:
            st.gateways[g.name] = {
                "version": g.version, "local_interface": g.local_interface,
                "local_ip": g.local_ip, "peer": fw.resolve(g.peer),
                "local_id": g.local_id.id if g.local_id else None,
                "peer_id": g.peer_id.id if g.peer_id else None,
                "ike_profile": g.ike_crypto_profile, "nat_traversal": bool(g.nat_traversal),
                "dpd": bool(g.dpd)}
        for t in fw.ipsec_tunnels:
            st.tunnels[t.name] = {
                "interface": t.tunnel_interface, "gateway": t.gateways[0] if t.gateways else None,
                "ipsec_profile": t.ipsec_crypto_profile,
                "proxy_ids": frozenset((p.local, p.remote) for p in t.proxy_ids),
                "monitor": t.monitor_enabled, "monitor_destination": t.monitor_destination,
                "monitor_profile": t.monitor_profile}
        for i in fw.interfaces:
            if i.kind == "tunnel":
                st.tunnel_ifs[i.name] = {"ip": i.ips[0] if i.ips else None, "comment": i.comment}
        for v in fw.virtual_routers:
            st.vr_members[v.name] = set(v.interfaces)
            for r in v.static_routes:
                st.routes.append({"name": r.name, "vr": v.name, "destination": fw.resolve(r.destination),
                                  "interface": r.interface, "metric": r.metric})
        for z in fw.zones:
            st.zone_members[z.name] = set(z.interfaces)
        return st

    @classmethod
    def from_observed(cls, hostname: str, body: Dict[str, Any]) -> "DeviceState":
        """Build from the demo inventory's ``observed.devices.<host>`` block (tunnel-level data only)."""
        st = cls(hostname=hostname, known_kinds={"tunnel-interface", "ike-gateway", "ipsec-tunnel"})
        for t in body.get("tunnels") or []:
            st.gateways[t["name"]] = {"local_id": t.get("local_id"), "peer_id": t.get("peer_id"),
                                      "ike_profile": t.get("ike")}
            st.tunnels[t["name"]] = {"interface": t.get("interface"), "gateway": t["name"],
                                     "ipsec_profile": t.get("ipsec"),
                                     "proxy_ids": frozenset((p[0], p[1]) for p in t.get("proxy_ids") or [])}
            if t.get("interface"):
                st.tunnel_ifs[t["interface"]] = {"ip": t.get("tunnel_ip")}
        return st


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

@dataclass
class _End:
    """One end of one path, resolved against the inventory."""
    site: str
    device: str
    wan_key: str
    wan: Dict[str, Any]
    lan: List[str]
    vr: str
    zone: str
    unit_range: Tuple[int, int]


class PlanError(ValueError):
    """The inventory is inconsistent and no safe plan can be produced."""


class TunnelPlanner:
    """Compute per-device create/update actions from inventory links and current state.

    >>> planner = TunnelPlanner(inventory)                     # doctest: +SKIP
    >>> plans = planner.build_device_plans(states)             # doctest: +SKIP
    >>> for action, xpath, element in (a.as_tuple() for a in plans["FW-01"]): ...
    """

    def __init__(self, inventory: Dict[str, Any], standards: Optional[Dict[str, Any]] = None):
        self.inventory = inventory
        self.standards = standards if standards is not None else (inventory.get("standards") or {})
        self.sites: Dict[str, Dict[str, Any]] = inventory.get("sites") or {}
        self.device_plans: Dict[str, DevicePlan] = {}
        self._used_nets: Set[ipaddress.IPv4Network] = set()
        self._allocated_units: Dict[str, Set[int]] = {}
        self._managed: Dict[str, Set[Tuple[str, str]]] = {}

    # -- public API ----------------------------------------------------------
    def build_device_plans(self, states: Optional[Dict[str, DeviceState]] = None,
                           blocked: Optional[Dict[str, List[str]]] = None) -> Dict[str, List[PlanAction]]:
        """Return ``{device: [PlanAction, ...]}`` in apply order. Details are in :attr:`device_plans`.

        *states* maps hostname to :class:`DeviceState`. A device without a state
        is treated as empty, so everything for it is a ``create``. *blocked* maps
        a site to the reasons ``apply`` must refuse it (e.g. auditor HA findings).
        """
        states = dict(states or {})
        self.device_plans = {}
        self._managed = {}
        self._used_nets = {n for st in states.values() for n in
                           (_net30(i.get("ip")) for i in st.tunnel_ifs.values()) if n}
        self._allocated_units = {}

        for link in self.inventory.get("links") or []:
            if not link.get("enabled", True):
                continue
            a_site, b_site = link.get("a"), link.get("b")
            for s in (a_site, b_site):
                if s not in self.sites:
                    raise PlanError(f"link {a_site} <-> {b_site}: unknown site {s!r}")
            for path in link.get("paths") or []:
                self._plan_path(link, path, states)

        for dev, dp in self.device_plans.items():
            st = states.get(dev)
            if st is not None:
                dp.unmanaged = self._unmanaged(dev, st)
            for reason in (blocked or {}).get(dp.site, []):
                dp.blocked.append(reason)
            dp.actions.sort(key=lambda a: (KIND_ORDER.index(a.kind), a.name))
        return {d: p.actions for d, p in sorted(self.device_plans.items()) if p.actions}

    # -- per path --------------------------------------------------------------
    def _end(self, site: str, wan_key: str) -> _End:
        s = self.sites[site]
        wan = (s.get("wan") or {}).get(wan_key)
        if not wan:
            raise PlanError(f"site {site} has no WAN {wan_key!r}")
        fws = s.get("firewalls") or []
        if not fws:
            raise PlanError(f"site {site} has no firewalls")
        rng = s.get("tunnel_unit_range") or [1, 9999]
        return _End(site=site, device=fws[0]["hostname"], wan_key=wan_key, wan=wan,
                    lan=list(s.get("lan") or []), vr=s.get("virtual_router") or "default",
                    zone=s.get("vpn_zone") or "VPN", unit_range=(int(rng[0]), int(rng[1])))

    def _dp(self, end: _End) -> DevicePlan:
        if end.device not in self.device_plans:
            dp = DevicePlan(device=end.device, site=end.site)
            if len(self.sites[end.site].get("firewalls") or []) > 1:
                dp.notes.append("HA pair: apply pushes to the active member; config sync replicates to the peer")
            self.device_plans[end.device] = dp
        return self.device_plans[end.device]

    def _plan_path(self, link: Dict[str, Any], path: Dict[str, Any], states: Dict[str, DeviceState]) -> None:
        role = path.get("role", "primary")
        a, b = self._end(link["a"], path["a"]), self._end(link["b"], path["b"])
        naming = self.standards.get("naming") or {}
        fmt = naming.get("link", "{local}-{remote}")
        suffix = naming.get("failover_suffix", ".Failover") if role != "primary" else ""
        names = {a.site: fmt.format(local=a.site, remote=b.site) + suffix,
                 b.site: fmt.format(local=b.site, remote=a.site) + suffix}
        link_id = f"{a.site}_{b.site}_{role}"
        label = f"{a.site} <-> {b.site} ({role})"
        sa = states.get(a.device) or DeviceState(hostname=a.device, known_kinds=set(KIND_ORDER))
        sb = states.get(b.device) or DeviceState(hostname=b.device, known_kinds=set(KIND_ORDER))

        # Existing objects (matched by name, else by IKE identities).
        ga = sa.find_gateway(names[a.site], a.wan["public_ip"], b.wan["public_ip"])
        gb = sb.find_gateway(names[b.site], b.wan["public_ip"], a.wan["public_ip"])
        ta = _tunnel_for_gateway(sa, ga) if ga else None
        tb = _tunnel_for_gateway(sb, gb) if gb else None
        name_a, name_b = ta or ga or names[a.site], tb or gb or names[b.site]
        for end, n in ((a, name_a), (b, name_b)):
            if len(n) > PAN_NAME_MAX:
                raise PlanError(f"{end.device}: name {n!r} exceeds {PAN_NAME_MAX} characters")

        if_a = sa.tunnels.get(ta, {}).get("interface") if ta else None
        if_b = sb.tunnels.get(tb, {}).get("interface") if tb else None
        if_a = if_a or self._next_unit(a, sa)
        if_b = if_b or self._next_unit(b, sb)

        ip_a, ip_b = self._tunnel_ips(sa.tunnel_ifs.get(if_a, {}).get("ip"),
                                      sb.tunnel_ifs.get(if_b, {}).get("ip"),
                                      new_a=if_a not in sa.tunnel_ifs, new_b=if_b not in sb.tunnel_ifs)

        monitor = self._monitor_for(role)
        for end, peer, st, name, ifn, my_ip, peer_ip, existing in (
                (a, b, sa, name_a, if_a, ip_a, ip_b, (ga, ta)),
                (b, a, sb, name_b, if_b, ip_b, ip_a, (gb, tb))):
            dp = self._dp(end)
            self._managed.setdefault(end.device, set()).update(
                {("ike-gateway", existing[0] or name), ("ipsec-tunnel", existing[1] or name)})
            if existing[0] and existing[0] != names[end.site]:
                dp.notes.append(f"{label}: existing gateway '{existing[0]}' doesn't follow the naming standard "
                                f"('{names[end.site]}'); kept as-is (renames aren't automated)")
            new_tunnel = ifn not in st.tunnel_ifs
            proxies = sorted({(l, r) for l in end.lan for r in peer.lan + list(link.get("extra_remote_prefixes") or [])})
            route_dsts = list(dict.fromkeys(peer.lan + list(link.get("extra_remote_prefixes") or [])))
            metric = int((self.standards.get("route_metrics") or {}).get(role, 10 if role == "primary" else 12))

            self._diff(dp, st, "tunnel-interface", ifn, label, new_tunnel,
                       xpath=child(FW_NETWORK, "interface", "tunnel", "units", ("entry", ifn)),
                       desired={"ip": my_ip, "comment": name},
                       element=_tunnel_if_xml(ifn, my_ip, name))
            self._membership(dp, st, "zone-member", end.zone, ifn, label, new_tunnel,
                             child(fw_vsys(), "zone", ("entry", end.zone), "network", "layer3"),
                             st.zone_members)
            self._membership(dp, st, "vr-member", end.vr, ifn, label, new_tunnel,
                             child(FW_NETWORK, "virtual-router", ("entry", end.vr), "interface"),
                             st.vr_members)
            gw_desired = {
                "version": self.standards.get("ike_version", "ikev2"),
                "local_interface": end.wan.get("interface"), "local_ip": end.wan.get("local_ip"),
                "peer": peer.wan["public_ip"], "local_id": end.wan["public_ip"], "peer_id": peer.wan["public_ip"],
                "ike_profile": self.standards.get("ike_crypto_profile"),
                "nat_traversal": bool(self.standards.get("nat_traversal", False)),
                "dpd": bool(self.standards.get("dpd", True))}
            gw_name = existing[0] or name
            self._diff(dp, st, "ike-gateway", gw_name, label, gw_name not in st.gateways,
                       xpath=child(FW_NETWORK, "ike", "gateway", ("entry", gw_name)),
                       desired=gw_desired, element=_gateway_xml(gw_name, gw_desired, link_id))
            tun_name = existing[1] or name
            mon_dst = str(ipaddress.ip_interface(peer_ip).ip) if (monitor and peer_ip) else None
            tun_desired = {
                "interface": ifn, "gateway": gw_name,
                "ipsec_profile": self.standards.get("ipsec_crypto_profile"),
                "proxy_ids": frozenset(proxies),
                "monitor": bool(mon_dst), "monitor_destination": mon_dst,
                "monitor_profile": self.standards.get("tunnel_monitor_profile") if mon_dst else None}
            self._diff(dp, st, "ipsec-tunnel", tun_name, label, tun_name not in st.tunnels,
                       xpath=child(FW_NETWORK, "tunnel", "ipsec", ("entry", tun_name)),
                       desired=tun_desired, element=_ipsec_xml(tun_name, tun_desired, peer.site))
            for i, dst in enumerate(route_dsts, 1):
                rname = name if len(route_dsts) == 1 else f"{name}-{i}"
                self._route(dp, st, end.vr, rname, dst, ifn, metric, label, new_tunnel)

    # -- diff primitives -------------------------------------------------------
    def _diff(self, dp: DevicePlan, st: DeviceState, kind: str, name: str, label: str, is_new: bool,
              xpath: str, desired: Dict[str, Any], element: str) -> None:
        current = {"tunnel-interface": st.tunnel_ifs, "ike-gateway": st.gateways,
                   "ipsec-tunnel": st.tunnels}[kind].get(name)
        if is_new or current is None:
            dp.actions.append(PlanAction(dp.device, "create", kind, name, "set", xpath,
                                         _inner(element), label))
            return
        changes = []
        for k, want in desired.items():
            if k not in current:               # unknown in the current source: not diffed
                continue
            have = current[k]
            if kind == "tunnel-interface" and k == "ip" and want is None:
                continue                       # never strip an existing tunnel address
            if kind == "tunnel-interface" and k == "comment":
                continue                       # cosmetic
            if _norm(have) != _norm(want):
                changes.append(_describe_change(k, have, want))
        if changes:
            dp.actions.append(PlanAction(dp.device, "update", kind, name, "edit", xpath, element, label, changes))
        else:
            dp.unchanged += 1

    def _membership(self, dp: DevicePlan, st: DeviceState, kind: str, container: str, ifn: str, label: str,
                    new_tunnel: bool, xpath: str, members: Dict[str, Set[str]]) -> None:
        if kind not in st.known_kinds and not new_tunnel:
            dp.unchanged += 1                  # source doesn't describe it; existing tunnel assumed complete
            return
        if ifn in members.get(container, set()):
            dp.unchanged += 1
            return
        what = "zone" if kind == "zone-member" else "virtual router"
        dp.actions.append(PlanAction(dp.device, "create", kind, f"{container}:{ifn}", "set", xpath,
                                     f"<member>{_esc(ifn)}</member>", label,
                                     [f"add {ifn} to {what} '{container}'"]))

    def _route(self, dp: DevicePlan, st: DeviceState, vr: str, name: str, dst: str, ifn: str, metric: int,
               label: str, new_tunnel: bool) -> None:
        if "static-route" not in st.known_kinds and not new_tunnel:
            dp.unchanged += 1
            return
        match = [r for r in st.routes if r["vr"] == vr and r["destination"] == dst and r["interface"] == ifn]
        xpath = child(FW_NETWORK, "virtual-router", ("entry", vr), "routing-table", "ip", "static-route",
                      ("entry", match[0]["name"] if match else name))
        element = (f"<destination>{_esc(dst)}</destination><interface>{_esc(ifn)}</interface>"
                   f"<metric>{metric}</metric>")
        if not match:
            dp.actions.append(PlanAction(dp.device, "create", "static-route", name, "set", xpath, element, label,
                                         [f"{dst} via {ifn} metric {metric}"]))
        elif match[0]["metric"] != metric:
            r = match[0]
            dp.actions.append(PlanAction(dp.device, "update", "static-route", r["name"], "edit", xpath,
                                         f"<entry name=\"{_esc(r['name'])}\">{element}</entry>", label,
                                         [f"metric: {r['metric']} -> {metric}"]))
        else:
            dp.unchanged += 1

    # -- allocation --------------------------------------------------------------
    def _next_unit(self, end: _End, st: DeviceState) -> str:
        used = st.used_units() | self._allocated_units.setdefault(end.device, set())
        lo, hi = end.unit_range
        for u in range(lo, hi + 1):
            if u not in used:
                self._allocated_units[end.device].add(u)
                return f"tunnel.{u}"
        raise PlanError(f"{end.device}: no free tunnel unit in range {lo}-{hi}")

    def _tunnel_ips(self, cur_a: Optional[str], cur_b: Optional[str], new_a: bool, new_b: bool
                    ) -> Tuple[Optional[str], Optional[str]]:
        """Reuse existing tunnel addresses. For new tunnels, use the peer's /30 or allocate a fresh one from the pool."""
        if cur_a and cur_b:
            return cur_a, cur_b
        if cur_a and new_b:
            return cur_a, _other_host(cur_a)
        if cur_b and new_a:
            return _other_host(cur_b), cur_b
        if new_a and new_b:
            net = self._alloc_net()
            if net:
                h = list(net.hosts())
                return f"{h[0]}/30", f"{h[1]}/30"
        return cur_a, cur_b                    # existing tunnels without addresses stay as they are

    def _alloc_net(self) -> Optional[ipaddress.IPv4Network]:
        pool = self.standards.get("tunnel_ip_pool")
        if not pool:
            return None
        for net in ipaddress.ip_network(pool).subnets(new_prefix=30):
            if net not in self._used_nets:
                self._used_nets.add(net)
                return net
        raise PlanError(f"tunnel IP pool {pool} is exhausted")

    def _monitor_for(self, role: str) -> bool:
        mode = self.standards.get("tunnel_monitor", "primary")
        return mode == "all" or (mode == "primary" and role == "primary")

    def _unmanaged(self, dev: str, st: DeviceState) -> List[str]:
        managed = self._managed.get(dev, set())
        out = [f"ike-gateway {n}" for n in sorted(st.gateways) if ("ike-gateway", n) not in managed]
        out += [f"ipsec-tunnel {n}" for n in sorted(st.tunnels)
                if ("ipsec-tunnel", n) not in managed and f"ike-gateway {n}" not in out]
        return out


# ---------------------------------------------------------------------------
# XML rendering
# ---------------------------------------------------------------------------

def _esc(v: Any) -> str:
    return (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _inner(entry_xml: str) -> str:
    """Return the children of ``<entry ...>...</entry>`` (for ``action=set`` on the entry xpath)."""
    root = ET.fromstring(entry_xml)
    return "".join(ET.tostring(c, encoding="unicode") for c in root)


def _tunnel_if_xml(name: str, ip: Optional[str], comment: str) -> str:
    ip_xml = f'<ip><entry name="{_esc(ip)}"/></ip>' if ip else ""
    return f'<entry name="{_esc(name)}">{ip_xml}<comment>{_esc(comment)}</comment></entry>'


def _gateway_xml(name: str, d: Dict[str, Any], link_id: str) -> str:
    ver = d["version"]
    proto = "ikev1" if ver == "ikev1" else "ikev2"
    local_ip = f"<ip>{_esc(d['local_ip'])}</ip>" if d.get("local_ip") else ""
    return (
        f'<entry name="{_esc(name)}">'
        f"<authentication><pre-shared-key><key>{_esc(PSK_PLACEHOLDER.format(link_id=link_id))}</key>"
        f"</pre-shared-key></authentication>"
        f"<protocol><{proto}><dpd><enable>{'yes' if d['dpd'] else 'no'}</enable></dpd>"
        f"<ike-crypto-profile>{_esc(d['ike_profile'])}</ike-crypto-profile></{proto}>"
        f"<version>{_esc(ver)}</version></protocol>"
        f"<protocol-common><nat-traversal><enable>{'yes' if d['nat_traversal'] else 'no'}</enable>"
        f"</nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>"
        f"<local-address><interface>{_esc(d['local_interface'])}</interface>{local_ip}</local-address>"
        f"<peer-address><ip>{_esc(d['peer'])}</ip></peer-address>"
        f"<local-id><id>{_esc(d['local_id'])}</id><type>ipaddr</type></local-id>"
        f"<peer-id><id>{_esc(d['peer_id'])}</id><type>ipaddr</type></peer-id>"
        f"<comment>Managed by corp-s2s. PSK reference: {_esc(link_id)}</comment>"
        f"</entry>")


def _ipsec_xml(name: str, d: Dict[str, Any], remote_site: str) -> str:
    pids = "".join(
        f'<entry name="{_esc(f"{remote_site}-{i}")}"><protocol><any/></protocol>'
        f"<local>{_esc(l)}</local><remote>{_esc(r)}</remote></entry>"
        for i, (l, r) in enumerate(sorted(d["proxy_ids"]), 1))
    mon = (f"<tunnel-monitor><enable>yes</enable><destination-ip>{_esc(d['monitor_destination'])}</destination-ip>"
           f"<tunnel-monitor-profile>{_esc(d['monitor_profile'])}</tunnel-monitor-profile></tunnel-monitor>"
           if d.get("monitor") else "<tunnel-monitor><enable>no</enable></tunnel-monitor>")
    return (
        f'<entry name="{_esc(name)}">'
        f'<auto-key><ike-gateway><entry name="{_esc(d["gateway"])}"/></ike-gateway>'
        f"<ipsec-crypto-profile>{_esc(d['ipsec_profile'])}</ipsec-crypto-profile>"
        f"<proxy-id>{pids}</proxy-id></auto-key>"
        f"{mon}<tunnel-interface>{_esc(d['interface'])}</tunnel-interface></entry>")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _tunnel_for_gateway(st: DeviceState, gw: Optional[str]) -> Optional[str]:
    if not gw:
        return None
    return next((n for n, t in st.tunnels.items() if t.get("gateway") == gw), None)


def _net30(ip: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    if not ip:
        return None
    try:
        return ipaddress.ip_network(f"{ipaddress.ip_interface(ip).ip}/30", strict=False)
    except ValueError:
        return None


def _other_host(ip: str) -> Optional[str]:
    net = _net30(ip)
    if not net:
        return None
    mine = ipaddress.ip_interface(ip).ip
    other = next((h for h in net.hosts() if h != mine), None)
    return f"{other}/30" if other else None


def _norm(v: Any) -> Any:
    if isinstance(v, (set, frozenset, list, tuple)):
        return frozenset(tuple(x) if isinstance(x, list) else x for x in v)
    return v


def _describe_change(k: str, have: Any, want: Any) -> str:
    if isinstance(want, (set, frozenset)):
        have = have or frozenset()
        add = sorted(set(want) - set(have))
        rem = sorted(set(have) - set(want))
        parts = []
        if add:
            parts.append("+ " + ", ".join(f"{l}->{r}" for l, r in add))
        if rem:
            parts.append("- " + ", ".join(f"{l}->{r}" for l, r in rem))
        return f"{k}: " + "; ".join(parts)
    return f"{k}: {have if have is not None else '(none)'} -> {want if want is not None else '(none)'}"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_C = {"create": "\033[32m", "update": "\033[33m", "blocked": "\033[1;31m", "dim": "\033[2m", "bold": "\033[1m"}
_R = "\033[0m"


def format_plan(planner: TunnelPlanner, color: bool = False, show_xml: bool = False) -> str:
    c = (lambda k, s: f"{_C[k]}{s}{_R}") if color else (lambda k, s: s)
    dps = sorted(planner.device_plans.values(), key=lambda d: d.device)
    n_create = sum(1 for d in dps for a in d.actions if a.op == "create")
    n_update = sum(1 for d in dps for a in d.actions if a.op == "update")
    out = [c("bold", "Site-to-site VPN plan (read-only, nothing has been sent)"),
           f"  {c('create', f'+{n_create} create')}   {c('update', f'~{n_update} update')}   "
           f"{sum(d.unchanged for d in dps)} unchanged   across {sum(1 for d in dps if d.actions)} device(s)", ""]
    for d in dps:
        if not (d.actions or d.unmanaged or d.blocked):
            continue
        out.append(c("bold", f"== {d.device}") + f"  ({d.site}, {len(d.actions)} change(s), {d.unchanged} unchanged)")
        for r in d.blocked:
            out.append(c("blocked", f"   BLOCKED: {r}"))
        for a in d.actions:
            sym = "+" if a.op == "create" else "~"
            out.append(f"   {c(a.op, sym + ' ' + a.op.ljust(6))} {a.kind:<16} {a.name}   {c('dim', a.link)}")
            for ch in a.changes:
                out.append(c("dim", f"        {ch}"))
            if show_xml:
                out.append(c("dim", f"        {a.api_action} {a.xpath}"))
                out.append(c("dim", f"        {a.redacted_element()}"))
        for u in d.unmanaged:
            out.append(c("dim", f"   ? unmanaged    {u}  (not in inventory; left untouched)"))
        for n in sorted(set(d.notes)):
            out.append(c("dim", f"   note: {n}"))
        out.append("")
    return "\n".join(out)


def plan_to_json(planner: TunnelPlanner) -> List[dict]:
    out = []
    for d in sorted(planner.device_plans.values(), key=lambda x: x.device):
        dd = asdict(d)
        for a, src in zip(dd["actions"], d.actions):
            a["element"] = src.redacted_element()
        out.append(dd)
    return out


# ---------------------------------------------------------------------------
# CLI: python -m s2s_vpn.planner --demo [--xml] [--json]
# ---------------------------------------------------------------------------

def demo_states(inv: Dict[str, Any]) -> Dict[str, DeviceState]:
    devices = ((inv.get("observed") or {}).get("devices") or {})
    return {h: DeviceState.from_observed(h, b) for h, b in devices.items()}


def main(argv: Optional[List[str]] = None) -> int:
    from .auditor import Auditor            # local import: the auditor is only needed for blockers
    ap = argparse.ArgumentParser(description="Plan site-to-site VPN changes (read-only).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--demo", action="store_true", help=f"plan against the fictional {DEMO_INVENTORY.name}")
    src.add_argument("--inventory", metavar="YAML", help="real inventory (sites, links, standards)")
    ap.add_argument("--exports", metavar="DIR", help="current-state exports to diff against (with --inventory)")
    ap.add_argument("--xml", action="store_true", help="show xpath + (redacted) element for each action")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = ap.parse_args(argv)

    if args.demo:
        inv = miniyaml.load(DEMO_INVENTORY)
        states = demo_states(inv)
        findings = Auditor.from_inventory(DEMO_INVENTORY).run()
    else:
        inv = miniyaml.load(args.inventory)
        states = {}
        findings = []
        if args.exports:
            fws, _, _ = parse_directory(args.exports)
            states = {h: DeviceState.from_firewall(fw) for h, fw in fws.items()}
            findings = Auditor.from_exports(args.exports, inventory=args.inventory).run()
    blocked: Dict[str, List[str]] = {}
    for f in findings:
        if f.code == "HA_OUT_OF_SYNC":
            blocked.setdefault(f.subject, []).append("HA members out of sync: " + f.message.split(";")[0])
    planner = TunnelPlanner(inv)
    planner.build_device_plans(states, blocked=blocked)
    if args.json:
        print(json.dumps(plan_to_json(planner), indent=1, default=sorted))
    else:
        import os
        color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))
        print(format_plan(planner, color=color, show_xml=args.xml))
    return 0


if __name__ == "__main__":
    sys.exit(main())
