"""
Address, service and application resolution for offline policy simulation.

Every match answers with one of four values:

* ``FULL``: the whole queried IP/subnet/port is covered.
* ``PARTIAL``: only part of a queried subnet is covered (some hosts match).
* ``UNKNOWN``: it depends on something not knowable from config alone
  (FQDN objects, dynamic address groups, EDLs, App-ID, users, URL categories).
* ``NONE``: definitely no match.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from common.parser import _entries, _members, _text

FULL, PARTIAL, UNKNOWN, NONE = "full", "partial", "unknown", "none"

#: (ip version, first address, last address) as integers.
Interval = Tuple[int, int, int]


# ---------------------------------------------------------------------------
# IP intervals
# ---------------------------------------------------------------------------

def parse_target(value: str) -> Interval:
    """Parse ``10.1.1.5``, ``10.1.1.0/24``, ``10.1.1.0/255.255.255.0`` or ``10.1.1.1-10.1.1.9``."""
    value = value.strip()
    if "-" in value and "/" not in value:
        a, b = (ipaddress.ip_address(x.strip()) for x in value.split("-", 1))
        if a.version != b.version or int(b) < int(a):
            raise ValueError(f"invalid IP range: {value}")
        return (a.version, int(a), int(b))
    net = ipaddress.ip_network(value, strict=False)
    return (net.version, int(net.network_address), int(net.broadcast_address))


def try_target(value: Optional[str]) -> Optional[Interval]:
    if not value:
        return None
    try:
        return parse_target(value)
    except ValueError:
        return None


def interval_str(iv: Interval) -> str:
    v, lo, hi = iv
    a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
    if lo == hi:
        return str(a)
    nets = list(ipaddress.summarize_address_range(a, b))
    return str(nets[0]) if len(nets) == 1 else f"{a}-{b}"


def first_ip(iv: Interval) -> str:
    return str(ipaddress.ip_address(iv[1]))


def contains(outer: Interval, inner: Interval) -> bool:
    return outer[0] == inner[0] and outer[1] <= inner[1] and inner[2] <= outer[2]


def overlaps(a: Interval, b: Interval) -> bool:
    return a[0] == b[0] and a[1] <= b[2] and b[1] <= a[2]


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                    "100.64.0.0/10", "fc00::/7")]


def is_private(iv: Interval) -> bool:
    """RFC 1918 / CGNAT / ULA space, i.e. addresses that need source NAT to reach the internet."""
    ip = ipaddress.ip_address(iv[1])
    return any(ip.version == n.version and ip in n for n in _INTERNAL_NETS)


def coverage(intervals: Iterable[Interval], target: Interval) -> str:
    """Return FULL / PARTIAL / NONE for how much of *target* the union of *intervals* covers."""
    v, lo, hi = target
    spans = sorted((a, b) for (ver, a, b) in intervals if ver == v and a <= hi and b >= lo)
    covered, cur = 0, lo
    for a, b in spans:
        a = max(a, cur)
        if a > hi:
            break
        if b >= a:
            covered += min(b, hi) - a + 1
            cur = min(b, hi) + 1
    if covered == 0:
        return NONE
    return FULL if covered >= hi - lo + 1 else PARTIAL


def negate(result: str) -> str:
    return {FULL: NONE, NONE: FULL}.get(result, result)


# ---------------------------------------------------------------------------
# Resolved sets
# ---------------------------------------------------------------------------

@dataclass
class AddrSet:
    any: bool = False
    intervals: List[Interval] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)   # FQDNs, dynamic groups, EDLs, unknown names

    def relation(self, target: Interval) -> str:
        if self.any:
            return FULL
        r = coverage(self.intervals, target)
        if r == FULL:
            return FULL
        if self.unresolved:
            return UNKNOWN if r == NONE else PARTIAL
        return r


@dataclass
class PortSpec:
    protocol: str                       # tcp | udp | sctp
    ranges: List[Tuple[int, int]]

    def __str__(self) -> str:
        return self.protocol + "/" + ",".join(str(a) if a == b else f"{a}-{b}" for a, b in self.ranges)


@dataclass
class ServiceSet:
    any: bool = False
    app_default: bool = False
    ports: List[PortSpec] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)

    def relation(self, protocol: Optional[str], port: Optional[int], app: Optional[str] = None,
                 rule_apps: Optional[List[str]] = None) -> str:
        """*rule_apps* lets ``application-default`` rule out ports when the flow's app is unknown."""
        if self.any:
            return FULL
        found = NONE
        if self.app_default:
            found = _app_default(app, protocol, port)
            if app is None and rule_apps and "any" not in rule_apps:
                per_app = [_app_default(a, protocol, port) for a in rule_apps]
                found = NONE if all(r == NONE for r in per_app) else UNKNOWN
        if protocol is not None and protocol not in ("tcp", "udp", "sctp"):
            return found                # port-based services never match ICMP/ESP/...
        if protocol is None or port is None:
            return found if found == FULL else (UNKNOWN if self.ports or self.unresolved or self.app_default
                                                else NONE)
        for spec in self.ports:
            if spec.protocol == protocol and any(a <= port <= b for a, b in spec.ranges):
                return FULL
        if found != NONE:
            return found
        return UNKNOWN if self.unresolved else NONE


# A small table of App-ID default ports, enough to judge "application-default" for common apps.
# Anything else is reported as UNKNOWN rather than guessed.
APP_DEFAULT_PORTS: Dict[str, List[Tuple[str, int, int]]] = {
    "web-browsing": [("tcp", 80, 80)], "ssl": [("tcp", 443, 443)], "http2": [("tcp", 80, 80), ("tcp", 443, 443)],
    "quic": [("udp", 443, 443), ("udp", 80, 80)], "ssh": [("tcp", 22, 22)], "telnet": [("tcp", 23, 23)],
    "dns": [("tcp", 53, 53), ("udp", 53, 53)], "dns-base": [("tcp", 53, 53), ("udp", 53, 53)],
    "ntp": [("udp", 123, 123)], "snmp": [("udp", 161, 162)], "syslog": [("udp", 514, 514), ("tcp", 514, 514)],
    "smtp": [("tcp", 25, 25), ("tcp", 587, 587)], "imap": [("tcp", 143, 143)], "pop3": [("tcp", 110, 110)],
    "ldap": [("tcp", 389, 389), ("udp", 389, 389)], "kerberos": [("tcp", 88, 88), ("udp", 88, 88)],
    "ms-rdp": [("tcp", 3389, 3389), ("udp", 3389, 3389)], "ms-ds-smb": [("tcp", 445, 445), ("tcp", 139, 139)],
    "mssql-db": [("tcp", 1433, 1433)], "mysql": [("tcp", 3306, 3306)], "postgres": [("tcp", 5432, 5432)],
    "oracle": [("tcp", 1521, 1521)], "ftp": [("tcp", 21, 21)], "radius": [("udp", 1812, 1813)],
    "ike": [("udp", 500, 500), ("udp", 4500, 4500)], "ipsec-esp-udp": [("udp", 4500, 4500)],
    "bgp": [("tcp", 179, 179)], "dhcp": [("udp", 67, 68)], "tftp": [("udp", 69, 69)],
}
_PORTLESS_APPS = {"ping", "icmp", "traceroute", "ipsec-esp", "ospf", "gre"}


def _app_default(app: Optional[str], protocol: Optional[str], port: Optional[int]) -> str:
    if not app or app in ("any", "incomplete", "unknown-tcp", "unknown-udp", "not-applicable"):
        return UNKNOWN
    if app in _PORTLESS_APPS:
        return FULL if protocol in (None, "icmp", "icmp6") or port in (None, 0) else NONE
    table = APP_DEFAULT_PORTS.get(app)
    if table is None:
        return UNKNOWN
    if protocol is None or port is None:
        return UNKNOWN
    return FULL if any(p == protocol and a <= port <= b for p, a, b in table) else NONE


# Predefined service objects
_PREDEFINED_SERVICES: Dict[str, List[PortSpec]] = {
    "service-http": [PortSpec("tcp", [(80, 80), (8080, 8080)])],
    "service-https": [PortSpec("tcp", [(443, 443)])],
}


def parse_ports(text: Optional[str]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for part in re.split(r"[,\s]+", text or ""):
        if not part:
            continue
        a, _, b = part.partition("-")
        try:
            out.append((int(a), int(b or a)))
        except ValueError:
            continue
    return out


# ---------------------------------------------------------------------------
# Object store
# ---------------------------------------------------------------------------

class ObjectStore:
    """Named objects from one or more scopes, searched in order (vsys first, then shared)."""

    def __init__(self, scopes: Sequence[Optional[ET.Element]]):
        self.addresses: Dict[str, Tuple[str, str]] = {}           # name -> (kind, value)
        self.address_groups: Dict[str, Optional[List[str]]] = {}   # None = dynamic group
        self.services: Dict[str, List[PortSpec]] = dict(_PREDEFINED_SERVICES)
        self.service_groups: Dict[str, List[str]] = {}
        self.app_groups: Dict[str, List[str]] = {}
        self.app_filters: set = set()
        self.edls: Dict[str, str] = {}                              # name -> type
        self.regions: Dict[str, List[str]] = {}
        for scope in reversed([s for s in scopes if s is not None]):   # first scope wins
            self._load(scope)

    def _load(self, scope: ET.Element) -> None:
        for a in _entries(scope, "address"):
            for kind in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
                v = _text(a, kind)
                if v:
                    self.addresses[a.get("name", "")] = (kind, v)
                    break
        for g in _entries(scope, "address-group"):
            self.address_groups[g.get("name", "")] = (None if g.find("dynamic") is not None
                                                      else _members(g, "static"))
        for s in _entries(scope, "service"):
            specs = []
            proto_el = s.find("protocol")
            for proto in ("tcp", "udp", "sctp"):
                ranges = parse_ports(_text(proto_el, f"{proto}/port"))
                if ranges:
                    specs.append(PortSpec(proto, ranges))
            self.services[s.get("name", "")] = specs
        for g in _entries(scope, "service-group"):
            self.service_groups[g.get("name", "")] = _members(g, "members")
        for g in _entries(scope, "application-group"):
            self.app_groups[g.get("name", "")] = _members(g, "members")
        self.app_filters.update(_n.get("name", "") for _n in _entries(scope, "application-filter"))
        for e in _entries(scope, "external-list"):
            t = e.find("type")
            self.edls[e.get("name", "")] = t[0].tag if t is not None and len(t) else "ip"
        for r in _entries(scope, "region"):
            self.regions[r.get("name", "")] = _members(r, "address")

    # -- addresses ----------------------------------------------------------
    def resolve_addresses(self, members: Iterable[str]) -> AddrSet:
        out = AddrSet()
        for m in members:
            if m == "any":
                return AddrSet(any=True)
            self._resolve_one(m, out, depth=0)
        return out

    def _resolve_one(self, name: str, out: AddrSet, depth: int) -> None:
        if depth > 16:
            out.unresolved.append(f"{name} (group nesting too deep)")
            return
        if name in self.addresses:
            kind, value = self.addresses[name]
            iv = try_target(value) if kind in ("ip-netmask", "ip-range") else None
            if iv:
                out.intervals.append(iv)
            else:
                out.unresolved.append(f"{name} ({kind} {value})")
            return
        if name in self.address_groups:
            members = self.address_groups[name]
            if members is None:
                out.unresolved.append(f"{name} (dynamic address group)")
                return
            for m in members:
                self._resolve_one(m, out, depth + 1)
            return
        if name in self.edls:
            out.unresolved.append(f"{name} (external dynamic list)")
            return
        if name in self.regions:
            for v in self.regions[name]:
                iv = try_target(v)
                if iv:
                    out.intervals.append(iv)
            return
        iv = try_target(name)
        if iv:
            out.intervals.append(iv)
        elif re.match(r"^[A-Z]{2}$", name):
            out.unresolved.append(f"{name} (country/region)")
        else:
            out.unresolved.append(f"{name} (unknown object)")

    def address_value(self, name: Optional[str]) -> Optional[Interval]:
        """Resolve a single object or literal to one interval (used for routes and NAT translations)."""
        if not name:
            return None
        if name in self.addresses:
            kind, value = self.addresses[name]
            return try_target(value) if kind in ("ip-netmask", "ip-range") else None
        return try_target(name)

    # -- services -----------------------------------------------------------
    def resolve_services(self, members: Iterable[str]) -> ServiceSet:
        out = ServiceSet()
        for m in members:
            if m == "any":
                return ServiceSet(any=True)
            if m == "application-default":
                out.app_default = True
                continue
            self._resolve_service(m, out, 0)
        return out

    def _resolve_service(self, name: str, out: ServiceSet, depth: int) -> None:
        if name in self.services:
            out.ports.extend(self.services[name])
        elif name in self.service_groups and depth < 16:
            for m in self.service_groups[name]:
                self._resolve_service(m, out, depth + 1)
        else:
            out.unresolved.append(name)

    # -- applications -------------------------------------------------------
    def app_relation(self, members: List[str], app: Optional[str]) -> str:
        if not members or "any" in members:
            return FULL
        if not app:
            return UNKNOWN
        expanded, opaque = self._expand_apps(members)
        if app in expanded:
            return FULL
        return UNKNOWN if opaque else NONE

    def _expand_apps(self, members: Iterable[str], depth: int = 0) -> Tuple[set, bool]:
        apps, opaque = set(), False
        for m in members:
            if m in self.app_groups and depth < 16:
                sub, o = self._expand_apps(self.app_groups[m], depth + 1)
                apps |= sub
                opaque = opaque or o
            elif m in self.app_filters:
                opaque = True
            else:
                apps.add(m)
        return apps, opaque
