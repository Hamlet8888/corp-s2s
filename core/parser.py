"""
Parse Palo Alto Networks firewall and Panorama configuration exports.

Two export formats are supported:

* **XML**: ``show config running`` via the XML API, or a saved config file.
  Both ``<response><result><config>`` and bare ``<config>`` roots are accepted.
* **Brace**: the hierarchical text that the CLI prints for
  ``show config running`` (``config { devices { ... } }``).

Brace exports are converted to the same XML tree, so a single extractor
handles both formats.

Security model
--------------
Exports can contain pre-shared keys, password hashes, RADIUS/SNMP secrets
and private keys. As soon as a tree is loaded, :func:`strip_secrets` removes
every secret leaf (see ``SECRET_TAGS``), so no code downstream of
:func:`load_config` can read them. The extracted model records only whether
a secret was present (for example ``IkeGateway.has_psk``), never its value.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Secrets handling
# ---------------------------------------------------------------------------

#: Element tags whose text is a secret (exact match). Their text is removed on load.
SECRET_TAGS: frozenset = frozenset({
    "key", "phash", "password", "secret", "private-key",
    "authcode", "api-key", "passphrase", "shared-secret", "psk",
    "authpwd", "privpwd", "community", "auth-password", "priv-password",
    "public-key", "otp-secret", "bind-password",
})

#: Marker attribute left on an element whose secret was removed.
REDACTED_ATTR = "redacted"


def strip_secrets(root: ET.Element) -> int:
    """Remove the text (and any children) of every secret element in place.

    Returns the number of elements redacted. The element itself is kept and
    tagged ``redacted="yes"``, so callers can still tell a secret was set.
    """
    count = 0
    for el in root.iter():
        if el.tag in SECRET_TAGS and ((el.text or "").strip() or len(el)):
            el.text = None
            for child in list(el):
                el.remove(child)
            el.set(REDACTED_ATTR, "yes")
            count += 1
    return count


# ---------------------------------------------------------------------------
# Format detection and loading
# ---------------------------------------------------------------------------

def detect_format(path: Path) -> str:
    """Return ``'xml'`` or ``'brace'`` by sniffing the first bytes of *path*."""
    with open(path, "rb") as fh:
        head = fh.read(512).lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<"):
        return "xml"
    if re.match(rb"^[A-Za-z0-9_.\-\"]+\s*\{", head):
        return "brace"
    raise ValueError(f"{path}: unrecognised config export format")


def load_config(path) -> Tuple[ET.Element, str]:
    """Load an export and return ``(config_root, fmt)`` with secrets stripped.

    ``config_root`` is the ``<config>`` element in both formats.
    """
    path = Path(path)
    fmt = detect_format(path)
    if fmt == "xml":
        root = ET.parse(path).getroot()
        cfg = root if root.tag == "config" else root.find(".//config")
        if cfg is None:
            raise ValueError(f"{path}: no <config> element found")
    else:
        cfg = brace_to_xml(path.read_text(encoding="utf-8", errors="replace"))
    strip_secrets(cfg)
    return cfg, fmt


# ---------------------------------------------------------------------------
# Brace ("show config") format -> XML
# ---------------------------------------------------------------------------

# In XML, list members are <entry name="...">. Brace output drops the
# "entry" wrapper and uses the name as the key (`ethernet1/1 { ... }`), so we
# must know which containers hold lists. Paths are relative to a device or
# template root; '*' stands for one list entry. This is PAN-OS schema
# knowledge, not site data.
_LIST_PATHS_DEVICE: frozenset = frozenset({
    "/network/ike/crypto-profiles/ike-crypto-profiles",
    "/network/ike/crypto-profiles/ipsec-crypto-profiles",
    "/network/ike/crypto-profiles/global-protect-app-crypto-profiles",
    "/network/ike/gateway",
    "/network/interface/ethernet",
    "/network/interface/ethernet/*/layer3/ip",
    "/network/interface/ethernet/*/layer3/units",
    "/network/interface/ethernet/*/layer3/units/*/ip",
    "/network/interface/ethernet/*/layer2/units",
    "/network/interface/aggregate-ethernet",
    "/network/interface/aggregate-ethernet/*/layer3/ip",
    "/network/interface/aggregate-ethernet/*/layer3/units",
    "/network/interface/aggregate-ethernet/*/layer3/units/*/ip",
    "/network/interface/aggregate-ethernet/*/layer2/units",
    "/network/interface/loopback/units",
    "/network/interface/loopback/units/*/ip",
    "/network/interface/tunnel/units",
    "/network/interface/tunnel/units/*/ip",
    "/network/interface/vlan/units",
    "/network/interface/vlan/units/*/ip",
    "/network/profiles/monitor-profile",
    "/network/profiles/interface-management-profile",
    "/network/tunnel/ipsec",
    "/network/tunnel/ipsec/*/auto-key/ike-gateway",
    "/network/tunnel/ipsec/*/auto-key/proxy-id",
    "/network/virtual-router",
    "/network/virtual-router/*/routing-table/ip/static-route",
    "/network/virtual-router/*/routing-table/ip/static-route/*/path-monitor/monitor-destinations",
    "/network/virtual-router/*/protocol/bgp/peer-group",
    "/network/virtual-router/*/protocol/bgp/peer-group/*/peer",
    "/network/logical-router",
    "/vsys",
    "/vsys/*/zone",
    "/vsys/*/address",
    "/vsys/*/address-group",
    "/vsys/*/rulebase/security/rules",
    "/vsys/*/rulebase/nat/rules",
})
_LIST_PATHS_TOP: frozenset = frozenset({"/devices", "/shared/address", "/shared/address-group"})

_VALID_TAG = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{};\[\]]|[^\s{};\[\]"]+')


def _is_list_path(path: str) -> bool:
    if path in _LIST_PATHS_TOP:
        return True
    # Strip a leading /devices/* (firewall) so device-relative paths match.
    if path.startswith("/devices/*"):
        return path[len("/devices/*"):] in _LIST_PATHS_DEVICE
    return False


def _tokens(text: str) -> Iterator[str]:
    for m in _TOKEN.finditer(text):
        tok = m.group(0)
        if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
            yield tok[1:-1].replace('\\"', '"')
        else:
            yield tok


class _ListValue(list):
    """Marker for a bracketed ``[ a b c ]`` value."""


def brace_to_xml(text: str) -> ET.Element:
    """Convert PAN-OS brace-format config text to a ``<config>`` element.

    Rules:
      * ``key { ... }`` becomes ``<key>...</key>``, or ``<entry name="key">`` when the
        parent is a known list container, or when *key* is not a valid XML tag
        (e.g. ``ethernet1/1``, ``10.1.1.1/24``).
      * ``key value;`` becomes ``<key>value</key>``.
      * ``key [ a b ];`` becomes ``<key><member>a</member>...``, or entries for list paths.
      * A bare ``name;`` inside a list container becomes ``<entry name="name"/>``.
    """
    root = ET.Element("config")
    stack: List[Tuple[ET.Element, str]] = [(root, "")]
    buf: list = []
    it = _tokens(text)
    for tok in it:
        parent, ppath = stack[-1]
        if tok == "{":
            if not buf:
                raise ValueError("brace format: '{' without a key")
            name = buf[-1]
            buf = []
            if name == "config" and parent is root and ppath == "":
                stack.append((root, ""))      # outer `config { ... }` wrapper
                continue
            if _is_list_path(ppath) or not _VALID_TAG.match(name):
                el = ET.SubElement(parent, "entry", name=name)
                npath = ppath + "/*"
            else:
                el = ET.SubElement(parent, name)
                npath = ppath + "/" + name
            stack.append((el, npath))
        elif tok == "}":
            if len(stack) > 1:
                stack.pop()
            buf = []
        elif tok == "[":
            items = _ListValue()
            for x in it:
                if x == "]":
                    break
                items.append(x)
            buf.append(items)
        elif tok == ";":
            if not buf:
                continue
            key, rest = buf[0], buf[1:]
            buf = []
            if isinstance(key, _ListValue):        # `[ a b ];` with no key: ignore
                continue
            in_list = _is_list_path(ppath)
            if not rest:
                if in_list or not _VALID_TAG.match(key):
                    ET.SubElement(parent, "entry", name=key)
                else:
                    ET.SubElement(parent, key)
                continue
            kpath = ppath + "/" + key
            el = (ET.SubElement(parent, "entry", name=key)
                  if not _VALID_TAG.match(key) else ET.SubElement(parent, key))
            if isinstance(rest[0], _ListValue):
                child_tag = "entry" if _is_list_path(kpath) else "member"
                for v in rest[0]:
                    if child_tag == "entry":
                        ET.SubElement(el, "entry", name=v)
                    else:
                        ET.SubElement(el, "member").text = v
            else:
                el.text = " ".join(str(x) for x in rest)
        else:
            buf.append(tok)
    return root


# ---------------------------------------------------------------------------
# Small XML helpers
# ---------------------------------------------------------------------------

def _text(el: Optional[ET.Element], path: str) -> Optional[str]:
    if el is None:
        return None
    x = el.find(path)
    if x is None or x.get(REDACTED_ATTR):
        return None
    t = (x.text or "").strip()
    return t or None


def _members(el: Optional[ET.Element], path: str) -> List[str]:
    """Return ``<member>`` values; also accepts a single-value leaf (brace format)."""
    if el is None:
        return []
    x = el.find(path)
    if x is None:
        return []
    vals = [(m.text or "").strip() for m in x.findall("member")]
    if vals:
        return [v for v in vals if v]
    t = (x.text or "").strip()
    return [t] if t else []


def _entries(el: Optional[ET.Element], path: str) -> List[ET.Element]:
    return [] if el is None else el.findall(path + "/entry")


def _names(el: Optional[ET.Element], path: str) -> List[str]:
    return [e.get("name", "") for e in _entries(el, path)]


def _first_child_tag(el: Optional[ET.Element], allowed: Iterable[str] = ()) -> Optional[str]:
    if el is None:
        return None
    allowed = set(allowed)
    for c in el:
        if not allowed or c.tag in allowed:
            return c.tag
    return None


def _yes(v: Optional[str]) -> Optional[bool]:
    return None if v is None else v.lower() == "yes"


def _lifetime(el: Optional[ET.Element]) -> Dict[str, int]:
    lt = el.find("lifetime") if el is not None else None
    out: Dict[str, int] = {}
    if lt is not None:
        for c in lt:
            try:
                out[c.tag] = int((c.text or "").strip())
            except ValueError:
                pass
    return out


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Interface:
    name: str
    kind: str                         # ethernet | aggregate-ethernet | subinterface | tunnel | loopback | vlan
    ips: List[str] = field(default_factory=list)
    dhcp: bool = False
    comment: Optional[str] = None
    mgmt_profile: Optional[str] = None
    mtu: Optional[int] = None

    @property
    def unit(self) -> Optional[int]:
        """The numeric unit of a logical interface (``tunnel.31`` -> 31)."""
        m = re.match(r"^[a-z]+\.(\d+)$", self.name)
        return int(m.group(1)) if m else None


@dataclass
class Zone:
    name: str
    vsys: str
    type: Optional[str]
    interfaces: List[str] = field(default_factory=list)


@dataclass
class StaticRoute:
    name: str
    vr: str
    destination: Optional[str]        # CIDR or address-object name
    interface: Optional[str]
    nexthop_type: Optional[str]       # ip-address | next-vr | fqdn | discard | None
    nexthop: Optional[str]
    metric: Optional[int]
    path_monitor: bool = False


@dataclass
class VirtualRouter:
    name: str
    interfaces: List[str] = field(default_factory=list)
    static_routes: List[StaticRoute] = field(default_factory=list)
    bgp_enabled: bool = False
    ospf_enabled: bool = False


@dataclass
class IkeCryptoProfile:
    name: str
    encryption: List[str]
    hash: List[str]
    dh_group: List[str]
    lifetime: Dict[str, int]

    def signature(self) -> Tuple:
        """Return the parameters that must match between two IKE peers (lifetime excluded)."""
        return (tuple(sorted(self.encryption)), tuple(sorted(self.hash)), tuple(sorted(self.dh_group)))


@dataclass
class IpsecCryptoProfile:
    name: str
    encryption: List[str]
    authentication: List[str]
    dh_group: Optional[str]
    lifetime: Dict[str, int]

    def signature(self) -> Tuple:
        """Return the parameters that must match between two IPsec peers (lifetime excluded)."""
        return (tuple(sorted(self.encryption)), tuple(sorted(self.authentication)), self.dh_group)


#: PAN-OS built-in "default" profiles, used when a gateway/tunnel references none.
DEFAULT_IKE = IkeCryptoProfile("default", ["aes-128-cbc", "3des"], ["sha1"], ["group2"], {"hours": 8})
DEFAULT_IPSEC = IpsecCryptoProfile("default", ["aes-128-cbc", "3des"], ["sha1"], "group2", {"hours": 1})


@dataclass
class Identity:
    type: Optional[str]
    id: Optional[str]


@dataclass
class IkeGateway:
    name: str
    version: str                      # ikev1 | ikev2 | ikev2-preferred
    local_interface: Optional[str]
    local_ip: Optional[str]
    peer_type: Optional[str]          # ip | fqdn | dynamic
    peer: Optional[str]               # IP, FQDN or address-object name
    auth: Optional[str]               # pre-shared-key | certificate
    has_psk: bool
    local_id: Optional[Identity]
    peer_id: Optional[Identity]
    ike_crypto_profile: Optional[str]  # the profile for the active version
    nat_traversal: Optional[bool]
    passive: Optional[bool]
    dpd: Optional[bool]
    disabled: bool = False
    comment: Optional[str] = None


@dataclass
class ProxyId:
    name: str
    local: Optional[str]
    remote: Optional[str]
    protocol: Optional[str] = "any"


@dataclass
class IpsecTunnel:
    name: str
    tunnel_interface: Optional[str]
    gateways: List[str]
    ipsec_crypto_profile: Optional[str]
    proxy_ids: List[ProxyId]
    manual_key: bool = False
    monitor_enabled: bool = False
    monitor_destination: Optional[str] = None
    monitor_profile: Optional[str] = None
    disabled: bool = False
    comment: Optional[str] = None


@dataclass
class HAConfig:
    enabled: bool
    group_id: Optional[str] = None
    mode: Optional[str] = None
    peer_ip: Optional[str] = None
    priority: Optional[str] = None
    preemptive: Optional[bool] = None


@dataclass
class FirewallConfig:
    hostname: Optional[str]
    source_file: str
    source_format: str
    sw_version: Optional[str] = None
    ha: Optional[HAConfig] = None
    interfaces: List[Interface] = field(default_factory=list)
    zones: List[Zone] = field(default_factory=list)
    virtual_routers: List[VirtualRouter] = field(default_factory=list)
    ike_crypto: Dict[str, IkeCryptoProfile] = field(default_factory=dict)
    ipsec_crypto: Dict[str, IpsecCryptoProfile] = field(default_factory=dict)
    ike_gateways: List[IkeGateway] = field(default_factory=list)
    ipsec_tunnels: List[IpsecTunnel] = field(default_factory=list)
    monitor_profiles: List[str] = field(default_factory=list)
    addresses: Dict[str, str] = field(default_factory=dict)

    # -- lookups --------------------------------------------------------
    def interface(self, name: str) -> Optional[Interface]:
        return next((i for i in self.interfaces if i.name == name), None)

    def zone_of(self, interface: str) -> Optional[str]:
        return next((z.name for z in self.zones if interface in z.interfaces), None)

    def vr_of(self, interface: str) -> Optional[str]:
        return next((v.name for v in self.virtual_routers if interface in v.interfaces), None)

    def gateway(self, name: str) -> Optional[IkeGateway]:
        return next((g for g in self.ike_gateways if g.name == name), None)

    def tunnel_for_gateway(self, gw_name: str) -> Optional[IpsecTunnel]:
        return next((t for t in self.ipsec_tunnels if gw_name in t.gateways), None)

    def resolve(self, value: Optional[str]) -> Optional[str]:
        """Resolve an address-object name to its value; IPs/CIDRs pass through."""
        if value is None:
            return None
        if _is_ip_or_cidr(value):
            return value
        return self.addresses.get(value, value)

    def gateway_peer_ip(self, gw: IkeGateway) -> Optional[str]:
        """Best-effort peer public IP: the peer-id when it's an IP, else the resolved peer address."""
        for cand in ((gw.peer_id.id if gw.peer_id else None), gw.peer):
            r = self.resolve(cand) if cand else None
            if r and _is_ip_or_cidr(r):
                return r.split("/")[0]
        return gw.peer

    def ike_profile(self, name: Optional[str], extra: Optional[Dict[str, IkeCryptoProfile]] = None) -> Optional[IkeCryptoProfile]:
        """Look up an IKE profile locally, then in *extra* (e.g. Panorama templates)."""
        if name is None:
            return DEFAULT_IKE
        return self.ike_crypto.get(name) or (extra or {}).get(name)

    def ipsec_profile(self, name: Optional[str], extra: Optional[Dict[str, IpsecCryptoProfile]] = None) -> Optional[IpsecCryptoProfile]:
        """Look up an IPsec profile locally, then in *extra* (e.g. Panorama templates)."""
        if name is None:
            return DEFAULT_IPSEC
        return self.ipsec_crypto.get(name) or (extra or {}).get(name)

    def used_tunnel_units(self) -> Set[int]:
        return {i.unit for i in self.interfaces if i.kind == "tunnel" and i.unit is not None}

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TemplateConfig:
    name: str
    ike_crypto: Dict[str, IkeCryptoProfile] = field(default_factory=dict)
    ipsec_crypto: Dict[str, IpsecCryptoProfile] = field(default_factory=dict)
    monitor_profiles: List[str] = field(default_factory=list)
    ike_gateways: List[IkeGateway] = field(default_factory=list)
    ipsec_tunnels: List[IpsecTunnel] = field(default_factory=list)


@dataclass
class PanoramaConfig:
    source_file: str
    source_format: str
    managed_serials: List[str] = field(default_factory=list)
    device_groups: Dict[str, List[str]] = field(default_factory=dict)       # name -> serials
    template_stacks: Dict[str, dict] = field(default_factory=dict)          # name -> {templates, devices}
    templates: Dict[str, TemplateConfig] = field(default_factory=dict)

    def crypto_catalog(self) -> Tuple[Dict[str, IkeCryptoProfile], Dict[str, IpsecCryptoProfile]]:
        """Merge every template's crypto profiles (name -> profile)."""
        ike: Dict[str, IkeCryptoProfile] = {}
        ipsec: Dict[str, IpsecCryptoProfile] = {}
        for t in self.templates.values():
            ike.update(t.ike_crypto)
            ipsec.update(t.ipsec_crypto)
        return ike, ipsec

    def to_dict(self) -> dict:
        return asdict(self)


def _is_ip_or_cidr(v: str) -> bool:
    try:
        ipaddress.ip_interface(v)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Extractors (operate on a device or template root: <entry name="localhost.localdomain">)
# ---------------------------------------------------------------------------

def _parse_interfaces(net: ET.Element) -> List[Interface]:
    out: List[Interface] = []
    for kind in ("ethernet", "aggregate-ethernet"):
        for e in _entries(net, f"interface/{kind}"):
            l3 = e.find("layer3")
            out.append(Interface(
                name=e.get("name", ""), kind=kind,
                ips=_names(l3, "ip"), dhcp=l3 is not None and l3.find("dhcp-client") is not None,
                comment=_text(e, "comment"), mgmt_profile=_text(l3, "interface-management-profile"),
                mtu=_int(_text(l3, "mtu"))))
            for u in _entries(l3, "units"):
                out.append(Interface(
                    name=u.get("name", ""), kind="subinterface", ips=_names(u, "ip"),
                    dhcp=u.find("dhcp-client") is not None, comment=_text(u, "comment"),
                    mgmt_profile=_text(u, "interface-management-profile"), mtu=_int(_text(u, "mtu"))))
    for kind in ("tunnel", "loopback", "vlan"):
        for u in _entries(net, f"interface/{kind}/units"):
            out.append(Interface(
                name=u.get("name", ""), kind=kind, ips=_names(u, "ip"),
                comment=_text(u, "comment"), mgmt_profile=_text(u, "interface-management-profile"),
                mtu=_int(_text(u, "mtu"))))
    return out


def _int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def _parse_vrs(net: ET.Element) -> List[VirtualRouter]:
    vrs: List[VirtualRouter] = []
    for v in _entries(net, "virtual-router"):
        vr = VirtualRouter(
            name=v.get("name", ""), interfaces=_members(v, "interface"),
            bgp_enabled=_text(v, "protocol/bgp/enable") == "yes",
            ospf_enabled=_text(v, "protocol/ospf/enable") == "yes")
        for r in _entries(v, "routing-table/ip/static-route"):
            nh = r.find("nexthop")
            nht = _first_child_tag(nh)
            vr.static_routes.append(StaticRoute(
                name=r.get("name", ""), vr=vr.name, destination=_text(r, "destination"),
                interface=_text(r, "interface"), nexthop_type=nht,
                nexthop=_text(nh, nht) if nht in ("ip-address", "next-vr", "fqdn", "ipv6-address") else None,
                metric=_int(_text(r, "metric")),
                path_monitor=_text(r, "path-monitor/enable") == "yes"))
        vrs.append(vr)
    return vrs


def _parse_crypto(net: ET.Element) -> Tuple[Dict[str, IkeCryptoProfile], Dict[str, IpsecCryptoProfile]]:
    ike: Dict[str, IkeCryptoProfile] = {}
    for p in _entries(net, "ike/crypto-profiles/ike-crypto-profiles"):
        n = p.get("name", "")
        ike[n] = IkeCryptoProfile(n, _members(p, "encryption"), _members(p, "hash"),
                                  _members(p, "dh-group"), _lifetime(p))
    ipsec: Dict[str, IpsecCryptoProfile] = {}
    for p in _entries(net, "ike/crypto-profiles/ipsec-crypto-profiles"):
        n = p.get("name", "")
        proto = "esp" if p.find("esp") is not None else "ah"
        ipsec[n] = IpsecCryptoProfile(n, _members(p, f"{proto}/encryption"),
                                      _members(p, f"{proto}/authentication"),
                                      _text(p, "dh-group"), _lifetime(p))
    return ike, ipsec


def _identity(el: Optional[ET.Element]) -> Optional[Identity]:
    if el is None:
        return None
    return Identity(type=_text(el, "type"), id=_text(el, "id"))


def _parse_gateways(net: ET.Element) -> List[IkeGateway]:
    gws: List[IkeGateway] = []
    for g in _entries(net, "ike/gateway"):
        pa = g.find("peer-address")
        pat = _first_child_tag(pa, ("ip", "fqdn", "dynamic"))
        auth = g.find("authentication")
        aut = _first_child_tag(auth, ("pre-shared-key", "certificate"))
        version = _text(g, "protocol/version") or "ikev1"
        proto = "ikev1" if version == "ikev1" else "ikev2"
        gws.append(IkeGateway(
            name=g.get("name", ""), version=version,
            local_interface=_text(g, "local-address/interface"), local_ip=_text(g, "local-address/ip"),
            peer_type=pat, peer=_text(pa, pat) if pat in ("ip", "fqdn") else pat,
            auth=aut, has_psk=auth is not None and auth.find("pre-shared-key/key") is not None,
            local_id=_identity(g.find("local-id")), peer_id=_identity(g.find("peer-id")),
            ike_crypto_profile=_text(g, f"protocol/{proto}/ike-crypto-profile"),
            nat_traversal=_yes(_text(g, "protocol-common/nat-traversal/enable")),
            passive=_yes(_text(g, "protocol-common/passive-mode")),
            dpd=_yes(_text(g, f"protocol/{proto}/dpd/enable")),
            disabled=_text(g, "disabled") == "yes", comment=_text(g, "comment")))
    return gws


def _parse_tunnels(net: ET.Element) -> List[IpsecTunnel]:
    tuns: List[IpsecTunnel] = []
    for t in _entries(net, "tunnel/ipsec"):
        ak = t.find("auto-key")
        pids = [ProxyId(name=p.get("name", ""), local=_text(p, "local"), remote=_text(p, "remote"),
                        protocol=_first_child_tag(p.find("protocol")) or "any")
                for p in _entries(ak, "proxy-id")]
        tuns.append(IpsecTunnel(
            name=t.get("name", ""), tunnel_interface=_text(t, "tunnel-interface"),
            gateways=_names(ak, "ike-gateway"), ipsec_crypto_profile=_text(ak, "ipsec-crypto-profile"),
            proxy_ids=pids, manual_key=t.find("manual-key") is not None,
            monitor_enabled=_text(t, "tunnel-monitor/enable") == "yes",
            monitor_destination=_text(t, "tunnel-monitor/destination-ip"),
            monitor_profile=_text(t, "tunnel-monitor/tunnel-monitor-profile"),
            disabled=_text(t, "disabled") == "yes", comment=_text(t, "comment")))
    return tuns


_ZONE_TYPES = ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external")


def _parse_vsys(dev: ET.Element) -> Tuple[List[Zone], Dict[str, str]]:
    zones: List[Zone] = []
    addrs: Dict[str, str] = {}
    for vs in _entries(dev, "vsys"):
        vname = vs.get("name", "")
        for z in _entries(vs, "zone"):
            zn = z.find("network")
            zt = _first_child_tag(zn, _ZONE_TYPES)
            zones.append(Zone(name=z.get("name", ""), vsys=vname, type=zt,
                              interfaces=_members(zn, zt) if zt else []))
        addrs.update(_parse_addresses(vs))
    return zones, addrs


def _parse_addresses(scope: Optional[ET.Element]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for a in _entries(scope, "address"):
        v = _text(a, "ip-netmask") or _text(a, "ip-range") or _text(a, "fqdn") or _text(a, "ip-wildcard")
        if v:
            out[a.get("name", "")] = v
    return out


def _parse_ha(dev: ET.Element) -> Optional[HAConfig]:
    ha = dev.find("deviceconfig/high-availability")
    if ha is None:
        return None
    return HAConfig(
        enabled=_text(ha, "enabled") == "yes",
        group_id=_text(ha, "group/group-id"),
        mode=_first_child_tag(ha.find("group/mode"), ("active-passive", "active-active")),
        peer_ip=_text(ha, "group/peer-ip"),
        priority=_text(ha, "group/election-option/device-priority"),
        preemptive=_yes(_text(ha, "group/election-option/preemptive")))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_firewall(path) -> FirewallConfig:
    """Parse a firewall export (XML or brace) into a :class:`FirewallConfig`."""
    cfg, fmt = load_config(path)
    dev = cfg.find("devices/entry")
    if dev is None:
        raise ValueError(f"{path}: no devices/entry in config")
    fw = FirewallConfig(hostname=_text(dev, "deviceconfig/system/hostname"),
                        source_file=str(path), source_format=fmt,
                        sw_version=cfg.get("detail-version") or cfg.get("version"),
                        ha=_parse_ha(dev))
    net = dev.find("network")
    if net is not None:
        fw.interfaces = _parse_interfaces(net)
        fw.virtual_routers = _parse_vrs(net)
        fw.ike_crypto, fw.ipsec_crypto = _parse_crypto(net)
        fw.ike_gateways = _parse_gateways(net)
        fw.ipsec_tunnels = _parse_tunnels(net)
        fw.monitor_profiles = _names(net, "profiles/monitor-profile")
    fw.zones, fw.addresses = _parse_vsys(dev)
    shared = _parse_addresses(cfg.find("shared"))
    for k, v in shared.items():
        fw.addresses.setdefault(k, v)
    return fw


def parse_panorama(path) -> PanoramaConfig:
    """Parse a Panorama export into device groups, template stacks and template contents."""
    cfg, fmt = load_config(path)
    pano = PanoramaConfig(source_file=str(path), source_format=fmt,
                          managed_serials=_names(cfg, "mgt-config/devices"))
    pe = cfg.find("devices/entry")
    if pe is None:
        return pano
    for dg in _entries(pe, "device-group"):
        pano.device_groups[dg.get("name", "")] = _names(dg, "devices")
    for ts in _entries(pe, "template-stack"):
        pano.template_stacks[ts.get("name", "")] = {
            "templates": _members(ts, "templates"), "devices": _names(ts, "devices")}
    for t in _entries(pe, "template"):
        tc = TemplateConfig(name=t.get("name", ""))
        net = t.find("config/devices/entry/network")
        if net is not None:
            tc.ike_crypto, tc.ipsec_crypto = _parse_crypto(net)
            tc.monitor_profiles = _names(net, "profiles/monitor-profile")
            tc.ike_gateways = _parse_gateways(net)
            tc.ipsec_tunnels = _parse_tunnels(net)
        pano.templates[tc.name] = tc
    return pano


def is_panorama_export(path) -> bool:
    """Return True if *path* looks like a Panorama export rather than a firewall export."""
    cfg, _ = load_config(path)
    pe = cfg.find("devices/entry")
    return pe is not None and (pe.find("device-group") is not None or pe.find("template") is not None)


def parse_directory(directory, pattern: str = "*") -> Tuple[Dict[str, FirewallConfig], List[PanoramaConfig], List[Tuple[str, str]]]:
    """Parse every export in *directory*.

    Returns ``(firewalls_by_hostname, panoramas, errors)``. Duplicate exports
    of the same hostname keep the most recently modified file.
    """
    fws: Dict[str, FirewallConfig] = {}
    mtimes: Dict[str, float] = {}
    panos: List[PanoramaConfig] = []
    errors: List[Tuple[str, str]] = []
    for p in sorted(Path(directory).glob(pattern)):
        if not p.is_file():
            continue
        try:
            detect_format(p)
        except (ValueError, OSError):
            continue
        try:
            cfg, fmt = load_config(p)
            pe = cfg.find("devices/entry")
            if pe is not None and (pe.find("device-group") is not None or pe.find("template") is not None):
                panos.append(parse_panorama(p))
                continue
            fw = parse_firewall(p)
            key = fw.hostname or p.stem
            mt = p.stat().st_mtime
            if key not in fws or mt > mtimes[key]:
                fws[key], mtimes[key] = fw, mt
        except Exception as exc:  # keep going; report per-file failures
            errors.append((str(p), f"{type(exc).__name__}: {exc}"))
    return fws, panos, errors


# ---------------------------------------------------------------------------
# CLI: python -m core.parser <export> [--json]
# ---------------------------------------------------------------------------

def _summary(fw: FirewallConfig) -> str:
    ha = "HA " + (fw.ha.mode or "on") if fw.ha and fw.ha.enabled else "standalone"
    lines = [f"{fw.hostname}  ({fw.source_format}, PAN-OS {fw.sw_version or '?'}, {ha})",
             f"  interfaces={len(fw.interfaces)} tunnels-ifs={len([i for i in fw.interfaces if i.kind == 'tunnel'])} "
             f"zones={len(fw.zones)} vrs={[v.name for v in fw.virtual_routers]}",
             f"  ike-gateways={len(fw.ike_gateways)} ipsec-tunnels={len(fw.ipsec_tunnels)} "
             f"ike-profiles={sorted(fw.ike_crypto)} ipsec-profiles={sorted(fw.ipsec_crypto)}"]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Parse a PAN-OS export (secrets are always stripped).")
    ap.add_argument("export", help="firewall or Panorama export (XML or brace format)")
    ap.add_argument("--json", action="store_true", help="print the full parsed model as JSON")
    args = ap.parse_args(argv)
    path = Path(args.export)
    if is_panorama_export(path):
        pano = parse_panorama(path)
        if args.json:
            print(json.dumps(pano.to_dict(), indent=1))
        else:
            print(f"Panorama  ({pano.source_format}) managed={len(pano.managed_serials)} "
                  f"device-groups={sorted(pano.device_groups)} stacks={sorted(pano.template_stacks)}")
            for t in pano.templates.values():
                if t.ike_crypto or t.ipsec_crypto:
                    print(f"  template {t.name}: ike={sorted(t.ike_crypto)} ipsec={sorted(t.ipsec_crypto)}")
        return 0
    fw = parse_firewall(path)
    print(json.dumps(fw.to_dict(), indent=1) if args.json else _summary(fw))
    return 0


if __name__ == "__main__":
    sys.exit(main())
