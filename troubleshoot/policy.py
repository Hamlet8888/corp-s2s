"""
Policy model for troubleshooting: zones, security rules, NAT rules, security profiles and routes.

Built from the same exports :mod:`core.parser` reads (XML or brace format, secrets stripped on
load), or from a live ``show config running``. Rulebases are evaluated in PAN-OS order:

    Panorama pre-rules  ->  local rules  ->  Panorama post-rules  ->  intrazone/interzone default

Panorama-pushed rules are read from ``config/panorama/vsys/entry/{pre,post}-rulebase`` and from
``{pre,post}-rulebase`` under the vsys, whichever the export contains.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.parser import (_entries, _first_child_tag, _members, _names, _parse_gateways, _parse_interfaces,
                         _parse_tunnels, _parse_vrs, _text, _yes, load_config)
from core.parser import IkeGateway, Interface, IpsecTunnel

from .objects import ObjectStore
from .routing import RouteTable, routes_from_config

#: Security-profile types a rule can carry, in the order PAN-OS shows them.
PROFILE_TYPES = ("virus", "spyware", "vulnerability", "url-filtering", "file-blocking",
                 "wildfire-analysis", "data-filtering")

ALLOW_ACTIONS = {"allow"}
DENY_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}


@dataclass
class ZoneInfo:
    name: str
    type: Optional[str]
    interfaces: List[str] = field(default_factory=list)
    zone_protection: Optional[str] = None


@dataclass
class SecurityRule:
    name: str
    rulebase: str                     # pre | local | post | default
    position: int
    from_zones: List[str]
    to_zones: List[str]
    source: List[str]
    destination: List[str]
    action: str
    application: List[str] = field(default_factory=lambda: ["any"])
    service: List[str] = field(default_factory=lambda: ["any"])
    source_user: List[str] = field(default_factory=lambda: ["any"])
    category: List[str] = field(default_factory=lambda: ["any"])
    negate_source: bool = False
    negate_destination: bool = False
    disabled: bool = False
    rule_type: str = "universal"      # universal | intrazone | interzone
    profile_group: Optional[str] = None
    profiles: Dict[str, List[str]] = field(default_factory=dict)
    log_start: bool = False
    log_end: bool = True
    log_setting: Optional[str] = None
    description: Optional[str] = None

    @property
    def label(self) -> str:
        where = {"pre": "Panorama pre-rule", "post": "Panorama post-rule", "default": "default rule"}
        return f"'{self.name}'" + (f" ({where[self.rulebase]})" if self.rulebase in where else f" (#{self.position})")


@dataclass
class NatRule:
    name: str
    rulebase: str
    position: int
    from_zones: List[str]
    to_zones: List[str]
    source: List[str]
    destination: List[str]
    service: str = "any"
    to_interface: Optional[str] = None
    disabled: bool = False
    src_type: Optional[str] = None            # dynamic-ip-and-port | dynamic-ip | static-ip
    src_addresses: List[str] = field(default_factory=list)
    src_interface: Optional[str] = None
    dst_address: Optional[str] = None
    dst_port: Optional[int] = None
    dst_dynamic: bool = False

    @property
    def label(self) -> str:
        where = {"pre": "Panorama pre-rule", "post": "Panorama post-rule"}
        return f"'{self.name}'" + (f" ({where[self.rulebase]})" if self.rulebase in where else f" (#{self.position})")

    def describe(self) -> str:
        parts = []
        if self.src_type:
            what = self.src_interface or ", ".join(self.src_addresses) or "?"
            parts.append(f"source -> {what} ({self.src_type})")
        if self.dst_address or self.dst_dynamic:
            parts.append(f"destination -> {self.dst_address or '?'}"
                         + (f":{self.dst_port}" if self.dst_port else "")
                         + (" (dynamic)" if self.dst_dynamic else ""))
        return "; ".join(parts) or "no translation"


@dataclass
class DecryptionRule:
    name: str
    from_zones: List[str]
    to_zones: List[str]
    source: List[str]
    destination: List[str]
    action: str                       # decrypt | no-decrypt | decrypt-and-forward
    type: Optional[str] = None        # ssl-forward-proxy | ssl-inbound-inspection | ssh-proxy
    category: List[str] = field(default_factory=lambda: ["any"])
    disabled: bool = False


@dataclass
class UrlProfile:
    name: str
    actions: Dict[str, List[str]] = field(default_factory=dict)   # action -> categories

    def action_for(self, category: Optional[str]) -> Optional[str]:
        for action in ("block", "continue", "override", "alert", "allow"):
            if category in self.actions.get(action, []):
                return action
        return None


@dataclass
class PolicyConfig:
    hostname: Optional[str]
    vsys: str
    source: str
    interfaces: List[Interface] = field(default_factory=list)
    zones: Dict[str, ZoneInfo] = field(default_factory=dict)
    store: ObjectStore = field(default_factory=lambda: ObjectStore([]))
    security_rules: List[SecurityRule] = field(default_factory=list)
    nat_rules: List[NatRule] = field(default_factory=list)
    decryption_rules: List[DecryptionRule] = field(default_factory=list)
    default_rules: Dict[str, SecurityRule] = field(default_factory=dict)
    profile_groups: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    url_profiles: Dict[str, UrlProfile] = field(default_factory=dict)
    custom_url_categories: Dict[str, List[str]] = field(default_factory=dict)
    routes: RouteTable = field(default_factory=RouteTable)
    dynamic_routing: List[str] = field(default_factory=list)      # VRs with BGP/OSPF enabled
    ipsec_tunnels: List[IpsecTunnel] = field(default_factory=list)
    ike_gateways: List[IkeGateway] = field(default_factory=list)

    # -- lookups --------------------------------------------------------------
    def zone_of(self, interface: Optional[str]) -> Optional[str]:
        return next((z.name for z in self.zones.values() if interface in z.interfaces), None)

    def rule(self, name: Optional[str]) -> Optional[SecurityRule]:
        if not name:
            return None
        return (next((r for r in self.security_rules if r.name == name), None)
                or self.default_rules.get(name))

    def nat_rule(self, name: Optional[str]) -> Optional[NatRule]:
        return next((r for r in self.nat_rules if r.name == name), None)

    def vpn_for(self, dst, src=None):
        """IPsec tunnels whose proxy-ids cover *dst* (and *src* when given): [(tunnel, proxy-id name, remote)]."""
        out = []
        for t in self.ipsec_tunnels:
            for pid in t.proxy_ids:
                remote, local = self.store.address_value(pid.remote), self.store.address_value(pid.local)
                if remote and remote[0] == dst[0] and remote[1] <= dst[1] and dst[2] <= remote[2] and (
                        src is None or local is None or (local[1] <= src[1] and src[2] <= local[2])):
                    out.append((t, pid.name, remote))
        return out

    def effective_profiles(self, rule: SecurityRule) -> Dict[str, str]:
        """Return ``{profile type: profile name}`` for a rule, expanding its profile group."""
        if rule.profile_group:
            grp = self.profile_groups.get(rule.profile_group, {})
            return {t: v[0] for t, v in grp.items() if v}
        return {t: v[0] for t, v in rule.profiles.items() if v}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _security_rule(e: ET.Element, rulebase: str, position: int) -> SecurityRule:
    ps = e.find("profile-setting")
    profiles = {t: _members(ps, f"profiles/{t}") for t in PROFILE_TYPES} if ps is not None else {}
    group = _members(ps, "group") if ps is not None else []
    return SecurityRule(
        name=e.get("name", ""), rulebase=rulebase, position=position,
        from_zones=_members(e, "from") or ["any"], to_zones=_members(e, "to") or ["any"],
        source=_members(e, "source") or ["any"], destination=_members(e, "destination") or ["any"],
        action=(_text(e, "action") or "allow").lower(),
        application=_members(e, "application") or ["any"], service=_members(e, "service") or ["any"],
        source_user=_members(e, "source-user") or ["any"], category=_members(e, "category") or ["any"],
        negate_source=_yes(_text(e, "negate-source")) or False,
        negate_destination=_yes(_text(e, "negate-destination")) or False,
        disabled=_yes(_text(e, "disabled")) or False,
        rule_type=_text(e, "rule-type") or "universal",
        profile_group=group[0] if group else None,
        profiles={t: v for t, v in profiles.items() if v},
        log_start=_yes(_text(e, "log-start")) or False,
        log_end=_text(e, "log-end") != "no",
        log_setting=_text(e, "log-setting"), description=_text(e, "description"))


def _nat_rule(e: ET.Element, rulebase: str, position: int) -> NatRule:
    st = e.find("source-translation")
    st_type = _first_child_tag(st, ("dynamic-ip-and-port", "dynamic-ip", "static-ip"))
    st_el = st.find(st_type) if st is not None and st_type else None
    src_addrs: List[str] = []
    src_if = None
    if st_el is not None:
        if st_type == "static-ip":
            v = _text(st_el, "translated-address")
            src_addrs = [v] if v else []
        else:
            src_addrs = _members(st_el, "translated-address")
            src_if = _text(st_el, "interface-address/interface")
            if not src_addrs and not src_if:
                src_if = _text(st_el, "interface-address") or None
    dt = e.find("destination-translation")
    ddt = e.find("dynamic-destination-translation")
    d = dt if dt is not None else ddt
    port = _text(d, "translated-port")
    return NatRule(
        name=e.get("name", ""), rulebase=rulebase, position=position,
        from_zones=_members(e, "from") or ["any"], to_zones=_members(e, "to") or ["any"],
        source=_members(e, "source") or ["any"], destination=_members(e, "destination") or ["any"],
        service=_text(e, "service") or "any", to_interface=_text(e, "to-interface"),
        disabled=_yes(_text(e, "disabled")) or False,
        src_type=st_type, src_addresses=src_addrs, src_interface=src_if,
        dst_address=_text(d, "translated-address"), dst_port=int(port) if port and port.isdigit() else None,
        dst_dynamic=ddt is not None)


def _rulebases(vsys_el: Optional[ET.Element], pano_vsys: Optional[ET.Element]):
    """Yield (rulebase label, <rulebase> element) in evaluation order."""
    for label, tag in (("pre", "pre-rulebase"), ("local", "rulebase"), ("post", "post-rulebase")):
        for scope in (pano_vsys, vsys_el):
            if scope is None:
                continue
            rb = scope.find(tag)
            if rb is not None:
                yield label, rb


def _default_rules(vsys_el: Optional[ET.Element]) -> Dict[str, SecurityRule]:
    out = {
        "intrazone-default": SecurityRule("intrazone-default", "default", 0, ["any"], ["any"], ["any"], ["any"],
                                          "allow", rule_type="intrazone", log_end=False),
        "interzone-default": SecurityRule("interzone-default", "default", 0, ["any"], ["any"], ["any"], ["any"],
                                          "deny", rule_type="interzone", log_end=False),
    }
    for e in _entries(vsys_el, "rulebase/default-security-rules/rules"):
        base = out.get(e.get("name", ""))
        if base is None:
            continue
        base.action = (_text(e, "action") or base.action).lower()
        if _text(e, "log-end"):
            base.log_end = _text(e, "log-end") == "yes"
        ps = e.find("profile-setting")
        if ps is not None:
            group = _members(ps, "group")
            base.profile_group = group[0] if group else None
            base.profiles = {t: _members(ps, f"profiles/{t}") for t in PROFILE_TYPES if _members(ps, f"profiles/{t}")}
    return out


def policy_from_root(cfg: ET.Element, vsys: str = "vsys1", source: str = "") -> PolicyConfig:
    """Build a :class:`PolicyConfig` from a ``<config>`` element (secrets already stripped)."""
    dev = cfg.find("devices/entry")
    if dev is None:
        raise ValueError(f"{source}: no devices/entry in config")
    vsys_el = next((v for v in _entries(dev, "vsys") if v.get("name") == vsys), None)
    if vsys_el is None:
        names = _names(dev, "vsys")
        raise ValueError(f"{source}: vsys {vsys!r} not found (have: {', '.join(names) or 'none'})")
    pano = cfg.find("panorama")
    pano_vsys = next((v for v in _entries(pano, "vsys") if v.get("name") == vsys), None) if pano is not None else None
    shared, pano_shared = cfg.find("shared"), pano.find("shared") if pano is not None else None

    pol = PolicyConfig(hostname=_text(dev, "deviceconfig/system/hostname"), vsys=vsys, source=source)
    pol.store = ObjectStore([vsys_el, pano_vsys, shared, pano_shared])
    net = dev.find("network")
    if net is not None:
        pol.interfaces = _parse_interfaces(net)
        vrs = _parse_vrs(net)
        pol.routes = routes_from_config(net, vrs, pol.interfaces, pol.store)
        pol.dynamic_routing = [v.name for v in vrs if v.bgp_enabled or v.ospf_enabled]
        pol.ipsec_tunnels = _parse_tunnels(net)
        pol.ike_gateways = _parse_gateways(net)
        for lr in _entries(net, "logical-router"):
            for vrf in _entries(lr, "vrf"):
                if any(_text(vrf, f"{p}/enable") == "yes" for p in ("bgp", "ospf", "ospfv3")):
                    pol.dynamic_routing.append(f"{lr.get('name')}/{vrf.get('name')}")
    for z in _entries(vsys_el, "zone"):
        zn = z.find("network")
        zt = _first_child_tag(zn, ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"))
        pol.zones[z.get("name", "")] = ZoneInfo(z.get("name", ""), zt, _members(zn, zt) if zt else [],
                                                _text(zn, "zone-protection-profile"))

    pos = 0
    for label, rb in _rulebases(vsys_el, pano_vsys):
        for e in _entries(rb, "security/rules"):
            pos += 1
            pol.security_rules.append(_security_rule(e, label, pos))
    pos = 0
    for label, rb in _rulebases(vsys_el, pano_vsys):
        for e in _entries(rb, "nat/rules"):
            pos += 1
            pol.nat_rules.append(_nat_rule(e, label, pos))
    for label, rb in _rulebases(vsys_el, pano_vsys):
        for e in _entries(rb, "decryption/rules"):
            pol.decryption_rules.append(DecryptionRule(
                name=e.get("name", ""), from_zones=_members(e, "from") or ["any"],
                to_zones=_members(e, "to") or ["any"], source=_members(e, "source") or ["any"],
                destination=_members(e, "destination") or ["any"], action=_text(e, "action") or "no-decrypt",
                type=_first_child_tag(e.find("type")), category=_members(e, "category") or ["any"],
                disabled=_yes(_text(e, "disabled")) or False))
    pol.default_rules = _default_rules(vsys_el)

    for scope in (pano_shared, shared, pano_vsys, vsys_el):     # later scopes override earlier ones
        if scope is None:
            continue
        for g in _entries(scope, "profile-group"):
            pol.profile_groups[g.get("name", "")] = {t: _members(g, t) for t in PROFILE_TYPES if _members(g, t)}
        for p in _entries(scope, "profiles/url-filtering"):
            up = UrlProfile(p.get("name", ""))
            for action in ("block", "continue", "override", "alert", "allow"):
                up.actions[action] = _members(p, action)
            # PAN-OS 10.x+ keeps per-category actions in the same lists; credential-enforcement is separate.
            pol.url_profiles[up.name] = up
        for c in _entries(scope, "profiles/custom-url-category"):
            pol.custom_url_categories[c.get("name", "")] = _members(c, "list")
    return pol


def load_policy(path, vsys: str = "vsys1") -> PolicyConfig:
    """Parse a firewall export (XML or brace format) into a :class:`PolicyConfig`."""
    cfg, _ = load_config(path)
    return policy_from_root(cfg, vsys=vsys, source=str(path))
