"""
Drift detection for site-to-site IPsec tunnels across a fleet of PAN-OS firewalls.

The auditor works on a normalized view of the estate (:class:`AuditData`),
which can be built two ways:

* :meth:`Auditor.from_inventory`: from an inventory YAML that includes an
  ``observed:`` section. This is how ``--demo`` runs against
  ``examples/mock_inventory.yaml``.
* :meth:`Auditor.from_exports`: from real firewall exports (XML or brace
  format) parsed by :mod:`core.parser`, optionally with a Panorama export for
  the crypto standards and an inventory for site metadata.

Checks:

=================  ===========================================================
crypto             Missing/undefined profiles, non-standard profiles, local
                   copies that shadow a Panorama standard (e.g. DH14 vs DH20),
                   and Phase 1 / Phase 2 mismatches between the two ends.
gateway            Local identity vs the site's WAN IPs, one-sided gateways,
                   wrong peer IP and swapped ISP bindings.
proxy-id           Mirror symmetry between both ends, plus prefixes a site
                   advertises that it doesn't own (copy-paste errors).
collision          Tunnel /30s reused by unrelated links, mismatched tunnel
                   subnets, duplicate or out-of-range tunnel units.
ha                 HA members whose VPN config differs. ``apply`` refuses to
                   run against such a pair.
coverage           Links defined in the inventory that aren't built yet.
=================  ===========================================================

Severities, from most to least serious: ``ERROR`` (traffic is or will be
broken, or apply would be unsafe), ``DRIFT`` (deviates from the standard but
may work), ``WARNING`` (risky or ambiguous) and ``INFO``.

Standard library only (Python 3.9+). The inventory is read with
:mod:`core.miniyaml`, which uses PyYAML when it is installed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from . import miniyaml
from .parser import (DEFAULT_IKE, DEFAULT_IPSEC, FirewallConfig, IkeCryptoProfile,
                     IpsecCryptoProfile, PanoramaConfig, parse_directory, parse_panorama)

SEVERITIES: Tuple[str, ...] = ("ERROR", "DRIFT", "WARNING", "INFO")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEMO_INVENTORY = Path(__file__).resolve().parent.parent / "examples" / "mock_inventory.yaml"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str                     # ERROR | DRIFT | WARNING | INFO
    check: str                        # crypto | gateway | proxy-id | collision | ha | coverage
    code: str                         # stable machine-readable identifier
    subject: str                      # site pair, device or link the finding is about
    message: str
    details: List[str] = field(default_factory=list)
    devices: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Normalized model
# ---------------------------------------------------------------------------

ProxyPair = Tuple[str, str]           # (local, remote)


@dataclass
class TunnelRecord:
    """One IKE gateway + IPsec tunnel as configured on one firewall."""
    device: str
    site: str
    name: str
    interface: Optional[str]
    tunnel_ip: Optional[str]
    local_id: Optional[str]
    peer_id: Optional[str]
    ike: Optional[str]
    ipsec: Optional[str]
    proxy_ids: List[ProxyPair] = field(default_factory=list)
    local_interface: Optional[str] = None
    has_tunnel: bool = True
    disabled: bool = False

    def ha_key(self) -> tuple:
        """Return the fields HA members must agree on (everything except the device)."""
        return (self.name, self.interface, self.tunnel_ip, self.local_id, self.peer_id,
                self.ike, self.ipsec, tuple(sorted(self.proxy_ids)), self.has_tunnel, self.disabled)


@dataclass
class SiteInfo:
    name: str
    firewalls: List[str]
    wan: Dict[str, str] = field(default_factory=dict)        # wan key (isp1 / ethernet1/1) -> public IP
    lan: Optional[List[str]] = None                          # None means unknown (skip ownership checks)
    unit_range: Optional[Tuple[int, int]] = None
    vpn_zone: Optional[str] = None

    @property
    def primary(self) -> str:
        return self.firewalls[0]

    def wan_key(self, ip: Optional[str]) -> Optional[str]:
        return next((k for k, v in self.wan.items() if v == ip), None)


@dataclass
class Standards:
    ike: Dict[str, IkeCryptoProfile] = field(default_factory=dict)      # Panorama-managed IKE profiles
    ipsec: Dict[str, IpsecCryptoProfile] = field(default_factory=dict)  # Panorama-managed IPsec profiles
    preferred_ike: Optional[str] = None
    preferred_ipsec: Optional[str] = None
    tunnel_ip_pool: Optional[str] = None


@dataclass
class AuditData:
    source: str
    sites: Dict[str, SiteInfo]
    records: Dict[str, List[TunnelRecord]]                   # device -> tunnels
    local_ike: Dict[str, Dict[str, IkeCryptoProfile]] = field(default_factory=dict)
    local_ipsec: Dict[str, Dict[str, IpsecCryptoProfile]] = field(default_factory=dict)
    standards: Standards = field(default_factory=Standards)
    links: List[dict] = field(default_factory=list)          # desired state from the inventory
    out_of_scope: Dict[str, int] = field(default_factory=dict)  # site -> # non-site-to-site gateways ignored


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _net30(ip: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Return the /30 a tunnel address belongs to (host /32s are widened to /30)."""
    if not ip:
        return None
    try:
        iface = ipaddress.ip_interface(ip)
    except ValueError:
        return None
    if iface.network.prefixlen >= 30:
        return ipaddress.ip_network(f"{iface.ip}/30", strict=False)
    return iface.network


def _covered(prefix: str, supernets: Iterable[str]) -> bool:
    try:
        p = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return True                   # address-object names etc.: can't judge, don't flag
    for s in supernets:
        try:
            if p.subnet_of(ipaddress.ip_network(s, strict=False)):
                return True
        except (ValueError, TypeError):
            continue
    return False


def _unit(interface: Optional[str]) -> Optional[int]:
    m = re.match(r"^tunnel\.(\d+)$", interface or "")
    return int(m.group(1)) if m else None


def _ike_from_dict(name: str, d: dict) -> IkeCryptoProfile:
    return IkeCryptoProfile(name, list(d.get("encryption", [])), list(d.get("hash", [])),
                            [d["dh_group"]] if isinstance(d.get("dh_group"), str) else list(d.get("dh_group", [])),
                            dict(d.get("lifetime", {})))


def _ipsec_from_dict(name: str, d: dict) -> IpsecCryptoProfile:
    dh = d.get("dh_group")
    return IpsecCryptoProfile(name, list(d.get("encryption", [])), list(d.get("authentication", [])),
                              dh[0] if isinstance(dh, list) and dh else dh, dict(d.get("lifetime", {})))


def _describe_ike(p: IkeCryptoProfile) -> str:
    return f"{'/'.join(p.encryption)} {'/'.join(p.hash)} {'/'.join(p.dh_group)}"


def _describe_ipsec(p: IpsecCryptoProfile) -> str:
    return f"{'/'.join(p.encryption)} {'/'.join(p.authentication)} {p.dh_group}"


def _site_of_hostname(hostname: str) -> str:
    return re.sub(r"-FW-?\d+$", "", hostname, flags=re.I)


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class Auditor:
    """Runs every drift check over an :class:`AuditData` snapshot."""

    def __init__(self, data: AuditData):
        self.data = data
        self.findings: List[Finding] = []
        self._ip2site: Dict[str, str] = {}
        for s in data.sites.values():
            for ip in s.wan.values():
                self._ip2site[ip] = s.name
        self.pairs: List[Tuple[TunnelRecord, TunnelRecord]] = []
        self.unmatched: List[TunnelRecord] = []

    # -- construction --------------------------------------------------------
    @classmethod
    def from_inventory(cls, path) -> "Auditor":
        """Build from an inventory that contains an ``observed:`` section (demo / offline)."""
        inv = miniyaml.load(path)
        sites = _sites_from_inventory(inv)
        dev2site = {fw: s.name for s in sites.values() for fw in s.firewalls}
        observed = inv.get("observed") or {}
        records: Dict[str, List[TunnelRecord]] = {}
        for dev, body in (observed.get("devices") or {}).items():
            site = dev2site.get(dev, _site_of_hostname(dev))
            records[dev] = [TunnelRecord(
                device=dev, site=site, name=t["name"], interface=t.get("interface"),
                tunnel_ip=t.get("tunnel_ip"), local_id=t.get("local_id"), peer_id=t.get("peer_id"),
                ike=t.get("ike"), ipsec=t.get("ipsec"),
                proxy_ids=[(p[0], p[1]) for p in (t.get("proxy_ids") or [])],
                disabled=bool(t.get("disabled", False))) for t in (body.get("tunnels") or [])]
        local_ike: Dict[str, Dict[str, IkeCryptoProfile]] = {}
        local_ipsec: Dict[str, Dict[str, IpsecCryptoProfile]] = {}
        for dev, prof in (observed.get("local_profiles") or {}).items():
            local_ike[dev] = {n: _ike_from_dict(n, d) for n, d in (prof.get("ike") or {}).items()}
            local_ipsec[dev] = {n: _ipsec_from_dict(n, d) for n, d in (prof.get("ipsec") or {}).items()}
        return cls(AuditData(source=str(path), sites=sites, records=records, local_ike=local_ike,
                             local_ipsec=local_ipsec, standards=_standards_from_inventory(inv),
                             links=list(inv.get("links") or [])))

    @classmethod
    def from_exports(cls, directory, panorama: Optional[str] = None,
                     inventory: Optional[str] = None, pattern: str = "*") -> "Auditor":
        """Build from real firewall exports.

        Sites are inferred from hostnames (``SITE-FW-01``) and WAN identities
        from the gateways' local IDs, unless *inventory* supplies them.
        Crypto standards come from the Panorama export (every template profile
        counts as Panorama-managed) and/or the inventory's ``standards``.
        """
        fws, panos, errors = parse_directory(directory, pattern)
        if errors:
            for f, e in errors:
                print(f"warning: could not parse {f}: {e}", file=sys.stderr)
        pano: Optional[PanoramaConfig] = parse_panorama(panorama) if panorama else (panos[0] if panos else None)
        inv = miniyaml.load(inventory) if inventory else {}
        return cls(_data_from_firewalls(fws, pano, inv, source=str(directory)))

    # -- run -----------------------------------------------------------------
    def run(self) -> List[Finding]:
        self.findings = []
        self._match_pairs()
        self.check_gateway_symmetry()
        self.check_crypto()
        self.check_proxy_ids()
        self.check_collisions()
        self.check_ha()
        self.check_coverage()
        self.findings.sort(key=lambda f: (_SEV_RANK[f.severity], f.check, f.subject, f.code))
        return self.findings

    def _add(self, *args, **kwargs) -> Finding:
        f = Finding(*args, **kwargs)
        self.findings.append(f)
        return f

    def _primary_records(self) -> Iterable[TunnelRecord]:
        for s in self.data.sites.values():
            yield from self.data.records.get(s.primary, [])

    def _match_pairs(self) -> None:
        """Pair each tunnel with its mirror on the remote site's primary firewall."""
        self.pairs, self.unmatched = [], []
        seen: Set[int] = set()
        for r in self._primary_records():
            if r.disabled or id(r) in seen:
                continue
            peer_site = self._ip2site.get(r.peer_id or "")
            mirror = None
            if peer_site and peer_site in self.data.sites:
                for c in self.data.records.get(self.data.sites[peer_site].primary, []):
                    if c.local_id == r.peer_id and c.peer_id == r.local_id and not c.disabled and id(c) not in seen:
                        mirror = c
                        break
            if mirror:
                seen.update((id(r), id(mirror)))
                self.pairs.append((r, mirror))
            else:
                self.unmatched.append(r)

    # -- crypto -------------------------------------------------------------
    def _eff_ike(self, dev: str, name: Optional[str]) -> Optional[IkeCryptoProfile]:
        if name is None:
            return DEFAULT_IKE
        return self.data.local_ike.get(dev, {}).get(name) or self.data.standards.ike.get(name)

    def _eff_ipsec(self, dev: str, name: Optional[str]) -> Optional[IpsecCryptoProfile]:
        if name is None:
            return DEFAULT_IPSEC
        return self.data.local_ipsec.get(dev, {}).get(name) or self.data.standards.ipsec.get(name)

    def check_crypto(self) -> None:
        std = self.data.standards
        # 1) Local copies that shadow a Panorama-managed profile with different parameters.
        shadows: Dict[Tuple[str, str], Finding] = {}
        for kind, local_map, std_map, describe in (
                ("IKE", self.data.local_ike, std.ike, _describe_ike),
                ("IPsec", self.data.local_ipsec, std.ipsec, _describe_ipsec)):
            by_profile: Dict[Tuple[str, Tuple], List[str]] = defaultdict(list)
            for dev, profs in local_map.items():
                for name, p in profs.items():
                    s = std_map.get(name)
                    if s is not None and p.signature() != s.signature():
                        by_profile[(name, p.signature())].append(dev)
            for (name, _sig), devs in sorted(by_profile.items()):
                p = local_map[devs[0]][name]
                s = std_map[name]
                f = self._add("DRIFT", "crypto", "CRYPTO_LOCAL_SHADOW", ", ".join(sorted(devs)),
                              f"Local {kind} profile '{name}' overrides the Panorama standard with different parameters",
                              [f"local:    {describe(p)}", f"standard: {describe(s)}"]
                              + _dh_note(p, s), sorted(devs))
                for d in devs:
                    shadows[(d, name)] = f

        # 2) Per-tunnel profile references.
        nonstandard: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
        missing: Set[Tuple[str, str]] = set()
        # Per-tunnel checks look at each site's primary member; HA differences are
        # reported by check_ha, so they aren't repeated once per member here.
        for r in self._primary_records():
            if True:
                if not r.has_tunnel or r.disabled:
                    continue
                for kind, name, std_map, local_map in (("IKE", r.ike, std.ike, self.data.local_ike),
                                                       ("IPsec", r.ipsec, std.ipsec, self.data.local_ipsec)):
                    if name is None:
                        missing.add((r.device, r.name))
                        d = DEFAULT_IKE if kind == "IKE" else DEFAULT_IPSEC
                        desc = _describe_ike(d) if kind == "IKE" else _describe_ipsec(d)
                        self._add("ERROR", "crypto", f"CRYPTO_NO_{kind.upper()}_PROFILE", f"{r.device}: {r.name}",
                                  f"No {kind} crypto profile is set, so PAN-OS falls back to 'default' ({desc})",
                                  ["The far end uses a standard profile, so this negotiation fails"], [r.device])
                    elif name not in std_map and name not in local_map.get(r.device, {}):
                        self._add("ERROR", "crypto", "CRYPTO_UNDEFINED_PROFILE", f"{r.device}: {r.name}",
                                  f"{kind} profile '{name}' is referenced but not defined locally or in Panorama",
                                  [], [r.device])
                    elif std_map and name not in std_map:
                        nonstandard[(r.device, kind, name)].append(r.name)
        by_name: Dict[Tuple[str, str], Dict[str, List[str]]] = defaultdict(dict)
        for (dev, kind, name), tuns in nonstandard.items():
            by_name[(kind, name)][dev] = tuns
        for (kind, name), devs in sorted(by_name.items()):
            n = sum(len(t) for t in devs.values())
            sample = next(iter(devs))
            p = (self.data.local_ike if kind == "IKE" else self.data.local_ipsec).get(sample, {}).get(name)
            desc = (_describe_ike(p) if kind == "IKE" else _describe_ipsec(p)) if p else "?"
            self._add("DRIFT", "crypto", "CRYPTO_NONSTANDARD_PROFILE", f"{kind} '{name}'",
                      f"Local {kind} profile '{name}' ({desc}) is used by {n} tunnel(s) on {len(devs)} device(s); "
                      f"it is not a Panorama standard",
                      [f"{d}: " + ", ".join(sorted(t)[:6]) + (" ..." if len(t) > 6 else "")
                       for d, t in sorted(devs.items())], sorted(devs))

        # 3) Both ends of each matched pair must negotiate the same parameters.
        for a, b in self.pairs:
            if (a.device, a.name) in missing or (b.device, b.name) in missing:
                continue  # already reported as a missing-profile ERROR
            for kind, eff, attr, describe in (("Phase 1 (IKE)", self._eff_ike, "ike", _describe_ike),
                                               ("Phase 2 (IPsec)", self._eff_ipsec, "ipsec", _describe_ipsec)):
                pa, pb = eff(a.device, getattr(a, attr)), eff(b.device, getattr(b, attr))
                if pa is None or pb is None or pa.signature() == pb.signature():
                    continue
                shadow = shadows.get((a.device, getattr(a, attr))) or shadows.get((b.device, getattr(b, attr)))
                line = f"{a.device}:{a.name} [{describe(pa)}]  vs  {b.device}:{b.name} [{describe(pb)}]"
                if shadow is not None:
                    shadow.severity = "ERROR"     # the shadow copy breaks live tunnels
                    if not any(d.startswith("breaks:") for d in shadow.details):
                        shadow.details.append("breaks:")
                    shadow.details.append("  " + line)
                    continue
                self._add("ERROR", "crypto", "CRYPTO_MISMATCH", _pair_subject(a, b),
                          f"{kind} parameters differ between the two ends",
                          [line] + (_dh_note(pa, pb) if attr == "ipsec" else []), [a.device, b.device])

    # -- gateway / ISP symmetry ------------------------------------------------
    def check_gateway_symmetry(self) -> None:
        reported: Set[FrozenSet[str]] = set()
        for r in self._primary_records():
            site = self.data.sites.get(r.site)
            if r.disabled:
                self._add("INFO", "gateway", "GW_DISABLED", f"{r.device}: {r.name}", "Tunnel or gateway is disabled", [], [r.device])
                continue
            if not r.has_tunnel:
                self._add("WARNING", "gateway", "GW_NO_TUNNEL", f"{r.device}: {r.name}",
                          "IKE gateway is not referenced by any IPsec tunnel", [], [r.device])
            if site and site.wan and r.local_id and r.local_id not in site.wan.values():
                self._add("ERROR", "gateway", "GW_LOCAL_ID", f"{r.device}: {r.name}",
                          f"Local IKE identity {r.local_id} is not one of {r.site}'s WAN addresses",
                          [f"{k}: {v}" for k, v in site.wan.items()], [r.device])
        for r in self.unmatched:
            peer_site = self._ip2site.get(r.peer_id or "")
            if peer_site is None:
                self._add("WARNING", "gateway", "GW_UNKNOWN_PEER", f"{r.device}: {r.name}",
                          f"One-sided gateway: peer {r.peer_id} does not belong to any known site",
                          ["The remote site may be decommissioned, or the peer IP may be stale. "
                           "Verify it, then remove the gateway, tunnel, interface and routes"], [r.device])
                continue
            if (r.device, r.name) in reported:
                continue
            local_site, remote = self.data.sites[r.site], self.data.sites[peer_site]
            toward_us = [c for c in self.data.records.get(remote.primary, [])
                         if self._ip2site.get(c.peer_id or "") == r.site and not c.disabled
                         and c in self.unmatched]
            # A half-match (one identity agrees, the other doesn't) means the two ends
            # disagree about which WAN one of the sites uses for this tunnel.
            half = [c for c in toward_us if (c.local_id == r.peer_id) != (c.peer_id == r.local_id)]
            disabled_mirror = next((c for c in self.data.records.get(remote.primary, [])
                                    if c.disabled and c.local_id == r.peer_id and c.peer_id == r.local_id), None)
            if disabled_mirror is not None:
                self._add("WARNING", "gateway", "GW_PEER_DISABLED", _pair_subject_sites(r.site, peer_site),
                          f"'{r.name}' is enabled on {r.device}, but its mirror '{disabled_mirror.name}' "
                          f"is disabled on {remote.primary}",
                          ["Either re-enable the far end or disable/remove this side so monitoring stays honest"],
                          [r.device, remote.primary])
            elif not toward_us:
                self._add("ERROR", "gateway", "GW_ONE_SIDED", _pair_subject_sites(r.site, peer_site),
                          f"Only {r.site} has a gateway toward {peer_site}: '{r.name}' "
                          f"({r.local_id} -> {r.peer_id}); {remote.primary} has none back",
                          [], [r.device, remote.primary])
            elif half:
                c = half[0]
                reported.update({(r.device, r.name), (c.device, c.name)})
                # Which site's WAN is disputed?
                if c.local_id == r.peer_id:
                    disputed, rec_says, peer_says = local_site, r.local_id, c.peer_id
                    other, fixed_wan = remote, remote.wan_key(r.peer_id)
                else:
                    disputed, rec_says, peer_says = remote, r.peer_id, c.local_id
                    other, fixed_wan = local_site, local_site.wan_key(r.local_id)
                rec_on, peer_on = r.device, c.device   # rec_says comes from r, peer_says from c
                details = [f"{r.device}: '{r.name}' {r.site} {local_site.wan_key(r.local_id) or '?'} ({r.local_id}) "
                           f"-> {peer_site} {remote.wan_key(r.peer_id) or '?'} ({r.peer_id})",
                           f"{c.device}: '{c.name}' {peer_site} {remote.wan_key(c.local_id) or '?'} ({c.local_id}) "
                           f"-> {r.site} {local_site.wan_key(c.peer_id) or '?'} ({c.peer_id})",
                           f"{rec_on} uses {disputed.name} {disputed.wan_key(rec_says) or '?'}; "
                           f"{peer_on} expects {disputed.name} {disputed.wan_key(peer_says) or '?'}"]
                want = self._desired_path(disputed.name, other.name, fixed_wan)
                if want:
                    wrong = peer_on if want == disputed.wan_key(rec_says) else rec_on
                    details.append(f"inventory link says {disputed.name} should use {want}, so fix {wrong}")
                self._add("ERROR", "gateway", "GW_ISP_SWAP", _pair_subject_sites(r.site, peer_site),
                          f"ISP binding mismatch: the two ends disagree on which {disputed.name} WAN this tunnel uses",
                          details, sorted({r.device, c.device}))
            else:
                self._add("ERROR", "gateway", "GW_PEER_MISMATCH", _pair_subject_sites(r.site, peer_site),
                          f"'{r.name}' ({r.local_id} -> {r.peer_id}) has no mirror on {remote.primary}",
                          [f"{remote.primary} gateways toward {r.site}: " +
                           ", ".join(f"{c.name} ({c.local_id} -> {c.peer_id})" for c in toward_us)],
                          [r.device, remote.primary])

    def _desired_path(self, a: str, b: str, b_wan: Optional[str]) -> Optional[str]:
        """Return the WAN key site *a* should use toward *b*'s *b_wan* according to the inventory links."""
        for link in self.data.links:
            for p in link.get("paths", []):
                if link.get("a") == a and link.get("b") == b and p.get("b") == b_wan:
                    return p.get("a")
                if link.get("b") == a and link.get("a") == b and p.get("a") == b_wan:
                    return p.get("b")
        return None

    # -- proxy-IDs ---------------------------------------------------------------
    def check_proxy_ids(self) -> None:
        for a, b in self.pairs:
            pa = set(a.proxy_ids)
            pb_mirrored = {(rem, loc) for loc, rem in b.proxy_ids}
            only_a, only_b = sorted(pa - pb_mirrored), sorted(pb_mirrored - pa)
            foreign: List[str] = []
            for rec in (a, b):
                site = self.data.sites.get(rec.site)
                if site and site.lan:
                    bad = sorted({loc for loc, _ in rec.proxy_ids if not _covered(loc, site.lan)})
                    if bad:
                        foreign.append(f"{rec.device}:{rec.name} claims local {', '.join(bad)}, "
                                       f"but {rec.site} owns {', '.join(site.lan)}")
            if not (only_a or only_b or foreign):
                continue
            details = []
            if only_a:
                details.append(f"only on {a.device}: " + ", ".join(f"{l} -> {r}" for l, r in only_a))
            if only_b:
                details.append(f"only on {b.device} (mirrored): " + ", ".join(f"{l} -> {r}" for l, r in only_b))
            details += foreign
            if only_a or only_b:
                msg = "Proxy-IDs don't mirror each other, so the unmatched SAs never come up"
                if foreign:
                    msg += " (looks like a copy-paste from another tunnel)"
                self._add("ERROR", "proxy-id", "PROXY_ID_MISMATCH", _pair_subject(a, b), msg, details,
                          [a.device, b.device])
            else:
                self._add("WARNING", "proxy-id", "PROXY_ID_FOREIGN_PREFIX", _pair_subject(a, b),
                          "Proxy-IDs mirror each other but include prefixes the site doesn't own", details,
                          [a.device, b.device])

    # -- collisions ------------------------------------------------------------
    def check_collisions(self) -> None:
        # Tunnel /30 reused by unrelated links.
        users: Dict[ipaddress.IPv4Network, Set[Tuple[str, str]]] = defaultdict(set)
        for a, b in self.pairs:
            for rec in (a, b):
                n = _net30(rec.tunnel_ip)
                if n:
                    users[n].add(tuple(sorted((a.site, b.site))))
        for n, links in sorted(users.items(), key=lambda kv: str(kv[0])):
            if len(links) > 1:
                self._add("WARNING", "collision", "TUNNEL_IP_REUSED", str(n),
                          f"Tunnel subnet {n} is used by {len(links)} different links",
                          [" <-> ".join(l) for l in sorted(links)] +
                          ["No single device has both, but monitoring and troubleshooting become ambiguous"])
        # Both ends of a pair must share one /30.
        for a, b in self.pairs:
            na, nb = _net30(a.tunnel_ip), _net30(b.tunnel_ip)
            if na and nb and (na != nb or a.tunnel_ip.split("/")[0] == b.tunnel_ip.split("/")[0]):
                self._add("ERROR", "collision", "TUNNEL_IP_MISMATCH", _pair_subject(a, b),
                          "The two ends' tunnel addresses aren't a valid point-to-point pair",
                          [f"{a.device} {a.interface} {a.tunnel_ip}", f"{b.device} {b.interface} {b.tunnel_ip}"],
                          [a.device, b.device])
        # Per-device tunnel unit conflicts and range.
        pool = ipaddress.ip_network(self.data.standards.tunnel_ip_pool) if self.data.standards.tunnel_ip_pool else None
        for dev, recs in sorted(self.data.records.items()):
            by_if: Dict[str, List[str]] = defaultdict(list)
            for r in recs:
                if r.interface:
                    by_if[r.interface].append(r.name)
            for ifn, names in sorted(by_if.items()):
                if len(names) > 1:
                    self._add("ERROR", "collision", "TUNNEL_UNIT_CONFLICT", f"{dev}: {ifn}",
                              f"{ifn} is bound to {len(names)} IPsec tunnels", names, [dev])
            site = self.data.sites.get(recs[0].site) if recs else None
            if site and site.unit_range:
                lo, hi = site.unit_range
                out = sorted(f"{r.interface} ({r.name})" for r in recs
                             if _unit(r.interface) is not None and not lo <= _unit(r.interface) <= hi)
                if out:
                    self._add("INFO", "collision", "TUNNEL_UNIT_OUT_OF_RANGE", dev,
                              f"{len(out)} tunnel unit(s) outside the site's range {lo}-{hi}", out[:10], [dev])
            if pool:
                outside = sorted({r.tunnel_ip for r in recs if r.tunnel_ip and
                                  ipaddress.ip_interface(r.tunnel_ip).ip not in pool})
                if outside:
                    self._add("INFO", "collision", "TUNNEL_IP_OUTSIDE_POOL", dev,
                              f"{len(outside)} tunnel address(es) outside the standard pool {pool}", outside[:10], [dev])

    # -- HA ------------------------------------------------------------------
    def check_ha(self) -> None:
        for s in sorted(self.data.sites.values(), key=lambda x: x.name):
            members = [fw for fw in s.firewalls if fw in self.data.records]
            if len(s.firewalls) > 1 and len(members) < len(s.firewalls):
                missing = sorted(set(s.firewalls) - set(members))
                self._add("WARNING", "ha", "HA_MEMBER_MISSING", s.name,
                          f"No data for HA member(s) {', '.join(missing)}; sync state can't be verified",
                          [], missing)
            if len(members) < 2:
                continue
            base = members[0]
            for other in members[1:]:
                ra = {r.name: r for r in self.data.records[base]}
                rb = {r.name: r for r in self.data.records[other]}
                details = []
                only_a, only_b = sorted(set(ra) - set(rb)), sorted(set(rb) - set(ra))
                if only_a:
                    details.append(f"only on {base}: {', '.join(only_a)}")
                if only_b:
                    details.append(f"only on {other}: {', '.join(only_b)}")
                changed = sorted(n for n in set(ra) & set(rb) if ra[n].ha_key() != rb[n].ha_key())
                if changed:
                    details.append(f"differs: {', '.join(changed)}")
                for label, m in (("IKE", self.data.local_ike), ("IPsec", self.data.local_ipsec)):
                    pa, pb = m.get(base, {}), m.get(other, {})
                    diff = sorted(n for n in set(pa) | set(pb)
                                  if n not in pa or n not in pb or pa[n].signature() != pb[n].signature())
                    if diff:
                        details.append(f"local {label} profiles differ: {', '.join(diff)}")
                if details:
                    self._add("ERROR", "ha", "HA_OUT_OF_SYNC", s.name,
                              f"HA members {base} and {other} have different VPN configuration; apply will refuse this pair",
                              details + ["Run 'request high-availability sync-to-remote running-config' from the "
                                         "correct member after review"], [base, other])

    # -- coverage ----------------------------------------------------------------
    def check_coverage(self) -> None:
        built: Set[Tuple[str, str]] = set()
        for recs in self.data.records.values():
            for r in recs:
                if r.local_id and r.peer_id:
                    built.add((r.local_id, r.peer_id))
        for link in self.data.links:
            a, b = self.data.sites.get(link.get("a")), self.data.sites.get(link.get("b"))
            if not a or not b:
                self._add("ERROR", "coverage", "LINK_UNKNOWN_SITE", f"{link.get('a')} <-> {link.get('b')}",
                          "Link references a site that isn't in the inventory")
                continue
            todo = []
            for p in link.get("paths", []):
                ia, ib = a.wan.get(p.get("a")), b.wan.get(p.get("b"))
                if (ia, ib) not in built and (ib, ia) not in built:
                    todo.append(f"{p.get('role')}: {a.name}.{p.get('a')} <-> {b.name}.{p.get('b')}")
            if todo:
                self._add("INFO", "coverage", "LINK_NOT_BUILT", f"{a.name} <-> {b.name}",
                          f"{len(todo)} path(s) defined in the inventory are not built yet ('plan' will create them)",
                          todo, [a.primary, b.primary])
        for site, n in sorted(self.data.out_of_scope.items()):
            if n:
                self._add("INFO", "coverage", "OUT_OF_SCOPE_GATEWAYS", site,
                          f"{n} gateway(s) to peers outside the site-to-site estate were skipped (client/third-party VPNs)")


def _pair_subject(a: TunnelRecord, b: TunnelRecord) -> str:
    return f"{a.site} <-> {b.site} ({a.name} / {b.name})"


def _pair_subject_sites(a: str, b: str) -> str:
    return f"{a} <-> {b}"


def _dh_note(p, s) -> List[str]:
    da = getattr(p, "dh_group", None)
    db = getattr(s, "dh_group", None)
    da = "/".join(da) if isinstance(da, list) else da
    db = "/".join(db) if isinstance(db, list) else db
    if da != db and da and db:
        return [f"PFS/DH group differs: {da} vs {db}"]
    return []


# ---------------------------------------------------------------------------
# Inventory / export adapters
# ---------------------------------------------------------------------------

def _sites_from_inventory(inv: dict) -> Dict[str, SiteInfo]:
    sites: Dict[str, SiteInfo] = {}
    for name, s in (inv.get("sites") or {}).items():
        rng = s.get("tunnel_unit_range")
        sites[name] = SiteInfo(
            name=name, firewalls=[f["hostname"] for f in s.get("firewalls", [])],
            wan={k: v["public_ip"] for k, v in (s.get("wan") or {}).items() if v.get("public_ip")},
            lan=list(s.get("lan") or []) or None,
            unit_range=(int(rng[0]), int(rng[1])) if rng else None, vpn_zone=s.get("vpn_zone"))
    return sites


def _standards_from_inventory(inv: dict) -> Standards:
    st = inv.get("standards") or {}
    defs = st.get("profile_definitions") or {}
    return Standards(
        ike={n: _ike_from_dict(n, d) for n, d in (defs.get("ike") or {}).items()},
        ipsec={n: _ipsec_from_dict(n, d) for n, d in (defs.get("ipsec") or {}).items()},
        preferred_ike=st.get("ike_crypto_profile"), preferred_ipsec=st.get("ipsec_crypto_profile"),
        tunnel_ip_pool=st.get("tunnel_ip_pool"))


def _data_from_firewalls(fws: Dict[str, FirewallConfig], pano: Optional[PanoramaConfig],
                         inv: dict, source: str) -> AuditData:
    sites = _sites_from_inventory(inv) if inv.get("sites") else {}
    dev2site = {fw: s.name for s in sites.values() for fw in s.firewalls}
    for host in sorted(fws):
        if host not in dev2site:
            sname = _site_of_hostname(host)
            sites.setdefault(sname, SiteInfo(name=sname, firewalls=[])).firewalls.append(host)
            dev2site[host] = sname
    for s in sites.values():
        s.firewalls.sort()

    # Infer WAN identities (local-ids) for sites the inventory didn't describe.
    for s in sites.values():
        if s.wan:
            continue
        fw = fws.get(s.primary)
        if not fw:
            continue
        for g in fw.ike_gateways:
            lid = g.local_id.id if g.local_id and g.local_id.id else None
            if lid and _is_ip(lid) and lid not in s.wan.values():
                key = g.local_interface or "wan"
                k, n = key, 2
                while k in s.wan:
                    k, n = f"{key}#{n}", n + 1
                s.wan[k] = lid
    ip2site = {ip: s.name for s in sites.values() for ip in s.wan.values()}

    records: Dict[str, List[TunnelRecord]] = {}
    local_ike: Dict[str, Dict[str, IkeCryptoProfile]] = {}
    local_ipsec: Dict[str, Dict[str, IpsecCryptoProfile]] = {}
    out_of_scope: Dict[str, int] = defaultdict(int)
    site_prefixes = sorted(sites, key=len, reverse=True)
    for host, fw in fws.items():
        site = dev2site[host]
        recs: List[TunnelRecord] = []
        for g in fw.ike_gateways:
            peer = fw.gateway_peer_ip(g)
            internal_name = re.match(rf"^{re.escape(site)}(-DC)?-", g.name, re.I) is not None and \
                any(re.search(rf"-{re.escape(p)}(-DC)?(\.Failover)?$", g.name, re.I) for p in site_prefixes if p != site)
            if peer not in ip2site and not internal_name:
                out_of_scope[site] += 1 if host == sites[site].primary else 0
                continue
            t = fw.tunnel_for_gateway(g.name)
            ifc = fw.interface(t.tunnel_interface) if t and t.tunnel_interface else None
            recs.append(TunnelRecord(
                device=host, site=site, name=t.name if t else g.name,
                interface=t.tunnel_interface if t else None,
                tunnel_ip=(ifc.ips[0] if ifc and ifc.ips else None),
                local_id=(g.local_id.id if g.local_id and g.local_id.id else fw.resolve(g.local_ip)),
                peer_id=peer, ike=g.ike_crypto_profile, ipsec=t.ipsec_crypto_profile if t else None,
                proxy_ids=[(p.local, p.remote) for p in (t.proxy_ids if t else []) if p.local and p.remote],
                local_interface=g.local_interface, has_tunnel=t is not None,
                disabled=g.disabled or bool(t and t.disabled)))
        records[host] = recs
        local_ike[host] = dict(fw.ike_crypto)
        local_ipsec[host] = dict(fw.ipsec_crypto)

    standards = _standards_from_inventory(inv)
    if pano is not None:
        p_ike, p_ipsec = pano.crypto_catalog()
        for k, v in p_ike.items():
            standards.ike.setdefault(k, v)
        for k, v in p_ipsec.items():
            standards.ipsec.setdefault(k, v)
    # PAN-OS ships these on every firewall; they aren't site drift.
    builtin = {"default", "Suite-B-GCM-128", "Suite-B-GCM-256"}
    for m in (local_ike, local_ipsec):
        for dev in m:
            m[dev] = {k: v for k, v in m[dev].items() if k not in builtin or k in standards.ike or k in standards.ipsec}
    return AuditData(source=source, sites=sites, records=records, local_ike=local_ike,
                     local_ipsec=local_ipsec, standards=standards, links=list(inv.get("links") or []),
                     out_of_scope=dict(out_of_scope))


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

_COLORS = {"ERROR": "\033[1;31m", "DRIFT": "\033[1;35m", "WARNING": "\033[1;33m", "INFO": "\033[36m"}
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"


def _use_color(mode: str, stream) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def format_report(findings: List[Finding], source: str = "", color: bool = False,
                  min_severity: str = "INFO") -> str:
    """Render findings as a human-readable report grouped by severity."""
    c = (lambda code, s: f"{code}{s}{_RESET}") if color else (lambda code, s: s)
    shown = [f for f in findings if _SEV_RANK[f.severity] <= _SEV_RANK[min_severity]]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    out = [c(_BOLD, "Site-to-site VPN audit") + (c(_DIM, f"  ({source})") if source else ""),
           "  " + "   ".join(c(_COLORS[s], f"{s} {counts[s]}") for s in SEVERITIES), ""]
    for sev in SEVERITIES:
        group = [f for f in shown if f.severity == sev]
        if not group:
            continue
        out.append(c(_COLORS[sev], f"== {sev} ({len(group)}) " + "=" * max(0, 60 - len(sev))))
        for f in group:
            out.append(f"{c(_COLORS[sev], f'[{sev}]')} {c(_BOLD, f.check)}/{f.code}  {f.subject}")
            out.append(f"    {f.message}")
            for d in f.details:
                out.append(c(_DIM, f"      - {d}") if not d.startswith("  ") else c(_DIM, f"        {d.strip()}"))
        out.append("")
    if not shown:
        out.append("No findings at or above " + min_severity + ".")
    return "\n".join(out)


def exit_code(findings: List[Finding]) -> int:
    """Return 2 if there are ERRORs, 1 if there are DRIFT/WARNING findings, else 0."""
    if any(f.severity == "ERROR" for f in findings):
        return 2
    if any(f.severity in ("DRIFT", "WARNING") for f in findings):
        return 1
    return 0


# ---------------------------------------------------------------------------
# CLI: python -m core.auditor --demo | --inventory FILE | --exports DIR
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Audit site-to-site VPN drift (read-only).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--demo", action="store_true", help=f"audit the fictional {DEMO_INVENTORY.name}")
    src.add_argument("--exports", metavar="DIR", help="directory of firewall exports (XML or brace format)")
    src.add_argument("--observed", metavar="YAML", help="inventory with an 'observed:' section")
    ap.add_argument("--inventory", metavar="YAML", help="site/standards inventory to use with --exports")
    ap.add_argument("--panorama", metavar="FILE", help="Panorama export providing the crypto standards")
    ap.add_argument("--pattern", default="*", help="glob for files inside --exports (default: *)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="INFO")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = ap.parse_args(argv)

    if args.demo:
        auditor = Auditor.from_inventory(DEMO_INVENTORY)
    elif args.observed:
        auditor = Auditor.from_inventory(args.observed)
    else:
        auditor = Auditor.from_exports(args.exports, panorama=args.panorama,
                                       inventory=args.inventory, pattern=args.pattern)
    findings = auditor.run()
    if args.json:
        print(json.dumps([f.to_dict() for f in findings
                          if _SEV_RANK[f.severity] <= _SEV_RANK[args.min_severity]], indent=1))
    else:
        print(format_report(findings, auditor.data.source if not args.demo else "demo: " + DEMO_INVENTORY.name,
                            color=_use_color(args.color, sys.stdout), min_severity=args.min_severity))
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
