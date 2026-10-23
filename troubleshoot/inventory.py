"""
Firewall inventory for the web app: which firewalls the helpdesk can pick from.

The inventory is a small YAML or CSV file kept out of git (``inventory/`` is ignored):

    defaults:                      # optional, applied to every firewall
      ca_bundle: /etc/fwcheck/mgmt-ca.pem
    firewalls:
      - name: BLR-FW-01            # shown in the drop-down
        host: 10.9.10.2            # management IP or name
        site: Bangalore, India     # optional, shown next to the name
        group: APAC                # optional, groups the drop-down
        networks: [10.9.0.0/16]    # the site's address space: the app picks this firewall for these IPs
      - name: LVD-FW-01
        host: 10.14.10.2
        site: Las Vegas Data Center
        networks: [10.14.0.0/16]
        east_west: Cisco Nexus     # traffic inside the site is switched by the Nexus, not this firewall
        firewalled_networks: [10.14.200.0/24]   # optional: parts of the site that DO sit behind the firewall
      - name: LAB-TEST-FIREWALL
        host: 192.168.10.200
        lab: true                  # listed separately as "test / lab - don't use"
        note: Test firewall, not for helpdesk checks
      - name: OFFLINE-FW
        config: exports/fw.xml     # offline: a saved config (and optional logs: [...])

CSV works too, with a header row: ``name,host,ha_peer,ha,site,group,networks,lab,note,east_west,firewalled_networks``
(lists separated by spaces).

It can be generated instead of typed:

* :func:`from_configs` reads a folder of config exports (XML or ``show config`` text) and takes
  each firewall's hostname, management IP and internal networks. Configs are read locally and
  only those fields are written out; secrets never leave the machine.
* :func:`from_panorama` asks Panorama for its connected firewalls (``show devices connected``).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

from common import miniyaml
from common.parser import _entries, _text, load_config

_HOST_OK = re.compile(r"^[A-Za-z0-9.\-:\[\]]+$")
_NAME_OK = re.compile(r"^[A-Za-z0-9 _.\-()]{1,64}$")


@dataclass
class FirewallEntry:
    name: str
    host: Optional[str] = None          # live: management IP or name
    ha_peer: Optional[str] = None       # live: HA partner, used when 'host' is passive or unreachable
    ha: Optional[bool] = None           # False: standalone by design; True: must be a pair; None: not stated
    site: str = ""
    group: str = ""
    networks: List[str] = field(default_factory=list)
    config: Optional[str] = None        # offline: config export
    logs: List[str] = field(default_factory=list)
    serial: Optional[str] = None        # reach it through Panorama (defaults.panorama) instead
    vsys: str = "vsys1"
    ca_bundle: Optional[str] = None
    insecure: bool = False
    lab: bool = False                   # test/lab firewall: shown separately, never the default
    note: str = ""                      # shown to users when they pick it
    east_west: str = ""                 # e.g. "Cisco Nexus": traffic inside the site doesn't pass this firewall
    firewalled_networks: List[str] = field(default_factory=list)   # exceptions inside such a site

    def in_firewalled(self, ip: str) -> bool:
        probe = FirewallEntry(self.name, host="x", networks=self.firewalled_networks)
        return probe.covers(ip)

    @property
    def label(self) -> str:
        return self.name + (f" · {self.site}" if self.site else "")

    def match_len(self, ip: str) -> int:
        """Prefix length of the most specific listed network containing *ip*, or -1."""
        try:
            addr = ipaddress.ip_address(ip.split("/")[0])
        except ValueError:
            return -1
        best = -1
        for n in self.networks:
            try:
                net = ipaddress.ip_network(n, strict=False)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                best = max(best, net.prefixlen)
        return best

    def covers(self, ip: str) -> bool:
        return self.match_len(ip) >= 0


class InventoryError(ValueError):
    pass


def _as_list(v) -> List[str]:
    if v is None or v == "":
        return []
    if isinstance(v, str):
        return [x for x in re.split(r"[\s,;]+", v) if x]
    return [str(x) for x in v]


def _yes(v) -> bool:
    return str(v).strip().lower() in ("1", "yes", "true", "y")


def _entry(raw: dict, defaults: dict, base: Path, where: str) -> FirewallEntry:
    d = dict(defaults)
    d.update({k: v for k, v in raw.items() if v not in (None, "")})
    name = str(d.get("name", "")).strip()
    if not _NAME_OK.match(name):
        raise InventoryError(f"{where}: invalid or missing name {name!r}")
    host = str(d["host"]).strip() if d.get("host") else None
    if host and not _HOST_OK.match(host):
        raise InventoryError(f"{where}: invalid host {host!r}")
    ha_peer = str(d["ha_peer"]).strip() if d.get("ha_peer") else None
    if ha_peer and not _HOST_OK.match(ha_peer):
        raise InventoryError(f"{where}: invalid ha_peer {ha_peer!r}")
    config = d.get("config")
    if not host and not config:
        raise InventoryError(f"{where}: {name} needs 'host' (live) or 'config' (offline)")
    resolve = lambda p: str((base / p).expanduser()) if not Path(p).expanduser().is_absolute() else str(Path(p).expanduser())  # noqa: E731
    networks = _as_list(d.get("networks"))
    firewalled = _as_list(d.get("firewalled_networks"))
    for n in networks + firewalled:
        try:
            ipaddress.ip_network(n, strict=False)
        except ValueError:
            raise InventoryError(f"{where}: {name}: invalid network {n!r}") from None
    return FirewallEntry(
        name=name, host=host, ha_peer=ha_peer, site=str(d.get("site", "")).strip(), group=str(d.get("group", "")).strip(),
        networks=networks, config=resolve(config) if config else None,
        logs=[resolve(p) for p in _as_list(d.get("logs"))], serial=str(d["serial"]) if d.get("serial") else None,
        vsys=str(d.get("vsys") or "vsys1"),
        ca_bundle=resolve(d["ca_bundle"]) if d.get("ca_bundle") else None, insecure=_yes(d.get("insecure", False)),
        ha=None if d.get("ha") is None else _yes(d["ha"]), lab=_yes(d.get("lab", False)), note=str(d.get("note", "")).strip()[:200],
        east_west=str(d.get("east_west", "")).strip()[:64], firewalled_networks=firewalled)


def load_inventory(path) -> List[FirewallEntry]:
    """Load a YAML or CSV inventory; relative paths are taken from the file's folder."""
    path = Path(path).expanduser()
    base = path.parent
    if path.suffix.lower() == ".csv":
        rows = list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig"))))
        raw_list, defaults = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in rows], {}
    else:
        data = miniyaml.load(path) or {}
        if not isinstance(data, dict) or not isinstance(data.get("firewalls"), list):
            raise InventoryError(f"{path}: expected a 'firewalls:' list")
        raw_list, defaults = data["firewalls"], data.get("defaults") or {}
    entries, seen = [], set()
    for i, raw in enumerate(raw_list, 1):
        if not isinstance(raw, dict):
            raise InventoryError(f"{path}: entry {i} is not a mapping")
        e = _entry(raw, defaults, base, f"{path.name} entry {i}")
        if e.name.lower() in seen:
            raise InventoryError(f"{path}: duplicate firewall name {e.name}")
        seen.add(e.name.lower())
        entries.append(e)
    if not entries:
        raise InventoryError(f"{path}: no firewalls listed")
    return entries


# ---------------------------------------------------------------------------
# Generating an inventory
# ---------------------------------------------------------------------------

def _internal_networks(policy) -> List[str]:
    """Private networks behind the firewall: connected LANs plus static routes to private space,
    leaving out tunnels, /30-/32 links and anything reached through the default route."""
    from .objects import interval_str, is_private
    nets = []
    for routes in policy.routes.routes.values():
        for r in routes:
            iface = r.interface or ""
            if r.prefixlen == 0 or r.prefixlen > 29 or iface.startswith("tunnel") or r.nexthop_type == "discard":
                continue
            if not is_private(r.destination) or (r.nexthop_type == "next-vr"):
                continue
            nets.append(interval_str(r.destination))
    out = []
    for n in sorted(set(nets), key=lambda x: (ipaddress.ip_network(x).version, ipaddress.ip_network(x))):
        net = ipaddress.ip_network(n)
        if not any(net != ipaddress.ip_network(o) and net.subnet_of(ipaddress.ip_network(o)) for o in nets
                   if ipaddress.ip_network(o).version == net.version):
            out.append(n)
    return out


def drop_other_sites(networks: List[str], other_hosts: List[str]) -> List[str]:
    """Remove networks that contain another firewall's management IP: those are routes to other sites
    (a branch's static route to the data center), not the firewall's own address space."""
    others = []
    for h in other_hosts:
        try:
            others.append(ipaddress.ip_address(h))
        except (ValueError, TypeError):
            continue
    keep = []
    for n in networks:
        net = ipaddress.ip_network(n, strict=False)
        if not any(o.version == net.version and o in net for o in others):
            keep.append(n)
    return keep


def from_configs(folder, name_filter: Optional[str] = None, site_prefix: Optional[int] = None) -> List[FirewallEntry]:
    """Read every firewall config export in *folder* (recursively) and return inventory entries.

    *site_prefix* (e.g. 16) is for address plans where each site owns one block that also holds the
    firewall's management IP: the site's network is then management-IP/prefix (10.9.10.2 -> 10.9.0.0/16)
    instead of the subnets and routes found in the config.
    """
    from .policy import policy_from_root
    rx = re.compile(name_filter, re.I) if name_filter else None
    found = {}
    for p in sorted(Path(folder).expanduser().rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".xml", ".txt", ".conf", ".cfg", ""):
            continue
        try:
            cfg, _ = load_config(p)
        except Exception:
            continue
        dev = cfg.find("devices/entry")
        if dev is None or dev.find("device-group") is not None or dev.find("template") is not None:
            continue                                       # not a firewall (Panorama or unrelated XML)
        system = dev.find("deviceconfig/system")
        name = _text(system, "hostname")
        host = _text(system, "ip-address")
        if not name or (rx and not rx.search(name)):
            continue
        networks: List[str] = []
        if site_prefix and host:
            try:
                networks = [str(ipaddress.ip_network(f"{host}/{site_prefix}", strict=False))]
            except ValueError:
                networks = []
        if not networks:
            try:
                vsys = next((v.get("name") for v in _entries(dev, "vsys")), "vsys1") or "vsys1"
                networks = _internal_networks(policy_from_root(cfg, vsys=vsys, source=str(p)))
            except Exception:
                networks = []
        mtime = p.stat().st_mtime
        if name not in found or mtime > found[name][1]:      # newest export wins
            found[name] = (FirewallEntry(name=name, host=host, networks=networks,
                                         config=None if host else str(p.resolve())), mtime)
    entries = [e for e, _ in sorted(found.values(), key=lambda x: x[0].name)]
    if not site_prefix:
        for e in entries:
            e.networks = drop_other_sites(e.networks, [o.host for o in entries if o is not e and o.host])
    return entries


def from_panorama(client, name_filter: Optional[str] = None) -> List[FirewallEntry]:
    """Firewalls connected to Panorama (``show devices connected``): hostname, management IP, serial."""
    rx = re.compile(name_filter, re.I) if name_filter else None
    root = client.op("<show><devices><connected/></devices></show>")
    out = []
    for e in root.iter("entry"):
        name = (e.findtext("hostname") or "").strip()
        host = (e.findtext("ip-address") or "").strip()
        if not name or not host or (rx and not rx.search(name)):
            continue
        out.append(FirewallEntry(name=name, host=host, serial=(e.findtext("serial") or "").strip() or None,
                                 site=""))
    return sorted(out, key=lambda x: x.name)


def to_yaml(entries: List[FirewallEntry], note: str = "") -> str:
    """Write an inventory as YAML that load_inventory reads back (and humans can edit)."""
    def q(v: str) -> str:
        return v if re.match(r"^[A-Za-z0-9_.\-/:]+$", v or "") else '"' + (v or "").replace('"', "'") + '"'
    lines = ["# Firewall inventory for pan-troubleshoot serve (keep it out of git: inventory/ is ignored).",
             "# Fill in 'site' (shown to the helpdesk) and optionally 'group' (e.g. APAC, EMEA, Americas)."]
    if note:
        lines.append(f"# {note}")
    lines.append("firewalls:")
    for e in entries:
        lines.append(f"  - name: {q(e.name)}")
        if e.host:
            lines.append(f"    host: {q(e.host)}")
        if e.ha_peer:
            lines.append(f"    ha_peer: {q(e.ha_peer)}")
        if e.config:
            lines.append(f"    config: {q(e.config)}")
        lines.append(f"    site: {q(e.site)}" if e.site else "    site: \"\"")
        if e.group:
            lines.append(f"    group: {q(e.group)}")
        if e.serial:
            lines.append(f"    serial: \"{e.serial}\"")
        if e.networks:
            lines.append(f"    networks: [{', '.join(e.networks)}]")
        if e.east_west:
            lines.append(f"    east_west: {q(e.east_west)}")
        if e.firewalled_networks:
            lines.append(f"    firewalled_networks: [{', '.join(e.firewalled_networks)}]")
        if e.ha is not None:
            lines.append(f"    ha: {'true' if e.ha else 'false'}")
        if e.lab:
            lines.append("    lab: true")
        if e.note:
            lines.append(f"    note: {q(e.note)}")
    return "\n".join(lines) + "\n"


def to_dict(e: FirewallEntry) -> dict:
    d = asdict(e)
    d.pop("logs", None)
    d.pop("config", None)
    d.pop("ca_bundle", None)
    return d
