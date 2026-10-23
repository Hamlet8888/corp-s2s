"""
High-availability health, from ``show high-availability all`` on one member of each pair.

The member we talk to reports its own state, its peer's state as it sees it, the HA1/HA2 links
and whether the running config is synchronized, so the peer's address isn't needed. Read-only.

Levels: ``ok`` (healthy pair), ``standalone`` (no HA, as the inventory says), ``warn`` (still
fails over, but something is degraded), ``fail`` (no working failover), ``unknown`` (couldn't ask).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional
import xml.etree.ElementTree as ET

HA_COMMAND = "<show><high-availability><all></all></show>"
CLI_COMMAND = "show high-availability all"

ACTIVE_STATES = ("active", "active-primary", "active-secondary")
_BROKEN = ("suspended", "non-functional", "tentative", "initial", "unknown")


@dataclass
class HaInfo:
    enabled: bool
    mode: str = ""
    local: str = ""
    peer: str = ""
    peer_conn: str = ""
    peer_ip: str = ""
    ha1: str = ""
    ha1_backup: str = ""
    ha2: str = ""
    running_sync: str = ""
    running_sync_enabled: str = ""
    state_sync: str = ""


@dataclass
class HaHealth:
    firewall: str
    level: str
    headline: str
    problems: List[str] = field(default_factory=list)
    info: Optional[HaInfo] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _t(el: Optional[ET.Element], path: str) -> str:
    if el is None:
        return ""
    return (el.findtext(path) or "").strip().lower()


def parse_ha(root: ET.Element) -> HaInfo:
    """Parse the op response (``<response><result>...``, or the ``<result>`` itself)."""
    res = root.find(".//result") if root.tag != "result" else root
    res = res if res is not None else root
    if _t(res, "enabled") != "yes":
        return HaInfo(enabled=False)
    g = res.find("group")
    local, peer = (g.find("local-info"), g.find("peer-info")) if g is not None else (None, None)
    return HaInfo(
        enabled=True, mode=_t(g, "mode") or _t(local, "mode"), local=_t(local, "state"), peer=_t(peer, "state"),
        peer_conn=_t(peer, "conn-status"), peer_ip=(peer.findtext("mgmt-ip") or "").strip().split("/")[0] if peer is not None else "",
        ha1=_t(peer, "conn-ha1/conn-status"), ha1_backup=_t(peer, "conn-ha1-backup/conn-status"),
        ha2=_t(peer, "conn-ha2/conn-status"), running_sync=_t(g, "running-sync"),
        running_sync_enabled=_t(g, "running-sync-enabled"), state_sync=_t(local, "state-sync"))


def evaluate(name: str, info: HaInfo, expected: Optional[bool] = None) -> HaHealth:
    """Judge one firewall. ``expected``: the inventory's ``ha`` (False = standalone by design)."""
    if not info.enabled:
        if expected is False:
            return HaHealth(name, "standalone", "Standalone (by design)", info=info)
        if expected is True:
            return HaHealth(name, "fail", "HA is not enabled", ["The inventory says this firewall is in an HA pair, "
                                                                "but HA is turned off: there is no failover."], info)
        return HaHealth(name, "warn", "HA is not enabled",
                        ["No failover partner. If this firewall is standalone by design, add  ha: false  to its "
                         "inventory entry and this becomes a normal 'standalone' result."], info)

    fail, warn = [], []
    if expected is False:
        warn.append("HA is enabled, but the inventory lists this firewall as standalone (ha: false).")
    if info.local in _BROKEN:
        fail.append(f"This member is {info.local}: it can't take over if its peer fails.")
    if (info.peer_conn and info.peer_conn != "up") or info.peer in ("", "unknown"):
        fail.append("It can't see its HA peer (peer connection down): if this member fails, nothing takes over.")
    elif info.peer in _BROKEN:
        fail.append(f"The peer is {info.peer}: it can't take over if this member fails.")
    elif info.local in ACTIVE_STATES and info.peer in ACTIVE_STATES and "active-active" not in info.mode.replace(" ", "-"):
        fail.append("Both members say they are active (split brain): traffic and ARP may flap between them.")
    elif info.local not in ACTIVE_STATES and info.peer not in ACTIVE_STATES:
        fail.append(f"Neither member is active ({info.local or '?'} / {info.peer or '?'}): no firewall is passing traffic.")
    if info.ha1 and info.ha1 != "up":
        fail.append(f"HA1 (control link) is {info.ha1}.")
    if info.ha1_backup and info.ha1_backup not in ("up", "n/a", "not configured"):
        warn.append(f"HA1 backup link is {info.ha1_backup}: one more link failure and the pair splits.")
    if info.ha2 and info.ha2 != "up":
        warn.append(f"HA2 (session sync link) is {info.ha2}: open connections will drop on a failover.")
    if info.running_sync_enabled == "no":
        warn.append("Config synchronization is turned off: the members can drift apart.")
    elif info.running_sync and info.running_sync != "synchronized":
        warn.append(f"Config is not in sync between the members ({info.running_sync}): a failover may run "
                    "different rules. Sync it from the active member.")
    if info.state_sync and info.state_sync not in ("complete", "n/a"):
        warn.append(f"Session state sync is {info.state_sync}.")

    pair = f"{info.local or '?'} / peer {info.peer or '?'}"
    if fail:
        return HaHealth(name, "fail", f"Failover not working ({pair})", fail + warn, info)
    if warn:
        return HaHealth(name, "warn", f"Degraded ({pair})", warn, info)
    return HaHealth(name, "ok", f"Healthy ({pair}, config in sync)" if info.running_sync == "synchronized"
                    else f"Healthy ({pair})", [], info)
