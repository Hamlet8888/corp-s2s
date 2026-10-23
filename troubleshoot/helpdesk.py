"""
Plain-language answers for helpdesk staff, plus friendly input parsing.

:func:`summarize` turns a :class:`~troubleshoot.engine.Diagnosis` into a traffic-light answer:
what happened, why (in one or two sentences, no firewall jargon), what to do next, who to
escalate to, and a block of text ready to paste into a ticket. The technical findings stay
available for the network team.

:func:`parse_destination` accepts what people actually paste: ``github.com``,
``https://github.com/org/repo``, ``10.1.2.3:8443`` or a plain IP.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from .engine import Diagnosis, Finding

NETWORK_TEAM = "network team"
SECURITY_TEAM = "security team"

_SECURITY_WORDS = re.compile(r"quarantin|soc\b|incident|compromis|isolat|malware|infect", re.I)


@dataclass
class Destination:
    text: str                       # what the user typed
    host: Optional[str]             # hostname, if one was given
    ip: str                         # resolved/parsed IP
    port: Optional[int]
    protocol: Optional[str]
    note: str = ""                  # e.g. "github.com resolved to 140.82.114.3 (2 more addresses)"

    @property
    def label(self) -> str:
        return f"{self.host} ({self.ip})" if self.host else self.ip


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def resolve(host: str) -> List[str]:
    """IPv4 first, then IPv6; de-duplicated, in resolver order."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    return list(dict.fromkeys(v4 + v6))


def parse_destination(text: str, port: Optional[int] = None, resolver=resolve) -> Destination:
    """Turn a URL, host[:port] or IP[/prefix] into an IP plus port/protocol."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("destination is empty")
    proto = None
    if "://" in raw:
        u = urlsplit(raw)
        host = u.hostname or ""
        port = port or u.port or {"http": 80, "https": 443, "ssh": 22, "ftp": 21, "rdp": 3389}.get(u.scheme)
        proto = "tcp" if port else None
    else:
        host = raw.split("/")[0] if not _is_ip(raw) else raw
        m = re.match(r"^\[?([^\]]+?)\]?:(\d{1,5})$", host)
        if m and not _is_ip(host):
            host, port = m.group(1), port or int(m.group(2))
    if not host or not re.match(r"^[A-Za-z0-9.\-:_/\[\]]+$", host):
        raise ValueError(f"not a valid address or website: {text!r}")
    if port is not None and not 0 < int(port) < 65536:
        raise ValueError(f"port out of range: {port}")
    if _is_ip(host):
        return Destination(raw, None, host, port, proto or ("tcp" if port else None))
    try:
        ips = resolver(host)
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError(f"could not resolve {host!r} (check the spelling)") from None
    if not ips:
        raise ValueError(f"{host!r} has no address")
    note = f"{host} resolved to {ips[0]}" + (f" ({len(ips) - 1} more address(es) not checked)" if len(ips) > 1 else "")
    return Destination(raw, host, ips[0], port, proto or ("tcp" if port else None), note)


def parse_device(text: str, resolver=resolve) -> Tuple[str, str]:
    """A device is an IP/subnet or a hostname; returns (ip, note)."""
    raw = (text or "").strip()
    if _is_ip(raw):
        return raw, ""
    if not re.match(r"^[A-Za-z0-9.\-_]+$", raw or "-"):
        raise ValueError(f"not a valid device IP or name: {text!r}")
    try:
        ips = [i for i in resolver(raw) if ":" not in i]
    except (socket.gaierror, UnicodeError, OSError):
        raise ValueError(f"could not resolve device {raw!r}; use its IP address") from None
    if not ips:
        raise ValueError(f"device {raw!r} has no IPv4 address")
    return ips[0], f"device {raw} resolved to {ips[0]}"


# ---------------------------------------------------------------------------
# Plain-language summary
# ---------------------------------------------------------------------------

@dataclass
class HelpdeskAnswer:
    status: str                     # blocked | allowed | check | unknown
    headline: str
    explanation: str
    next_steps: List[str] = field(default_factory=list)
    escalate_to: Optional[str] = None
    ticket_text: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _first(d: Diagnosis, *codes: str) -> Optional[Finding]:
    return next((f for f in d.findings if f.code in codes and f.severity in ("ERROR", "WARNING")), None)


def _rule_from(msg: str) -> Optional[str]:
    m = re.search(r"rule '([^']+)'", msg)
    return m.group(1) if m else None


def summarize(d: Diagnosis, device: str, dest: Optional[str] = None, port: Optional[int] = None,
              firewall: Optional[str] = None, policy=None) -> HelpdeskAnswer:
    """Explain *d* for someone who doesn't know firewalls."""
    if dest is None and not d.peer and d.traces:      # no destination given: name what the logs showed
        dsts = list(dict.fromkeys(str(t.flow).split(" -> ")[1].split("/")[0] for t in d.traces))
        dest = ", ".join(dsts[:3]) + (" and others" if len(dsts) > 3 else "")
    to = dest or d.peer or "the destination"
    where = f"{to}" + (f" on port {port}" if port else "")
    a = HelpdeskAnswer("unknown", "Couldn't tell", "")

    threat = _first(d, "LOG_THREAT_BLOCK")
    zone_prot = _first(d, "LOG_ZONE_PROTECTION")
    url = _first(d, "LOG_URL_BLOCK", "PROFILE_URL_BLOCK")
    deny = _first(d, "POLICY_DENY", "LOG_DENY")
    default_deny = _first(d, "POLICY_DEFAULT_DENY", "LOG_DEFAULT_DENY")
    network = _first(d, "ROUTE_NONE", "ROUTE_DISCARD", "ROUTE_NO_RETURN", "ROUTE_PRIVATE_VIA_DEFAULT", "ZONE_MISSING",
                     "NAT_DNAT_NO_ROUTE", "NAT_NO_SOURCE_NAT")
    conflict = _first(d, "APP_PORT_CONFLICT")
    no_reply = _first(d, "LOG_NO_REPLY")

    if threat:
        t = threat.data or {}
        a = HelpdeskAnswer(
            "blocked", "Blocked by threat protection",
            f"The firewall detected '{t.get('threat', 'a threat')}' (severity: {t.get('severity', '?')}) in traffic "
            f"between {device} and {to} and stopped it. This is either real malicious content or, occasionally, "
            f"a false alarm.",
            ["Do not try to work around the block (other networks, VPNs, other devices).",
             f"If {device} may be infected, disconnect it from the network and follow the security procedure.",
             "Escalate to the security team with this report."], SECURITY_TEAM)
    elif zone_prot:
        a = HelpdeskAnswer(
            "blocked", "Blocked by attack protection",
            f"The firewall saw traffic from {device} that looks like scanning or flooding and blocked it "
            f"temporarily.", ["Escalate to the network team with this report."], NETWORK_TEAM)
    elif url:
        u = url.data or {}
        urls = ", ".join(list(dict.fromkeys(x.split("/")[0] for x in (u.get("urls") or []) if x))[:2])
        a = HelpdeskAnswer(
            "blocked", f"Blocked by web filtering (category: {u.get('category', '?')})",
            f"{urls or to} is classified as '{u.get('category', '?')}', a category company policy blocks. "
            f"The block is intentional, not a fault.",
            ["If the user needs this site for work, escalate to the network team to request an exception.",
             "If the site looks wrongly classified, say so in the ticket: the network team can ask Palo Alto "
             "to re-categorise it."], NETWORK_TEAM)
    elif deny and not default_deny:
        rule = _rule_from(deny.message)
        desc = next((x[len("description: "):] for x in deny.details if x.startswith("description: ")), "")
        if policy is not None and rule and not desc:
            r = policy.rule(rule)
            desc = (r.description or "") if r else ""
        security = bool(_SECURITY_WORDS.search(f"{rule or ''} {desc}"))
        a = HelpdeskAnswer(
            "blocked", "Blocked on purpose by a firewall rule",
            f"A firewall rule ('{rule or '?'}') specifically blocks {device} from reaching {where}."
            + (f" The rule's note says: \"{desc}\"." if desc else ""),
            (["This device appears to be isolated for security reasons. Do not try to work around it.",
              "Escalate to the security team with this report."] if security else
             ["Escalate to the network team with this report; they decide whether the block should stay."]),
            SECURITY_TEAM if security else NETWORK_TEAM)
    elif default_deny:
        a = HelpdeskAnswer(
            "blocked", "No access has been granted",
            f"No firewall rule allows {device} to reach {where}, so the firewall blocks it by default. Access "
            f"was never set up (or was removed).",
            ["Escalate to the network team with this report: it already says exactly what they need to add."],
            NETWORK_TEAM)
    elif network:
        a = HelpdeskAnswer(
            "blocked", "Network setup problem",
            f"The firewall doesn't have a working path between {device} and {to} (a missing route or network "
            f"setting). This is a configuration issue, not a permission issue.",
            ["Escalate to the network team with this report."], NETWORK_TEAM)
    elif conflict:
        a = HelpdeskAnswer(
            "blocked", "A firewall rule is set up incorrectly",
            "The rule meant to allow this traffic is configured in a way that drops the connection after it "
            "starts (application and port don't match).",
            ["Escalate to the network team with this report."], NETWORK_TEAM)
    elif d.verdict.startswith("TERMINATES"):
        a = HelpdeskAnswer(
            "blocked", "The address belongs to the firewall itself",
            f"{to} is the firewall's own address and nothing is published behind it.",
            ["Escalate to the network team with this report."], NETWORK_TEAM)
    elif d.verdict.startswith("DEPENDS") or any(t.verdict == "CONDITIONAL" for t in d.traces):
        a = HelpdeskAnswer(
            "check", "Depends on which program is used",
            f"The firewall allows some programs from {device} to {where} but not others.",
            ["Ask the user which program or app they are using and check again with that application.",
             "If it's still unclear, escalate to the network team with this report."], NETWORK_TEAM)
    elif no_reply:
        a = HelpdeskAnswer(
            "check", "The firewall let it through, but nobody answered",
            f"Traffic from {device} to {where} was allowed, but {to} never replied.",
            [f"Check whether {to} is up (another user, a status page, or ping from another network).",
             "If it is up, escalate to the network team with this report (the reply may be lost on the way back)."],
            NETWORK_TEAM)
    elif d.verdict.startswith("ALLOWED") or d.verdict.startswith("NO BLOCKS"):
        what = (f"{device} to {where}" if d.peer else f"anything from {device} in the time window checked")
        a = HelpdeskAnswer(
            "allowed", "The firewall is not blocking this",
            f"The firewall allows {what}. The problem is somewhere else.",
            ["Check the device is online (Wi-Fi/cable, can it open other sites?).",
             "Check the website or service itself (is it down for others?).",
             "Check for a VPN, proxy or security software on the device.",
             "Try the same thing from another device on the same network."], None)
    else:
        a = HelpdeskAnswer(
            "unknown", "Not enough information",
            "The check couldn't reach a conclusion" + ("" if d.peer else ": add the website or address the user "
                                                        "is trying to reach") + ".",
            ["Add the destination (website or IP) and check again.",
             "If it still can't tell, escalate to the network team with this report."], NETWORK_TEAM)

    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"Firewall check ({when}) on {firewall or d.hostname or 'firewall'}",
             f"Device: {device}" + (f"   Destination: {where}" if dest or d.peer else ""),
             f"Result: {a.status.upper()} - {a.headline}",
             f"Why: {a.explanation}"]
    tech = [t.reason for t in d.traces if t.reason]
    if tech:
        lines.append("Technical: " + "; ".join(dict.fromkeys(tech)))
    if a.escalate_to:
        lines.append(f"Escalate to: {a.escalate_to}")
    a.ticket_text = "\n".join(lines)
    return a


# ---------------------------------------------------------------------------
# Paths through more than one firewall, and traffic that never reaches one
# ---------------------------------------------------------------------------

def _where(name: str, site: str) -> str:
    return f"{name} ({site})" if site else name


def bypass_answer(device: str, dest: str, firewall: str, site: str, reason: str, carried_by: str = "",
                  network: str = "") -> HelpdeskAnswer:
    """The traffic never passes the firewall: say so and point to what does carry it."""
    where = site or firewall
    if reason == "east-west":
        headline = f"Not a firewall issue: this traffic stays inside {where} on the {carried_by or 'core switches'}"
        why = (f"{device} and {dest} are both in {where}" + (f" ({network})" if network else "") + ". Traffic "
               f"between them is switched by the {carried_by or 'core switches'} and never passes {firewall}, so the "
               f"firewall can't block it and has no logs for it.")
        steps = [f"Check that both {device} and {dest} are up and on the right VLAN/subnet.",
                 f"Check access lists (ACLs) and routing (VRFs) on the {carried_by or 'core switches'}.",
                 "Escalate to the network team (data center switching) with this note."]
    else:
        headline = "Not a firewall issue: both are on the same network"
        why = (f"{device} and {dest} are on the same network" + (f" ({network})" if network else "") +
               f", so they talk directly without passing {firewall}.")
        steps = [f"Check that {dest} is up and the service is running.",
                 f"Check the local firewall/antivirus on {dest} and {device}.",
                 "Check the switch port / VLAN of both devices, or escalate to the network team."]
    a = HelpdeskAnswer("allowed", headline, why, steps, NETWORK_TEAM)
    a.ticket_text = "\n".join([f"Firewall check ({datetime.now():%Y-%m-%d %H:%M})",
                               f"Device: {device}   Destination: {dest}",
                               f"Result: NOT A FIREWALL ISSUE - {headline}", f"Why: {why}",
                               f"Escalate to: {NETWORK_TEAM}"])
    return a


def combine(hops: List[dict], device: str, dest: Optional[str], port: Optional[int]) -> HelpdeskAnswer:
    """One answer for a path through several firewalls. *hops* are dicts with name, site, role and answer."""
    if len(hops) == 1:
        return hops[0]["answer"]
    rank = {"blocked": 0, "check": 1, "unknown": 2, "allowed": 3}
    worst = min(hops, key=lambda h: rank.get(h["answer"].status, 2))
    a = worst["answer"]
    others = [h for h in hops if h is not worst]
    where = _where(worst["name"], worst["site"])
    to = f"{dest}" + (f" on port {port}" if port else "") if dest else "the destination"
    if a.status == "allowed":
        out = HelpdeskAnswer("allowed", "No firewall on the path is blocking this",
                             f"Traffic from {device} to {to} passes "
                             + " and ".join(_where(h['name'], h['site']) for h in hops) + "; neither blocks it.",
                             a.next_steps, None)
    else:
        verdict = {"blocked": "Blocked", "check": "Needs a closer look", "unknown": "Unclear"}[a.status]
        ok = [_where(h["name"], h["site"]) for h in others if h["answer"].status == "allowed"]
        out = HelpdeskAnswer(a.status, f"{verdict} at {where}: {a.headline}",
                             a.explanation + (f" ({', '.join(ok)} lets it through.)" if ok else ""),
                             a.next_steps, a.escalate_to)
    lines = [f"Firewall check ({datetime.now():%Y-%m-%d %H:%M})",
             f"Device: {device}" + (f"   Destination: {to}" if dest else ""),
             "Path: " + " -> ".join(f"{_where(h['name'], h['site'])} [{h['role']}]" for h in hops),
             f"Result: {out.status.upper()} - {out.headline}"]
    for h in hops:
        lines.append(f"  {h['name']}: {h['answer'].status.upper()} - {h['answer'].headline}")
    if out.escalate_to:
        lines.append(f"Escalate to: {out.escalate_to}")
    out.ticket_text = "\n".join(lines)
    return out
