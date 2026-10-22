"""
Traffic, threat and URL-filtering logs: load them from files or pull them over the XML API.

Supported inputs, normalised into :class:`LogEntry`:

* the XML API log-query output (``<response><result><log><logs><entry>``), live or saved;
* CSV exports from the web UI (Monitor > Logs > Export to CSV) for traffic, threat and URL logs.

URL-filtering logs are threat logs with subtype ``url``; they are classified as ``url``.

Standard library only (plus :mod:`core.api` for live queries). Python 3.9+.
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .objects import Interval, interval_str, overlaps, try_target

#: Traffic-log actions that mean the session was refused.
TRAFFIC_DENY = {"deny", "drop", "drop-icmp", "reset-client", "reset-server", "reset-both", "drop-all"}
#: Threat/URL actions that stop traffic (everything except alert/allow).
THREAT_BLOCK = {"drop", "drop-all-packets", "drop-packet", "reset-client", "reset-server", "reset-both",
                "block-ip", "sinkhole", "block", "deny", "block-url", "block-continue", "block-override",
                "override-lockout", "continue", "override", "random-drop", "syn-cookies"}


@dataclass
class LogEntry:
    kind: str                         # traffic | threat | url
    time: Optional[str] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    proto: Optional[str] = None
    app: Optional[str] = None
    rule: Optional[str] = None
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    inbound_if: Optional[str] = None
    outbound_if: Optional[str] = None
    action: Optional[str] = None
    session_end_reason: Optional[str] = None
    natsrc: Optional[str] = None
    natdst: Optional[str] = None
    subtype: Optional[str] = None
    threat: Optional[str] = None
    threat_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    url: Optional[str] = None
    bytes_received: Optional[int] = None
    packets_received: Optional[int] = None
    vsys: Optional[str] = None

    @property
    def blocked(self) -> bool:
        a = (self.action or "").lower()
        return a in (TRAFFIC_DENY if self.kind == "traffic" else THREAT_BLOCK)

    def involves(self, target: Interval) -> bool:
        return any(iv and overlaps(iv, target) for iv in (try_target(self.src), try_target(self.dst),
                                                          try_target(self.natdst)))

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

# XML API field -> LogEntry attribute
_XML_FIELDS = {
    "receive_time": "time", "time_generated": "time", "src": "src", "dst": "dst", "sport": "sport",
    "dport": "dport", "proto": "proto", "app": "app", "rule": "rule", "from": "from_zone", "to": "to_zone",
    "inbound_if": "inbound_if", "outbound_if": "outbound_if", "action": "action",
    "session_end_reason": "session_end_reason", "natsrc": "natsrc", "natdst": "natdst", "subtype": "subtype",
    "threatid": "threat", "tid": "threat_id", "severity": "severity", "category": "category", "misc": "url",
    "bytes_received": "bytes_received", "pkts_received": "packets_received", "vsys": "vsys",
    "url_category_list": "category",
}

# CSV header (lower-cased) -> LogEntry attribute
_CSV_FIELDS = {
    "receive time": "time", "generate time": "time", "source address": "src", "destination address": "dst",
    "source port": "sport", "destination port": "dport", "ip protocol": "proto", "application": "app",
    "rule": "rule", "rule name": "rule", "source zone": "from_zone", "destination zone": "to_zone",
    "inbound interface": "inbound_if", "outbound interface": "outbound_if", "action": "action",
    "session end reason": "session_end_reason", "nat source ip": "natsrc", "nat destination ip": "natdst",
    "threat/content type": "subtype", "content type": "subtype", "threat/content name": "threat",
    "threat name": "threat", "threat id": "threat_id", "severity": "severity", "category": "category",
    "url category": "category", "url/filename": "url", "url": "url", "bytes received": "bytes_received",
    "packets received": "packets_received", "virtual system": "vsys", "type": "_type",
}

_INT_FIELDS = {"sport", "dport", "bytes_received", "packets_received"}


def _make(fields: Dict[str, str], hint: Optional[str]) -> LogEntry:
    raw_type = (fields.pop("_type", None) or hint or "").lower()
    e = LogEntry(kind="traffic")
    for k, v in fields.items():
        v = (v or "").strip()
        if not v:
            continue
        if k in _INT_FIELDS:
            try:
                setattr(e, k, int(v))
            except ValueError:
                pass
        elif getattr(e, k, None) is None:
            setattr(e, k, v)
    if e.threat:                                   # "Name(12345)" -> name + id
        m = re.match(r"^(.*?)\s*\((\d+)\)\s*$", e.threat)
        if m:
            e.threat, e.threat_id = m.group(1), e.threat_id or m.group(2)
    sub = (e.subtype or "").lower()
    if raw_type in ("url", "url-filtering") or sub == "url":
        e.kind = "url"
    elif raw_type == "threat" or (raw_type != "traffic" and e.threat):
        e.kind = "threat"
    else:
        e.kind = "traffic"
    if e.proto:
        e.proto = e.proto.lower()
    if e.action:
        e.action = e.action.lower()
    return e


def parse_xml_entries(entries: Iterable[ET.Element], hint: Optional[str] = None) -> List[LogEntry]:
    out = []
    for el in entries:
        fields = {}
        for c in el:
            attr = _XML_FIELDS.get(c.tag)
            if attr and (c.text or "").strip() and attr not in fields:
                fields[attr] = c.text or ""
        fields["_type"] = (el.findtext("type") or hint or "").strip()
        out.append(_make(fields, hint))
    return out


def parse_csv(text: str, hint: Optional[str] = None) -> List[LogEntry]:
    reader = csv.reader(io.StringIO(text))
    try:
        header = [h.strip().lower() for h in next(reader)]
    except StopIteration:
        return []
    cols = [(i, _CSV_FIELDS[h]) for i, h in enumerate(header) if h in _CSV_FIELDS]
    out = []
    for row in reader:
        if not row:
            continue
        fields: Dict[str, str] = {}
        for i, attr in cols:
            if i < len(row) and attr not in fields and row[i].strip():
                fields[attr] = row[i]
        out.append(_make(fields, hint))
    return out


def load_logs(path, hint: Optional[str] = None) -> List[LogEntry]:
    """Load one log file (XML API output or a CSV export). *hint* is traffic|threat|url if known."""
    path = Path(path)
    data = path.read_text(encoding="utf-8-sig", errors="replace")
    if hint is None:
        low = path.name.lower()
        hint = next((k for k in ("traffic", "threat", "url") if k in low), None)
    if data.lstrip().startswith("<"):
        root = ET.fromstring(data)
        return parse_xml_entries(root.iter("entry"), hint)
    return parse_csv(data, hint)


# ---------------------------------------------------------------------------
# Live queries
# ---------------------------------------------------------------------------

def build_query(target: Interval, peer: Optional[Interval] = None, port: Optional[int] = None,
                since: Optional[str] = None) -> str:
    """Monitor-tab filter for *target* (and optionally the far end, port and a start time)."""
    parts = [f"( addr in {interval_str(target)} )"]
    if peer is not None:
        parts.append(f"( addr in {interval_str(peer)} )")
    if port is not None:
        parts.append(f"( port.dst eq {int(port)} )")
    if since:
        if not re.match(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}$", since):
            raise ValueError("--since must look like 'YYYY/MM/DD HH:MM:SS'")
        parts.append(f"( receive_time geq '{since}' )")
    return " and ".join(parts)


def fetch_logs(client, target: Interval, peer: Optional[Interval] = None, port: Optional[int] = None,
               since: Optional[str] = None, nlogs: int = 500,
               kinds: Tuple[str, ...] = ("traffic", "threat", "url")) -> Tuple[List[LogEntry], Dict[str, ET.Element]]:
    """Query each log type for *target*; returns the entries and the raw XML per type (for --save)."""
    query = build_query(target, peer, port, since)
    out: List[LogEntry] = []
    raw: Dict[str, ET.Element] = {}
    for kind in kinds:
        entries = client.query_logs(kind, query, nlogs=nlogs)
        holder = ET.Element("logs", {"type": kind, "query": query})
        holder.extend(entries)
        raw[kind] = holder
        out.extend(parse_xml_entries(entries, kind))
    return out, raw


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

@dataclass
class FlowKey:
    src: str
    dst: str
    proto: Optional[str]
    dport: Optional[int]
    app: Optional[str]

    def __hash__(self):
        return hash((self.src, self.dst, self.proto, self.dport, self.app))

    def __str__(self) -> str:
        port = f":{self.dport}" if self.dport is not None else ""
        return f"{self.src} -> {self.dst}{port}/{self.proto or '?'}" + (f" app={self.app}" if self.app else "")


def top_flows(entries: Iterable[LogEntry], limit: int = 5, blocked_only: bool = True) -> List[Tuple[FlowKey, int]]:
    c: Counter = Counter()
    for e in entries:
        if not e.src or not e.dst or (blocked_only and not e.blocked):
            continue
        c[FlowKey(e.src, e.dst, e.proto, e.dport, e.app if e.app not in ("incomplete", "not-applicable") else None)] += 1
    return c.most_common(limit)

