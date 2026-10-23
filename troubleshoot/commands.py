"""
Copy-paste PAN-OS operational commands that confirm a diagnosis on the firewall itself.

They're filled in from a traced flow (zones, VR, pre/post-NAT addresses), so the engineer can check
the offline result on the box: policy match, NAT match, FIB lookup, live sessions, global counters
for the flow (packet-diag filter) and the Monitor-tab log filter.

Every command is read-only except the ``debug dataplane packet-diag`` filter, which only scopes the
counters and is switched off again at the end.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import List, Optional

from .engine import PROTO_NUMBERS, FlowTrace
from .logs import LogEntry
from .objects import first_ip, interval_str
from .policy import PolicyConfig


@dataclass
class CommandSet:
    flow: str
    groups: List[tuple] = field(default_factory=list)      # (title, [commands])

    def add(self, title: str, cmds: List[str]) -> None:
        self.groups.append((title, cmds))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["groups"] = [{"title": t, "commands": c} for t, c in self.groups]
        return d


def q(value: Optional[str]) -> str:
    """Quote a name for the PAN-OS CLI if it has spaces or special characters."""
    if value is None:
        return "<?>"
    return f'"{value}"' if any(ch in value for ch in ' "\'[];') else value


def verification_commands(policy: PolicyConfig, t: FlowTrace, logs: Optional[List[LogEntry]] = None) -> CommandSet:
    f = t.flow
    src, dst = first_ip(f.src), first_ip(f.dst)
    proto = PROTO_NUMBERS.get(f.proto or "")
    cs = CommandSet(str(f))

    pm = []
    if t.from_zone and t.to_zone:
        base = f"from {q(t.from_zone)} to {q(t.to_zone)} source {src} destination {dst}"
        if proto:
            base += f" protocol {proto}"
        if f.dport is not None:
            base += f" destination-port {f.dport}"
        sec = base + (f" application {f.app}" if f.app else "") + (f" source-user {q(f.user)}" if f.user else "") \
            + (f" category {f.url_category}" if f.url_category else "")
        pm.append(f"test security-policy-match {sec} show-all yes")
        if proto:
            nat = base.replace(f"to {q(t.to_zone)}", f"to {q(t.pre_nat_zone or t.to_zone)}", 1)
            pm.append(f"test nat-policy-match {nat}")
    if pm:
        cs.add("Policy lookups (the firewall's own answer)", pm)

    rt = []
    if t.vr:
        lr = policy.routes.logical.get(t.vr)
        if lr:
            rt.append(f"show advanced-routing route logical-router {q(lr[0])}")
        else:
            rt.append(f"test routing fib-lookup virtual-router {q(t.vr)} ip {dst}")
            if t.post_nat_dst:
                rt.append(f"test routing fib-lookup virtual-router {q(t.vr)} ip {t.post_nat_dst.split('/')[0]}")
            rt.append(f"test routing fib-lookup virtual-router {q(t.vr)} ip {src}      # return path")
    if t.egress_if:
        rt.append(f"show interface {t.egress_if}")
    if rt:
        cs.add("Routing", rt)

    sess = f"show session all filter source {src} destination {dst}"
    if f.dport is not None:
        sess += f" destination-port {f.dport}"
    cs.add("Live sessions", [sess, "show session id <id-from-above>      # rule, NAT, App-ID, end reason"])

    pdf = f"debug dataplane packet-diag set filter match source {src} destination {dst}"
    if f.dport is not None:
        pdf += f" destination-port {f.dport}"
    if proto:
        pdf += f" protocol {proto}"
    cs.add("Why packets are dropped (global counters for this flow only)", [
        "debug dataplane packet-diag clear all",
        pdf,
        "debug dataplane packet-diag set filter on",
        "show counter global filter packet-filter yes delta yes      # run twice while reproducing",
        "debug dataplane packet-diag set filter off",
    ])

    mon = [f"( addr.src in {interval_str(f.src)} ) and ( addr.dst in {interval_str(f.dst)} )"
           + (f" and ( port.dst eq {f.dport} )" if f.dport is not None else "")]
    cs.add("Monitor > Logs filter (traffic, threat, URL)", mon)
    urls = [e.url for e in (logs or []) if e.kind == "url" and e.url and e.blocked
            and e.src == src and e.dst == dst]
    hosts = list(dict.fromkeys(u.split("/")[0] for u in urls))[:3]
    if hosts:
        cs.add("URL category lookup", [f"test url {h}" for h in hosts])
    return cs


def format_commands(cs: CommandSet) -> List[str]:
    out = []
    for title, cmds in cs.groups:
        out.append(f"  # {title}")
        out += [f"    {c}" for c in cmds]
    return out
