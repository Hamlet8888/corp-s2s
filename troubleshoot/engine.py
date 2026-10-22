"""
Troubleshooting engine: why is traffic to or from an IP/subnet blocked?

It answers that two ways and cross-checks them:

1. **Simulation** of the firewall's packet flow from config, in PAN-OS order:
   ingress interface/zone (route back to the source)  ->  route lookup on the original destination
   (egress zone)  ->  NAT policy  ->  route lookup on the translated destination  ->  security policy
   (pre-NAT addresses, post-NAT zone)  ->  security profiles  ->  return route.
2. **Evidence** from traffic, threat and URL-filtering logs: which rule denied the session, which
   threat/URL profile blocked it, sessions that got no reply, and logs that disagree with the
   simulation (stale config, asymmetric routing, App-ID or user-based rules).

Anything that cannot be decided from config alone (App-ID, User-ID, FQDN objects, dynamic groups,
EDLs, URL categories) is reported as *conditional* instead of guessed.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from .logs import LogEntry, top_flows
from .objects import (FULL, NONE, PARTIAL, UNKNOWN, Interval, interval_str, is_private,
                      negate, overlaps, parse_target, try_target)
from .policy import DENY_ACTIONS, NatRule, PolicyConfig, SecurityRule
from .routing import RouteResult

SEVERITIES = ("ERROR", "WARNING", "INFO")
PROTO_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17, "sctp": 132, "icmp6": 58}

#: Threat-log subtype -> the rule profile type responsible for it.
SUBTYPE_PROFILE = {"virus": "virus", "wildfire-virus": "virus", "spyware": "spyware",
                   "vulnerability": "vulnerability", "file": "file-blocking", "wildfire": "wildfire-analysis",
                   "data": "data-filtering", "url": "url-filtering", "ml-virus": "virus"}
#: Threat-log subtypes raised by zone protection / DoS protection rather than a rule's profiles.
ZONE_PROTECTION_SUBTYPES = {"flood", "scan", "packet"}


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str                     # ERROR | WARNING | INFO
    code: str
    message: str
    details: List[str] = field(default_factory=list)
    category: str = "policy"          # routing | zone | nat | policy | profile | threat | url | logs | live

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Flow:
    src: Interval
    dst: Interval
    proto: Optional[str] = None
    dport: Optional[int] = None
    app: Optional[str] = None
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    origin: str = "query"             # query | logs
    hits: int = 0

    def __str__(self) -> str:
        port = f":{self.dport}" if self.dport is not None else ""
        return (f"{interval_str(self.src)} -> {interval_str(self.dst)}{port}/{self.proto or 'any'}"
                + (f" app={self.app}" if self.app else ""))


@dataclass
class Step:
    stage: str
    status: str                       # ok | fail | warn | info
    text: str


@dataclass
class FlowTrace:
    flow: Flow
    steps: List[Step] = field(default_factory=list)
    verdict: str = "UNKNOWN"          # ALLOW | DENY | DROP | UNKNOWN
    reason: str = ""
    vr: Optional[str] = None
    ingress_if: Optional[str] = None
    from_zone: Optional[str] = None
    egress_if: Optional[str] = None
    to_zone: Optional[str] = None
    nat_rule: Optional[str] = None
    post_nat_dst: Optional[str] = None
    security_rule: Optional[str] = None
    conditional_rules: List[str] = field(default_factory=list)

    def step(self, stage: str, status: str, text: str) -> None:
        self.steps.append(Step(stage, status, text))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["flow"] = str(self.flow)
        return d


@dataclass
class Diagnosis:
    hostname: Optional[str]
    target: str
    peer: Optional[str]
    verdict: str = "INCONCLUSIVE"     # BLOCKED | ALLOWED | INCONCLUSIVE
    reasons: List[str] = field(default_factory=list)
    traces: List[FlowTrace] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    log_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"hostname": self.hostname, "target": self.target, "peer": self.peer, "verdict": self.verdict,
                "reasons": self.reasons, "log_counts": self.log_counts,
                "traces": [t.to_dict() for t in self.traces], "findings": [f.to_dict() for f in self.findings]}


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------

Dim = Tuple[str, str, str]            # (dimension, FULL|PARTIAL|UNKNOWN|NONE, explanation)


def _combine(dims: List[Dim]) -> str:
    if any(r == NONE for _, r, _ in dims):
        return NONE
    return FULL if all(r == FULL for _, r, _ in dims) else UNKNOWN


def _zone_dim(name: str, members: List[str], zone: Optional[str]) -> Dim:
    if "any" in members:
        return (name, FULL, "")
    if zone is None:
        return (name, UNKNOWN, f"{name} zone unknown; rule needs {', '.join(members)}")
    return (name, FULL if zone in members else NONE, f"{name} zone '{zone}' not in [{', '.join(members)}]")


def _addr_dim(name: str, store, members: List[str], neg: bool, target: Interval) -> Dim:
    aset = store.resolve_addresses(members)
    r = aset.relation(target)
    if neg:
        r = negate(r)
    label = ("NOT " if neg else "") + ", ".join(members)
    if r == FULL:
        return (name, FULL, "")
    if r == NONE:
        return (name, NONE, f"{name} {interval_str(target)} not in [{label}]")
    if r == PARTIAL:
        return (name, PARTIAL, f"{name} [{label}] covers only part of {interval_str(target)}")
    return (name, UNKNOWN, f"{name} depends on unresolved objects: {'; '.join(aset.unresolved[:3])}")


class Matcher:
    def __init__(self, policy: PolicyConfig):
        self.p = policy
        self.store = policy.store

    def security(self, rule: SecurityRule, flow: Flow, fz: Optional[str], tz: Optional[str]) -> List[Dim]:
        dims: List[Dim] = []
        if rule.rule_type == "intrazone" and fz and tz and fz != tz:
            dims.append(("rule-type", NONE, "intrazone rule, but traffic crosses zones"))
        if rule.rule_type == "interzone" and fz and tz and fz == tz:
            dims.append(("rule-type", NONE, "interzone rule, but traffic stays in one zone"))
        dims.append(_zone_dim("from", rule.from_zones, fz))
        to_members = rule.from_zones if rule.rule_type == "intrazone" else rule.to_zones
        dims.append(_zone_dim("to", to_members, tz))
        dims.append(_addr_dim("source", self.store, rule.source, rule.negate_source, flow.src))
        dims.append(_addr_dim("destination", self.store, rule.destination, rule.negate_destination, flow.dst))
        if "any" not in rule.source_user:
            dims.append(("user", UNKNOWN, f"source-user must be {', '.join(rule.source_user)} (User-ID)"))
        ar = self.store.app_relation(rule.application, flow.app)
        dims.append(("application", ar,
                     f"application {flow.app or '(unknown)'} vs [{', '.join(rule.application)}]"
                     + (" (App-ID decides)" if ar == UNKNOWN else "")))
        sset = self.store.resolve_services(rule.service)
        sr = sset.relation(flow.proto, flow.dport, flow.app, rule.application)
        port = f"{flow.proto or '?'}/{flow.dport if flow.dport is not None else '?'}"
        dims.append(("service", sr, f"service {port} not in [{', '.join(rule.service)}]" if sr == NONE
                     else f"service [{', '.join(rule.service)}] vs {port}"
                     + (" (application-default ports depend on App-ID)" if sset.app_default else "")))
        if "any" not in rule.category:
            dims.append(("url-category", UNKNOWN, f"URL category must be {', '.join(rule.category)}"))
        return dims

    def nat(self, rule: NatRule, flow: Flow, fz: Optional[str], tz: Optional[str], egress_if: Optional[str]) -> List[Dim]:
        dims = [_zone_dim("from", rule.from_zones, fz), _zone_dim("to", rule.to_zones, tz)]
        if rule.to_interface and rule.to_interface != "any":
            dims.append(("to-interface", FULL if rule.to_interface == egress_if else NONE,
                         f"to-interface {rule.to_interface} != egress {egress_if}"))
        dims.append(_addr_dim("source", self.store, rule.source, False, flow.src))
        dims.append(_addr_dim("destination", self.store, rule.destination, False, flow.dst))
        if rule.service != "any":
            sr = self.store.resolve_services([rule.service]).relation(flow.proto, flow.dport)
            dims.append(("service", sr, f"service {flow.proto}/{flow.dport} vs {rule.service}"))
        return dims


def _why(dims: List[Dim]) -> List[str]:
    return [why for _, r, why in dims if r != FULL and why]


# ---------------------------------------------------------------------------
# Troubleshooter
# ---------------------------------------------------------------------------

class Troubleshooter:
    """Diagnose reachability for an IP/subnet against one firewall's config and logs."""

    def __init__(self, policy: PolicyConfig, logs: Optional[List[LogEntry]] = None, live=None):
        self.p = policy
        self.logs = list(logs or [])
        self.m = Matcher(policy)
        self.live = live                  # optional troubleshoot.live.LiveVerifier

    # -- public ---------------------------------------------------------------
    def diagnose(self, target: str, peer: Optional[str] = None, *, port: Optional[int] = None,
                 proto: Optional[str] = None, app: Optional[str] = None, direction: str = "out",
                 from_zone: Optional[str] = None, to_zone: Optional[str] = None,
                 max_flows: int = 5) -> Diagnosis:
        """*target* is the IP/subnet in question; *peer* the other end. ``direction='out'`` means target
        is the source (target -> peer); ``'in'`` means peer -> target."""
        tiv = parse_target(target)
        piv = parse_target(peer) if peer else None
        proto = proto.lower() if proto else (("tcp" if port is not None else None))
        diag = Diagnosis(self.p.hostname, interval_str(tiv), interval_str(piv) if piv else None)
        findings: List[Finding] = []

        rel = [e for e in self.logs if e.involves(tiv) and (piv is None or e.involves(piv))]
        for kind in ("traffic", "threat", "url"):
            diag.log_counts[kind] = sum(1 for e in rel if e.kind == kind)
            diag.log_counts[kind + "_blocked"] = sum(1 for e in rel if e.kind == kind and e.blocked)

        flows: List[Flow] = []
        if piv is not None:
            src, dst = (tiv, piv) if direction == "out" else (piv, tiv)
            flows.append(Flow(src, dst, proto, port, app, from_zone, to_zone))
        for key, n in top_flows(rel, limit=max_flows):
            s, d = try_target(key.src), try_target(key.dst)
            if s is None or d is None or (port is not None and key.dport != port):
                continue
            if any(f.src == s and f.dst == d and f.dport == key.dport and f.proto == key.proto for f in flows):
                continue
            flows.append(Flow(s, d, key.proto, key.dport, key.app, origin="logs", hits=n))
            if len(flows) >= max_flows:
                break

        if not flows:
            findings += self._target_overview(tiv)
        for flow in flows:
            inferred = None if flow.app else _app_from_logs(flow, rel)
            if inferred:
                flow.app = inferred
            trace, fnd = self.simulate(flow)
            if inferred:
                trace.steps.insert(0, Step("app", "info", f"App-ID '{inferred}' taken from matching traffic logs"))
            diag.traces.append(trace)
            findings += fnd
            findings += self._compare_with_logs(trace, rel)
            if self.live is not None:
                findings += self.live.verify(trace)
        findings += self._log_findings(rel, tiv)
        findings += self._log_absence(rel, diag.traces)

        diag.findings = _dedupe(findings)
        diag.verdict, diag.reasons = _verdict(diag)
        return diag

    # -- simulation ------------------------------------------------------------
    def simulate(self, flow: Flow) -> Tuple[FlowTrace, List[Finding]]:
        p, rt = self.p, self.p.routes
        t = FlowTrace(flow)
        out: List[Finding] = []
        fs = str(flow)

        # 1. ingress: the interface the source lives behind (route back to the source)
        if flow.from_zone:
            t.from_zone = flow.from_zone
            zone = p.zones.get(flow.from_zone)
            t.vr = next((rt.vr_of(i) for i in (zone.interfaces if zone else []) if rt.vr_of(i)), None)
            t.step("ingress", "info", f"zone {flow.from_zone} (given)")
        else:
            t.vr = rt.ingress_vr(flow.src)
            back = rt.resolve(t.vr, flow.src) if t.vr else None
            if back is None or not back.ok:
                t.step("ingress", "fail", f"no route back to source {interval_str(flow.src)} in any virtual router")
                out.append(Finding("ERROR", "ROUTE_NO_RETURN",
                                   f"The firewall has no route back to {interval_str(flow.src)}: it can't tell the "
                                   f"ingress zone, and replies would be dropped",
                                   [f"flow {fs}", "add a route (or fix the connected interface) for the source network",
                                    "or re-run with --from-zone to evaluate policy anyway"], "routing"))
                if len(rt.vrs) == 1:
                    t.vr = rt.vrs[0]
            else:
                t.ingress_if = back.interface
                t.from_zone = p.zone_of(back.interface)
                t.step("ingress", "ok" if t.from_zone else "fail",
                       f"{back.interface} zone {t.from_zone or '(NONE)'} vr {t.vr}  [{back.route.describe()}]")
                if not t.from_zone:
                    out.append(_no_zone(back.interface, fs))
        if t.vr is None:
            t.verdict, t.reason = "UNKNOWN", "ingress virtual router unknown"
            return t, out

        # 2. route lookup on the original destination
        fwd = rt.resolve(t.vr, flow.dst)
        self._route_step(t, "route", fwd)
        if not fwd.ok and not flow.to_zone:
            out.append(_route_finding(fwd, flow.dst, fs, t.vr, p.dynamic_routing, rt.live))
            t.verdict, t.reason = "DROP", fwd.error or "no route"
            return t, out
        out += self._split_check(t.vr, flow.dst, fwd, fs)
        t.egress_if = fwd.interface
        t.to_zone = flow.to_zone or p.zone_of(fwd.interface)
        if not t.to_zone:
            t.step("route", "fail", f"egress interface {fwd.interface} is not in any zone")
            out.append(_no_zone(fwd.interface, fs))
            t.verdict, t.reason = "DROP", f"egress interface {fwd.interface} has no zone"
            return t, out
        pre_nat_zone = t.to_zone

        # 3. NAT policy (pre-NAT zones, original addresses)
        nat, nat_cond, nat_disabled = None, [], []
        for r in p.nat_rules:
            dims = self.m.nat(r, flow, t.from_zone, pre_nat_zone, fwd.interface)
            res = _combine(dims)
            if res == NONE:
                continue
            if r.disabled:
                nat_disabled.append(r)
                continue
            if res == FULL:
                nat = r
                break
            nat_cond.append((r, _why(dims)))
        if nat is not None:
            t.nat_rule = nat.name
            t.step("nat", "ok", f"rule {nat.label}: {nat.describe()}")
        else:
            t.step("nat", "info", "no NAT rule matches (traffic is not translated)")
        for r, why in nat_cond:
            t.step("nat", "warn", f"rule {r.label} may match: {'; '.join(why)}")
        if nat is None and is_private(flow.src) and not is_private(flow.dst):
            out.append(Finding("WARNING", "NAT_NO_SOURCE_NAT",
                               f"Private source {interval_str(flow.src)} goes to public {interval_str(flow.dst)} "
                               f"({t.from_zone} -> {pre_nat_zone}) with no source NAT; replies cannot come back",
                               [f"flow {fs}"] + [f"disabled NAT rule {r.label} would match" for r in nat_disabled]
                               + ["add a source NAT rule (dynamic-ip-and-port) for this zone pair"], "nat"))

        # 4. destination NAT: route the translated address to find the post-NAT zone
        if nat is not None and nat.dst_address:
            post = self.p.store.address_value(nat.dst_address)
            if post is None:
                t.step("route-post-nat", "warn", f"translated address {nat.dst_address} can't be resolved offline")
            else:
                t.post_nat_dst = interval_str(post)
                fwd2 = rt.resolve(t.vr, post)
                self._route_step(t, "route-post-nat", fwd2)
                if not fwd2.ok:
                    out.append(Finding("ERROR", "NAT_DNAT_NO_ROUTE",
                                       f"NAT rule {nat.label} translates to {t.post_nat_dst}, but "
                                       + (fwd2.error or "there is no route to it"), [f"flow {fs}"], "nat"))
                    t.verdict, t.reason = "DROP", "no route to the NAT-translated destination"
                    return t, out
                t.egress_if = fwd2.interface
                t.to_zone = flow.to_zone or p.zone_of(fwd2.interface) or t.to_zone

        # 5. security policy: pre-NAT addresses, post-NAT destination zone
        out += self._security(t, flow)

        # 6. return route from the egress virtual router (matters when next-vr was involved)
        last_vr = fwd.vr_path[-1] if fwd.vr_path else t.vr
        if t.verdict == "ALLOW" and last_vr != t.vr:
            back = rt.resolve(last_vr, flow.src)
            if not back.ok:
                t.step("return-route", "fail", back.error or "no return route")
                out.append(Finding("ERROR", "ROUTE_NO_RETURN",
                                   f"Virtual router '{last_vr}' has no route back to {interval_str(flow.src)}",
                                   [f"flow {fs}", f"forward path crosses VRs {' -> '.join(fwd.vr_path)}"], "routing"))
            else:
                t.step("return-route", "ok", f"{back.interface} via {' -> '.join(back.vr_path)}")
        return t, out

    def _route_step(self, t: FlowTrace, stage: str, rr: RouteResult) -> None:
        if rr.ok:
            hops = f" (via {' -> '.join(rr.vr_path)})" if len(rr.vr_path) > 1 else ""
            t.step(stage, "ok", f"{rr.interface} zone {self.p.zone_of(rr.interface) or '(NONE)'}{hops}  "
                                f"[{rr.route.describe()}]")
        else:
            t.step(stage, "fail", rr.error or "no route")

    def _split_check(self, vr: str, dst: Interval, fwd: RouteResult, fs: str) -> List[Finding]:
        if dst[1] == dst[2]:
            return []
        last = (dst[0], dst[2], dst[2])
        other = self.p.routes.resolve(vr, last)
        if other.interface != fwd.interface:
            return [Finding("WARNING", "ROUTE_SPLIT",
                            f"{interval_str(dst)} is not routed as one block: the first address leaves via "
                            f"{fwd.interface}, the last via {other.interface or 'nowhere'}",
                            [f"flow {fs}", "query single hosts to see each path"], "routing")]
        return []

    def _security(self, t: FlowTrace, flow: Flow) -> List[Finding]:
        p, out, fs = self.p, [], str(flow)
        final: Optional[SecurityRule] = None
        cond: List[Tuple[SecurityRule, List[str]]] = []
        disabled: List[Tuple[SecurityRule, List[str]]] = []
        near: List[Tuple[SecurityRule, str]] = []
        idx = 0
        for idx, r in enumerate(p.security_rules):
            dims = self.m.security(r, flow, t.from_zone, t.to_zone)
            res = _combine(dims)
            if res == NONE:
                misses = [why for _, rr, why in dims if rr == NONE]
                if len(misses) == 1 and r.action == "allow" and not r.disabled:
                    near.append((r, misses[0]))
                continue
            if r.disabled:
                disabled.append((r, _why(dims)))
                continue
            if res == FULL:
                final = r
                break
            cond.append((r, _why(dims)))
        rest = p.security_rules[idx + 1:] if final is not None else []
        if final is None:
            final = p.default_rules["intrazone-default" if t.from_zone == t.to_zone else "interzone-default"]

        t.security_rule = final.name
        t.conditional_rules = [r.name for r, _ in cond]
        for r, why in cond:
            t.step("security", "warn", f"rule {r.label} ({r.action}) may match first: {'; '.join(why)}")
        allowed = final.action == "allow"
        cond_allow = [(r, why) for r, why in cond if r.action == "allow"]
        t.step("security", "ok" if allowed else "warn" if cond_allow else "fail",
               f"rule {final.label} -> {final.action.upper()}  ({t.from_zone} -> {t.to_zone})"
               + ("  (unless a conditional allow above matches)" if cond_allow and not allowed else ""))
        t.verdict = "ALLOW" if allowed else "CONDITIONAL" if cond_allow else "DENY"
        t.reason = f"security rule {final.label} action {final.action}"
        if t.verdict == "CONDITIONAL":
            t.reason = (f"allowed by {cond_allow[0][0].label} only if {'; '.join(cond_allow[0][1])}; "
                        f"otherwise {final.label} {_verb(final.action)} it")

        log_note = ([] if final.log_end else
                    [f"{final.name} has logging at session end disabled, so these sessions leave NO traffic log"])
        hint = (["pass --app <name> (or provide traffic logs) so App-ID conditions can be decided"]
                if cond_allow and not flow.app else [])
        if final.rulebase == "default" and not allowed:
            if cond_allow:
                msg = (f"Only {', '.join(r.label for r, _ in cond_allow)} can allow this traffic, and only when: "
                       f"{'; '.join(cond_allow[0][1])}. Anything else falls through to {final.name} (deny)")
            else:
                msg = (f"No security rule allows {t.from_zone} -> {t.to_zone} for this traffic; "
                       f"it falls through to {final.name} ({final.action})")
            details = [f"flow {fs}"] + log_note + hint
            details += [f"near miss: rule {r.label} matches except {why}" for r, why in near[:5]]
            details.append("add an allow rule above the default rules (or fix the near-miss rule)")
            out.append(Finding("WARNING" if cond_allow else "ERROR",
                               "POLICY_DEPENDS_ON_APP" if cond_allow else "POLICY_DEFAULT_DENY", msg, details,
                               "policy"))
        elif not allowed:
            out.append(Finding("WARNING" if cond_allow else "ERROR",
                               "POLICY_DEPENDS_ON_APP" if cond_allow else "POLICY_DENY",
                               f"Security rule {final.label} explicitly {_verb(final.action)} this traffic"
                               + (f" unless {cond_allow[0][0].label} above matches first ({'; '.join(cond_allow[0][1])})"
                                  if cond_allow else ""),
                               [f"flow {fs}", f"rule: {_rule_summary(final)}"] + log_note + hint
                               + (["description: " + final.description] if final.description else []), "policy"))
            for r in rest:
                dims = self.m.security(r, flow, t.from_zone, t.to_zone)
                if r.action == "allow" and not r.disabled and _combine(dims) != NONE:
                    out.append(Finding("INFO", "POLICY_SHADOWED",
                                       f"Rule {r.label} further down would allow this traffic; {final.label} wins "
                                       f"because it is evaluated first",
                                       [f"flow {fs}", "if the deny is unintended, narrow it or move the allow rule "
                                        "above it"], "policy"))
                    break
        else:
            out.append(Finding("INFO", "POLICY_ALLOW", f"Security rule {final.label} allows this traffic",
                               [f"flow {fs}", f"rule: {_rule_summary(final)}"] + log_note, "policy"))
            if not final.log_end:
                out.append(Finding("WARNING", "POLICY_NO_LOGGING",
                                   f"Allow rule {final.label} does not log at session end, so traffic logs will "
                                   f"not show this flow", [f"flow {fs}"], "logs"))
            profiles = p.effective_profiles(final)
            if profiles:
                src = f"group '{final.profile_group}'" if final.profile_group else "rule"
                t.step("profiles", "info", ", ".join(f"{k}={v}" for k, v in profiles.items()) + f"  (from {src})")
                out.append(Finding("INFO", "PROFILES_ATTACHED",
                                   f"Rule {final.label} inspects allowed traffic with security profiles; "
                                   f"they can still block individual sessions (see threat/URL logs)",
                                   [f"{k}: {v}" for k, v in profiles.items()], "profile"))
            else:
                t.step("profiles", "info", "no security profiles attached")

        for r, why in cond:
            if r.action in DENY_ACTIONS and allowed:
                dynamic_only = all("unresolved objects" in w for w in why)
                out.append(Finding("INFO" if dynamic_only else "WARNING", "POLICY_CONDITIONAL_DENY",
                                   f"Deny rule {r.label} sits above {final.label} and matches this traffic when: "
                                   + "; ".join(why), [f"flow {fs}"], "policy"))
        # App-ID vs service-port conflicts on the rules that decide this flow
        from .advisor import _app_ports, _fmt_ports, app_port_conflicts
        for r in [final] + [r for r, _ in cond_allow] + ([r for r, _ in near] if not allowed else []):
            for c in app_port_conflicts(r, p):
                out.append(Finding("ERROR" if c.severity == "HIGH" else "WARNING",
                                   "APP_PORT_CONFLICT", f"Rule {r.label}: {c.message}",
                                   [f"flow {fs}", f"fix: use application-default or add {c.app_ports} to the "
                                    f"service"], "policy"))
        if flow.app and flow.dport is not None and flow.proto:
            std = _app_ports(flow.app)
            if std and not any(pp == flow.proto and lo <= flow.dport <= hi for pp, lo, hi in std):
                ad = [r.label for r, _ in cond_allow + [(final, [])] if "application-default" in r.service]
                out.append(Finding("WARNING", "APP_NONSTANDARD_PORT",
                                   f"'{flow.app}' on {flow.proto}/{flow.dport} is a non-standard port "
                                   f"(App-ID default: {_fmt_ports(std)})",
                                   [f"flow {fs}", "rules with service application-default will not match it"
                                    + (f" (e.g. {', '.join(ad)})" if ad else ""),
                                    "allow the port explicitly in a dedicated rule, or move the service to its "
                                    "standard port"], "policy"))
        for r, why in disabled:
            if r.action == "allow" and not allowed:
                out.append(Finding("WARNING", "POLICY_DISABLED_RULE",
                                   f"Disabled rule {r.label} would allow this traffic",
                                   [f"flow {fs}"] + why, "policy"))
        return out

    # -- single-IP overview (no flow to simulate) ------------------------------
    def _target_overview(self, tiv: Interval) -> List[Finding]:
        p, rt, out = self.p, self.p.routes, []
        located = []
        for vr in rt.vrs:
            rr = rt.resolve(vr, tiv)
            if rr.ok:
                located.append(f"vr {vr}: {rr.interface} zone {p.zone_of(rr.interface) or '(NONE)'}  "
                               f"[{rr.route.describe()}]")
                if not p.zone_of(rr.interface):
                    out.append(_no_zone(rr.interface, interval_str(tiv)))
            elif rr.discard:
                out.append(Finding("ERROR", "ROUTE_DISCARD", f"{interval_str(tiv)} is blackholed in vr {vr}",
                                   [rr.error or ""], "routing"))
        if located:
            out.append(Finding("INFO", "TARGET_LOCATION", f"{interval_str(tiv)} is reached via", located, "routing"))
        else:
            out.append(Finding("ERROR", "ROUTE_NONE", f"No virtual router has a route to {interval_str(tiv)}",
                               ["traffic to it is dropped and replies from the firewall can't return"]
                               + _dyn_note(p.dynamic_routing, rt.live), "routing"))
        for r in p.security_rules:
            if r.disabled or r.action not in DENY_ACTIONS:
                continue
            for side, members, neg in (("source", r.source, r.negate_source),
                                       ("destination", r.destination, r.negate_destination)):
                if "any" in members:
                    continue
                rel = p.store.resolve_addresses(members).relation(tiv)
                rel = negate(rel) if neg else rel
                if rel in (FULL, PARTIAL):
                    out.append(Finding("WARNING", "POLICY_LISTS_TARGET",
                                       f"Deny rule {r.label} lists {interval_str(tiv)} as {side}"
                                       + (" (part of the subnet)" if rel == PARTIAL else ""),
                                       [f"rule: {_rule_summary(r)}"], "policy"))
        out.append(Finding("INFO", "NO_FLOW",
                           "No peer given and no blocked flows in the logs, so no path was simulated",
                           ["re-run with --peer IP [--port N] to trace a specific flow"], "logs"))
        return out

    # -- log evidence ----------------------------------------------------------
    def _log_findings(self, rel: List[LogEntry], tiv: Interval) -> List[Finding]:
        p, out = self.p, []
        traffic = [e for e in rel if e.kind == "traffic"]
        threats = [e for e in rel if e.kind == "threat"]
        urls = [e for e in rel if e.kind == "url"]

        # traffic denies, grouped by rule
        groups: Dict[str, List[LogEntry]] = defaultdict(list)
        for e in traffic:
            if e.blocked:
                groups[e.rule or "(no rule)"].append(e)
        for name, entries in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            rule = p.rule(name)
            details = _samples(entries) + [_counter("apps", entries, "app"), _counter("end reasons", entries,
                                                                                      "session_end_reason")]
            if name == "interzone-default" or (rule is not None and rule.rulebase == "default" and rule.action != "allow"):
                out.append(Finding("ERROR", "LOG_DEFAULT_DENY",
                                   f"{len(entries)} session(s) denied by {name}: no rule allows them",
                                   details + ["add an allow rule for this zone pair/service"], "logs"))
            elif rule is None:
                out.append(Finding("ERROR", "LOG_DENY",
                                   f"{len(entries)} session(s) denied by rule '{name}', which is not in the config",
                                   details + ["the config export may be stale, or the rule is Panorama-pushed and "
                                              "missing from this export"], "logs"))
            elif rule.action in DENY_ACTIONS:
                out.append(Finding("ERROR", "LOG_DENY",
                                   f"{len(entries)} session(s) denied by rule {rule.label} ({rule.action})",
                                   details + [f"rule: {_rule_summary(rule)}"], "logs"))
            else:
                reasons = {e.session_end_reason for e in entries}
                out.append(Finding("ERROR", "LOG_DENY",
                                   f"{len(entries)} session(s) logged as {entries[0].action} under rule '{name}', "
                                   f"whose configured action is {rule.action}",
                                   details + (["App-ID shifted the app after the first packets and no rule allows "
                                               "the identified app"] if "policy-deny" in reasons else
                                              ["the config may have changed since these logs"]), "logs"))

        # allowed sessions that were ended by a threat, or never got an answer
        by_threat = [e for e in traffic if not e.blocked and (e.session_end_reason or "") == "threat"]
        if by_threat:
            out.append(Finding("ERROR", "LOG_SESSION_ENDED_BY_THREAT",
                               f"{len(by_threat)} allowed session(s) were torn down by a security profile "
                               f"(session end reason 'threat')", _samples(by_threat)
                               + ["see the threat log findings for which profile and signature"], "threat"))
        no_reply = [e for e in traffic if not e.blocked and _no_reply(e)]
        if no_reply:
            out.append(Finding("WARNING", "LOG_NO_REPLY",
                               f"{len(no_reply)} session(s) were allowed but got no reply",
                               _samples(no_reply)
                               + ["the server didn't answer, a return route is missing upstream, the path is "
                                  "asymmetric, or source NAT is missing", "check the egress interface and NAT columns"],
                               "routing"))

        # threat-log blocks, grouped by signature + rule
        tgroups: Dict[tuple, List[LogEntry]] = defaultdict(list)
        alerts: List[LogEntry] = []
        for e in threats:
            if e.blocked:
                tgroups[(e.subtype or "?", e.threat or "?", e.threat_id, e.rule or "")].append(e)
            else:
                alerts.append(e)
        for (sub, threat, tid, rname), entries in sorted(tgroups.items(), key=lambda kv: -len(kv[1])):
            sev = entries[0].severity or "?"
            actions = ", ".join(sorted({e.action for e in entries if e.action}))
            if sub in ZONE_PROTECTION_SUBTYPES:
                zones = sorted({e.from_zone for e in entries if e.from_zone})
                zpp = [f"zone {z}: zone-protection profile '{p.zones[z].zone_protection}'"
                       for z in zones if z in p.zones and p.zones[z].zone_protection]
                out.append(Finding("ERROR", "LOG_ZONE_PROTECTION",
                                   f"{len(entries)} x {threat} ({sub}, {sev}) {actions} by zone/DoS protection",
                                   _samples(entries) + zpp + ["review flood/reconnaissance thresholds, or exempt the "
                                                              "source in the zone protection profile"], "threat"))
                continue
            rule = p.rule(rname)
            ptype = SUBTYPE_PROFILE.get(sub, sub)
            prof = p.effective_profiles(rule).get(ptype) if rule else None
            where = (f"{ptype} profile '{prof}' on rule {rule.label}" if prof else
                     f"rule '{rname}'" + ("" if rule else " (not in config)"))
            fix = (f"if this is a false positive, add a threat exception for ID {tid} in '{prof}' (optionally only "
                   f"for the affected IPs) instead of removing the profile" if tid and prof else
                   "if this is a false positive, add a threat exception for this signature in the profile")
            out.append(Finding("ERROR", "LOG_THREAT_BLOCK",
                               f"{len(entries)} x '{threat}'" + (f" (ID {tid})" if tid else "")
                               + f" [{sub}, {sev}] {actions} by {where}",
                               _samples(entries) + [fix], "threat"))
        if alerts:
            names = Counter(f"{e.threat} [{e.subtype}, {e.severity}]" for e in alerts)
            out.append(Finding("INFO", "LOG_THREAT_ALERT", f"{len(alerts)} threat event(s) only alerted (not blocked)",
                               [f"{n} x {k}" for k, n in names.most_common(5)], "threat"))

        # URL filtering blocks
        ugroups: Dict[tuple, List[LogEntry]] = defaultdict(list)
        for e in urls:
            if e.blocked:
                ugroups[(e.category or "?", e.rule or "", e.action or "")].append(e)
        for (cat, rname, action), entries in sorted(ugroups.items(), key=lambda kv: -len(kv[1])):
            rule = p.rule(rname)
            prof_name = p.effective_profiles(rule).get("url-filtering") if rule else None
            prof = p.url_profiles.get(prof_name) if prof_name else None
            cfg_action = prof.action_for(cat) if prof else None
            details = [f"url: {u}" for u in list(dict.fromkeys(e.url for e in entries if e.url))[:5]]
            if prof:
                details.append(f"url-filtering profile '{prof.name}' sets category '{cat}' to "
                               f"{cfg_action or 'its default (allow) - config may be stale'}")
            elif prof_name:
                details.append(f"url-filtering profile '{prof_name}' (not found in this export)")
            customs = [c for c, lst in p.custom_url_categories.items() if c == cat]
            if customs:
                details.append(f"'{cat}' is a custom URL category: entries {', '.join(p.custom_url_categories[cat][:5])}")
            details.append("to allow it: set the category to alert/allow in the profile, or add the site to an "
                           "allow-listed custom URL category; to re-categorise, submit it to PAN-DB")
            out.append(Finding("ERROR", "LOG_URL_BLOCK",
                               f"{len(entries)} request(s) to category '{cat}' {action} by URL filtering on rule "
                               f"'{rname or '?'}'", details, "url"))
        return out

    def _compare_with_logs(self, t: FlowTrace, rel: List[LogEntry]) -> List[Finding]:
        f = t.flow
        hits = [e for e in rel if e.kind == "traffic" and _in(e.src, f.src) and _in(e.dst, f.dst)
                and (f.dport is None or e.dport == f.dport)]
        if not hits:
            return []
        out: List[Finding] = []
        rules = Counter(e.rule for e in hits if e.rule)
        if t.security_rule and rules and t.security_rule not in rules:
            out.append(Finding("WARNING", "LOG_RULE_MISMATCH",
                               f"Logs show {f} hitting {', '.join(f'{r} ({n})' for r, n in rules.most_common(3))}, "
                               f"but the config evaluates to '{t.security_rule}'",
                               ["App-ID / User-ID / URL-category conditions, a changed config, or a Panorama push "
                                "missing from this export"], "logs"))
        ins = Counter(e.inbound_if for e in hits if e.inbound_if)
        if t.ingress_if and ins and t.ingress_if not in ins:
            out.append(Finding("WARNING", "ROUTE_ASYMMETRIC",
                               f"Traffic from {interval_str(f.src)} arrives on {', '.join(ins)}, but the route back "
                               f"to it uses {t.ingress_if}",
                               ["asymmetric path: replies leave a different interface/zone; TCP sessions may be "
                                "dropped as non-SYN", "fix the routing, or check that both interfaces are in the "
                                "same zone"], "routing"))
        zones = Counter(e.to_zone for e in hits if e.to_zone)
        if t.to_zone and zones and t.to_zone not in zones:
            out.append(Finding("WARNING", "LOG_ZONE_MISMATCH",
                               f"Logs show destination zone {', '.join(zones)}; the config route gives {t.to_zone}",
                               ["routes learned dynamically (BGP/OSPF) or a PBF rule may differ from the static "
                                "config; use --host to read the live routing table"], "routing"))
        return out

    def _log_absence(self, rel: List[LogEntry], traces: List[FlowTrace]) -> List[Finding]:
        if rel:
            return []
        if not self.logs:
            return [Finding("INFO", "LOG_NOT_PROVIDED", "No logs were provided; the result is from config only",
                            ["pass --logs FILE (traffic/threat/URL exports) or --host to pull them live"], "logs")]
        details = ["traffic may not be reaching the firewall (upstream routing, another firewall, or a typo in "
                   "the IP)"]
        for t in traces:
            rule = self.p.rule(t.security_rule)
            if rule is not None and not rule.log_end:
                details.insert(0, f"the matching rule '{rule.name}' does not log at session end, which alone "
                                  f"explains missing traffic logs")
        return [Finding("WARNING", "LOG_NONE", "No traffic, threat or URL logs mention this IP", details, "logs")]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _no_zone(interface: Optional[str], fs: str) -> Finding:
    return Finding("ERROR", "ZONE_MISSING", f"Interface {interface} is not assigned to a zone: the firewall "
                   f"drops all traffic on it", [f"flow {fs}", f"add {interface} to a zone (Network > Zones)"], "zone")


def _dyn_note(dynamic: List[str], live: bool) -> List[str]:
    if dynamic and not live:
        return [f"BGP/OSPF is enabled on {', '.join(dynamic)}; dynamic routes are not in the config, so use "
                f"--host to read the live routing table"]
    return []


def _route_finding(rr: RouteResult, dst: Interval, fs: str, vr: str, dynamic: List[str], live: bool) -> Finding:
    if rr.discard:
        return Finding("ERROR", "ROUTE_DISCARD", f"Traffic to {interval_str(dst)} hits a discard route",
                       [f"flow {fs}", rr.error or ""], "routing")
    return Finding("ERROR", "ROUTE_NONE", f"No route to {interval_str(dst)} in virtual router '{vr}'",
                   [f"flow {fs}", rr.error or "", "add a static route (or a default route) towards the destination"]
                   + _dyn_note(dynamic, live), "routing")


def _verb(action: str) -> str:
    return {"deny": "denies", "drop": "drops", "allow": "allows"}.get(action, f"applies {action} to")


def _rule_summary(r: SecurityRule) -> str:
    def j(x):
        return ",".join(x)
    neg_s = "NOT " if r.negate_source else ""
    neg_d = "NOT " if r.negate_destination else ""
    return (f"{j(r.from_zones)} -> {j(r.to_zones)}  src {neg_s}{j(r.source)}  dst {neg_d}{j(r.destination)}  "
            f"app {j(r.application)}  svc {j(r.service)}  action {r.action}")


def _samples(entries: List[LogEntry], n: int = 3) -> List[str]:
    out = []
    for e in entries[:n]:
        port = f":{e.dport}" if e.dport is not None else ""
        extra = " ".join(x for x in (
            f"app={e.app}" if e.app else "", f"{e.from_zone}->{e.to_zone}" if e.from_zone else "",
            f"in={e.inbound_if}" if e.inbound_if else "", f"natdst={e.natdst}" if e.natdst and e.natdst != "0.0.0.0" else "",
            f"end={e.session_end_reason}" if e.session_end_reason else "", f"url={e.url}" if e.kind == "url" and e.url else "")
            if x)
        out.append(f"{e.time or '?'}  {e.src} -> {e.dst}{port}/{e.proto or '?'}  action={e.action}  {extra}".rstrip())
    return out


def _counter(label: str, entries: List[LogEntry], attr: str) -> str:
    c = Counter(getattr(e, attr) for e in entries if getattr(e, attr))
    return f"{label}: " + (", ".join(f"{k} ({n})" for k, n in c.most_common(4)) or "-")


def _no_reply(e: LogEntry) -> bool:
    if e.packets_received == 0 or (e.packets_received is None and e.bytes_received == 0):
        return True
    return e.app == "incomplete" and (e.session_end_reason or "") == "aged-out" and not e.packets_received


_VAGUE_APPS = {"incomplete", "insufficient-data", "not-applicable", "unknown-tcp", "unknown-udp", "unknown-p2p"}


def _app_from_logs(flow: Flow, rel: List[LogEntry]) -> Optional[str]:
    apps = Counter(e.app for e in rel if e.kind == "traffic" and e.app and e.app not in _VAGUE_APPS
                   and _in(e.src, flow.src) and _in(e.dst, flow.dst)
                   and (flow.dport is None or e.dport == flow.dport))
    return apps.most_common(1)[0][0] if apps else None


def _in(ip: Optional[str], iv: Interval) -> bool:
    x = try_target(ip)
    return x is not None and overlaps(x, iv)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.code, f.message)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(out, key=lambda f: rank[f.severity])


_BLOCK_REASON = {
    "ROUTE_NONE": "no route", "ROUTE_DISCARD": "discard route", "ROUTE_NO_RETURN": "no return route",
    "ZONE_MISSING": "interface without zone", "NAT_DNAT_NO_ROUTE": "NAT target unroutable",
    "POLICY_DENY": "security rule denies", "POLICY_DEFAULT_DENY": "no allow rule (interzone-default)",
    "LOG_DENY": "denied in traffic logs", "LOG_DEFAULT_DENY": "interzone-default in traffic logs",
    "LOG_THREAT_BLOCK": "threat prevention profile", "LOG_SESSION_ENDED_BY_THREAT": "session ended by a security profile",
    "LOG_ZONE_PROTECTION": "zone protection", "LOG_URL_BLOCK": "URL filtering",
    "APP_PORT_CONFLICT": "App-ID vs service-port conflict",
}


def _verdict(d: Diagnosis) -> Tuple[str, List[str]]:
    reasons = []
    for f in d.findings:
        if f.severity == "ERROR" and f.code in _BLOCK_REASON and _BLOCK_REASON[f.code] not in reasons:
            reasons.append(_BLOCK_REASON[f.code])
    if reasons:
        return "BLOCKED", reasons
    if any(t.verdict == "CONDITIONAL" for t in d.traces):
        return "DEPENDS ON APP-ID/USER-ID", [t.reason for t in d.traces if t.verdict == "CONDITIONAL"][:1]
    if d.traces and all(t.verdict == "ALLOW" for t in d.traces):
        cond = any(t.conditional_rules for t in d.traces) or any(f.code == "LOG_NO_REPLY" for f in d.findings)
        return ("ALLOWED (with caveats)" if cond else "ALLOWED"), []
    return "INCONCLUSIVE", []
