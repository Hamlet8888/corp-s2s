"""
Policy advisor: what is allowed between two endpoints, which rules fight App-ID, and which rules
fall short of Palo Alto Networks best practice.

* :func:`build_matrix`: every security rule that can match traffic between a source and a
  destination, flattened into (application, port/service, action) rows in evaluation order, with
  shadowed rows marked and the default-rule fallback at the end.
* :func:`app_port_conflicts`: App-ID vs service-port mismatches, e.g. ``web-browsing`` on
  ``tcp/22``. Such a rule matches the first packets on the port, then App-ID identifies the real
  application, the policy is re-evaluated, and the session is dropped mid-handshake
  (``session end reason: policy-deny``, ``app: incomplete``/the real app), which looks like a
  silent, intermittent drop. Real traffic of the configured app on its standard port never
  matches the rule at all.
* :func:`audit_policy`: rule-by-rule best-practice recommendations (application-default instead of
  service any, no any/any rules, threat profiles and SSL decryption on allow rules, logging, zone
  protection on internet-facing zones, shadowed and disabled rules).

Standard library only. Python 3.9+.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from .engine import Flow, Matcher, Troubleshooter, _combine
from .objects import APP_DEFAULT_PORTS, FULL, NONE, PARTIAL, _PORTLESS_APPS, PortSpec, interval_str, parse_target
from .policy import PolicyConfig, SecurityRule

# Profile types every allow rule should carry (url-filtering only matters for internet-bound rules).
REQUIRED_PROFILES = ("virus", "spyware", "vulnerability", "file-blocking", "wildfire-analysis")
# Applications whose payload is TLS: threat and URL profiles see little unless the traffic is decrypted.
TLS_APPS = {"ssl", "web-browsing", "http2", "quic", "any"}
SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")


# Ports where an app legitimately shows up besides its App-ID default (e.g. decrypted HTTPS is web-browsing).
TOLERATED_PORTS: Dict[str, List[Tuple[str, int, int]]] = {
    "web-browsing": [("tcp", 443, 443), ("tcp", 8080, 8080)],
    "ssl": [("tcp", 8443, 8443)],
}


def _app_ports(app: str) -> Optional[List[Tuple[str, int, int]]]:
    """Default ports for *app*: a list of (proto, lo, hi), [] for port-less apps, None if unknown."""
    if app in _PORTLESS_APPS:
        return []
    return APP_DEFAULT_PORTS.get(app)


def _fmt_ports(ports: List[Tuple[str, int, int]]) -> str:
    return ", ".join(f"{p}/{a}" if a == b else f"{p}/{a}-{b}" for p, a, b in ports) or "no ports (ICMP/IP)"


def _specs_overlap(specs: List[PortSpec], ports: List[Tuple[str, int, int]]) -> bool:
    return any(s.protocol == p and any(a <= hi and lo <= b for a, b in s.ranges)
               for s in specs for p, lo, hi in ports)


# ---------------------------------------------------------------------------
# App-ID vs service conflicts
# ---------------------------------------------------------------------------

@dataclass
class Conflict:
    rule: str
    severity: str                     # HIGH | MEDIUM
    app: str
    app_ports: str
    service: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def app_port_conflicts(rule: SecurityRule, policy: PolicyConfig) -> List[Conflict]:
    """Flag applications whose standard ports are not in the rule's explicit service ports."""
    if "any" in rule.application or "any" in rule.service or "application-default" in rule.service:
        return []
    store = policy.store
    sset = store.resolve_services(rule.service)
    if sset.unresolved and not sset.ports:
        return []
    apps, _ = store._expand_apps(rule.application)
    svc = ", ".join(str(s) for s in sset.ports) or ", ".join(rule.service)
    bad: List[Conflict] = []
    known = 0
    for app in sorted(apps):
        ports = _app_ports(app)
        if ports is None:
            continue
        known += 1
        if ports == [] and sset.ports:
            bad.append(Conflict(rule.name, "HIGH", app, _fmt_ports(ports), svc,
                                f"'{app}' has no ports (ICMP/IP protocol) but the rule only allows {svc}: "
                                f"'{app}' traffic can never match this rule"))
        elif ports and not _specs_overlap(sset.ports, ports + TOLERATED_PORTS.get(app, [])):
            bad.append(Conflict(rule.name, "HIGH", app, _fmt_ports(ports), svc,
                                f"'{app}' normally runs on {_fmt_ports(ports)}, but the rule only allows {svc}. "
                                f"Real '{app}' traffic never matches; whatever really runs on {svc} matches the "
                                f"first packets, then App-ID re-classifies it and the session is dropped "
                                f"mid-handshake (session end reason policy-deny)"))
    if bad and known > len(bad):
        for c in bad:
            c.severity = "MEDIUM"
            c.message += "; other applications in this rule do fit the service"
    return bad


# ---------------------------------------------------------------------------
# Port & application matrix
# ---------------------------------------------------------------------------

@dataclass
class MatrixRow:
    rule: str
    position: str
    action: str
    application: str
    ports: str
    match: str                        # full | partial | conditional
    note: str = ""
    shadowed_by: Optional[str] = None
    conflict: Optional[str] = None


@dataclass
class Matrix:
    src: str
    dst: str
    from_zone: Optional[str]
    to_zone: Optional[str]
    path: List[str] = field(default_factory=list)
    rows: List[MatrixRow] = field(default_factory=list)
    default: str = ""
    error: Optional[str] = None

    @property
    def permitted(self) -> List[MatrixRow]:
        return [r for r in self.rows if r.action == "allow" and not r.shadowed_by]

    @property
    def blocked(self) -> List[MatrixRow]:
        return [r for r in self.rows if r.action != "allow" and not r.shadowed_by]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["permitted"] = [asdict(r) for r in self.permitted]
        d["blocked"] = [asdict(r) for r in self.blocked]
        return d


def _service_label(policy: PolicyConfig, rule: SecurityRule, app: str) -> str:
    if "any" in rule.service:
        return "any"
    parts = []
    for s in rule.service:
        if s == "application-default":
            ports = _app_ports(app) if app != "any" else None
            parts.append("app-default" + (f" ({_fmt_ports(ports)})" if ports is not None else ""))
        else:
            sset = policy.store.resolve_services([s])
            parts.append(f"{s} ({', '.join(str(p) for p in sset.ports)})" if sset.ports else s)
    return ", ".join(parts)


def _covers(earlier: SecurityRule, app: str, later: SecurityRule) -> bool:
    """Does a fully matching *earlier* rule take every (app, service) the later row describes?"""
    app_ok = "any" in earlier.application or app in earlier.application
    svc_ok = "any" in earlier.service or sorted(earlier.service) == sorted(later.service)
    return app_ok and svc_ok


def build_matrix(policy: PolicyConfig, src: str, dst: str, from_zone: Optional[str] = None,
                 to_zone: Optional[str] = None) -> Matrix:
    """Summarise every application/port permitted or blocked from *src* to *dst*."""
    s_iv, d_iv = parse_target(src), parse_target(dst)
    ts = Troubleshooter(policy)
    trace, _ = ts.simulate(Flow(s_iv, d_iv, from_zone=from_zone, to_zone=to_zone))
    m = Matrix(interval_str(s_iv), interval_str(d_iv), trace.from_zone, trace.to_zone)
    m.path = [f"{s.stage}: {s.text}" for s in trace.steps if s.stage in ("ingress", "route", "nat", "route-post-nat")]
    if not trace.from_zone or not trace.to_zone:
        m.error = trace.reason or "zones could not be determined (no route?)"
        return m
    matcher = Matcher(policy)
    full_earlier: List[SecurityRule] = []
    for r in policy.security_rules:
        if r.disabled:
            continue
        dims = matcher.security(r, Flow(s_iv, d_iv), trace.from_zone, trace.to_zone)
        base = [d for d in dims if d[0] not in ("application", "service")]
        res = _combine(base)
        if res == NONE:
            continue
        partial = any(rr == PARTIAL for _, rr, _ in base)
        match = "full" if res == FULL else "partial" if partial else "conditional"
        note = "; ".join(w for _, rr, w in base if rr != FULL and w)
        conflicts = {c.app: c.message for c in app_port_conflicts(r, policy)}
        apps = r.application
        for app in apps:
            row = MatrixRow(r.name, r.label, r.action, app, _service_label(policy, r, app), match, note,
                            conflict=conflicts.get(app))
            row.shadowed_by = next((e.name for e in full_earlier if _covers(e, app, r)), None)
            m.rows.append(row)
        if res == FULL:
            full_earlier.append(r)
    dflt = policy.default_rules["intrazone-default" if trace.from_zone == trace.to_zone else "interzone-default"]
    m.default = (f"everything else: {dflt.name} -> {dflt.action}"
                 + ("" if dflt.log_end else " (not logged)"))
    return m


def format_matrix(m: Matrix) -> str:
    out = [f"Application / port matrix: {m.src} -> {m.dst}   ({m.from_zone or '?'} -> {m.to_zone or '?'})"]
    out += [f"  {p}" for p in m.path]
    if m.error:
        out.append(f"  cannot evaluate policy: {m.error}")
        return "\n".join(out)

    def table(title: str, rows: List[MatrixRow]) -> None:
        out.append(f"  {title}")
        if not rows:
            out.append("    (none)")
            return
        w_app = max(11, *(len(r.application) for r in rows))
        w_port = max(13, *(len(r.ports) for r in rows))
        out.append(f"    {'APPLICATION':<{w_app}}  {'PORTS/SERVICE':<{w_port}}  RULE")
        for r in rows:
            flag = "" if r.match == "full" else f"   [{r.match}: {r.note}]"
            out.append(f"    {r.application:<{w_app}}  {r.ports:<{w_port}}  {r.position} {r.action}{flag}")
            if r.conflict:
                out.append(f"      ! App-ID/port conflict: {r.conflict}")

    table("PERMITTED", m.permitted)
    table("BLOCKED", m.blocked)
    shadowed = [r for r in m.rows if r.shadowed_by]
    if shadowed:
        out.append("  NEVER REACHED (an earlier rule takes this traffic first)")
        for r in shadowed:
            out.append(f"    {r.application} {r.ports}  {r.position} {r.action}  <- shadowed by '{r.shadowed_by}'")
    out.append(f"  {m.default}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Best-practice audit
# ---------------------------------------------------------------------------

@dataclass
class Advice:
    severity: str                     # HIGH | MEDIUM | LOW | INFO
    code: str
    rule: Optional[str]               # None = device-wide
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _internet_zones(policy: PolicyConfig) -> List[str]:
    """Zones that hold the egress interface of a default route."""
    zones = []
    for routes in policy.routes.routes.values():
        for r in routes:
            if r.prefixlen == 0 and r.interface:
                z = policy.zone_of(r.interface)
                if z and z not in zones:
                    zones.append(z)
    return zones


def _zone_overlap(rule_zones: List[str], zones: List[str]) -> bool:
    return "any" in rule_zones or any(z in zones for z in rule_zones)


def _addr_superset(policy: PolicyConfig, outer: List[str], inner: List[str]) -> bool:
    if "any" in outer:
        return True
    if "any" in inner:
        return False
    o, i = policy.store.resolve_addresses(outer), policy.store.resolve_addresses(inner)
    if o.unresolved or i.unresolved:
        return set(inner) <= set(outer)
    return all(o.relation(iv) == FULL for iv in i.intervals)


def _shadows(policy: PolicyConfig, a: SecurityRule, b: SecurityRule) -> bool:
    """True if earlier rule *a* matches everything later rule *b* can match."""
    def zones(x, y):
        return "any" in x or ("any" not in y and set(y) <= set(x))
    return (zones(a.from_zones, b.from_zones) and zones(a.to_zones, b.to_zones)
            and not a.negate_source and not a.negate_destination
            and not b.negate_source and not b.negate_destination
            and _addr_superset(policy, a.source, b.source) and _addr_superset(policy, a.destination, b.destination)
            and "any" in a.source_user and "any" in a.category
            and ("any" in a.application or ("any" not in b.application and set(b.application) <= set(a.application)))
            and ("any" in a.service or sorted(a.service) == sorted(b.service)))


def _decrypted(policy: PolicyConfig, rule: SecurityRule) -> bool:
    for d in policy.decryption_rules:
        if d.disabled or d.action not in ("decrypt", "decrypt-and-forward"):
            continue
        if (_zone_overlap(d.from_zones, rule.from_zones) or "any" in rule.from_zones) and \
                (_zone_overlap(d.to_zones, rule.to_zones) or "any" in rule.to_zones):
            return True
    return False


def audit_policy(policy: PolicyConfig, rule_name: Optional[str] = None) -> List[Advice]:
    out: List[Advice] = []
    inet = _internet_zones(policy)
    rules = policy.security_rules
    for idx, r in enumerate(rules):
        if rule_name and r.name != rule_name:
            continue
        A = lambda sev, code, msg, rec: out.append(Advice(sev, code, r.name, msg, rec))  # noqa: E731
        if r.disabled:
            A("LOW", "BP_DISABLED_RULE", "Rule is disabled", "remove it, or document why it is kept")
            continue
        allow = r.action == "allow"
        to_inet = _zone_overlap(r.to_zones, inet)
        from_inet = _zone_overlap(r.from_zones, inet)
        for e in rules[:idx]:
            if not e.disabled and _shadows(policy, e, r):
                A("MEDIUM", "BP_SHADOWED_RULE", f"Rule is fully shadowed by '{e.name}' above it and never matches",
                  "delete it, or move it above the shadowing rule if its action is the intended one")
                break
        if allow:
            app_any, svc_any = "any" in r.application, "any" in r.service
            if app_any and svc_any:
                A("HIGH", "BP_ANY_ANY", "Allows any application on any port",
                  "replace with App-ID based rules (use Policy Optimizer on this rule to see the apps it carries)")
            elif svc_any:
                A("MEDIUM", "BP_SERVICE_ANY",
                  f"Applications [{', '.join(r.application)}] are allowed on ANY port",
                  "set service to application-default so apps only run on their standard ports "
                  "(stops evasive apps tunnelling over non-standard ports)")
            elif app_any:
                A("MEDIUM", "BP_APP_ANY", f"Port-based rule: any application on {', '.join(r.service)}",
                  "convert to App-ID: name the applications and use application-default")
            if "any" in r.source and "any" in r.destination:
                A("HIGH" if (from_inet or to_inet) else "MEDIUM", "BP_ANY_SOURCE_DEST",
                  "Source and destination are both 'any'", "restrict source and/or destination addresses")
            if "any" in r.from_zones or "any" in r.to_zones:
                A("MEDIUM", "BP_ZONE_ANY", "Allow rule uses zone 'any'", "name the source and destination zones")
            for c in app_port_conflicts(r, policy):
                A(c.severity, "BP_APP_PORT_CONFLICT", c.message,
                  f"use application-default, or add {c.app_ports} to the service, or remove '{c.app}' from the rule")
            if "application-default" in r.service and "any" in r.application:
                A("LOW", "BP_APPDEFAULT_WITH_ANY", "application-default combined with application 'any'",
                  "name the applications; with 'any', application-default gives no port control")
            profiles = policy.effective_profiles(r)
            if not profiles:
                A("HIGH", "BP_NO_SECURITY_PROFILES", "Allowed traffic is not inspected (no security profiles)",
                  "attach a security profile group with antivirus, anti-spyware, vulnerability protection, "
                  "URL filtering, file blocking and WildFire")
            else:
                missing = [t for t in REQUIRED_PROFILES if t not in profiles]
                if to_inet and "url-filtering" not in profiles:
                    missing.append("url-filtering")
                if missing:
                    A("MEDIUM", "BP_PROFILE_GAPS", f"Missing profile types: {', '.join(missing)}",
                      "use a complete profile group (best-practice profiles) on every allow rule")
            if (to_inet or from_inet) and (set(r.application) & TLS_APPS) and not _decrypted(policy, r):
                A("MEDIUM", "BP_NO_DECRYPTION",
                  "TLS traffic through this rule is not covered by an SSL decryption rule",
                  "add a decryption policy rule (forward proxy outbound / inbound inspection for published "
                  "servers) so threat and URL profiles can see the payload; exempt sensitive categories")
            if not r.log_end:
                A("MEDIUM", "BP_NO_LOGGING", "Session-end logging is disabled",
                  "enable 'log at session end' so allowed traffic is visible")
        else:
            if not r.log_end:
                A("MEDIUM", "BP_DENY_NOT_LOGGED", "Deny rule does not log",
                  "enable logging so blocked traffic can be troubleshot")
            if r.action == "deny" and from_inet:
                A("LOW", "BP_DENY_ACTION", "Inbound internet deny uses 'deny'",
                  "use 'drop' for internet-facing denies so nothing is sent back to scanners")
        if not r.log_setting:
            A("LOW", "BP_NO_LOG_FORWARDING", "No log forwarding profile",
              "forward logs to Panorama/SIEM (log forwarding profile)")
        if not r.description:
            A("LOW", "BP_NO_DESCRIPTION", "Rule has no description",
              "document owner, purpose and ticket in the description (or use tags)")

    if rule_name:
        return _sorted(out)
    dflt = policy.default_rules
    for name in ("interzone-default", "intrazone-default"):
        if not dflt[name].log_end:
            out.append(Advice("MEDIUM" if name == "interzone-default" else "LOW", "BP_DEFAULT_RULE_NOT_LOGGED", None,
                              f"{name} does not log",
                              f"override {name} and enable log at session end; otherwise denied traffic "
                              f"leaves no trace"))
    for z in inet:
        info = policy.zones.get(z)
        if info is not None and not info.zone_protection:
            out.append(Advice("HIGH", "BP_NO_ZONE_PROTECTION", None,
                              f"Internet-facing zone '{z}' has no zone protection profile",
                              "attach a zone protection profile (flood, reconnaissance and packet-based protection)"))
    if not policy.decryption_rules:
        out.append(Advice("MEDIUM", "BP_NO_DECRYPTION_POLICY", None, "No SSL decryption policy is configured",
                          "decrypt outbound traffic (exempt finance/health categories) and inspect inbound to "
                          "published servers"))
    zoned = {i for z in policy.zones.values() for i in z.interfaces}
    for i in policy.interfaces:
        if i.ips and i.kind in ("ethernet", "aggregate-ethernet", "subinterface", "vlan") and i.name not in zoned:
            out.append(Advice("LOW", "BP_INTERFACE_NO_ZONE", None, f"Interface {i.name} has an IP but no zone",
                              "assign it to a zone or remove the IP; traffic on it is dropped"))
    return _sorted(out)


def _sorted(items: List[Advice]) -> List[Advice]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(items, key=lambda a: (rank[a.severity], a.rule is not None))


def format_audit(items: List[Advice], policy: PolicyConfig, min_severity: str = "LOW") -> str:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    shown = [a for a in items if rank[a.severity] <= rank[min_severity]]
    counts = {s: sum(1 for a in items if a.severity == s) for s in SEVERITY_ORDER[:3]}
    total_rules = len(policy.security_rules) or 1
    flagged = {a.rule for a in items if a.rule and a.severity in ("HIGH", "MEDIUM")}
    score = round(100 * (1 - len(flagged) / total_rules))
    out = [f"Best-practice audit: {policy.hostname or '?'}  ({policy.source})",
           "  " + "   ".join(f"{s} {n}" for s, n in counts.items())
           + f"   rules without HIGH/MEDIUM issues: {score}%", ""]
    device = [a for a in shown if a.rule is None]
    if device:
        out.append("== Device-wide")
        for a in device:
            out.append(f"  [{a.severity}] {a.code}: {a.message}")
            out.append(f"      -> {a.recommendation}")
        out.append("")
    by_rule: Dict[str, List[Advice]] = {}
    for a in shown:
        if a.rule:
            by_rule.setdefault(a.rule, []).append(a)
    for r in policy.security_rules:
        if r.name not in by_rule:
            continue
        out.append(f"== Rule {r.label}  [{r.action}]  {','.join(r.from_zones)} -> {','.join(r.to_zones)}")
        for a in sorted(by_rule[r.name], key=lambda a: rank[a.severity]):
            out.append(f"  [{a.severity}] {a.code}: {a.message}")
            out.append(f"      -> {a.recommendation}")
        out.append("")
    if not shown:
        out.append(f"No recommendations at or above {min_severity}.")
    return "\n".join(out)
