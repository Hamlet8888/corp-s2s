"""
Fix planner: what to add or change so a blocked flow works, and where.

For one traced flow it works through every layer that can stop the traffic, in the order PAN-OS
needs them, and only proposes what is actually missing:

1. **Routing**: a route to the destination (or back to the source), or a more specific route
   than a discard route. ``--next-hop`` / ``--return-next-hop`` make the route concrete; the
   resulting egress zone is then used for the NAT and security steps that follow.
2. **Zones**: an interface that isn't in any zone.
3. **NAT**: source NAT for private-to-public traffic (enable a disabled rule, extend an existing
   rule with the missing zone/source, or add one), and destination NAT with ``--dnat-to``.
4. **Security policy**: enable a disabled rule that already fits; otherwise extend the closest
   existing allow rule when it differs only by application, service, address, user, URL category
   or one zone ("add application ssh to rule X"); otherwise create a dedicated rule, with
   address/service objects, and place it above the rule that currently denies the traffic.
5. **Profiles** (from log evidence): threat exceptions for false positives, URL allow-listing,
   App-ID/port conflicts, zone protection.

Everything is a proposal: ``set`` commands for the candidate config, to review and commit by hand.
Nothing here talks to a firewall.
"""

from __future__ import annotations

import dataclasses
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Tuple

from .commands import q
from .engine import Finding, Flow, FlowTrace, Matcher, Troubleshooter
from .objects import NONE, Interval, first_ip, interval_str, is_private, try_target
from .policy import DENY_ACTIONS, PolicyConfig, SecurityRule

# How far an existing rule may be from the flow and still be worth extending (zones cost most).
_MISS_WEIGHT = {"from": 3, "to": 3, "source": 2, "destination": 2, "user": 2, "url-category": 2,
                "application": 1, "service": 1}
_MAX_SCORE = 4


@dataclass
class Hints:
    next_hop: Optional[str] = None            # next hop towards the destination
    return_next_hop: Optional[str] = None     # next hop back towards the source
    dnat_to: Optional[str] = None             # internal server for destination NAT


@dataclass
class FixStep:
    area: str                                  # routing | zone | nat | security | profile | url | review
    title: str
    why: str
    commands: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    alternative: bool = False                  # an option, not the recommended path


@dataclass
class FixPlan:
    flow: str
    needed: List[str] = field(default_factory=list)
    summary: str = ""
    steps: List[FixStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


_AREA_LABEL = {"routing": "route", "zone": "zone", "nat": "NAT rule", "security": "security rule",
               "profile": "security profile", "url": "URL filtering"}
_AREA_ORDER = ["routing", "zone", "nat", "security", "profile", "url", "review"]


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-")


class Planner:
    def __init__(self, policy: PolicyConfig, trace: FlowTrace, findings: List[Finding], hints: Optional[Hints]):
        self.p = policy
        self.t = trace
        self.f = trace.flow
        self.findings = findings
        self.h = hints or Hints()
        self.m = Matcher(policy)
        self.steps: List[FixStep] = []
        self.pfx = "" if policy.vsys == "vsys1" else f"vsys {policy.vsys} "
        self.new_objects: set = set()
        self.handled_conflicts: set = set()

    # -- helpers -----------------------------------------------------------------
    def has(self, code: str) -> List[Finding]:
        return [f for f in self.findings if f.code == code]

    def set_cmd(self, path: str) -> str:
        return f"set {self.pfx}{path}"

    def rule_path(self, rule) -> Tuple[str, List[str]]:
        """CLI path of a rule's rulebase; Panorama-pushed rules must be changed on Panorama."""
        kind = "security" if isinstance(rule, SecurityRule) else "nat"
        if rule.rulebase in ("pre", "post"):
            return (f"set device-group <device-group> {rule.rulebase}-rulebase {kind} rules {q(rule.name)}",
                    [f"'{rule.name}' is pushed from Panorama: make this change in its device group on Panorama, "
                     f"then commit and push"])
        return f"set {self.pfx}rulebase {kind} rules {q(rule.name)}", []

    def address(self, iv: Interval) -> Tuple[str, List[str]]:
        """An existing address object for *iv*, or a new one (with the command to create it)."""
        for name, (kind, value) in self.p.store.addresses.items():
            if kind in ("ip-netmask", "ip-range") and try_target(value) == iv:
                return name, []
        text = interval_str(iv)
        if iv[1] == iv[2]:
            name, kind, value = f"H-{text}", "ip-netmask", f"{text}/{32 if iv[0] == 4 else 128}"
        elif "/" in text:
            name, kind, value = f"N-{text.replace('/', '_')}", "ip-netmask", text
        else:
            name, kind, value = f"R-{text}", "ip-range", text
        name = _slug(name)
        if name in self.new_objects:
            return name, []
        self.new_objects.add(name)
        return name, [self.set_cmd(f"address {name} {kind} {value}")]

    def service(self, proto: str, port: int) -> Tuple[str, List[str]]:
        for name, specs in self.p.store.services.items():
            if len(specs) == 1 and specs[0].protocol == proto and specs[0].ranges == [(port, port)]:
                return name, []
        name = f"{proto}-{port}"
        if name in self.new_objects:
            return name, []
        self.new_objects.add(name)
        return name, [self.set_cmd(f"service {name} protocol {proto} port {port}")]

    def add(self, *steps: FixStep) -> None:
        self.steps.extend(steps)

    # -- routing / zones ----------------------------------------------------------
    def route_step(self, iv: Interval, vr: Optional[str], next_hop: Optional[str], label: str,
                   discard: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        rt = self.p.routes
        vr = vr or (rt.vrs[0] if len(rt.vrs) == 1 else "<virtual-router>")
        iface = zone = None
        notes = []
        if next_hop:
            nh = try_target(next_hop)
            r = rt.lookup(vr, nh) if nh else None
            if r is not None and r.nexthop_type == "connected":
                iface = r.interface
                zone = self.p.zone_of(iface)
            else:
                notes.append(f"next hop {next_hop} is not on a connected subnet of '{vr}'; "
                             f"check the next hop or add the interface first")
        else:
            notes.append("re-run with --next-hop IP (or --return-next-hop for the source side) so the plan can "
                         "name the interface and zone and finish the NAT/security steps")
        dest = interval_str(iv)
        if "/" not in dest:
            dest += "/32" if iv[0] == 4 else "/128"
        lr = rt.logical.get(vr)
        path = (f"network logical-router {q(lr[0])} vrf {q(lr[1])} routing-table ip static-route" if lr
                else f"network virtual-router {q(vr)} routing-table ip static-route")
        cmd = (f"set {path} {_slug('to-' + dest.replace('/', '_'))} destination {dest} "
               f"interface {iface or '<egress-interface>'} nexthop ip-address {next_hop or '<next-hop-ip>'} metric 10")
        why = f"the firewall has no usable route {label}"
        if discard:
            why = f"traffic {label} hits the discard route {discard}"
            notes.append("a more specific static route wins over the discard summary, so the blackhole stays "
                         "in place for everything else")
        if self.p.dynamic_routing and not rt.live:
            notes.append(f"or advertise {dest} via BGP/OSPF ({', '.join(self.p.dynamic_routing)})")
        notes.append("summarise to the remote site's whole subnet if more hosts there need access")
        where = f" via {next_hop}" if next_hop else ""
        where += f" ({iface}, zone {zone or '?'})" if iface else ""
        self.add(FixStep("routing", f"Add a static route {label}: {dest}{where}", why, [cmd], notes))
        return iface, zone

    def zone_step(self, iface: str) -> str:
        i = next((x for x in self.p.interfaces if x.name == iface), None)
        name = _slug((i.comment or "").split("(")[0].strip().lower()) if i and i.comment else ""
        name = name or f"zone-{_slug(iface.replace('/', '-'))}"
        self.add(FixStep("zone", f"Put interface {iface} in a zone (suggested name '{name}')",
                         f"{iface} has no zone, so the firewall drops every packet on it",
                         [self.set_cmd(f"zone {q(name)} network layer3 {iface}")],
                         ["use an existing zone instead if the network belongs to one", "attach a zone protection "
                          "profile if this zone faces untrusted networks"]))
        return name

    # -- NAT ---------------------------------------------------------------------
    def snat_steps(self, flow: Flow, t2: FlowTrace, fz: str, tz: str, egress_if: Optional[str]) -> None:
        for r in self.p.nat_rules:
            if r.disabled and r.src_type and self.m_nat_ok(r, flow, fz, tz, egress_if, allow_misses=0):
                path, notes = self.rule_path(r)
                self.add(FixStep("nat", f"Enable NAT rule '{r.name}'",
                                 "it would source-NAT this traffic but is disabled",
                                 [f"{path} disabled no"], notes))
                return
        best = None
        for r in self.p.nat_rules:
            if r.disabled or not r.src_type:
                continue
            dims = self.m.nat(r, flow, fz, tz, egress_if)
            misses = [n for n, res, _ in dims if res == NONE]
            if misses and set(misses) <= {"from", "source"}:
                best = (r, misses)
                break
        if best:
            r, misses = best
            path, notes = self.rule_path(r)
            cmds = []
            for miss in misses:
                if miss == "from":
                    cmds.append(f"{path} from {q(fz)}")
                else:
                    obj, mk = self.address(flow.src)
                    cmds += mk + [f"{path} source {q(obj)}"]
            what = " and ".join(f"zone {fz} to 'from'" if m == "from" else f"{interval_str(flow.src)} to 'source'"
                                for m in misses)
            self.add(FixStep("nat", f"Add {what} of existing source NAT rule '{r.name}'",
                             f"'{r.name}' already translates {', '.join(r.from_zones)} -> {', '.join(r.to_zones)} "
                             f"({r.describe()}), it just doesn't include this "
                             + ("zone" if misses == ["from"] else "source"), cmds,
                             notes + ["set adds a member to the list; existing members stay"]))
            return
        obj, mk = self.address(flow.src)
        iface = egress_if or "<egress-interface>"
        name = _slug(f"SNAT-{fz}-to-{tz}")
        self.add(FixStep("nat", f"Add source NAT rule '{name}' ({fz} -> {tz}, hide behind {iface})",
                         f"private source {interval_str(flow.src)} going to a public address needs source NAT, "
                         f"and no NAT rule covers {fz} -> {tz}",
                         mk + [self.set_cmd(f"rulebase nat rules {name} from {q(fz)} to {q(tz)} source {q(obj)} "
                                            f"destination any service any source-translation dynamic-ip-and-port "
                                            f"interface-address interface {iface}")],
                         ["NAT rules are first-match: if a broader NAT rule above it matches this traffic, "
                          f"move it up with: move {self.pfx}rulebase nat rules {name} top"]))

    def m_nat_ok(self, r, flow, fz, tz, egress_if, allow_misses: int) -> bool:
        dims = self.m.nat(r, flow, fz, tz, egress_if)
        return sum(1 for _, res, _ in dims if res == NONE) <= allow_misses

    def dnat_step(self, flow: Flow, fz: str, pre_zone: str) -> Optional[str]:
        target = try_target(self.h.dnat_to)
        if target is None:
            return None
        dst_obj, mk1 = self.address(flow.dst)
        srv_obj, mk2 = self.address(target)
        svc, mk3 = self.service(flow.proto or "tcp", flow.dport) if flow.dport is not None else ("any", [])
        name = _slug(f"DNAT-{interval_str(flow.dst)}-to-{self.h.dnat_to}")
        rr = self.p.routes.resolve(self.t.vr or (self.p.routes.vrs or ["default"])[0], target)
        post_zone = self.p.zone_of(rr.interface) if rr.ok else None
        notes = [f"the security rule must use the PRE-NAT destination ({interval_str(flow.dst)}) and the POST-NAT "
                 f"zone ({post_zone or '?'})"]
        if not rr.ok:
            notes.append(f"there is no route to {self.h.dnat_to}: add one first")
        self.add(FixStep("nat", f"Add destination NAT rule '{name}' ({interval_str(flow.dst)} -> {self.h.dnat_to})",
                         f"no NAT rule publishes {interval_str(flow.dst)}",
                         mk1 + mk2 + mk3 + [self.set_cmd(
                             f"rulebase nat rules {name} from {q(fz)} to {q(pre_zone)} source any "
                             f"destination {q(dst_obj)} service {svc} destination-translation "
                             f"translated-address {q(srv_obj)}")], notes))
        return post_zone

    # -- security ----------------------------------------------------------------
    def security_steps(self, flow: Flow, t2: FlowTrace, fz: str, tz: str) -> None:
        final = self.p.rule(t2.security_rule)
        explicit_deny = final is not None and final.rulebase != "default" and final.action in DENY_ACTIONS
        limit = final.position if explicit_deny else None

        # 1. a disabled rule that already fits
        for r in self.p.security_rules:
            if limit is not None and r.position >= limit:
                break
            if r.disabled and r.action == "allow" and \
                    all(res != NONE for _, res, _ in self.m.security(r, flow, fz, tz)):
                path, notes = self.rule_path(r)
                self.add(FixStep("security", f"Enable existing rule '{r.name}'",
                                 "it already allows exactly this traffic but is disabled", [f"{path} disabled no"],
                                 notes + ["check why it was disabled before enabling it"]))
                return

        group_fix = explicit_deny and self.deny_exception_step(final, flow)

        # 2. the closest existing allow rule
        best = None
        for r in self.p.security_rules:
            if limit is not None and r.position >= limit:
                break
            if r.disabled or r.action != "allow":
                continue
            dims = self.m.security(r, flow, fz, tz)
            if any(n == "rule-type" and res == NONE for n, res, _ in dims):
                continue
            misses = [(n, why) for n, res, why in dims if res == NONE]
            names = {n for n, _ in misses}
            if not misses or {"from", "to"} <= names:
                continue
            if "service" in names and "application-default" in r.service:
                continue                     # would change ports for every app in the rule
            # A zone may only be added when the rule already names this exact address on that side
            # (a wrong-zone mistake); adding a zone to an any-address rule opens a whole new zone pair.
            if "to" in names and "any" in r.destination or "from" in names and "any" in r.source:
                continue
            score = sum(_MISS_WEIGHT.get(n, 3) for n in names)
            score += ("any" in r.application) + ("any" in r.source) + ("any" in r.destination)   # prefer narrow rules
            if score <= _MAX_SCORE and (best is None or score < best[0]):
                best = (score, r, misses)
        if group_fix:
            self.new_rule_step(flow, fz, tz, final, explicit_deny, alternative=True)
        elif best is not None and (len(best[2]) > 1 or flow.app and "any" in best[1].application):
            # widening a rule in several ways, or a port-based rule for every app: a dedicated rule is cleaner
            self.new_rule_step(flow, fz, tz, final, explicit_deny, alternative=False)
            self.modify_step(best[1], best[2], flow, fz, tz, alternative=True)
        elif best is not None:
            self.modify_step(best[1], best[2], flow, fz, tz)
            self.new_rule_step(flow, fz, tz, final, explicit_deny, alternative=True)
        else:
            self.new_rule_step(flow, fz, tz, final, explicit_deny, alternative=False)

    def modify_step(self, r: SecurityRule, misses, flow: Flow, fz: str, tz: str, alternative: bool = False) -> None:
        path, notes = self.rule_path(r)
        cmds, what = [], []
        for n, why in misses:
            if n == "from":
                cmds.append(f"{path} from {q(fz)}")
                what.append(f"zone {fz} to 'from'")
            elif n == "to":
                cmds.append(f"{path} to {q(tz)}")
                what.append(f"zone {tz} to 'to'")
            elif n in ("source", "destination"):
                obj, mk = self.address(flow.src if n == "source" else flow.dst)
                cmds += mk + [f"{path} {n} {q(obj)}"]
                what.append(f"{obj} to '{n}'")
            elif n == "application":
                cmds.append(f"{path} application {flow.app}")
                what.append(f"application {flow.app}")
                from .advisor import app_port_conflicts
                for c in app_port_conflicts(r, self.p):
                    if c.app != flow.app:
                        cmds.append(f"delete {path[4:]} application {c.app}")
                        what.append(f"remove conflicting application {c.app}")
                        self.handled_conflicts.add(r.name)
            elif n == "service":
                svc, mk = self.service(flow.proto or "tcp", flow.dport)
                cmds += mk + [f"{path} service {svc}"]
                what.append(f"service {svc}")
            elif n == "user":
                cmds.append(f"{path} source-user {q(flow.user)}")
                what.append(f"user {flow.user}")
            elif n == "url-category":
                cmds.append(f"{path} category {flow.url_category}")
                what.append(f"URL category {flow.url_category}")
        scope = (f"this also opens it for everything else the rule matches "
                 f"(source {', '.join(r.source)} -> destination {', '.join(r.destination)})")
        if "any" in r.application and any(n == "service" for n, _ in misses):
            scope += f"; '{r.name}' is port-based (application any), so this opens every app on that port"
        self.add(FixStep("security", ("Or extend" if alternative else "Extend") + f" existing rule '{r.name}': "
                         f"add {', '.join(what)}",
                         f"'{r.name}' already allows {', '.join(r.from_zones)} -> {', '.join(r.to_zones)} for "
                         f"{', '.join(r.application)} and differs from this flow only by: "
                         + "; ".join(w for _, w in misses), cmds,
                         notes + ["set adds a member to the list; existing members stay", scope],
                         alternative=alternative))

    def new_rule_step(self, flow: Flow, fz: str, tz: str, final: Optional[SecurityRule], explicit_deny: bool,
                      alternative: bool) -> None:
        from .advisor import _app_ports
        src, mk1 = self.address(flow.src)
        dst, mk2 = self.address(flow.dst)
        cmds = mk1 + mk2
        notes = []
        app = flow.app
        if app:
            std = _app_ports(app)
            if flow.dport is None or std is None or any(p == flow.proto and lo <= flow.dport <= hi
                                                          for p, lo, hi in std):
                svc = "application-default"
            else:
                svc, mk = self.service(flow.proto or "tcp", flow.dport)
                cmds += mk
                notes.append(f"{app} on {flow.proto}/{flow.dport} is a non-standard port, so the rule names the "
                             f"port explicitly instead of application-default")
        elif flow.dport is not None:
            app, (svc, mk) = "any", self.service(flow.proto or "tcp", flow.dport)
            cmds += mk
            notes.append("the application is unknown, so this starts as a port-based rule; once traffic flows, "
                         "use Policy Optimizer to replace 'any' with the real App-ID and application-default")
        else:
            app, svc = "<application>", "application-default"
            notes.append("name the application(s) (from traffic logs or the application owner)")
        groups = Counter(r.profile_group for r in self.p.security_rules
                         if r.action == "allow" and not r.disabled and r.profile_group)
        logset = Counter(r.log_setting for r in self.p.security_rules if r.log_setting)
        zn = lambda z, d: d if z.startswith("<") else z      # noqa: E731
        name = _slug(f"Allow-{zn(fz, 'src')}-to-{zn(tz, 'dst')}-"
                     f"{flow.app or (flow.proto or 'ip') + '-' + str(flow.dport or 'any')}")[:63]
        line = (f"rulebase security rules {name} from {q(fz)} to {q(tz)} source {q(src)} destination {q(dst)} "
                f"source-user {q(flow.user) if flow.user else 'any'} category {flow.url_category or 'any'} "
                f"application {app} service {svc} action allow log-end yes")
        if groups:
            line += f" profile-setting group {q(groups.most_common(1)[0][0])}"
        else:
            notes.append("attach a security profile group (none is used elsewhere on this firewall)")
        if logset:
            line += f" log-setting {q(logset.most_common(1)[0][0])}"
        line += f' description "pan-troubleshoot: {flow}"'
        cmds.append(self.set_cmd(line))
        if explicit_deny and final is not None:
            cmds.append(f"move {self.pfx}rulebase security rules {name} before {q(final.name)}")
            notes.append(f"it must sit above '{final.name}', which denies this traffic today")
        else:
            same = [r for r in self.p.security_rules if r.rulebase == "local" and fz in r.from_zones
                    and tz in r.to_zones]
            if same:
                cmds.append(f"move {self.pfx}rulebase security rules {name} after {q(same[-1].name)}")
                notes.append(f"placed with the other {fz} -> {tz} rules")
        if self.p.security_rules and any(r.rulebase in ("pre", "post") for r in self.p.security_rules):
            notes.append("this firewall is Panorama-managed: consider adding the rule to the device group instead")
        why = (f"'{final.name}' denies it and no allow rule above it is close enough to extend" if explicit_deny
               else f"no security rule allows {fz} -> {tz} for this traffic (it falls to "
                    f"{final.name if final else 'the default rule'})")
        self.add(FixStep("security", ("Or create" if alternative else "Create") + f" a dedicated allow rule '{name}'",
                         "a narrow rule only for this flow, leaving existing rules unchanged" if alternative else why,
                         cmds, notes, alternative=alternative))

    def deny_exception_step(self, deny: SecurityRule, flow: Flow) -> bool:
        """When the deny lists the host via an address group, removing it there is often the real fix."""
        path, notes = self.rule_path(deny)
        for side, iv in (("source", flow.src), ("destination", flow.dst)):
            members = deny.source if side == "source" else deny.destination
            for g in members:
                group = self.p.store.address_groups.get(g)
                if not group:
                    continue
                for m in group:
                    obj = self.p.store.address_value(m)
                    if obj is not None and obj[1] <= iv[1] and iv[2] <= obj[2]:
                        self.add(FixStep("security", f"Remove '{m}' from address group '{g}' (used by deny rule "
                                                     f"'{deny.name}')",
                                         f"{interval_str(iv)} is denied because it is listed in '{g}'; if the block "
                                         f"is no longer needed (e.g. the host was cleaned), take it out of the group "
                                         f"rather than punching an exception rule through the deny",
                                         [f"delete {self.pfx}address-group {q(g)} static {q(m)}"],
                                         ([f"rule description: {deny.description}"] if deny.description else [])
                                         + ["confirm with the owner of the deny rule first"] + notes))
                        return True
        return False

    # -- evidence-based steps ----------------------------------------------------
    def profile_steps(self, flow: Flow) -> None:
        ips = {first_ip(flow.src), first_ip(flow.dst)}
        for f in self.has("LOG_THREAT_BLOCK"):
            d = f.data
            if ips and not ips & set(d.get("ips", [])):
                continue
            ptype, prof, tid = d.get("profile_type"), d.get("profile") or "<profile>", d.get("threat_id")
            if ptype in ("vulnerability", "spyware") and tid:
                exempt = [first_ip(flow.dst)] if first_ip(flow.dst) in d.get("ips", []) else sorted(
                    ips & set(d.get("ips", [])))[:1]
                cmds = [self.set_cmd(f"profiles {ptype} {q(prof)} threat-exception {tid} action allow")]
                cmds += [self.set_cmd(f"profiles {ptype} {q(prof)} threat-exception {tid} exempt-ip {ip}")
                         for ip in exempt]
                self.add(FixStep("profile", f"Threat exception for '{d.get('threat')}' ({tid}) in {ptype} profile "
                                            f"'{prof}', limited to {', '.join(exempt)}",
                                 f"the {ptype} profile on rule '{d.get('rule')}' blocks it ({d.get('severity')})", cmds,
                                 ["ONLY if this is a confirmed false positive; otherwise the block is doing its job",
                                  "predefined profiles (default/strict) can't be edited: clone them first",
                                  "exempt-ip keeps the signature active for sessions not involving this IP"]))
            elif ptype in ("virus", "wildfire-analysis") and tid:
                self.add(FixStep("profile", f"Antivirus exception for signature {tid} in '{prof}'",
                                 f"the antivirus/WildFire profile on '{d.get('rule')}' blocks '{d.get('threat')}'",
                                 [self.set_cmd(f"profiles virus {q(prof)} threat-exception {tid}")],
                                 ["ONLY for a confirmed false positive (submit the file to WildFire for a verdict "
                                  "change first)"]))
            else:
                self.add(FixStep("review", f"Review {ptype} profile '{prof}' on rule '{d.get('rule')}'",
                                 f"it blocks '{d.get('threat')}'", [],
                                 ["file-blocking/data-filtering have no per-signature exceptions: adjust the "
                                  "profile rule or use a dedicated rule with a different profile"]))
        for f in self.has("LOG_URL_BLOCK") + self.has("PROFILE_URL_BLOCK"):
            d = f.data
            prof, cat = d.get("profile") or "<url-profile>", d.get("category")
            hosts = list(dict.fromkeys(u.split("/")[0] for u in d.get("urls", []) if u))
            cmds, notes = [], ["confirm there is a business need: the category is blocked by policy"]
            if hosts:
                cuc = "Troubleshoot-Allow"
                cmds = [self.set_cmd(f'profiles custom-url-category {cuc} type "URL List"')]
                cmds += [self.set_cmd(f"profiles custom-url-category {cuc} list {h}") for h in hosts]
                cmds.append(self.set_cmd(f"profiles url-filtering {q(prof)} allow {cuc}"))
                notes.append("allow-lists only these sites; the rest of the category stays blocked")
            else:
                cmds = [f"delete {self.pfx}profiles url-filtering {q(prof)} block {cat}",
                        self.set_cmd(f"profiles url-filtering {q(prof)} alert {cat}")]
                notes.append(f"this unblocks the whole '{cat}' category for every rule using '{prof}'; "
                             f"allow-listing specific sites in a custom URL category is narrower")
            notes.append("if the site is mis-categorised, request a change at https://urlfiltering.paloaltonetworks.com")
            self.add(FixStep("url", f"Allow {', '.join(hosts) or 'category ' + str(cat)} through URL profile '{prof}'",
                             f"URL filtering on rule '{d.get('rule')}' blocks category '{cat}'", cmds, notes))
        for f in self.has("APP_PORT_CONFLICT"):
            r = self.p.rule(f.data.get("rule"))
            if r is None or r.name in self.handled_conflicts:
                continue
            self.handled_conflicts.add(r.name)
            path, notes = self.rule_path(r)
            app = f.data.get("app")
            cmds = [f"delete {path[4:]} service", f"{path} service application-default"]
            if self.f.app and self.f.app != app:
                cmds = [f"delete {path[4:]} application {app}", f"{path} application {self.f.app}"]
            self.add(FixStep("security", f"Fix App-ID/port conflict on '{r.name}'", f.message, cmds,
                             notes + ["or keep the explicit port and name the application that really runs on it"]))
        for f in self.has("LOG_ZONE_PROTECTION"):
            d = f.data
            self.add(FixStep("review", f"Zone protection blocks '{d.get('threat')}' in zone(s) "
                                       f"{', '.join(d.get('zones', []))}",
                             "flood/reconnaissance protection acted on this traffic",
                             [f"show zone-protection zone {z}" for z in d.get("zones", [])],
                             ["if the source is a legitimate scanner/monitoring host, exempt it in the zone "
                              f"protection profile ({', '.join(d.get('profiles', [])) or 'see the zone'}) "
                              "reconnaissance settings, or raise the thresholds"]))
        for f in self.has("ROUTE_ASYMMETRIC") + self.has("LOG_NO_REPLY"):
            self.add(FixStep("review", f.message, "the firewall allowed it, but the path or the server is the problem",
                             [], [d for d in f.details if not d.startswith("20")][:3]))

    # -- main --------------------------------------------------------------------
    def plan(self) -> FixPlan:
        t, flow = self.t, self.f
        fz, tz, egress_if = t.from_zone, t.to_zone, t.egress_if
        changed = False

        if t.ingress_if is None and not flow.from_zone and self.has("ROUTE_NO_RETURN"):
            iface, zone = self.route_step(flow.src, t.vr, self.h.return_next_hop, f"back to {interval_str(flow.src)}")
            fz = zone or (self.zone_step(iface) if iface else "<source-zone>")
            changed = True
        elif t.ingress_if and not t.from_zone:
            fz, changed = self.zone_step(t.ingress_if), True

        route_fail = self.has("ROUTE_NONE") + self.has("ROUTE_DISCARD")
        if route_fail and not t.egress_if:
            discard = next((f.data.get("route") for f in self.has("ROUTE_DISCARD")), None)
            iface, zone = self.route_step(flow.dst, t.vr, self.h.next_hop, f"to {interval_str(flow.dst)}", discard)
            egress_if = iface
            tz = zone or (self.zone_step(iface) if iface else "<destination-zone>")
            changed = True
        elif t.egress_if and not t.to_zone:
            tz, changed = self.zone_step(t.egress_if), True
        if self.has("NAT_DNAT_NO_ROUTE"):
            self.route_step(try_target(t.post_nat_dst) or flow.dst, t.vr, self.h.next_hop,
                            f"to the NAT target {t.post_nat_dst}")

        fz, tz = fz or "<source-zone>", tz or "<destination-zone>"
        t2 = t
        if changed:
            t2, _ = Troubleshooter(self.p).simulate(dataclasses.replace(flow, from_zone=fz, to_zone=tz))
        pre_zone = t2.pre_nat_zone or tz

        # NAT
        if self.h.dnat_to and not (t2.nat_rule and t2.post_nat_dst):
            post = self.dnat_step(flow, fz, pre_zone)
            if post:
                tz = post
                t2, _ = Troubleshooter(self.p).simulate(dataclasses.replace(flow, from_zone=fz, to_zone=tz))
        elif t2.nat_rule is None and is_private(flow.src) and not is_private(flow.dst):
            self.snat_steps(flow, t2, fz, pre_zone, egress_if)
        elif self.has("DST_IS_FIREWALL"):
            self.add(FixStep("review", f"{first_ip(flow.dst)} is the firewall's own address",
                             "traffic to it terminates on the firewall unless a destination NAT rule publishes a "
                             "server behind it", [],
                             ["to publish a server: re-run with --dnat-to <internal-server-ip>",
                              "to manage the firewall on it: check the interface management profile instead"]))
            self.profile_steps(flow)
            return self._finish()

        # Security
        if t2.verdict in ("DENY", "CONDITIONAL", "DROP", "UNKNOWN") and not self.has("PROFILE_URL_BLOCK"):
            if t2.verdict == "CONDITIONAL" and not flow.app:
                self.add(FixStep("review", "Identify the application first",
                                 t2.reason, [], ["find the App-ID in the traffic logs (or re-run with --app); the "
                                                 "plan then says whether an existing rule covers it"]))
            else:
                self.security_steps(flow, t2, fz, tz)

        self.profile_steps(flow)
        return self._finish()

    def _finish(self) -> FixPlan:
        t = self.t
        plan = FixPlan(str(self.f))
        plan.steps = sorted(self.steps, key=lambda s: (_AREA_ORDER.index(s.area), s.alternative))
        plan.needed = list(dict.fromkeys(_AREA_LABEL[s.area] for s in plan.steps
                                         if not s.alternative and s.area in _AREA_LABEL))
        if plan.needed:
            plan.summary = "To make this flow work: " + " + ".join(plan.needed)
        elif plan.steps:
            plan.summary = "No config is missing; review the items below"
        else:
            plan.summary = (f"Nothing to change: rule '{t.security_rule}' already allows this flow"
                            if t.verdict == "ALLOW" else "No change can be proposed from the data available")
        return plan


def plan_fixes(policy: PolicyConfig, trace: FlowTrace, findings: List[Finding], hints: Optional[Hints] = None) -> FixPlan:
    return Planner(policy, trace, findings, hints).plan()


def format_plan(plan: FixPlan) -> List[str]:
    out = [f"  {plan.summary}"]
    n = 0
    for s in plan.steps:
        if s.alternative:
            label = "   or"
        else:
            n += 1
            label = f"  {n:>2}."
        out.append(f"{label} [{s.area}] {s.title}")
        out.append(f"       why: {s.why}")
        out += [f"         {c}" for c in s.commands]
        out += [f"       note: {x}" for x in s.notes]
    if any(s.commands for s in plan.steps):
        out.append("       then: commit (or commit and push from Panorama). Review every command first; "
                   "pan-troubleshoot never changes the firewall.")
    return out
