"""Offline tests for the troubleshoot package, on the fictional examples/troubleshoot data."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.api import PanosApiClient
from troubleshoot import cli
from troubleshoot.advisor import app_port_conflicts, audit_policy, build_matrix
from troubleshoot.engine import Troubleshooter
from troubleshoot.live import LiveVerifier
from troubleshoot.logs import LogEntry, build_query, load_logs, parse_csv
from troubleshoot.objects import FULL, NONE, PARTIAL, UNKNOWN, ObjectStore, coverage, parse_target
from troubleshoot.policy import load_policy
from troubleshoot.remediate import Hints
from troubleshoot.report import render_html

DEMO = Path(__file__).resolve().parent.parent / "examples" / "troubleshoot"
CFG = DEMO / "branch-fw.xml"
LOG_FILES = sorted(DEMO.glob("*-logs.*"))


def policy():
    return load_policy(CFG)


def logs():
    return [e for p in LOG_FILES for e in load_logs(p)]


def codes(diag):
    return {f.code for f in diag.findings}


class TestObjects(unittest.TestCase):
    def test_parse_target_forms(self):
        self.assertEqual(parse_target("10.0.0.0/24"), parse_target("10.0.0.0-10.0.0.255"))
        self.assertEqual(parse_target("10.0.0.5/24"), parse_target("10.0.0.0/24"))   # host bits ignored

    def test_coverage(self):
        t = parse_target("10.0.0.0/24")
        self.assertEqual(coverage([parse_target("10.0.0.0/16")], t), FULL)
        self.assertEqual(coverage([parse_target("10.0.0.0/25")], t), PARTIAL)
        self.assertEqual(coverage([parse_target("10.0.0.0/25"), parse_target("10.0.0.128/25")], t), FULL)
        self.assertEqual(coverage([parse_target("10.1.0.0/16")], t), NONE)

    def test_dynamic_group_and_fqdn_are_unknown(self):
        p = policy()
        self.assertEqual(p.store.resolve_addresses(["DAG-Compromised"]).relation(parse_target("1.2.3.4")), UNKNOWN)
        self.assertEqual(p.store.resolve_addresses(["FQDN-Partner-API"]).relation(parse_target("1.2.3.4")), UNKNOWN)
        self.assertEqual(p.store.resolve_addresses(["AG-Quarantine"]).relation(parse_target("10.10.20.66")), FULL)

    def test_application_default(self):
        s = ObjectStore([]).resolve_services(["application-default"])
        self.assertEqual(s.relation("tcp", 443, "ssl"), FULL)
        self.assertEqual(s.relation("tcp", 22, "ssl"), NONE)
        self.assertEqual(s.relation("tcp", 443, None), UNKNOWN)
        self.assertEqual(s.relation("tcp", 1433, None, ["ntp"]), NONE)   # ntp can never be tcp/1433

    def test_port_services_never_match_icmp(self):
        s = ObjectStore([]).resolve_services(["service-https"])
        self.assertEqual(s.relation("icmp", None), NONE)


class TestRouting(unittest.TestCase):
    def test_longest_prefix_and_discard(self):
        rt = policy().routes
        self.assertEqual(rt.resolve("default", parse_target("10.10.40.9")).interface, "ethernet1/3")
        self.assertEqual(rt.resolve("default", parse_target("8.8.8.8")).interface, "ethernet1/1")
        self.assertTrue(rt.resolve("default", parse_target("172.20.1.1")).discard)


class TestDiagnose(unittest.TestCase):
    def setUp(self):
        self.ts = Troubleshooter(policy(), logs())

    def test_explicit_deny(self):
        d = self.ts.diagnose("10.10.20.66", "198.51.100.25", port=443)
        self.assertEqual(d.verdict, "BLOCKED")
        self.assertEqual(d.traces[0].security_rule, "Block-Quarantine")
        self.assertTrue({"POLICY_DENY", "LOG_DENY"} <= codes(d))

    def test_default_deny_with_disabled_rule_and_no_logs(self):
        d = self.ts.diagnose("10.10.30.0/24", "10.10.40.10", port=1433)
        self.assertEqual(d.traces[0].security_rule, "interzone-default")
        self.assertTrue({"POLICY_DEFAULT_DENY", "POLICY_DISABLED_RULE", "LOG_NONE"} <= codes(d))

    def test_threat_profile_block(self):
        d = self.ts.diagnose("10.10.20.15", "192.0.2.80", port=443)
        self.assertEqual(d.traces[0].flow.app, "ssl")                 # inferred from traffic logs
        self.assertEqual(d.traces[0].verdict, "PROFILE-BLOCK")
        self.assertIn("then blocked by vulnerability", d.traces[0].reason)
        f = next(f for f in d.findings if f.code == "LOG_THREAT_BLOCK")
        self.assertIn("VP-Strict", f.message)
        self.assertIn("91991", f.message)
        self.assertEqual(d.verdict, "BLOCKED")

    def test_url_block(self):
        d = self.ts.diagnose("10.10.20.33", "198.51.100.77", port=443)
        f = next(f for f in d.findings if f.code == "LOG_URL_BLOCK")
        self.assertIn("gambling", f.message)
        self.assertTrue(any("URL-Corp" in x and "block" in x for x in f.details))

    def test_discard_route(self):
        d = self.ts.diagnose("10.10.20.15", "172.31.5.5", port=22)
        self.assertEqual(d.traces[0].verdict, "DROP")
        self.assertIn("ROUTE_DISCARD", codes(d))

    def test_inbound_dnat(self):
        d = self.ts.diagnose("203.0.113.10", "192.0.2.150", port=443, direction="in")
        t = d.traces[0]
        self.assertEqual((t.nat_rule, t.post_nat_dst, t.to_zone, t.security_rule),
                         ("DNAT-Web-DMZ", "10.10.50.10", "dmz", "Inbound-Web-DMZ"))
        self.assertTrue(d.verdict.startswith("ALLOWED"))

    def test_flows_discovered_from_logs(self):
        d = self.ts.diagnose("10.10.20.66")
        self.assertEqual(len(d.traces), 2)
        self.assertTrue(all(t.flow.origin == "logs" for t in d.traces))

    def test_app_id_dependence_is_not_reported_as_blocked(self):
        d = Troubleshooter(policy()).diagnose("10.10.20.40", "198.51.100.9", port=443)
        self.assertEqual(d.traces[0].verdict, "CONDITIONAL")
        self.assertIn("POLICY_DEPENDS_ON_APP", codes(d))

    def test_no_source_nat_warning(self):
        p = policy()
        p.nat_rules = [r for r in p.nat_rules if r.name != "SNAT-Outbound"]
        d = Troubleshooter(p).diagnose("10.10.20.40", "198.51.100.9", port=443, app="ssl")
        self.assertIn("NAT_NO_SOURCE_NAT", codes(d))

    def test_interface_without_zone(self):
        d = Troubleshooter(policy()).diagnose("10.10.60.5", "10.10.40.10", port=443)
        self.assertIn("ZONE_MISSING", codes(d))

    def test_app_port_conflict_in_flow(self):
        d = Troubleshooter(policy()).diagnose("10.10.20.15", "10.10.40.22", port=22, app="ssh")
        self.assertIn("APP_PORT_CONFLICT", codes(d))
        self.assertEqual(d.verdict, "BLOCKED")

    def test_zone_protection_and_asymmetry_from_logs(self):
        extra = [LogEntry("threat", src="192.0.2.99", dst="203.0.113.2", subtype="scan", threat="TCP Port Scan",
                          action="block-ip", from_zone="untrust", severity="high"),
                 LogEntry("traffic", src="10.10.20.15", dst="10.10.40.10", dport=443, proto="tcp",
                          inbound_if="ethernet1/5", rule="Users-to-Servers-HTTPS", action="allow",
                          packets_received=0)]
        ts = Troubleshooter(policy(), extra)
        d = ts.diagnose("192.0.2.99")
        f = next(f for f in d.findings if f.code == "LOG_ZONE_PROTECTION")
        self.assertTrue(any("ZP-Internet" in x for x in f.details))
        d = ts.diagnose("10.10.20.15", "10.10.40.10", port=443)
        self.assertTrue({"ROUTE_ASYMMETRIC", "LOG_NO_REPLY"} <= codes(d))


class TestLogs(unittest.TestCase):
    def test_csv_url_classification(self):
        entries = load_logs(DEMO / "url-logs.csv")
        self.assertTrue(all(e.kind == "url" for e in entries))
        self.assertEqual(entries[0].category, "gambling")
        self.assertTrue(entries[0].blocked)
        self.assertFalse(entries[2].blocked)                  # alert only

    def test_threat_id_split(self):
        e = next(e for e in load_logs(DEMO / "threat-logs.xml") if e.subtype == "vulnerability")
        self.assertEqual((e.threat_id, e.kind), ("91991", "threat"))
        self.assertFalse(e.threat.endswith(")"))

    def test_csv_traffic(self):
        e = parse_csv("Type,Source address,Destination address,Destination Port,Action,Rule\n"
                      "TRAFFIC,10.0.0.1,10.0.0.2,443,deny,x\n")[0]
        self.assertEqual((e.kind, e.dport, e.blocked), ("traffic", 443, True))

    def test_query(self):
        self.assertEqual(build_query(parse_target("10.0.0.0/24"), parse_target("1.1.1.1"), 443),
                         "( addr in 10.0.0.0/24 ) and ( addr in 1.1.1.1 ) and ( port.dst eq 443 )")
        with self.assertRaises(ValueError):
            build_query(parse_target("10.0.0.1"), since="yesterday' or 1=1")


class TestAdvisor(unittest.TestCase):
    def test_conflict_detection(self):
        p = policy()
        c = app_port_conflicts(p.rule("Admins-to-Jumphost"), p)
        self.assertEqual((len(c), c[0].severity, c[0].app), (1, "HIGH", "web-browsing"))
        self.assertEqual(app_port_conflicts(p.rule("Inbound-Web-DMZ"), p), [])     # decrypted HTTPS is fine
        self.assertEqual(app_port_conflicts(p.rule("Users-to-Internet"), p), [])   # application-default

    def test_matrix(self):
        m = build_matrix(policy(), "10.10.20.15", "10.10.40.0/24")
        self.assertEqual((m.from_zone, m.to_zone), ("trust", "servers"))
        self.assertEqual({r.rule for r in m.permitted}, {"Users-to-Servers-HTTPS", "Admins-to-Jumphost"})
        self.assertEqual({r.rule for r in m.blocked}, {"Block-Quarantine"})
        self.assertTrue(any(r.conflict for r in m.permitted))
        self.assertIn("interzone-default", m.default)

    def test_matrix_marks_shadowed_rows(self):
        m = build_matrix(policy(), "10.10.20.66", "198.51.100.25")
        self.assertEqual(m.blocked[0].rule, "Block-Quarantine")
        self.assertTrue(all(r.shadowed_by == "Block-Quarantine" for r in m.rows if r.rule != "Block-Quarantine"))

    def test_audit(self):
        items = audit_policy(policy())
        by = {(a.code, a.rule) for a in items}
        for expected in [("BP_APP_PORT_CONFLICT", "Admins-to-Jumphost"), ("BP_SERVICE_ANY", "IoT-to-Cloud"),
                         ("BP_NO_SECURITY_PROFILES", "IoT-to-Cloud"), ("BP_NO_LOGGING", "IoT-to-Cloud"),
                         ("BP_APP_ANY", "Users-to-Servers-HTTPS"), ("BP_NO_DECRYPTION", "Inbound-Web-DMZ"),
                         ("BP_DISABLED_RULE", "IoT-to-SQL"), ("BP_DEFAULT_RULE_NOT_LOGGED", None),
                         ("BP_INTERFACE_NO_ZONE", None)]:
            self.assertIn(expected, by)
        self.assertNotIn(("BP_NO_DECRYPTION", "Users-to-Internet"), by)   # covered by Decrypt-Users-Outbound

    def test_shadowed_rule(self):
        p = policy()
        dup = p.rule("Users-to-Servers-HTTPS")
        import dataclasses
        p.security_rules.append(dataclasses.replace(dup, name="Dup-HTTPS", position=99))
        self.assertIn(("BP_SHADOWED_RULE", "Dup-HTTPS"), {(a.code, a.rule) for a in audit_policy(p)})


class FakeResp:
    def __init__(self, body):
        self.content, self.status_code = body.encode(), 200


def plan_for(*args, logs_=None, **kw):
    d = Troubleshooter(policy(), logs_ or []).diagnose(*args, **kw)
    return d, d.plans[0]


def recommended(plan):
    return [s for s in plan.steps if not s.alternative]


class TestRemediation(unittest.TestCase):
    def test_add_application_to_existing_rule(self):
        _, plan = plan_for("10.10.20.15", "10.10.40.22", port=22, app="ssh")
        first = recommended(plan)[0]
        self.assertIn("Extend existing rule 'Admins-to-Jumphost'", first.title)
        self.assertIn("set rulebase security rules Admins-to-Jumphost application ssh", first.commands)
        self.assertIn("delete rulebase security rules Admins-to-Jumphost application web-browsing", first.commands)
        self.assertTrue(any(s.alternative for s in plan.steps))          # dedicated rule offered too

    def test_enable_disabled_rule(self):
        _, plan = plan_for("10.10.30.0/24", "10.10.40.10", port=1433)
        self.assertEqual(recommended(plan)[0].commands, ["set rulebase security rules IoT-to-SQL disabled no"])

    def test_nat_and_security_missing(self):
        _, plan = plan_for("10.10.70.25", "198.51.100.40", port=443, app="ssl")
        self.assertEqual(plan.needed, ["NAT rule", "security rule"])
        nat = recommended(plan)[0]
        self.assertEqual(nat.commands, ["set rulebase nat rules SNAT-Outbound from guest"])
        sec = recommended(plan)[1]
        self.assertTrue(any("from guest to untrust" in c and "application ssl service application-default" in c
                            for c in sec.commands))

    def test_route_and_security_missing_with_next_hop(self):
        _, plan = plan_for("10.10.20.15", "172.20.5.10", port=443, app="ssl",
                           hints=Hints(next_hop="10.255.0.2"))
        self.assertEqual(plan.needed, ["route", "security rule"])
        self.assertIn("interface ethernet1/8 nexthop ip-address 10.255.0.2", plan.steps[0].commands[0])
        self.assertTrue(any("from trust to wan" in c for c in recommended(plan)[1].commands))
        # an internet rule with destination any is never widened to a new zone
        self.assertFalse(any("Users-to-Internet" in s.title for s in plan.steps))

    def test_route_without_next_hop_uses_placeholders(self):
        _, plan = plan_for("10.10.20.15", "172.31.5.5", port=22)
        self.assertIn("<next-hop-ip>", plan.steps[0].commands[0])
        self.assertTrue(any("--next-hop" in n for n in plan.steps[0].notes))

    def test_zone_nat_security_missing(self):
        _, plan = plan_for("10.10.60.5", "198.51.100.40", port=443, app="ssl")
        self.assertEqual(plan.needed, ["zone", "NAT rule", "security rule"])
        self.assertEqual(plan.steps[0].commands, ["set zone lab network layer3 ethernet1/6"])

    def test_dnat_plan(self):
        d, plan = plan_for("203.0.113.2", "192.0.2.150", port=8443, app="ssl", direction="in",
                           hints=Hints(dnat_to="10.10.50.20"))
        self.assertEqual(d.verdict, "TERMINATES ON THE FIREWALL")
        self.assertEqual(plan.needed, ["NAT rule", "security rule"])
        self.assertIn("translated-address H-10.10.50.20", plan.steps[0].commands[-1])
        sec = recommended(plan)[1].commands[-2]
        self.assertIn("from untrust to dmz", sec)                          # post-NAT zone
        self.assertIn("destination H-203.0.113.2", sec)                    # pre-NAT address

    def test_explicit_deny_prefers_group_removal(self):
        _, plan = plan_for("10.10.20.66", "198.51.100.25", port=443)
        self.assertEqual(recommended(plan)[0].commands,
                         ["delete address-group AG-Quarantine static H-Quarantine-PC66"])
        alt = next(s for s in plan.steps if s.alternative)
        self.assertIn("move rulebase security rules Allow-trust-to-untrust-tcp-443 before Block-Quarantine",
                      alt.commands)

    def test_port_based_rule_is_not_the_recommendation(self):
        _, plan = plan_for("10.10.20.15", "10.10.40.22", port=3389, app="ms-rdp")
        self.assertIn("Create a dedicated allow rule", recommended(plan)[0].title)
        self.assertIn("Users-to-Servers-HTTPS", next(s for s in plan.steps if s.alternative).title)

    def test_threat_exception_and_url_allow_list(self):
        _, plan = plan_for("10.10.20.15", "192.0.2.80", port=443, logs_=logs())
        self.assertIn("set profiles vulnerability VP-Strict threat-exception 91991 action allow",
                      plan.steps[0].commands)
        self.assertIn("set profiles vulnerability VP-Strict threat-exception 91991 exempt-ip 192.0.2.80",
                      plan.steps[0].commands)
        _, plan = plan_for("10.10.20.33", "198.51.100.77", port=443, logs_=logs())
        self.assertIn("set profiles custom-url-category Troubleshoot-Allow list casino.example.com",
                      plan.steps[0].commands)

    def test_allowed_flow_needs_nothing(self):
        _, plan = plan_for("192.0.2.150", "203.0.113.10", port=443, app="ssl")
        self.assertEqual(plan.needed, [])
        self.assertTrue(plan.summary.startswith("Nothing to change"))

    def test_multi_vsys_prefix(self):
        p = policy()
        p.vsys = "vsys2"
        d = Troubleshooter(p).diagnose("10.10.70.25", "198.51.100.40", port=443, app="ssl")
        self.assertTrue(d.plans[0].steps[0].commands[0].startswith("set vsys vsys2 rulebase nat"))


    def test_private_destination_via_default_route_points_at_vpn(self):
        from core.parser import IpsecTunnel, ProxyId
        p = policy()
        p.ipsec_tunnels = [IpsecTunnel("VPN-SITE-B", "tunnel.9", ["GW-B"], None,
                                       [ProxyId("pid", "10.10.20.0/24", "192.168.99.0/24")], disabled=True)]
        d = Troubleshooter(p).diagnose("10.10.20.15", "192.168.99.5", port=443, app="ssl")
        f = next(f for f in d.findings if f.code == "ROUTE_PRIVATE_VIA_DEFAULT")
        self.assertEqual((f.severity, f.data["tunnel"]), ("ERROR", "VPN-SITE-B"))
        self.assertEqual(d.verdict, "BLOCKED")
        plan = d.plans[0]
        self.assertIn("destination 192.168.99.0/24 interface tunnel.9 metric 10", plan.steps[0].commands[0])
        self.assertIn("set network tunnel ipsec VPN-SITE-B disabled no",
                      [c for s in plan.steps for c in s.commands])
        # a public destination via the default route is normal
        self.assertNotIn("ROUTE_PRIVATE_VIA_DEFAULT", codes(Troubleshooter(p).diagnose("10.10.20.15", "198.51.100.9")))


class TestLogAbsence(unittest.TestCase):
    def test_live_query_with_no_results_is_not_reported_as_not_provided(self):
        d = Troubleshooter(policy(), [], logs_queried=True).diagnose("10.10.20.15", "198.51.100.9", port=443)
        self.assertIn("LOG_NONE", codes(d))
        self.assertNotIn("LOG_NOT_PROVIDED", codes(d))
        d = Troubleshooter(policy(), []).diagnose("10.10.20.15", "198.51.100.9", port=443)
        self.assertIn("LOG_NOT_PROVIDED", codes(d))


class TestUrlSummary(unittest.TestCase):
    def test_unblocked_url_logs_are_summarised(self):
        e = LogEntry("url", src="10.10.20.15", dst="198.51.100.9", dport=443, proto="tcp", action="alert",
                     category="high-risk", url="example.org/")
        d = Troubleshooter(policy(), [e]).diagnose("10.10.20.15")
        f = next(f for f in d.findings if f.code == "LOG_URL_SEEN")
        self.assertIn("1 x high-risk (alert)", f.details)


class TestUserAndCategory(unittest.TestCase):
    def test_url_category_prediction(self):
        d = Troubleshooter(policy()).diagnose("10.10.20.40", "198.51.100.9", port=443, app="ssl",
                                              url_category="gambling")
        self.assertIn("PROFILE_URL_BLOCK", codes(d))
        self.assertEqual(d.verdict, "BLOCKED")
        d = Troubleshooter(policy()).diagnose("10.10.20.40", "198.51.100.9", port=443, app="ssl",
                                              url_category="news")
        self.assertNotIn("PROFILE_URL_BLOCK", codes(d))

    def test_source_user(self):
        p = policy()
        r = p.rule("Users-to-Servers-HTTPS")
        r.source_user = ["corp\\alice"]
        t = Troubleshooter(p)
        self.assertEqual(t.diagnose("10.10.20.15", "10.10.40.9", port=443, user="corp\\alice").traces[0].security_rule,
                         "Users-to-Servers-HTTPS")
        self.assertEqual(t.diagnose("10.10.20.15", "10.10.40.9", port=443, user="corp\\bob").traces[0].security_rule,
                         "interzone-default")


class TestCommandsAndReport(unittest.TestCase):
    def test_verification_commands(self):
        d = Troubleshooter(policy()).diagnose("192.0.2.150", "203.0.113.10", port=443, app="ssl")
        cmds = [c for _, group in d.commands[0].groups for c in group]
        self.assertIn("test security-policy-match from untrust to dmz source 192.0.2.150 destination 203.0.113.10 "
                      "protocol 6 destination-port 443 application ssl show-all yes", cmds)
        # NAT is matched with the pre-NAT zone
        self.assertIn("test nat-policy-match from untrust to untrust source 192.0.2.150 destination 203.0.113.10 "
                      "protocol 6 destination-port 443", cmds)
        self.assertIn("test routing fib-lookup virtual-router default ip 10.10.50.10", cmds)
        self.assertIn("debug dataplane packet-diag set filter off", cmds)

    def test_html_report_escapes(self):
        d = Troubleshooter(policy(), logs()).diagnose("10.10.20.66", "198.51.100.25", port=443)
        d.findings[0].message = "<script>alert(1)</script>"
        html = render_html(d, policy())
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("delete address-group AG-Quarantine static H-Quarantine-PC66", html)


class TestLive(unittest.TestCase):
    def test_query_logs_polls_job(self):
        bodies = ['<response status="success"><result><job>7</job></result></response>',
                  '<response status="success"><result><job><status>ACT</status></job></result></response>',
                  '<response status="success"><result><job><status>FIN</status></job><log><logs>'
                  '<entry><src>10.0.0.1</src><action>deny</action><type>TRAFFIC</type></entry></logs></log>'
                  '</result></response>']
        s = mock.Mock()
        s.post.side_effect = [FakeResp(b) for b in bodies]
        c = PanosApiClient("fw.example.net", api_key="k", session=s)
        with mock.patch("core.api.time.sleep"):
            entries = c.query_logs("traffic", "( addr in 10.0.0.1 )")
        self.assertEqual(len(entries), 1)
        self.assertEqual(s.post.call_args_list[0].kwargs["data"]["log-type"], "traffic")
        self.assertEqual(s.post.call_args_list[2].kwargs["data"]["job-id"], "7")

    def test_verifier_flags_mismatch(self):
        p = policy()
        d = Troubleshooter(p).diagnose("10.10.20.66", "198.51.100.25", port=443)
        client = mock.Mock()
        import xml.etree.ElementTree as ET
        client.op.side_effect = [
            ET.fromstring('<response status="success"><result><rules><entry name="Other-Rule"/></rules></result></response>'),
            ET.fromstring('<response status="success"><result><rules><entry name="SNAT-Outbound"/></rules></result></response>'),
            ET.fromstring('<response status="success"><result><interface>ethernet1/1</interface></result></response>')]
        out = LiveVerifier(client, p).verify(d.traces[0])
        self.assertEqual([f.code for f in out], ["LIVE_POLICY_MISMATCH"])
        self.assertIn("<from>trust</from>", client.op.call_args_list[0].args[0])


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(argv))
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_demo_runs_without_network(self):
        with mock.patch("requests.Session.post", side_effect=AssertionError("network used")):
            rc, out, _ = run("demo", "--color", "never")
        self.assertEqual(rc, 0)
        self.assertIn("14/14 Best-practice audit", out)
        self.assertIn("To make this flow work: zone + NAT rule + security rule", out)
        self.assertIn("VERDICT: BLOCKED", out)

    def test_diagnose_json_and_exit_code(self):
        args = ["diagnose", "--config", str(CFG), "--ip", "10.10.20.66", "--peer", "198.51.100.25", "--port", "443"]
        for f in LOG_FILES:
            args += ["--logs", str(f)]
        rc, out, _ = run(*args, "--json")
        self.assertEqual(rc, 2)
        data = json.loads(out)
        self.assertEqual(data["verdict"], "BLOCKED")
        self.assertTrue(data["fix_plans"][0]["steps"])
        self.assertTrue(data["verification_commands"][0]["groups"])
        with tempfile.TemporaryDirectory() as d:
            rc, _, err = run(*args, "--html", f"{d}/r.html", "--next-hop", "10.255.0.2")
            self.assertIn("HTML report written", err)
            self.assertTrue(Path(d, "r.html").read_text().startswith("<!doctype html>"))

    def test_matrix_and_audit_commands(self):
        rc, out, _ = run("matrix", "--config", str(CFG), "--src", "10.10.20.15", "--dst", "10.10.40.22", "--one-way")
        self.assertIn("PERMITTED", out)
        rc, out, _ = run("audit", "--config", str(CFG), "--rule", "Admins-to-Jumphost", "--json")
        self.assertEqual(rc, 2)
        self.assertIn("BP_APP_PORT_CONFLICT", {a["code"] for a in json.loads(out)})

    def test_brace_format_config(self):
        brace = """config {
  devices { localhost.localdomain {
    deviceconfig { system { hostname FW-B; } }
    network {
      interface { ethernet { ethernet1/1 { layer3 { ip { 192.0.2.2/24; } } } ethernet1/2 { layer3 { ip { 10.0.0.1/24; } } } } }
      virtual-router { default { interface [ ethernet1/1 ethernet1/2 ];
        routing-table { ip { static-route { dflt { destination 0.0.0.0/0; interface ethernet1/1;
          nexthop { ip-address 192.0.2.1; } } } } } } }
    }
    vsys { vsys1 {
      zone { inside { network { layer3 ethernet1/2; } } outside { network { layer3 ethernet1/1; } } }
      service { tcp-22 { protocol { tcp { port 22; } } } }
      rulebase { security { rules { ssh-out { from inside; to outside; source any; destination any;
        source-user any; application ssh; service tcp-22; action allow; } } } }
    } }
  } }
}"""
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "fw.conf"
            path.write_text(brace)
            p = load_policy(path)
        d = Troubleshooter(p).diagnose("10.0.0.5", "198.51.100.1", port=22, app="ssh")
        self.assertEqual(d.traces[0].security_rule, "ssh-out")
        self.assertEqual(d.traces[0].to_zone, "outside")


if __name__ == "__main__":
    unittest.main()
