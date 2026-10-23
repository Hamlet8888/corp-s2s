"""Helpdesk summaries, friendly input parsing and the web server (offline, demo data, localhost only)."""

import argparse
import base64
import http.client
import json
import os
import threading
import unittest
from unittest import mock

from troubleshoot.cli import DEMO_DIR
from troubleshoot.engine import Troubleshooter
from troubleshoot.helpdesk import NETWORK_TEAM, SECURITY_TEAM, parse_destination, parse_device, summarize
from troubleshoot.logs import load_logs
from troubleshoot.policy import load_policy
from troubleshoot.web import make_server

CFG = DEMO_DIR / "branch-fw.xml"
LOGS = sorted(DEMO_DIR.glob("*-logs.*"))


def fake_resolver(host):
    return {"github.com": ["140.82.114.3", "140.82.114.4"], "laptop-1": ["10.10.20.15"]}.get(host, [])


class TestParsing(unittest.TestCase):
    def test_destinations(self):
        d = parse_destination("https://github.com/org/repo", resolver=fake_resolver)
        self.assertEqual((d.host, d.ip, d.port, d.protocol), ("github.com", "140.82.114.3", 443, "tcp"))
        self.assertIn("1 more", d.note)
        self.assertEqual(parse_destination("github.com:8443", resolver=fake_resolver).port, 8443)
        self.assertEqual(parse_destination("10.1.2.3").ip, "10.1.2.3")
        self.assertEqual(parse_destination("10.1.0.0/16").ip, "10.1.0.0/16")
        self.assertEqual(parse_destination("http://10.1.2.3/x").port, 80)
        with self.assertRaises(ValueError):
            parse_destination("nonexistent.invalid", resolver=fake_resolver)
        with self.assertRaises(ValueError):
            parse_destination("bad host<script>")

    def test_devices(self):
        self.assertEqual(parse_device("laptop-1", resolver=fake_resolver)[0], "10.10.20.15")
        self.assertEqual(parse_device("10.10.20.0/24")[0], "10.10.20.0/24")
        with self.assertRaises(ValueError):
            parse_device("not a host!")


class TestSummaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy(CFG)
        cls.logs = [e for p in LOGS for e in load_logs(p)]

    def answer(self, *args, logs=True, **kw):
        d = Troubleshooter(self.policy, self.logs if logs else []).diagnose(*args, **kw)
        return summarize(d, args[0], args[1] if len(args) > 1 else None, kw.get("port"), policy=self.policy)

    def test_url_block(self):
        a = self.answer("10.10.20.33", "198.51.100.77", port=443)
        self.assertEqual((a.status, a.escalate_to), ("blocked", NETWORK_TEAM))
        self.assertIn("gambling", a.headline)
        self.assertIn("casino.example.com", a.explanation)
        self.assertIn("Result: BLOCKED", a.ticket_text)

    def test_threat_goes_to_security(self):
        a = self.answer("10.10.20.15", "192.0.2.80", port=443)
        self.assertEqual((a.status, a.escalate_to), ("blocked", SECURITY_TEAM))
        self.assertIn("Log4j", a.explanation)

    def test_quarantine_goes_to_security(self):
        a = self.answer("10.10.20.66")
        self.assertEqual(a.escalate_to, SECURITY_TEAM)
        self.assertIn("INC-0042", a.explanation)
        self.assertIn("198.51.100.25", a.explanation)          # destination taken from the logs

    def test_no_access(self):
        a = self.answer("10.10.30.5", "10.10.40.10", port=1433, logs=False)
        self.assertEqual(a.headline, "No access has been granted")

    def test_network_problem(self):
        a = self.answer("10.10.20.15", "172.31.5.5", port=22, logs=False)
        self.assertEqual(a.headline, "Network setup problem")

    def test_allowed(self):
        a = self.answer("192.0.2.150", "203.0.113.10", port=443, direction="in", app="ssl", logs=False)
        self.assertEqual((a.status, a.escalate_to), ("allowed", None))

    def test_depends_on_app(self):
        a = self.answer("10.10.20.40", "198.51.100.9", port=443, logs=False)
        self.assertEqual(a.status, "check")

    def test_no_jargon_in_headlines(self):
        for args, kw in ((("10.10.20.33", "198.51.100.77"), {"port": 443}), (("10.10.30.5", "10.10.40.10"), {"port": 1433})):
            a = self.answer(*args, **kw)
            for word in ("interzone", "NAT", "zone", "PROFILE-BLOCK", "vsys"):
                self.assertNotIn(word, a.headline)


def serve_args(**kw):
    ns = argparse.Namespace(host=None, config=str(CFG), logs=[str(p) for p in LOGS], demo=True, vsys="vsys1",
                            username=None, serial=None, ca_bundle=None, insecure=False, listen="127.0.0.1", port=0,
                            tls_cert=None, tls_key=None, allow_plain_http=False, no_browser=True, inventory=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


class WebTestBase(unittest.TestCase):
    password = None

    @classmethod
    def setUpClass(cls):
        env = {"PT_WEB_PASSWORD": cls.password} if cls.password else {}
        with mock.patch.dict(os.environ, env, clear=False):
            if not cls.password:
                os.environ.pop("PT_WEB_PASSWORD", None)
            cls.srv = make_server(serve_args())
        cls.port = cls.srv.server_address[1]
        cls.quiet = mock.patch("sys.stderr", new_callable=lambda: open(os.devnull, "w"))
        cls.quiet.start()
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.quiet.stop()

    def req(self, method, path, body=None, headers=None, host="127.0.0.1"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": f"{host}:{self.port}"}
        h.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        c.close()
        return r, payload


class TestWebLocal(WebTestBase):
    def token(self):
        r, page = self.req("GET", "/")
        self.assertEqual(r.status, 200)
        self.assertIn("default-src 'self'", r.getheader("Content-Security-Policy"))
        return page.decode().split('name="pt-token" content="')[1].split('"')[0]

    def test_token_required(self):
        r, _ = self.req("GET", "/api/status")
        self.assertEqual(r.status, 403)
        r, body = self.req("GET", "/api/status", headers={"X-PT-Token": self.token()})
        self.assertEqual((r.status, json.loads(body)["mode"]), (200, "demo"))

    def test_foreign_host_rejected(self):          # DNS rebinding guard
        r, _ = self.req("GET", "/", host="attacker.example")
        self.assertEqual(r.status, 403)

    def test_check_and_report(self):
        t = self.token()
        r, body = self.req("POST", "/api/check", {"device": "10.10.20.33", "destination": "198.51.100.77", "port": "443"},
                           {"X-PT-Token": t})
        data = json.loads(body)
        self.assertEqual(r.status, 200, data)
        self.assertEqual(data["answer"]["status"], "blocked")
        r, html = self.req("GET", f"/api/report/{data['hops'][0]['report_id']}?t={t}")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Blocked by web filtering", html)
        self.assertIn("attachment", r.getheader("Content-Disposition"))

    def test_bad_input_is_a_clear_400(self):
        t = self.token()
        r, body = self.req("POST", "/api/check", {"device": "<script>", "destination": ""}, {"X-PT-Token": t})
        self.assertEqual(r.status, 400)
        self.assertIn("not a valid", json.loads(body)["error"])
        r, body = self.req("POST", "/api/check", {"device": "10.10.20.33", "app": "x'; rm -rf /"}, {"X-PT-Token": t})
        self.assertEqual(r.status, 400)

    def test_engineer_endpoints(self):
        t = {"X-PT-Token": self.token()}
        for path in ("/api/rules", "/api/profiles", "/api/audit"):
            r, body = self.req("GET", path, headers=t)
            self.assertEqual(r.status, 200, path)
        r, body = self.req("POST", "/api/logs", {"device": "10.10.20.66", "kind": "blocked"}, t)
        self.assertEqual(json.loads(body)["total"], 4)
        r, body = self.req("POST", "/api/matrix", {"source": "10.10.20.15", "destination": "10.10.40.0/24"}, t)
        self.assertEqual(len(json.loads(body)["matrices"]), 2)

    def test_static_and_favicon(self):
        self.assertEqual(self.req("GET", "/app.js")[0].status, 200)
        self.assertEqual(self.req("GET", "/favicon.ico")[0].status, 204)
        self.assertEqual(self.req("GET", "/../core/api.py")[0].status, 404)


class TestWebPassword(WebTestBase):
    password = "correct-horse-battery"

    def test_login_required(self):
        r, _ = self.req("GET", "/")
        self.assertEqual(r.status, 401)
        auth = "Basic " + base64.b64encode(b"helpdesk:" + self.password.encode()).decode()
        r, _ = self.req("GET", "/", headers={"Authorization": auth}, host="fwcheck.corp.example")
        self.assertEqual(r.status, 200)
        bad = "Basic " + base64.b64encode(b"helpdesk:wrong").decode()
        self.assertEqual(self.req("GET", "/", headers={"Authorization": bad})[0].status, 401)


class TestExposureRules(unittest.TestCase):
    def test_network_listen_needs_password_and_tls(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PT_WEB_PASSWORD", None)
            with self.assertRaises(SystemExit):
                make_server(serve_args(listen="0.0.0.0"))
        with mock.patch.dict(os.environ, {"PT_WEB_PASSWORD": "long-enough-password"}):
            with self.assertRaises(SystemExit):
                make_server(serve_args(listen="0.0.0.0"))          # no TLS and no --allow-plain-http
        with mock.patch.dict(os.environ, {"PT_WEB_PASSWORD": "short"}):
            with self.assertRaises(SystemExit):
                make_server(serve_args(listen="0.0.0.0", allow_plain_http=True))


if __name__ == "__main__":
    unittest.main()


class TestInventory(unittest.TestCase):
    def test_demo_inventory(self):
        from troubleshoot.inventory import load_inventory
        fws = load_inventory(DEMO_DIR / "firewalls.yaml")
        self.assertEqual([f.name for f in fws], ["BRANCH-FW-01", "HQ-FW-01", "LAB-TEST-FIREWALL"])
        self.assertTrue(fws[2].lab)
        self.assertTrue(fws[0].covers("10.10.20.15"))
        self.assertFalse(fws[1].covers("10.10.20.15"))

    def test_ha_peer_picks_the_active_member(self):
        import xml.etree.ElementTree as ET
        from troubleshoot.inventory import FirewallEntry
        from troubleshoot.web import Firewall

        def state_xml(state):
            return ET.fromstring(f"<response><result><enabled>yes</enabled><group><local-info>"
                                 f"<state>{state}</state></local-info></group></result></response>")

        def connect(states):
            """states: host -> HA state, or None for unreachable."""
            def make(host=None):
                if states[host] is None:
                    raise ConnectionError(f"{host} unreachable")
                return mock.Mock(op=mock.Mock(return_value=state_xml(states[host])), host=host)
            fw = Firewall(FirewallEntry("TKO-FW-01", host="10.18.10.11", ha_peer="10.18.10.12"), serve_args(demo=False))
            fw._make_client = make
            return fw._connect()[1]

        self.assertEqual(connect({"10.18.10.11": "active", "10.18.10.12": "passive"}), "10.18.10.11")
        self.assertEqual(connect({"10.18.10.11": "passive", "10.18.10.12": "active"}), "10.18.10.12")   # failed over
        self.assertEqual(connect({"10.18.10.11": None, "10.18.10.12": "active"}), "10.18.10.12")        # primary down
        self.assertEqual(connect({"10.18.10.11": "suspended", "10.18.10.12": None}), "10.18.10.11")    # only one answers
        with self.assertRaises(ConnectionError):
            connect({"10.18.10.11": None, "10.18.10.12": None})

    def test_ha_peer_round_trips_through_yaml(self):
        import tempfile
        from pathlib import Path
        from troubleshoot.inventory import FirewallEntry, InventoryError, load_inventory, to_yaml
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fw.yaml"
            p.write_text(to_yaml([FirewallEntry("TKO-FW-01", host="10.18.10.11", ha_peer="10.18.10.12")]))
            self.assertEqual(load_inventory(p)[0].ha_peer, "10.18.10.12")
            p.write_text("firewalls:\n  - {name: X, host: 10.1.1.1, ha_peer: 'bad host'}\n")
            with self.assertRaises(InventoryError):
                load_inventory(p)

    def test_ha_health(self):
        import xml.etree.ElementTree as ET
        from troubleshoot.ha import evaluate, parse_ha

        def ha(local="active", peer="passive", conn="up", ha1="up", ha2="up", sync="synchronized", mode="Active-Passive"):
            return parse_ha(ET.fromstring(
                f"<response status='success'><result><enabled>yes</enabled><group><mode>{mode}</mode>"
                f"<local-info><state>{local}</state><state-sync>Complete</state-sync></local-info>"
                f"<peer-info><conn-status>{conn}</conn-status><state>{peer}</state><mgmt-ip>10.14.10.5/24</mgmt-ip>"
                f"<conn-ha1><conn-status>{ha1}</conn-status></conn-ha1><conn-ha2><conn-status>{ha2}</conn-status></conn-ha2>"
                f"</peer-info><running-sync>{sync}</running-sync><running-sync-enabled>yes</running-sync-enabled>"
                f"</group></result></response>"))

        off = parse_ha(ET.fromstring("<response><result><enabled>no</enabled></result></response>"))
        self.assertEqual(ha().peer_ip, "10.14.10.5")
        self.assertEqual(evaluate("LVD", ha()).level, "ok")
        self.assertEqual(evaluate("LVD", ha(local="passive", peer="active")).level, "ok")
        self.assertEqual(evaluate("LVD", ha(local="active-primary", peer="active-secondary", mode="Active-Active")).level, "ok")
        self.assertEqual(evaluate("LVD", ha(sync="not synchronized")).level, "warn")
        self.assertEqual(evaluate("LVD", ha(ha2="down")).level, "warn")
        self.assertEqual(evaluate("LVD", ha(conn="down", peer="unknown")).level, "fail")
        self.assertEqual(evaluate("LVD", ha(peer="suspended")).level, "fail")
        self.assertIn("split brain", evaluate("LVD", ha(peer="active")).problems[0])
        self.assertEqual(evaluate("OHI-DC", off, expected=False).level, "standalone")
        self.assertEqual(evaluate("LVD", off, expected=True).level, "fail")
        self.assertEqual(evaluate("X", off).level, "warn")                       # not stated in the inventory

    def test_most_specific_network_wins(self):
        from troubleshoot.inventory import FirewallEntry
        branch = FirewallEntry("BLR-FW-01", host="10.9.10.2", networks=["10.9.0.0/16", "10.0.0.0/8"])
        lvd = FirewallEntry("LVD-FW-01", host="10.14.10.2", networks=["10.14.1.0/24"])
        self.assertEqual((branch.match_len("10.14.1.21"), lvd.match_len("10.14.1.21")), (8, 24))
        self.assertEqual(branch.match_len("192.168.1.1"), -1)

    def test_routes_to_other_sites_are_not_a_sites_own_network(self):
        from troubleshoot.inventory import drop_other_sites
        self.assertEqual(drop_other_sites(["10.9.0.0/16", "10.14.0.0/16"], ["10.14.10.2"]), ["10.9.0.0/16"])

    def test_site_prefix_from_management_ip(self):
        import tempfile
        from pathlib import Path
        from troubleshoot.inventory import from_configs
        xml = (DEMO_DIR / "branch-fw.xml").read_text().replace(
            "<hostname>BRANCH-FW-01</hostname>", "<hostname>LVD-FW-01</hostname><ip-address>10.14.10.2</ip-address>")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "lvd.xml").write_text(xml)
            self.assertEqual(from_configs(d, site_prefix=16)[0].networks, ["10.14.0.0/16"])

    def test_csv_and_validation(self):
        import tempfile
        from pathlib import Path
        from troubleshoot.inventory import InventoryError, load_inventory
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "fw.csv")
            p.write_text("name,host,site,networks,lab\nBLR-FW-01,10.9.10.2,\"Bangalore, India\",10.9.0.0/16,\n"
                         "LAB-TEST-FIREWALL,192.168.10.200,Lab,,yes\n")
            fws = load_inventory(p)
            self.assertEqual((fws[0].host, fws[0].site, fws[1].lab), ("10.9.10.2", "Bangalore, India", True))
            p.write_text("name,host\nBLR-FW-01,10.9.10.2\nblr-fw-01,10.9.10.3\n")
            with self.assertRaises(InventoryError):
                load_inventory(p)                       # duplicate names
            p.write_text("name,host\nX,bad host;rm\n")
            with self.assertRaises(InventoryError):
                load_inventory(p)

    def test_generate_from_configs_round_trip(self):
        import tempfile
        from pathlib import Path
        from troubleshoot.inventory import from_configs, load_inventory, to_yaml
        entries = from_configs(DEMO_DIR, "FW-01$")
        self.assertEqual([e.name for e in entries], ["BRANCH-FW-01", "HQ-FW-01"])
        self.assertIn("10.10.20.0/24", entries[0].networks)
        self.assertNotIn("10.255.0.0/30", entries[0].networks)    # point-to-point links left out
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "inv.yaml")
            p.write_text(to_yaml(entries))
            self.assertEqual([e.name for e in load_inventory(p)], ["BRANCH-FW-01", "HQ-FW-01"])

    def test_management_ip_is_taken_from_the_config(self):
        import tempfile
        from pathlib import Path
        from troubleshoot.inventory import from_configs
        xml = (DEMO_DIR / "branch-fw.xml").read_text().replace(
            "<hostname>BRANCH-FW-01</hostname>", "<hostname>BLR-FW-01</hostname><ip-address>10.9.10.2</ip-address>")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "blr.xml").write_text(xml)
            e = from_configs(d)[0]
        self.assertEqual((e.name, e.host, e.config), ("BLR-FW-01", "10.9.10.2", None))


class TestWebInventory(WebTestBase):
    @classmethod
    def setUpClass(cls):
        os.environ.pop("PT_WEB_PASSWORD", None)
        cls.srv = make_server(serve_args(inventory=str(DEMO_DIR / "firewalls.yaml")))
        cls.port = cls.srv.server_address[1]
        cls.quiet = mock.patch("sys.stderr", new_callable=lambda: open(os.devnull, "w"))
        cls.quiet.start()
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    def token(self):
        page = self.req("GET", "/")[1].decode()
        return {"X-PT-Token": page.split('name="pt-token" content="')[1].split('"')[0]}

    def test_list_lazy_and_default_skips_lab(self):
        t = self.token()
        data = json.loads(self.req("GET", "/api/firewalls", headers=t)[1])
        self.assertEqual(data["default"], "BRANCH-FW-01")
        branch = next(f for f in data["firewalls"] if f["name"] == "BRANCH-FW-01")
        self.assertFalse(branch["loaded"])            # no test picks it, so it was never read
        self.assertTrue(next(f for f in data["firewalls"] if f["name"] == "LAB-TEST-FIREWALL")["lab"])

    def test_ha_page_offline(self):
        data = json.loads(self.req("GET", "/api/ha", headers=self.token())[1])
        self.assertEqual(len(data["firewalls"]), 3)
        self.assertTrue(all(f["level"] == "unknown" for f in data["firewalls"]))   # config files: no live HA state
        self.assertEqual(data["firewalls"][-1]["firewall"], "LAB-TEST-FIREWALL")   # lab last
        self.assertEqual(data["command"], "show high-availability all")

    def check(self, **params):
        r, body = self.req("POST", "/api/check", params, self.token())
        data = json.loads(body)
        self.assertEqual(r.status, 200, data)
        return data

    def test_firewall_picked_from_the_device_ip(self):
        data = self.check(device="10.20.20.5", destination="198.51.100.9", port="443")
        self.assertEqual([h["name"] for h in data["hops"]], ["HQ-FW-01"])
        self.assertIn("10.20.20.5 is in HQ-FW-01", data["notes"][0])
        r, body = self.req("POST", "/api/check", {"device": "172.30.1.1", "destination": "198.51.100.9"}, self.token())
        self.assertEqual(r.status, 400)
        self.assertIn("isn't in any site", json.loads(body)["error"])

    def test_path_between_two_sites(self):
        data = self.check(device="10.10.20.15", destination="10.20.40.10", port="443", app="ssl")
        self.assertEqual([(h["name"], h["role"]) for h in data["hops"]],
                         [("BRANCH-FW-01", "source side"), ("HQ-FW-01", "destination side")])
        self.assertEqual([p["status"] for p in data["path"]], ["allowed", "blocked"])
        self.assertTrue(data["answer"]["headline"].startswith("Blocked at HQ-FW-01"))
        self.assertIn("BRANCH-FW-01", data["answer"]["explanation"])            # "... lets it through"
        self.assertIn("Path: BRANCH-FW-01", data["answer"]["ticket_text"])

    def test_east_west_inside_a_nexus_site_skips_the_firewall(self):
        data = self.check(device="10.20.20.5", destination="10.20.40.10", port="443")
        self.assertEqual((data["hops"], data["bypass"]["reason"]), ([], "east-west"))
        self.assertIn("Cisco Nexus", data["answer"]["headline"])
        data = self.check(device="10.20.20.5", destination="10.20.50.10", port="443")   # DMZ: behind the firewall
        self.assertEqual([h["name"] for h in data["hops"]], ["HQ-FW-01"])

    def test_same_subnet_skips_the_firewall(self):
        data = self.check(fw="BRANCH-FW-01", device="10.10.20.15", destination="10.10.20.99", port="445")
        self.assertEqual(data["bypass"]["reason"], "same-subnet")

    def test_manual_pick_overrides(self):
        t = self.token()
        r, body = self.req("POST", "/api/check", {"fw": "HQ-FW-01", "device": "10.10.20.15",
                                                 "destination": "198.51.100.9", "port": "443"}, t)
        data = json.loads(body)
        self.assertEqual((r.status, [h["name"] for h in data["hops"]]), (200, ["HQ-FW-01"]))
        self.assertEqual(json.loads(self.req("GET", "/api/status?fw=HQ-FW-01", headers=t)[1])["hostname"], "HQ-FW-01")
        r, body = self.req("POST", "/api/check", {"fw": "NOPE", "device": "10.20.20.5"}, t)
        self.assertEqual(r.status, 400)

    def test_lab_firewall_is_flagged_in_results(self):
        t = self.token()
        r, body = self.req("POST", "/api/check", {"fw": "LAB-TEST-FIREWALL", "device": "10.10.20.66"}, t)
        self.assertIn("TEST/LAB", json.loads(body)["hops"][0]["notes"][0])

    def test_locate(self):
        t = self.token()
        data = json.loads(self.req("POST", "/api/locate", {"device": "10.20.30.7"}, t)[1])
        self.assertEqual([m["name"] for m in data["matches"] if not m["lab"]], ["HQ-FW-01"])
