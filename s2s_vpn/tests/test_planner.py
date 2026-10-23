"""Planner behaviour on the fictional demo inventory."""

import ipaddress
import unittest
import xml.etree.ElementTree as ET

from common import miniyaml
from s2s_vpn.auditor import DEMO_INVENTORY
from s2s_vpn.planner import DeviceState, PlanError, TunnelPlanner, demo_states


def _plan(blocked=None, inv=None):
    inv = inv or miniyaml.load(DEMO_INVENTORY)
    p = TunnelPlanner(inv)
    plans = p.build_device_plans(demo_states(inv), blocked=blocked)
    return p, plans


def _find(plans, device, kind, name):
    return next((a for a in plans.get(device, []) if a.kind == kind and a.name == name), None)


class TestDemoPlan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.planner, cls.plans = _plan(blocked={"OFC-AUS": ["HA out of sync"]})

    def test_fixes_seeded_drift_as_updates(self):
        d1 = _find(self.plans, "OFC-AUS-FW-01", "ipsec-tunnel", "OFC-AUS-DC-EAST.Failover")
        self.assertEqual((d1.op, d1.api_action), ("update", "edit"))
        self.assertIn("ipsec_profile", d1.changes[0])
        d2 = _find(self.plans, "AWS-DC-SGP-FW-01", "ipsec-tunnel", "AWS-DC-SGP-DC-WEST")
        self.assertIn("10.60.0.0/16->10.20.0.0/16", d2.changes[0])
        d3 = _find(self.plans, "AZ-CENTRAL-FW-01", "ike-gateway", "AZ-CENTRAL-OFC-BER")
        self.assertEqual(d3.changes, ["peer_id: 198.51.100.50 -> 192.0.2.50"])

    def test_new_link_rendered_symmetrically_on_both_ends(self):
        a = _find(self.plans, "OFC-AUS-FW-01", "ike-gateway", "OFC-AUS-AWS-WS-OSL")
        b = _find(self.plans, "AWS-WS-OSL-FW-01", "ike-gateway", "AWS-WS-OSL-OFC-AUS")
        ea, eb = ET.fromstring(f"<r>{a.element}</r>"), ET.fromstring(f"<r>{b.element}</r>")
        self.assertEqual(ea.findtext("local-id/id"), eb.findtext("peer-id/id"))
        self.assertEqual(ea.findtext("peer-id/id"), eb.findtext("local-id/id"))
        self.assertEqual(ea.findtext("peer-address/ip"), eb.findtext("local-id/id"))
        ta = _find(self.plans, "OFC-AUS-FW-01", "ipsec-tunnel", "OFC-AUS-AWS-WS-OSL")
        tb = _find(self.plans, "AWS-WS-OSL-FW-01", "ipsec-tunnel", "AWS-WS-OSL-OFC-AUS")
        pa = {(e.findtext("local"), e.findtext("remote")) for e in ET.fromstring(f"<r>{ta.element}</r>").iter("entry") if e.find("local") is not None}
        pb = {(e.findtext("remote"), e.findtext("local")) for e in ET.fromstring(f"<r>{tb.element}</r>").iter("entry") if e.find("local") is not None}
        self.assertEqual(pa, pb)

    def test_new_tunnel_ips_share_a_fresh_30(self):
        ia = _find(self.plans, "OFC-AUS-FW-01", "tunnel-interface", "tunnel.7")
        ib = _find(self.plans, "AWS-WS-OSL-FW-01", "tunnel-interface", "tunnel.3")
        ipa = ET.fromstring(f"<r>{ia.element}</r>").find("ip/entry").get("name")
        ipb = ET.fromstring(f"<r>{ib.element}</r>").find("ip/entry").get("name")
        na, nb = ipaddress.ip_interface(ipa).network, ipaddress.ip_interface(ipb).network
        self.assertEqual(na, nb)
        self.assertNotEqual(ipa, ipb)
        used = {ipaddress.ip_interface(t["tunnel_ip"]).network
                for d in miniyaml.load(DEMO_INVENTORY)["observed"]["devices"].values()
                for t in d["tunnels"] if t.get("tunnel_ip")}
        self.assertNotIn(na, used)

    def test_new_units_avoid_existing_ones(self):
        units = [a.name for a in self.plans["OFC-AUS-FW-01"] if a.kind == "tunnel-interface"]
        self.assertEqual(units, ["tunnel.7", "tunnel.8"])   # tunnel.1-6 are in use

    def test_psk_is_placeholder_and_redacted(self):
        gw = _find(self.plans, "OFC-AUS-FW-01", "ike-gateway", "OFC-AUS-AWS-WS-OSL")
        self.assertIn("__PSK:OFC-AUS_AWS-WS-OSL_primary__", gw.element)
        self.assertNotIn("__PSK", gw.redacted_element())

    def test_never_deletes_and_reports_unmanaged(self):
        ops = {a.op for acts in self.plans.values() for a in acts}
        self.assertTrue(ops <= {"create", "update"})
        self.assertIn("ike-gateway DC-EAST-OFC-OLD", self.planner.device_plans["DC-EAST-FW-01"].unmanaged)

    def test_blocked_site_is_flagged(self):
        self.assertEqual(self.planner.device_plans["OFC-AUS-FW-01"].blocked, ["HA out of sync"])

    def test_apply_order(self):
        kinds = [a.kind for a in self.plans["DC-EAST-FW-01"]]
        order = ["tunnel-interface", "zone-member", "vr-member", "ike-gateway", "ipsec-tunnel", "static-route"]
        self.assertEqual(kinds, sorted(kinds, key=order.index))

    def test_idempotent_against_its_own_output(self):
        """A device that already has everything the plan creates yields no changes."""
        inv = miniyaml.load(DEMO_INVENTORY)
        inv["links"] = [{"a": "DC-EAST", "b": "DC-WEST", "paths": [{"role": "primary", "a": "isp1", "b": "isp1"}]}]
        p = TunnelPlanner(inv)
        plans = p.build_device_plans({})
        self.assertTrue(plans)
        states = {}
        for dev, acts in plans.items():
            st = DeviceState(hostname=dev, known_kinds=set())
            for a in acts:
                if a.kind == "ike-gateway":
                    e = ET.fromstring(f"<r>{a.element}</r>")
                    st.gateways[a.name] = {"local_id": e.findtext("local-id/id"), "peer_id": e.findtext("peer-id/id"),
                                           "ike_profile": e.findtext("protocol/ikev2/ike-crypto-profile")}
                elif a.kind == "ipsec-tunnel":
                    e = ET.fromstring(f"<r>{a.element}</r>")
                    st.tunnels[a.name] = {"interface": e.findtext("tunnel-interface"), "gateway": a.name,
                                          "ipsec_profile": e.findtext("auto-key/ipsec-crypto-profile"),
                                          "proxy_ids": frozenset((x.findtext("local"), x.findtext("remote"))
                                                                 for x in e.iter("entry") if x.find("local") is not None)}
                elif a.kind == "tunnel-interface":
                    e = ET.fromstring(f"<r>{a.element}</r>")
                    st.tunnel_ifs[a.name] = {"ip": e.find("ip/entry").get("name")}
            states[dev] = st
        self.assertEqual(TunnelPlanner(inv).build_device_plans(states), {})

    def test_unknown_site_rejected(self):
        inv = miniyaml.load(DEMO_INVENTORY)
        inv["links"].append({"a": "DC-EAST", "b": "NOPE", "paths": [{"role": "primary", "a": "isp1", "b": "isp1"}]})
        with self.assertRaises(PlanError):
            TunnelPlanner(inv).build_device_plans({})


if __name__ == "__main__":
    unittest.main()
