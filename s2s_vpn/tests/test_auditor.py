"""The demo inventory seeds 7 drift scenarios; the auditor must report each exactly once."""

import unittest

from s2s_vpn.auditor import DEMO_INVENTORY, Auditor, exit_code
from common.parser import brace_to_xml, strip_secrets

EXPECTED = {
    "D1 missing Phase 2 profile": ("CRYPTO_NO_IPSEC_PROFILE", "OFC-AUS-DC-EAST.Failover"),
    "D2 copy-pasted proxy-ID": ("PROXY_ID_MISMATCH", "DC-WEST <-> AWS-DC-SGP"),
    "D3 ISP swap": ("GW_ISP_SWAP", "OFC-BER"),
    "D4 HA pair out of sync": ("HA_OUT_OF_SYNC", "OFC-AUS"),
    "D5 local profile drift": ("CRYPTO_LOCAL_SHADOW", "AZ-CENTRAL"),
    "D6 reused tunnel /30": ("TUNNEL_IP_REUSED", "169.254.100.8/30"),
    "D7 one-sided gateway": ("GW_UNKNOWN_PEER", "DC-EAST-OFC-OLD"),
}


class TestDemoAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = Auditor.from_inventory(DEMO_INVENTORY).run()

    def test_each_scenario_found_exactly_once(self):
        for label, (code, subject) in EXPECTED.items():
            hits = [f for f in self.findings if f.code == code and subject in f.subject]
            self.assertEqual(len(hits), 1, f"{label}: {[(f.code, f.subject) for f in hits]}")

    def test_no_unexpected_problems(self):
        expected = {(c, s) for c, s in EXPECTED.values()}
        extra = [(f.severity, f.code, f.subject) for f in self.findings if f.severity != "INFO"
                 and not any(f.code == c and s in f.subject for c, s in expected)]
        self.assertEqual(extra, [])

    def test_isp_swap_names_the_device_to_fix(self):
        f = next(f for f in self.findings if f.code == "GW_ISP_SWAP")
        self.assertTrue(any("fix AZ-CENTRAL-FW-01" in d for d in f.details), f.details)

    def test_exit_code_signals_errors(self):
        self.assertEqual(exit_code(self.findings), 2)


class TestParserBrace(unittest.TestCase):
    SAMPLE = """config {
  devices {
    localhost.localdomain {
      network {
        ike {
          gateway {
            HUB-SPOKE {
              authentication { pre-shared-key { key -AQ==ZmFrZQ==; } }
              local-id { id 192.0.2.10; type ipaddr; }
              protocol { version ikev2; ikev2 { ike-crypto-profile STD-IKE; } }
            }
          }
        }
        interface { tunnel { units { tunnel.5 { ip { 169.254.0.1/30; } comment "HUB-SPOKE"; } } } }
        virtual-router { default { interface [ tunnel.5 ethernet1/1 ]; } }
      }
    }
  }
}"""

    def test_brace_conversion_and_secret_stripping(self):
        cfg = brace_to_xml(self.SAMPLE)
        self.assertEqual(strip_secrets(cfg), 1)
        dev = cfg.find("devices/entry")
        self.assertEqual(dev.get("name"), "localhost.localdomain")
        gw = dev.find("network/ike/gateway/entry")
        self.assertEqual(gw.get("name"), "HUB-SPOKE")
        self.assertIsNone(gw.find("authentication/pre-shared-key/key").text)
        self.assertEqual(dev.find("network/interface/tunnel/units/entry/ip/entry").get("name"), "169.254.0.1/30")
        self.assertEqual([m.text for m in dev.findall("network/virtual-router/entry/interface/member")],
                         ["tunnel.5", "ethernet1/1"])


if __name__ == "__main__":
    unittest.main()
