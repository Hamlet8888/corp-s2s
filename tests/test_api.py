"""Offline tests for core.api. A fake session replays canned PAN-OS responses, so no device is needed."""

import io
import logging
import os
import stat
import tempfile
import unittest
from unittest import mock

import requests

from core import api
from core.api import (PanosApiClient, PanosAuthError, PanosCommitError, PanosLockError,
                      PanosResponseError, PanosSafetyError, PanosTimeoutError, entry_xpath, template_root)

FAKE_KEY = "LUFRPT1FAKEKEYfakekeyFAKEKEY0123456789=="
HOST = "fw01.example.net"


class FakeResponse:
    def __init__(self, body, status=200):
        self.content = body.encode() if isinstance(body, str) else body
        self.status_code = status


class FakeSession:
    """Records each POST and returns queued responses (or raises queued exceptions)."""

    def __init__(self, *responses):
        self.queue = list(responses)
        self.calls = []

    def post(self, url, data=None, headers=None, verify=None, timeout=None):
        self.calls.append({"url": url, "data": dict(data or {}), "headers": dict(headers or {})})
        item = self.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok(result=""):
    return FakeResponse(f'<response status="success"><result>{result}</result></response>')


def err(msg, code="1"):
    return FakeResponse(f'<response status="error" code="{code}"><msg><line>{msg}</line></msg></response>')


def client(*responses, **kw):
    s = FakeSession(*responses)
    return PanosApiClient(HOST, api_key=FAKE_KEY, session=s, **kw), s


@mock.patch("core.api.time.sleep", lambda *_: None)
class TestTransport(unittest.TestCase):
    def test_key_only_in_header_never_in_body_or_url(self):
        c, s = client(ok("<system><hostname>FW01</hostname></system>"))
        self.assertEqual(c.system_info()["hostname"], "FW01")
        call = s.calls[0]
        self.assertEqual(call["headers"]["X-PAN-KEY"], FAKE_KEY)
        self.assertNotIn(FAKE_KEY, repr(call["data"]))
        self.assertNotIn(FAKE_KEY, call["url"])
        self.assertNotIn("key", call["data"])

    def test_repr_masks_key(self):
        c, _ = client()
        self.assertNotIn(FAKE_KEY, repr(c))
        self.assertIn("key=set", repr(c))

    def test_key_from_host_specific_env(self):
        with mock.patch.dict(os.environ, {"PANOS_API_KEY_FW01_EXAMPLE_NET": FAKE_KEY}, clear=False):
            c = PanosApiClient(HOST, session=FakeSession())
        self.assertTrue(c.has_key)

    def test_no_key_raises_auth_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            c = PanosApiClient(HOST, session=FakeSession())
        with self.assertRaises(PanosAuthError):
            c.system_info()

    def test_keygen_keeps_key_private(self):
        s = FakeSession(FakeResponse(f'<response status="success"><result><key>{FAKE_KEY}</key></result></response>'))
        c = PanosApiClient(HOST, session=s)
        c.generate_key("svc-automation", "S3cret-Pass!")
        self.assertTrue(c.has_key)
        self.assertEqual(s.calls[0]["data"]["type"], "keygen")
        self.assertNotIn("X-PAN-KEY", s.calls[0]["headers"])

    def test_error_mapping(self):
        c, _ = client(err("Invalid credentials.", code="403"))
        with self.assertRaises(PanosAuthError):
            c.system_info()
        c, _ = client(FakeResponse("forbidden", status=403))
        with self.assertRaises(PanosAuthError):
            c.system_info()
        c, _ = client(err("Config for scope shared is currently locked by admin2"))
        with self.assertRaises(PanosLockError):
            c.config_get("/config/shared")
        c, _ = client(FakeResponse("<response status='success'><result>"))
        with self.assertRaises(PanosResponseError):
            c.system_info()
        c, _ = client(err("No such node", code="7"))
        with self.assertRaises(PanosResponseError) as cm:
            c.config_get("/config/shared/address")
        self.assertEqual(cm.exception.code, "7")

    def test_reads_retry_then_timeout(self):
        c, s = client(requests.exceptions.Timeout(), requests.exceptions.Timeout(), requests.exceptions.Timeout(),
                      retries=2)
        with self.assertRaises(PanosTimeoutError):
            c.system_info()
        self.assertEqual(len(s.calls), 3)

    def test_reads_recover_after_connection_error(self):
        c, s = client(requests.exceptions.ConnectionError(), ok("<system><hostname>FW01</hostname></system>"))
        self.assertEqual(c.system_info()["hostname"], "FW01")
        self.assertEqual(len(s.calls), 2)

    def test_writes_are_never_retried(self):
        c, s = client(requests.exceptions.ConnectionError(), ok(), allow_writes=True)
        with self.assertRaises(api.PanosConnectionError):
            c.set(api.FW_NETWORK + "/interface/tunnel/units", "<entry name='tunnel.5'/>")
        self.assertEqual(len(s.calls), 1)


@mock.patch("core.api.time.sleep", lambda *_: None)
class TestWriteSafety(unittest.TestCase):
    GW = ("<entry name='A-B'><authentication><pre-shared-key><key>TopSecretPSK</key></pre-shared-key>"
          "</authentication><peer-address><ip>192.0.2.1</ip></peer-address></entry>")

    def test_read_only_client_refuses_writes(self):
        c, s = client()
        for fn in (lambda: c.set(api.FW_NETWORK + "/ike/gateway", self.GW),
                   lambda: c.edit(api.FW_NETWORK + "/ike/gateway/entry[@name='A-B']", self.GW),
                   lambda: c.delete(api.FW_NETWORK + "/ike/gateway/entry[@name='A-B']"),
                   lambda: c.commit("x")):
            with self.assertRaises(PanosSafetyError):
                fn()
        self.assertEqual(s.calls, [])

    def test_dry_run_records_redacted_journal_and_sends_nothing(self):
        c, s = client(dry_run=True)
        c.set(api.FW_NETWORK + "/ike/gateway", self.GW)
        self.assertIsNone(c.commit("demo"))
        self.assertEqual(s.calls, [])
        self.assertEqual([j.action for j in c.journal], ["set", "commit"])
        self.assertNotIn("TopSecretPSK", c.journal[0].element)
        self.assertIn("redacted", c.journal[0].element)
        self.assertIn("192.0.2.1", c.journal[0].element)

    def test_unsafe_xpath_and_names_rejected(self):
        c, _ = client(allow_writes=True)
        for bad in ("/config/devices/entry[@name='x' or 1=1]", "//entry", "/config/../x", "config/shared",
                    "/config/devices/entry[@name=\"x\"]"):
            with self.assertRaises(PanosSafetyError, msg=bad):
                c.config_get(bad)
        with self.assertRaises(PanosSafetyError):
            entry_xpath("devices", ("entry", "x' or '1'='1"))

    def test_malformed_element_rejected_before_sending(self):
        c, s = client(allow_writes=True)
        with self.assertRaises(PanosSafetyError):
            c.set(api.FW_NETWORK + "/ike/gateway", "<entry name='x'>")
        self.assertEqual(s.calls, [])

    def test_xpath_helpers(self):
        self.assertEqual(entry_xpath("devices", ("entry", "localhost.localdomain"), "network"), api.FW_NETWORK)
        self.assertTrue(template_root("Firewalls").endswith("/template/entry[@name='Firewalls']/config/devices/"
                                                            "entry[@name='localhost.localdomain']"))


@mock.patch("core.api.time.sleep", lambda *_: None)
class TestCommit(unittest.TestCase):
    def _job(self, status, result, lines=""):
        return ok(f"<job><id>42</id><type>Commit</type><status>{status}</status><result>{result}</result>"
                  f"<progress>{'100' if status == 'FIN' else '55'}</progress><details>{lines}</details></job>")

    def test_commit_polls_until_fin_ok(self):
        c, s = client(ok("<msg><line>Commit job enqueued</line></msg><job>42</job>"),
                      self._job("ACT", "PEND"), self._job("FIN", "OK", "<line>Configuration committed successfully</line>"),
                      allow_writes=True)
        job = c.commit("corp-s2s: add DC-EAST-OFC-AUS")
        self.assertTrue(job.ok)
        self.assertEqual(s.calls[0]["data"]["type"], "commit")
        self.assertIn("<description>corp-s2s: add DC-EAST-OFC-AUS</description>", s.calls[0]["data"]["cmd"])

    def test_commit_failure_raises_with_details(self):
        c, _ = client(ok("<job>42</job>"),
                      self._job("FIN", "FAIL", "<line>tunnel.5 is not a valid reference</line>"), allow_writes=True)
        with self.assertRaises(PanosCommitError) as cm:
            c.commit("x")
        self.assertIn("tunnel.5 is not a valid reference", str(cm.exception))
        self.assertFalse(cm.exception.job.ok)

    def test_commit_no_changes(self):
        c, _ = client(FakeResponse('<response status="success" code="19"><msg>There are no changes to commit.</msg></response>'),
                      allow_writes=True)
        self.assertIsNone(c.commit("x"))

    def test_partial_commit_escapes_admin(self):
        c, s = client(ok("<job>1</job>"), self._job("FIN", "OK"), allow_writes=True)
        c.commit("x", admins=["svc<auto>"])
        self.assertIn("<member>svc&lt;auto&gt;</member>", s.calls[0]["data"]["cmd"])

    def test_job_timeout(self):
        c, _ = client(ok("<job>42</job>"), *[self._job("ACT", "PEND") for _ in range(5)], allow_writes=True)
        with mock.patch("core.api.time.monotonic", side_effect=[0, 0, 1000]):
            with self.assertRaises(PanosTimeoutError):
                c.commit("x", timeout=10)


class TestReadHelpers(unittest.TestCase):
    def test_export_backup_is_owner_only(self):
        cfg = '<config version="11.2.0"><devices/></config>'
        c, s = client(FakeResponse(cfg))
        with tempfile.TemporaryDirectory() as d:
            p = c.export_config(os.path.join(d, "backups"), label="pre change")
            self.assertTrue(p.name.startswith("fw01.example.net_") and p.name.endswith("_pre_change.xml"))
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(p.read_text(), cfg)
        self.assertEqual(s.calls[0]["data"], {"type": "export", "category": "configuration"})

    def test_ha_state(self):
        c, _ = client(ok("<enabled>yes</enabled><group><local-info><state>active</state></local-info>"
                         "<peer-info><state>passive</state></peer-info><running-sync>synchronized</running-sync>"
                         "<running-sync-enabled>yes</running-sync-enabled></group>"))
        ha = c.ha_state()
        self.assertEqual((ha.local_state, ha.peer_state), ("active", "passive"))
        self.assertTrue(ha.in_sync)
        c, _ = client(ok("<enabled>yes</enabled><group><running-sync>not synchronized</running-sync></group>"))
        self.assertFalse(c.ha_state().in_sync)

    def test_locks(self):
        c, _ = client(ok("<config-locks><entry name='admin2'><type>config</type></entry></config-locks>"),
                      ok("<commit-locks/>"))
        self.assertEqual(c.locks(), {"config": ["admin2"], "commit": []})


class TestLogRedaction(unittest.TestCase):
    def test_secrets_never_reach_log_output(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        api.log.addHandler(handler)
        api.log.setLevel(logging.DEBUG)
        try:
            s = FakeSession(FakeResponse(f'<response status="success"><result><key>{FAKE_KEY}</key></result></response>'),
                            ok("<system/>"))
            c = PanosApiClient(HOST, session=s)
            c.generate_key("svc", "Pa55word-XYZ")
            c.system_info()
            api.log.info("debug dump: key=%s password=%s X-PAN-KEY: %s <key>-AQ==abc123=</key>",
                         FAKE_KEY, "Pa55word-XYZ", FAKE_KEY)
        finally:
            api.log.removeHandler(handler)
        out = stream.getvalue()
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("Pa55word-XYZ", out)
        self.assertNotIn("-AQ==abc123", out)
        self.assertIn("<redacted>", out)


if __name__ == "__main__":
    unittest.main()
