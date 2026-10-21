"""End-to-end CLI behaviour on the demo inventory. Nothing contacts a device."""

import contextlib
import io
import json
import unittest
from unittest import mock

from core import cli


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(argv))
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_audit_exit_code_reflects_errors(self):
        rc, out, _ = run("audit", "--demo", "--color", "never")
        self.assertEqual(rc, 2)
        self.assertIn("ERROR 5", out)

    def test_plan_json_is_redacted(self):
        rc, out, _ = run("plan", "--demo", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(any(a["kind"] == "ike-gateway" for d in data for a in d["actions"]))
        self.assertNotIn("__PSK", out)

    def test_demo_runs_all_stages_without_network(self):
        with mock.patch("requests.Session.post", side_effect=AssertionError("network used")):
            rc, out, _ = run("demo", "--color", "never")
        self.assertEqual(rc, 0)
        for stage in ("1/3 audit", "2/3 plan", "3/3 apply"):
            self.assertIn(stage, out)
        self.assertIn("OFC-AUS-FW-01: REFUSED", out)
        self.assertIn("Dry run only: nothing was sent", out)

    def test_execute_refused_on_demo(self):
        rc, _, err = run("apply", "--demo", "--device", "OFC-BER-FW-01", "--execute")
        self.assertIn("refusing --execute with --demo", str(rc) + err)

    def test_execute_requires_explicit_device(self):
        with mock.patch("core.cli.load_context") as lc:
            from core import miniyaml
            from core.auditor import DEMO_INVENTORY
            from core.planner import demo_states
            inv = miniyaml.load(DEMO_INVENTORY)
            lc.return_value = {"inventory": inv, "states": demo_states(inv), "auditor": None, "source": "x"}
            rc, _, _ = run("apply", "--inventory", "inv.yaml", "--execute")
        self.assertIn("requires at least one explicit --device", str(rc))

    def test_execute_aborts_when_confirmation_mismatches(self):
        with mock.patch("core.cli.load_context") as lc, mock.patch("builtins.input", return_value="wrong"), \
                mock.patch("requests.Session.post", side_effect=AssertionError("network used")):
            from core import miniyaml
            from core.auditor import DEMO_INVENTORY
            from core.planner import demo_states
            inv = miniyaml.load(DEMO_INVENTORY)
            lc.return_value = {"inventory": inv, "states": demo_states(inv), "auditor": None, "source": "x"}
            rc, _, err = run("apply", "--inventory", "inv.yaml", "--device", "OFC-BER-FW-01", "--execute",
                             "--color", "never")
        self.assertEqual(rc, 2)
        self.assertIn("confirmation did not match; nothing sent", err)


if __name__ == "__main__":
    unittest.main()
