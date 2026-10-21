"""
corp-s2s CLI orchestrator: audit, plan and apply PAN-OS site-to-site VPN tunnels.

    corp-s2s demo                                          # audit + plan + dry-run apply on fictional data
    corp-s2s audit --demo
    corp-s2s plan  --demo [--xml]
    corp-s2s apply --demo                                  # dry-run walk-through, sends nothing

    corp-s2s audit --exports DIR [--panorama FILE] [--inventory inventory/sites.yaml]
    corp-s2s plan  --inventory inventory/sites.yaml --exports DIR
    corp-s2s apply --inventory inventory/sites.yaml --exports DIR --device HOST [--device HOST] --execute

(``python3 vpn_manager.py ...`` and ``python3 -m core.cli ...`` are equivalent.)

``apply`` without ``--execute`` is a dry run: it shows exactly which API calls
would be made, with secrets redacted, and contacts nothing. ``--execute``
talks to live firewalls and enforces these gates, in order, for each device:

 1. The device was named explicitly with ``--device``. There is no fleet-wide apply.
 2. The auditor reports no HA_OUT_OF_SYNC for its site.
 3. The operator types the device hostname to confirm.
 4. Live pre-flight: the hostname matches, the HA pair is in sync, this member
    is active, no other admin holds a config or commit lock, and there are no
    pending uncommitted changes.
 5. A pre-change backup is exported to ``backups/`` (mode 0600).
 6. The backup is re-parsed and the plan recomputed. If the device changed
    since the plan was reviewed, apply aborts.
 7. The tool takes the config lock, sends the changes in dependency order and commits.
    On any error it reverts the candidate config and releases the lock.
 8. It triggers IKE/IPsec negotiation and reports each tunnel's SA state.

PSKs are read at apply time from ``PSK_<A>_<B>_<ROLE>`` environment variables
(for example ``PSK_DC_EAST_OFC_AUS_PRIMARY``) or an interactive prompt. They
are never written to disk or printed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import warnings
from pathlib import Path
from typing import Dict, List, Optional

# macOS system Python links LibreSSL; urllib3 warns about it on import. It is harmless for us.
warnings.filterwarnings("ignore", message=r"urllib3 v2 only supports OpenSSL")

from . import __version__, miniyaml  # noqa: E402
from .api import PanosApiClient, PanosApiError  # noqa: E402
from .auditor import DEMO_INVENTORY, Auditor, exit_code, format_report  # noqa: E402
from .parser import parse_directory, parse_firewall  # noqa: E402
from .planner import (PSK_PLACEHOLDER, DeviceState, PlanAction, TunnelPlanner, demo_states,  # noqa: E402
                      format_plan, plan_to_json)

ROOT = Path.cwd()
BACKUPS = Path(os.environ.get("CORP_S2S_BACKUPS", ROOT / "backups"))


def _color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_context(args) -> dict:
    """Return the inventory, current device states and audit findings for this run."""
    if args.demo:
        inv = miniyaml.load(DEMO_INVENTORY)
        return {"inventory": inv, "states": demo_states(inv),
                "auditor": Auditor.from_inventory(DEMO_INVENTORY), "source": f"demo: {DEMO_INVENTORY.name}"}
    inv = miniyaml.load(args.inventory) if getattr(args, "inventory", None) else {}
    states: Dict[str, DeviceState] = {}
    auditor = None
    if getattr(args, "exports", None):
        fws, _, errors = parse_directory(args.exports, getattr(args, "pattern", "*"))
        for f, e in errors:
            print(f"warning: could not parse {f}: {e}", file=sys.stderr)
        states = {h: DeviceState.from_firewall(fw) for h, fw in fws.items()}
        auditor = Auditor.from_exports(args.exports, panorama=getattr(args, "panorama", None),
                                       inventory=getattr(args, "inventory", None),
                                       pattern=getattr(args, "pattern", "*"))
    return {"inventory": inv, "states": states, "auditor": auditor, "source": str(args.exports or args.inventory)}


def ha_blockers(findings) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for f in findings:
        if f.code == "HA_OUT_OF_SYNC":
            out.setdefault(f.subject, []).append("HA members out of sync (see audit HA_OUT_OF_SYNC)")
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_audit(args) -> int:
    ctx = load_context(args)
    if ctx["auditor"] is None:
        sys.exit("audit needs --demo or --exports DIR")
    findings = ctx["auditor"].run()
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=1))
    else:
        print(format_report(findings, ctx["source"], color=_color(args.color), min_severity=args.min_severity))
    return exit_code(findings)


def _build_plan(ctx):
    findings = ctx["auditor"].run() if ctx["auditor"] else []
    planner = TunnelPlanner(ctx["inventory"])
    planner.build_device_plans(ctx["states"], blocked=ha_blockers(findings))
    return planner


def cmd_plan(args) -> int:
    ctx = load_context(args)
    if not ctx["inventory"].get("links"):
        sys.exit("plan needs --demo or --inventory with links")
    planner = _build_plan(ctx)
    if args.json:
        print(json.dumps(plan_to_json(planner), indent=1, default=sorted))
    else:
        print(format_plan(planner, color=_color(args.color), show_xml=args.xml))
    return 0


def cmd_apply(args) -> int:
    ctx = load_context(args)
    if not ctx["inventory"].get("links"):
        sys.exit("apply needs --demo or --inventory with links")
    planner = _build_plan(ctx)
    plans = {d: p for d, p in planner.device_plans.items() if p.actions}
    targets = args.device or (sorted(plans) if not args.execute else [])
    if args.execute:
        if args.demo:
            sys.exit("refusing --execute with --demo: the demo inventory is fictional")
        if not args.device:
            sys.exit("--execute requires at least one explicit --device HOST (no fleet-wide apply)")
    unknown = [d for d in targets if d not in planner.device_plans]
    if unknown:
        sys.exit(f"no plan for device(s): {', '.join(unknown)}")

    print(format_plan(planner, color=_color(args.color)))
    rc = 0
    for dev in targets:
        dp = planner.device_plans[dev]
        if not dp.actions:
            print(f"{dev}: nothing to do")
            continue
        if dp.blocked:
            print(f"{dev}: REFUSED: " + "; ".join(dp.blocked))
            rc = 2
            continue
        if not args.execute:
            _dry_run(dev, dp.actions)
            continue
        try:
            _execute(dev, dp, ctx, args)
        except (PanosApiError, ApplyAbort) as exc:
            print(f"{dev}: APPLY FAILED: {exc}", file=sys.stderr)
            rc = 2
            break                      # stop at the first failure; never continue to the far end
    if not args.execute:
        print("\nDry run only: nothing was sent. Re-run with --inventory/--exports, --device HOST and --execute "
              "to push after review.")
    return rc


class ApplyAbort(Exception):
    pass


def _dry_run(dev: str, actions: List[PlanAction]) -> None:
    client = PanosApiClient(dev, api_key="dry-run", dry_run=True)
    for a in actions:
        getattr(client, a.api_action)(a.xpath, a.element)
    client.commit(f"corp-s2s: {len(actions)} change(s)")
    print(f"--- {dev}: {len(client.journal)} API call(s) that --execute would send")
    for j in client.journal:
        print(f"    {j.action:<6} {j.xpath or ''}")
        if j.element:
            print(f"           {j.element[:220]}{'...' if len(j.element) > 220 else ''}")


def _resolve_psk(link_id: str) -> str:
    env = "PSK_" + re.sub(r"[^A-Za-z0-9]", "_", link_id).upper()
    val = os.environ.get(env)
    if val:
        return val
    val = getpass.getpass(f"PSK for {link_id} (env {env} not set): ")
    if not val:
        raise ApplyAbort(f"no PSK provided for {link_id}")
    return val


def _inject_psks(actions: List[PlanAction]) -> List[PlanAction]:
    out, cache = [], {}
    for a in actions:
        el = a.element
        for link_id in set(re.findall(r"__PSK:([A-Za-z0-9_.\-]+)__", el)):
            if link_id not in cache:
                cache[link_id] = _resolve_psk(link_id)
            psk = (cache[link_id].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            el = el.replace(PSK_PLACEHOLDER.format(link_id=link_id), psk)
        out.append(PlanAction(**{**a.__dict__, "element": el}))
    return out


def _members(inv: dict, site: str) -> List[dict]:
    return (inv.get("sites") or {}).get(site, {}).get("firewalls") or []


def _execute(dev: str, dp, ctx: dict, args) -> None:
    inv = ctx["inventory"]
    members = _members(inv, dp.site)
    print(f"\n=== {dev} ({dp.site}): {len(dp.actions)} change(s)")
    typed = input(f"Type the device hostname '{dev}' to push these changes: ").strip()
    if typed != dev:
        raise ApplyAbort("confirmation did not match; nothing sent")

    clients = {m["hostname"]: PanosApiClient(m["mgmt"], verify=args.ca_bundle or True, allow_writes=True)
               for m in members}
    for c in clients.values():
        if not c.has_key:
            c.generate_key()
    # Pre-flight on every member; pick the active one.
    active: Optional[str] = None
    for host, c in clients.items():
        info = c.system_info()
        if info.get("hostname") != host:
            raise ApplyAbort(f"{c.host} reports hostname {info.get('hostname')!r}, expected {host!r}")
        ha = c.ha_state()
        if len(members) > 1:
            if not ha.in_sync:
                raise ApplyAbort(f"{host}: HA running-config not synchronized ({ha.running_sync})")
            if ha.local_state == "active":
                active = host
        else:
            active = host
    if not active:
        raise ApplyAbort(f"{dp.site}: no active HA member found")
    c = clients[active]
    locks = c.locks()
    if locks["config"] or locks["commit"]:
        raise ApplyAbort(f"{active}: locks held by {locks}; coordinate with those admins first")
    if c.pending_changes():
        raise ApplyAbort(f"{active}: candidate config has uncommitted changes; refusing to mix them with ours")

    backup = c.export_config(BACKUPS, label="pre-corp-s2s")
    print(f"    backup: {backup}")
    # Re-plan against the device's live config so we only push what was reviewed.
    states = dict(ctx["states"])
    states[dev] = DeviceState.from_firewall(parse_firewall(backup))
    fresh = TunnelPlanner(inv)
    fresh.build_device_plans(states)
    key = lambda acts: [(a.op, a.kind, a.name, a.xpath) for a in acts]
    if key(fresh.device_plans.get(dev).actions if dev in fresh.device_plans else []) != key(dp.actions):
        raise ApplyAbort(f"{active}: live config differs from the reviewed state; re-run 'plan' and review again")

    actions = _inject_psks(dp.actions)
    with c.config_lock("corp-s2s apply"):
        try:
            for a in actions:
                print(f"    {a.op:<6} {a.kind:<16} {a.name}")
                getattr(c, a.api_action)(a.xpath, a.element)
            job = c.commit(f"corp-s2s: {len(actions)} change(s) for {', '.join(sorted({a.link for a in actions}))}"[:250])
            print(f"    commit: {'OK' if job is None or job.ok else job.result}")
        except Exception:
            print("    error: reverting candidate configuration", file=sys.stderr)
            try:
                c.revert_candidate()
            finally:
                raise
    del actions
    if len(members) > 1:
        print(f"    HA sync after commit: {clients[active].ha_state().running_sync}")
    for a in dp.actions:
        if a.kind == "ipsec-tunnel":
            try:
                c.test_vpn_tunnel(a.name)
                print(f"    verify {a.name}: {'SA up' if c.tunnel_up(a.name) else 'no SA yet (far end may not be configured)'}")
            except PanosApiError as exc:
                print(f"    verify {a.name}: {exc}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_demo(args) -> int:
    """Run the whole workflow on the fictional inventory: audit, then plan, then a dry-run apply."""
    ns = argparse.Namespace(demo=True, inventory=None, exports=None, panorama=None, pattern="*",
                            color=args.color, json=False, xml=False, min_severity="INFO",
                            device=None, execute=False, ca_bundle=None)
    banner = lambda t: print(("\033[1m" if _color(args.color) else "") + f"\n### {t}" + ("\033[0m" if _color(args.color) else ""))
    banner("1/3 audit: drift across the fictional estate")
    cmd_audit(ns)
    banner("2/3 plan: per-device changes that fix the drift and build missing links")
    cmd_plan(ns)
    banner("3/3 apply (dry run): the exact API calls --execute would send")
    cmd_apply(ns)
    return 0                           # a showcase run; use `audit` for a meaningful exit code


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="corp-s2s", description="Audit, plan and apply PAN-OS site-to-site VPN tunnels.",
                                 epilog="Run 'corp-s2s demo' for a safe walk-through on fictional data.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="audit + plan + dry-run apply on the fictional demo inventory")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.set_defaults(func=cmd_demo)

    def common(p, needs_inventory: bool):
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--demo", action="store_true", help="use the fictional examples/mock_inventory.yaml")
        if needs_inventory:
            g.add_argument("--inventory", metavar="YAML", help="real inventory (kept in git-ignored inventory/)")
        else:
            g.add_argument("--exports", metavar="DIR", help="directory of firewall exports")
            p.add_argument("--inventory", metavar="YAML", help="optional site/standards inventory")
        if needs_inventory:
            p.add_argument("--exports", metavar="DIR", help="current-state exports to diff against")
        p.add_argument("--panorama", metavar="FILE", help="Panorama export with crypto standards")
        p.add_argument("--pattern", default="*", help="glob for files in --exports")
        p.add_argument("--color", choices=("auto", "always", "never"), default="auto")

    p = sub.add_parser("audit", help="detect drift (read-only)")
    common(p, needs_inventory=False)
    p.add_argument("--json", action="store_true")
    p.add_argument("--min-severity", choices=("ERROR", "DRIFT", "WARNING", "INFO"), default="INFO")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("plan", help="show per-device changes (read-only)")
    common(p, needs_inventory=True)
    p.add_argument("--xml", action="store_true", help="show xpath + redacted element per action")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="dry-run by default; --execute pushes to explicitly named devices")
    common(p, needs_inventory=True)
    p.add_argument("--device", action="append", metavar="HOST", help="device to apply (repeatable)")
    p.add_argument("--execute", action="store_true", help="actually push (requires --device and confirmation)")
    p.add_argument("--ca-bundle", metavar="PEM", help="CA bundle for firewall management certificates")
    p.set_defaults(func=cmd_apply)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted; nothing further was sent", file=sys.stderr)
        return 130
    except BrokenPipeError:            # e.g. piping into `head`
        return 0


if __name__ == "__main__":
    sys.exit(main())
