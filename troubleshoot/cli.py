"""
pan-troubleshoot: why is this IP or subnet blocked by the Palo Alto firewall?

    pan-troubleshoot demo                                     # fictional scenarios, contacts nothing

    # offline: a config export plus log exports (XML API output or web-UI CSV)
    pan-troubleshoot diagnose --config exports/fw01.xml --logs exports/traffic.csv --logs exports/threat.csv \\
        --ip 10.20.1.15 --peer 203.0.113.80 --port 443

    # live: pulls running config, routing table and traffic/threat/URL logs (read-only)
    pan-troubleshoot diagnose --host fw01.example.net --ip 10.20.1.0/24 --since '2026/10/22 08:00:00' --verify

(``python3 fw_troubleshoot.py ...`` and ``python3 -m troubleshoot.cli ...`` are equivalent.)

``--ip`` is the address or subnet in question. With ``--peer`` (and ideally ``--port``) one flow is
traced end to end; without it the tool traces the most frequent blocked flows found in the logs.
``--direction in`` traces peer -> ip instead of ip -> peer.

Exit codes: 2 = blocked (or a blocking error found), 1 = warnings, 0 = clean.

Live mode is read-only. The API key comes from ``PANOS_API_KEY_<HOST>`` / ``PANOS_API_KEY`` or a
``type=keygen`` with ``--username`` (password from ``PANOS_PASSWORD`` or a prompt), exactly as in
:mod:`core.api`.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import warnings
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

warnings.filterwarnings("ignore", message=r"urllib3 v2 only supports OpenSSL")

from core import __version__  # noqa: E402

from .engine import SEVERITIES, Diagnosis, Troubleshooter, log_summary  # noqa: E402
from .logs import LogEntry, load_logs  # noqa: E402
from .policy import load_policy  # noqa: E402

DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "troubleshoot"

_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"
_COLORS = {"ERROR": "\033[31m", "WARNING": "\033[33m", "INFO": "\033[36m",
           "fail": "\033[31m", "warn": "\033[33m", "ok": "\033[32m", "info": "\033[36m"}
_VERDICT_COLORS = {"BLOCKED": "\033[1;31m", "ALLOWED": "\033[1;32m"}


def _color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def format_diagnosis(d: Diagnosis, source: str = "", color: bool = False, min_severity: str = "INFO",
                     show_commands: bool = True) -> str:
    c = (lambda code, s: f"{code}{s}{_RESET}") if color else (lambda code, s: s)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out = [c(_BOLD, f"Palo Alto troubleshooting: {d.hostname or '?'}") + (c(_DIM, f"  ({source})") if source else "")]
    out.append(f"  target {d.target}" + (f"   peer {d.peer}" if d.peer else "")
               + "   logs: " + log_summary(d))
    vcol = next((v for k, v in _VERDICT_COLORS.items() if d.verdict.startswith(k)), _BOLD)
    out.append("  VERDICT: " + c(vcol, d.verdict) + (f"  ({'; '.join(d.reasons)})" if d.reasons else ""))
    out.append("")
    for i, t in enumerate(d.traces, 1):
        origin = "your query" if t.flow.origin == "query" else f"seen {t.flow.hits}x in logs"
        out.append(c(_BOLD, f"== Flow {i}: {t.flow}") + c(_DIM, f"  [{origin}]"))
        for s in t.steps:
            tag = {"ok": " ok ", "fail": "FAIL", "warn": "WARN", "info": " -- "}[s.status]
            out.append(f"  {c(_COLORS[s.status], f'[{tag}]')} {s.stage:<15} {s.text}")
        out.append(f"  => {c(_VERDICT_COLORS.get('BLOCKED' if t.verdict in ('DENY', 'DROP') else 'ALLOWED' if t.verdict == 'ALLOW' else '', _BOLD), t.verdict)}"
                   f"  {t.reason}")
        out.append("")
    from .commands import format_commands
    from .remediate import format_plan
    for i, (plan, cmds) in enumerate(zip(d.plans, d.commands), 1):
        if plan.steps or len(d.plans) == 1:
            out.append(c(_BOLD, f"== Fix plan{f' (flow {i})' if len(d.plans) > 1 else ''}: {plan.flow}"))
            out += format_plan(plan)
            out.append("")
        if show_commands:
            out.append(c(_BOLD, f"== Verify on the firewall{f' (flow {i})' if len(d.plans) > 1 else ''}"))
            out += format_commands(cmds)
            out.append("")
    shown = [f for f in d.findings if rank[f.severity] <= rank[min_severity]]
    counts = {s: sum(1 for f in d.findings if f.severity == s) for s in SEVERITIES}
    out.append(c(_BOLD, "== Findings  ") + "   ".join(c(_COLORS[s], f"{s} {counts[s]}") for s in SEVERITIES))
    for f in shown:
        out.append(f"{c(_COLORS[f.severity], f'[{f.severity}]')} {c(_BOLD, f.category)}/{f.code}")
        out.append(f"    {f.message}")
        for det in f.details:
            if det:
                out.append(c(_DIM, f"      - {det}"))
    if not shown:
        out.append(f"No findings at or above {min_severity}.")
    return "\n".join(out)


def exit_code(d: Diagnosis) -> int:
    if d.verdict == "BLOCKED" or any(f.severity == "ERROR" for f in d.findings):
        return 2
    return 1 if any(f.severity == "WARNING" for f in d.findings) else 0


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _save(directory: Path, name: str, element: ET.Element) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, stat.S_IRWXU)
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(ET.tostring(element))
    return path


def _load_logs(paths: Optional[List[str]]) -> List[LogEntry]:
    entries: List[LogEntry] = []
    for p in paths or []:
        entries += load_logs(p)
    return entries


def _client(args):
    from core.api import PanosApiClient
    verify = args.ca_bundle or (False if args.insecure else True)
    client = PanosApiClient(args.host, username=args.username, verify=verify, target=args.serial)
    if not client.has_key:
        client.generate_key()
    return client


def _policy_only(args):
    """Load just the policy (no logs) from --config or --host."""
    if args.host:
        from core.api import PanosApiError
        from .live import pull_config, pull_routes
        try:
            client = _client(args)
            print(f"reading running config and routes from {args.host} (read-only) ...", file=sys.stderr)
            policy, _ = pull_config(client, vsys=args.vsys)
            pull_routes(client, policy)
        except PanosApiError as exc:
            sys.exit(f"error: {exc}")
        return policy
    if args.config:
        return load_policy(args.config, vsys=args.vsys)
    sys.exit("needs --config FILE or --host HOST")


def cmd_matrix(args) -> int:
    from .advisor import build_matrix, format_matrix
    from .objects import parse_target
    try:
        parse_target(args.src)
        parse_target(args.dst)
    except ValueError as exc:
        sys.exit(f"invalid address: {exc}")
    policy = _policy_only(args)
    pairs = [(args.src, args.dst, args.from_zone, args.to_zone)]
    if not args.one_way:
        pairs.append((args.dst, args.src, args.to_zone, args.from_zone))
    matrices = [build_matrix(policy, s, d, fz, tz) for s, d, fz, tz in pairs]
    if args.json:
        print(json.dumps([m.to_dict() for m in matrices], indent=1))
    else:
        print("\n\n".join(format_matrix(m) for m in matrices))
    return 2 if any(r.conflict for m in matrices for r in m.permitted) else 0


def cmd_audit(args) -> int:
    from .advisor import audit_policy, format_audit
    policy = _policy_only(args)
    if args.rule and policy.rule(args.rule) is None:
        sys.exit(f"rule {args.rule!r} not found")
    items = audit_policy(policy, rule_name=args.rule)
    if args.conflicts_only:
        items = [a for a in items if a.code == "BP_APP_PORT_CONFLICT"]
    if args.json:
        print(json.dumps([a.to_dict() for a in items], indent=1))
    else:
        print(format_audit(items, policy, min_severity=args.min_severity))
    sev = {a.severity for a in items}
    return 2 if "HIGH" in sev else 1 if "MEDIUM" in sev else 0


def cmd_diagnose(args) -> int:
    from .objects import parse_target
    try:
        target = parse_target(args.ip)
        peer = parse_target(args.peer) if args.peer else None
    except ValueError as exc:
        sys.exit(f"invalid address: {exc}")
    live = None
    capped: List[str] = []
    logs = _load_logs(args.logs)
    if args.host:
        from core.api import PanosApiError
        from .live import LiveVerifier, pull_config, pull_routes
        from .logs import fetch_logs
        try:
            client = _client(args)
            print(f"reading running config, routes and logs from {args.host} (read-only) ...", file=sys.stderr)
            policy, cfg = pull_config(client, vsys=args.vsys)
            routes_xml = pull_routes(client, policy)
            pulled, raw = fetch_logs(client, target, peer, args.port, args.since, nlogs=args.nlogs)
            logs += pulled
            capped = [k for k, el in raw.items() if len(el) >= args.nlogs]
            if capped:
                print(f"note: {', '.join(capped)} log query hit the --nlogs limit ({args.nlogs}); only the newest "
                      f"entries were analysed (raise --nlogs or narrow with --since/--port)", file=sys.stderr)
        except PanosApiError as exc:
            sys.exit(f"error: {exc}")
        if args.save:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            d = Path(args.save)
            _save(d, f"{args.host}_{ts}_config.xml", cfg)
            if routes_xml is not None:
                _save(d, f"{args.host}_{ts}_routes.xml", routes_xml)
            for kind, el in raw.items():
                _save(d, f"{args.host}_{ts}_{kind}.xml", el)
            print(f"saved config, routes and logs to {d}/ (mode 0600)", file=sys.stderr)
        if args.verify:
            live = LiveVerifier(client, policy)
    elif args.config:
        policy = load_policy(args.config, vsys=args.vsys)
    else:
        sys.exit("diagnose needs --config FILE or --host HOST")

    from .remediate import Hints
    for label, value in (("--next-hop", args.next_hop), ("--return-next-hop", args.return_next_hop),
                         ("--dnat-to", args.dnat_to)):
        if value:
            try:
                parse_target(value)
            except ValueError:
                sys.exit(f"invalid address for {label}: {value}")
    ts = Troubleshooter(policy, logs, live=live, logs_queried=bool(args.host))
    d = ts.diagnose(args.ip, args.peer, port=args.port, proto=args.protocol, app=args.app,
                    direction=args.direction, from_zone=args.from_zone, to_zone=args.to_zone,
                    user=args.user, url_category=args.url_category, max_flows=args.max_flows,
                    hints=Hints(args.next_hop, args.return_next_hop, args.dnat_to))
    for k in (capped if args.host else []):
        d.log_counts[k + "_capped"] = 1
    if args.html:
        from .report import write_html
        path = write_html(d, policy, args.html)
        print(f"HTML report written to {path}", file=sys.stderr)
    if args.json:
        print(json.dumps(d.to_dict(), indent=1))
    else:
        print(format_diagnosis(d, policy.source, color=_color(args.color), min_severity=args.min_severity,
                               show_commands=not args.no_commands))
    return exit_code(d)


DEMO_SCENARIOS = [
    ("Explicit deny rule (blocklisted host)", ["--ip", "10.10.20.66", "--peer", "198.51.100.25", "--port", "443"]),
    ("No security rule: falls through to interzone-default", ["--ip", "10.10.30.0/24", "--peer", "10.10.40.10",
                                                             "--port", "1433"]),
    ("Allowed by policy, but the vulnerability profile blocks it", ["--ip", "10.10.20.15", "--peer", "192.0.2.80",
                                                                    "--port", "443"]),
    ("Blocked by URL filtering", ["--ip", "10.10.20.33", "--peer", "198.51.100.77", "--port", "443"]),
    ("No route to the destination", ["--ip", "10.10.20.15", "--peer", "172.31.5.5", "--port", "22"]),
    ("Inbound DNAT to the DMZ web server", ["--ip", "203.0.113.10", "--peer", "192.0.2.150", "--port", "443",
                                           "--direction", "in"]),
    ("Single IP, flows discovered from the logs", ["--ip", "10.10.20.66"]),
    ("SSH to the jump host: App-ID vs service-port conflict", ["--ip", "10.10.20.15", "--peer", "10.10.40.22",
                                                              "--port", "22", "--app", "ssh"]),
    ("New guest Wi-Fi: NAT and security rule missing", ["--ip", "10.10.70.25", "--peer", "198.51.100.40",
                                                        "--port", "443", "--app", "ssl"]),
    ("Partner network behind the WAN router: route and security rule missing",
     ["--ip", "10.10.20.15", "--peer", "172.20.5.10", "--port", "443", "--app", "ssl", "--next-hop", "10.255.0.2"]),
    ("Lab interface: zone, NAT and security rule missing", ["--ip", "10.10.60.5", "--peer", "198.51.100.40",
                                                            "--port", "443", "--app", "ssl"]),
    ("Publish a server: destination NAT + security rule", ["--ip", "203.0.113.2", "--peer", "192.0.2.150",
                                                           "--port", "8443", "--app", "ssl", "--direction", "in",
                                                           "--dnat-to", "10.10.50.20"]),
]


def cmd_demo(args) -> int:
    cfg = DEMO_DIR / "branch-fw.xml"
    logs = [str(p) for p in sorted(DEMO_DIR.glob("*-logs.*"))]
    bold = (lambda s: f"{_BOLD}{s}{_RESET}") if _color(args.color) else (lambda s: s)
    for i, (title, argv) in enumerate(DEMO_SCENARIOS, 1):
        print(bold(f"\n### {i}/{len(DEMO_SCENARIOS) + 2} {title}"))
        print(bold(f"$ pan-troubleshoot diagnose --config {cfg.relative_to(DEMO_DIR.parent.parent)} --logs ... "
                   + " ".join(argv)))
        ns = _parser().parse_args(["diagnose", "--config", str(cfg)] + sum((["--logs", lp] for lp in logs), [])
                                  + argv + ["--color", args.color, "--min-severity", "WARNING"]
                                  + ([] if i == 1 else ["--no-commands"]))
        cmd_diagnose(ns)
    n = len(DEMO_SCENARIOS)
    print(bold(f"\n### {n + 1}/{n + 2} Port & application matrix between a user and the server subnet"))
    print(bold("$ pan-troubleshoot matrix --config ... --src 10.10.20.15 --dst 10.10.40.0/24"))
    cmd_matrix(_parser().parse_args(["matrix", "--config", str(cfg), "--src", "10.10.20.15",
                                     "--dst", "10.10.40.0/24"]))
    print(bold(f"\n### {n + 2}/{n + 2} Best-practice audit"))
    print(bold("$ pan-troubleshoot audit --config ... --min-severity MEDIUM"))
    cmd_audit(_parser().parse_args(["audit", "--config", str(cfg), "--min-severity", "MEDIUM"]))
    return 0


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pan-troubleshoot",
                                 description="Find out why a Palo Alto firewall blocks an IP or subnet: routing, "
                                             "zones, NAT, security rules, threat/URL profiles and logs.",
                                 epilog="Run 'pan-troubleshoot demo' for a walk-through on fictional data.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="run the troubleshooting scenarios on fictional data")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.set_defaults(func=cmd_demo)

    def source(p, logs: bool):
        g = p.add_argument_group("data source (one of)")
        g.add_argument("--config", metavar="FILE", help="firewall config export (XML or brace format)")
        g.add_argument("--host", metavar="HOST", help="read config and routes" + (", logs" if logs else "")
                       + " live from this firewall (read-only)")
        g.add_argument("--vsys", default="vsys1")
        lv = p.add_argument_group("live mode")
        lv.add_argument("--username", help="username for API keygen if no PANOS_API_KEY is set")
        lv.add_argument("--serial", help="firewall serial, to go through Panorama as --host")
        lv.add_argument("--ca-bundle", metavar="PEM")
        lv.add_argument("--insecure", action="store_true", help="skip TLS verification (not recommended)")
        p.add_argument("--json", action="store_true")
        return lv

    p = sub.add_parser("matrix", help="all applications/ports permitted or blocked between two endpoints")
    source(p, logs=False)
    p.add_argument("--src", required=True, help="source IP/CIDR")
    p.add_argument("--dst", required=True, help="destination IP/CIDR")
    p.add_argument("--from-zone", help="override the source zone")
    p.add_argument("--to-zone", help="override the destination zone")
    p.add_argument("--one-way", action="store_true", help="only src -> dst (default: both directions)")
    p.set_defaults(func=cmd_matrix)

    p = sub.add_parser("audit", help="rule-by-rule best-practice recommendations and App-ID/port conflicts")
    source(p, logs=False)
    p.add_argument("--rule", help="audit only this rule")
    p.add_argument("--conflicts-only", action="store_true", help="only App-ID vs service-port conflicts")
    p.add_argument("--min-severity", choices=("HIGH", "MEDIUM", "LOW", "INFO"), default="LOW")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("diagnose", help="diagnose an IP/subnet (read-only)")
    lv = source(p, logs=True)
    p.add_argument("--logs", action="append", metavar="FILE",
                   help="traffic/threat/URL log file: XML API output or web-UI CSV (repeatable)")
    q = p.add_argument_group("what to diagnose")
    q.add_argument("--ip", required=True, help="IP, CIDR or range in question")
    q.add_argument("--peer", help="the other end (IP/CIDR); omit to trace blocked flows found in the logs")
    q.add_argument("--port", type=int, help="destination port")
    q.add_argument("--protocol", choices=("tcp", "udp", "icmp", "sctp"), help="default tcp when --port is given")
    q.add_argument("--app", help="App-ID name, if known (e.g. ssl, ms-rdp)")
    q.add_argument("--direction", choices=("out", "in"), default="out",
                   help="out: ip -> peer (default); in: peer -> ip")
    q.add_argument("--user", help="User-ID user (e.g. corp\\alice) to evaluate source-user rules")
    q.add_argument("--url-category", help="URL category to evaluate rule categories and URL profiles")
    q.add_argument("--from-zone", help="override the ingress zone")
    q.add_argument("--to-zone", help="override the egress zone")
    q.add_argument("--max-flows", type=int, default=5, help="max flows taken from the logs (default 5)")
    lv.add_argument("--since", metavar="'YYYY/MM/DD HH:MM:SS'", help="only logs received after this time")
    lv.add_argument("--nlogs", type=int, default=500, help="max entries per log type (default 500)")
    lv.add_argument("--verify", action="store_true",
                    help="cross-check with the firewall's test security-policy-match / nat-policy-match / fib-lookup")
    lv.add_argument("--save", metavar="DIR", help="save the pulled config/routes/logs (use a git-ignored dir)")
    fx = p.add_argument_group("fix plan hints")
    fx.add_argument("--next-hop", metavar="IP", help="next hop towards the destination, for a missing route")
    fx.add_argument("--return-next-hop", metavar="IP", help="next hop back towards the source")
    fx.add_argument("--dnat-to", metavar="IP", help="internal server, to plan a destination NAT")
    p.add_argument("--no-commands", action="store_true", help="hide the verification commands")
    p.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    p.set_defaults(func=cmd_diagnose)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if getattr(args, "config", None) and getattr(args, "host", None):
        sys.exit("use either --config or --host, not both")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
