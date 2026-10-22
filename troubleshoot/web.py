"""
Web app for pan-troubleshoot: a browser front end for helpdesk and network engineers.

    pan-troubleshoot serve --demo                                   # fictional data, http://127.0.0.1:8080
    pan-troubleshoot serve --host fw01.example.net --ca-bundle mgmt.pem
    PT_WEB_PASSWORD=... pan-troubleshoot serve --host fw01 --listen 0.0.0.0 --tls-cert cert.pem --tls-key key.pem

Design
------
* **Read-only.** It reuses the same engine as the CLI; nothing it does can change the firewall.
  Fix plans are shown as text for the network team.
* **Secrets stay on the server.** The firewall API key is read from the environment of the
  process (``PANOS_API_KEY_<HOST>``), exactly as in the CLI, and is never sent to a browser.
* **Local by default.** It binds to 127.0.0.1. Listening on a network address requires a
  password (``PT_WEB_PASSWORD``, HTTP Basic) and TLS (``--tls-cert/--tls-key``), unless you
  explicitly pass ``--allow-plain-http`` on a trusted network.
* **Browser protections.** Every API call needs a per-run token that only the served page knows
  (so other web sites can't drive it), local mode checks the Host header (DNS rebinding), and
  responses carry a strict Content-Security-Policy.
* **Accountability.** Each check is logged to stderr with time, client address, user and query.

Standard library only (plus the engine's ``requests`` for live mode). Python 3.9+.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
from collections import OrderedDict, Counter
from dataclasses import asdict
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import parse_qs, urlsplit

from .engine import Troubleshooter, log_summary
from .helpdesk import parse_destination, parse_device, summarize
from .objects import parse_target
from .policy import PROFILE_TYPES, load_policy
from .remediate import Hints
from .report import render_html

WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC = {"/app.js": "application/javascript; charset=utf-8", "/app.css": "text/css; charset=utf-8"}
MAX_BODY = 32 * 1024
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9 _.\-:/\\@,=]{0,128}$")


class UserError(ValueError):
    """Bad input: shown to the user as-is."""


def _text(params: dict, key: str) -> Optional[str]:
    v = params.get(key)
    if v is None or str(v).strip() == "":
        return None
    v = str(v).strip()
    if not _SAFE_TEXT.match(v):
        raise UserError(f"'{key}' contains characters that aren't allowed")
    return v


def _int(params: dict, key: str, lo: int, hi: int) -> Optional[int]:
    v = params.get(key)
    if v in (None, ""):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise UserError(f"'{key}' must be a number") from None
    if not lo <= n <= hi:
        raise UserError(f"'{key}' must be between {lo} and {hi}")
    return n


# ---------------------------------------------------------------------------
# Backend: holds the policy, the API client and recent reports
# ---------------------------------------------------------------------------

class Backend:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()          # one firewall conversation at a time
        self.client = None
        self.policy = None
        self.loaded_at: Optional[str] = None
        self.offline_logs = []
        self.reports: "OrderedDict[str, str]" = OrderedDict()
        self.mode = "live" if args.host else ("demo" if args.demo else "offline")
        if not args.host:
            from .cli import _load_logs
            self.offline_logs = _load_logs(args.logs)
        self.refresh()

    # -- data --------------------------------------------------------------------
    def refresh(self) -> None:
        with self.lock:
            if self.args.host:
                from .cli import _client
                from .live import pull_config, pull_routes
                if self.client is None:
                    self.client = _client(self.args)
                policy, _ = pull_config(self.client, vsys=self.args.vsys)
                pull_routes(self.client, policy)
                self.policy = policy
            else:
                self.policy = load_policy(self.args.config, vsys=self.args.vsys)
            self.loaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def status(self) -> dict:
        p = self.policy
        return {"hostname": p.hostname, "source": p.source, "mode": self.mode, "vsys": p.vsys,
                "loaded_at": self.loaded_at, "zones": sorted(p.zones), "rules": len(p.security_rules),
                "nat_rules": len(p.nat_rules), "verify_available": self.mode == "live"}

    def _since(self, params: dict) -> Optional[str]:
        minutes = _int(params, "minutes", 1, 7 * 24 * 60)
        if minutes is None:
            return None
        return (datetime.now() - timedelta(minutes=minutes)).strftime("%Y/%m/%d %H:%M:%S")

    def _logs(self, target, peer, port, since, nlogs=500):
        """Live: query the firewall. Offline: the loaded files. Returns (entries, capped kinds)."""
        if self.mode != "live":
            return list(self.offline_logs), []
        from .logs import fetch_logs
        entries, raw = fetch_logs(self.client, target, peer, port, since, nlogs=nlogs)
        return entries, [k for k, el in raw.items() if len(el) >= nlogs]

    # -- endpoints -----------------------------------------------------------------
    def check(self, params: dict) -> dict:
        try:
            device_ip, device_note = parse_device(params.get("device", ""))
            port = _int(params, "port", 1, 65535)
            dest = parse_destination(params["destination"], port) if params.get("destination") else None
        except ValueError as exc:
            raise UserError(str(exc)) from None
        port = dest.port if dest and dest.port else port
        proto = _text(params, "protocol") or (dest.protocol if dest else None)
        if proto and proto not in ("tcp", "udp", "icmp", "sctp"):
            raise UserError("protocol must be tcp, udp, icmp or sctp")
        direction = params.get("direction") or "out"
        if direction not in ("out", "in"):
            raise UserError("direction must be 'out' or 'in'")
        zones = set(self.policy.zones)
        fz, tz = _text(params, "from_zone"), _text(params, "to_zone")
        for z in (fz, tz):
            if z and z not in zones:
                raise UserError(f"unknown zone {z!r}")
        hints = Hints(*(self._addr(params, k) for k in ("next_hop", "return_next_hop", "dnat_to")))
        since = self._since(params)
        with self.lock:
            target = parse_target(device_ip)
            peer = parse_target(dest.ip) if dest else None
            logs, capped = self._logs(target, peer, port, since)
            live = None
            if params.get("verify") and self.mode == "live":
                from .live import LiveVerifier
                live = LiveVerifier(self.client, self.policy)
            ts = Troubleshooter(self.policy, logs, live=live, logs_queried=self.mode == "live")
            d = ts.diagnose(device_ip, dest.ip if dest else None, port=port, proto=proto,
                            app=_text(params, "app"), direction=direction, from_zone=fz, to_zone=tz,
                            user=_text(params, "user"), url_category=_text(params, "url_category"), hints=hints)
        for k in capped:
            d.log_counts[k + "_capped"] = 1
        device_label = params.get("device", "").strip() if device_note else device_ip
        answer = summarize(d, device_label, dest.label if dest else None, port, firewall=self.policy.hostname,
                           policy=self.policy)
        rid = secrets.token_urlsafe(12)
        self.reports[rid] = render_html(d, self.policy, answer)
        while len(self.reports) > 50:
            self.reports.popitem(last=False)
        notes = [n for n in (device_note, dest.note if dest else "") if n]
        if capped:
            notes.append(f"Only the newest 500 {', '.join(capped)} log entries were checked; pick a shorter time "
                         f"window for a complete picture.")
        if since:
            notes.append(f"Logs checked since {since} (this computer's clock).")
        return {"answer": answer.to_dict(), "diagnosis": d.to_dict(), "log_summary": log_summary(d),
                "notes": notes, "report_id": rid}

    def _addr(self, params: dict, key: str) -> Optional[str]:
        v = _text(params, key)
        if v:
            try:
                parse_target(v)
            except ValueError:
                raise UserError(f"'{key}' must be an IP address") from None
        return v

    def matrix(self, params: dict) -> dict:
        from .advisor import build_matrix
        try:
            src, _ = parse_device(params.get("source", ""))
            dst = parse_destination(params.get("destination", "")).ip
        except ValueError as exc:
            raise UserError(str(exc)) from None
        pairs = [(src, dst)] + ([] if params.get("one_way") else [(dst, src)])
        return {"matrices": [build_matrix(self.policy, s, t).to_dict() for s, t in pairs]}

    def audit(self, params: dict) -> dict:
        from .advisor import audit_policy
        items = audit_policy(self.policy)
        counts = Counter(a.severity for a in items)
        flagged = {a.rule for a in items if a.rule and a.severity in ("HIGH", "MEDIUM")}
        total = len(self.policy.security_rules) or 1
        return {"items": [a.to_dict() for a in items], "counts": counts,
                "score": round(100 * (1 - len(flagged) / total)),
                "rules": [{"name": r.name, "label": r.label, "action": r.action,
                           "zones": f"{','.join(r.from_zones)} -> {','.join(r.to_zones)}"}
                          for r in self.policy.security_rules]}

    def rules(self, params: dict) -> dict:
        p = self.policy
        sec = [dict(asdict(r), label=r.label, profiles_effective=p.effective_profiles(r)) for r in p.security_rules]
        dflt = [dict(asdict(r), label=r.label) for r in p.default_rules.values()]
        nat = [dict(asdict(r), label=r.label, translation=r.describe()) for r in p.nat_rules]
        routes = [{"vr": vr, "route": r.describe()} for vr, rs in p.routes.routes.items() for r in rs]
        ifaces = [{"name": i.name, "kind": i.kind, "ips": i.ips, "dhcp": i.dhcp, "zone": p.zone_of(i.name),
                   "vr": p.routes.vr_of(i.name), "comment": i.comment} for i in p.interfaces]
        zones = [asdict(z) for z in p.zones.values()]
        return {"security": sec, "defaults": dflt, "nat": nat, "routes": routes, "interfaces": ifaces,
                "zones": zones, "routes_live": p.routes.live}

    def profiles(self, params: dict) -> dict:
        p = self.policy
        used: Dict[str, list] = {}
        for r in p.security_rules:
            if r.profile_group:
                used.setdefault(r.profile_group, []).append(r.name + (" (disabled)" if r.disabled else ""))
        groups = [{"name": n, "profiles": {t: (v[0] if v else None) for t, v in g.items()},
                   "used_by": used.get(n, [])} for n, g in p.profile_groups.items()]
        loose = [{"rule": r.name, "profiles": {t: v[0] for t, v in r.profiles.items() if v}}
                 for r in p.security_rules if r.profiles and not r.profile_group]
        urls = [{"name": u.name, "actions": {k: v for k, v in u.actions.items() if v}} for u in p.url_profiles.values()]
        return {"groups": groups, "rule_profiles": loose, "url_profiles": urls, "types": list(PROFILE_TYPES)}

    def logs(self, params: dict) -> dict:
        try:
            device_ip, _ = parse_device(params.get("device", ""))
            dest = parse_destination(params["destination"]) if params.get("destination") else None
        except ValueError as exc:
            raise UserError(str(exc)) from None
        port = _int(params, "port", 1, 65535)
        kind = params.get("kind") or "all"
        if kind not in ("all", "traffic", "threat", "url", "blocked"):
            raise UserError("unknown log type")
        target = parse_target(device_ip)
        peer = parse_target(dest.ip) if dest else None
        with self.lock:
            entries, capped = self._logs(target, peer, port, self._since(params), nlogs=300)
        rows = [e for e in entries if e.involves(target) and (peer is None or e.involves(peer))
                and (port is None or e.dport == port)]
        if kind == "blocked":
            rows = [e for e in rows if e.blocked]
        elif kind != "all":
            rows = [e for e in rows if e.kind == kind]
        rows.sort(key=lambda e: e.time or "", reverse=True)
        return {"entries": [dict(e.to_dict(), kind=e.kind, blocked=e.blocked) for e in rows[:500]],
                "capped": capped, "total": len(rows)}


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class Handler(BaseHTTPRequestHandler):
    server_version = "pan-troubleshoot"
    sys_version = ""

    # -- helpers ---------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str, csp: str = "default-src 'self'; img-src 'self' data:; "
              "frame-ancestors 'none'; base-uri 'none'; form-action 'none'", extra: Optional[dict] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", csp)
        if self.server.tls:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json; charset=utf-8")

    def log_message(self, fmt, *args):         # quiet default access log; we log checks ourselves
        pass

    def _audit(self, what: str) -> None:
        print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {self.client_address[0]} user={getattr(self, 'user', '-')} "
              f"{what}", file=sys.stderr, flush=True)

    def _authorized(self) -> bool:
        srv = self.server
        if srv.password is None:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            if host not in _LOCAL_HOSTS:              # DNS-rebinding guard for local mode
                self._send(403, b"forbidden host", "text/plain")
                return False
            self.user = "local"
            return True
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
            except Exception:
                user, pw = "", ""
            if hmac.compare_digest(pw.encode(), srv.password.encode()):
                self.user = re.sub(r"[^A-Za-z0-9_.@\-]", "_", user)[:64] or "user"
                return True
        self._send(401, b"login required", "text/plain", extra={"WWW-Authenticate": 'Basic realm="Firewall Check"'})
        return False

    def _token_ok(self, query: dict) -> bool:
        given = self.headers.get("X-PT-Token") or (query.get("t") or [""])[0]
        if hmac.compare_digest(given.encode(), self.server.token.encode()):
            return True
        self._json(403, {"error": "missing or wrong page token: reload the page"})
        return False

    # -- routing ---------------------------------------------------------------
    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method: str) -> None:
        if not self._authorized():
            return
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query)
        try:
            if method == "GET" and path in ("/", "/index.html"):
                page = (WEB_DIR / "index.html").read_text(encoding="utf-8").replace("__PT_TOKEN__", self.server.token)
                return self._send(200, page.encode(), "text/html; charset=utf-8")
            if method == "GET" and path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if method == "GET" and path in STATIC:
                return self._send(200, (WEB_DIR / path.lstrip("/")).read_bytes(), STATIC[path])
            if not path.startswith("/api/"):
                return self._send(404, b"not found", "text/plain")
            if not self._token_ok(query):
                return
            if method == "GET" and path.startswith("/api/report/"):
                html = self.server.backend.reports.get(path.rsplit("/", 1)[-1])
                if html is None:
                    return self._send(404, b"report expired: run the check again", "text/plain")
                self._audit("download report")
                return self._send(200, html.encode(), "text/html; charset=utf-8",
                                  csp="default-src 'none'; style-src 'unsafe-inline'; img-src data:",
                                  extra={"Content-Disposition": 'attachment; filename="firewall-check.html"'})
            params = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    return self._json(413, {"error": "request too large"})
                if (self.headers.get("Content-Type") or "").split(";")[0] != "application/json":
                    return self._json(415, {"error": "expected application/json"})
                params = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(params, dict):
                    return self._json(400, {"error": "expected a JSON object"})
            b = self.server.backend
            routes = {("GET", "/api/status"): lambda: b.status(),
                      ("POST", "/api/check"): lambda: b.check(params),
                      ("POST", "/api/matrix"): lambda: b.matrix(params),
                      ("GET", "/api/audit"): lambda: b.audit(params),
                      ("GET", "/api/rules"): lambda: b.rules(params),
                      ("GET", "/api/profiles"): lambda: b.profiles(params),
                      ("POST", "/api/logs"): lambda: b.logs(params),
                      ("POST", "/api/refresh"): lambda: (b.refresh(), b.status())[1]}
            fn = routes.get((method, path))
            if fn is None:
                return self._json(404, {"error": "unknown endpoint"})
            if path not in ("/api/status",):
                self._audit(f"{path} {json.dumps({k: v for k, v in params.items() if v not in (None, '', False)})}")
            started = time.monotonic()
            result = fn()
            if isinstance(result, dict):
                result["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            return self._json(200, result)
        except UserError as exc:
            return self._json(400, {"error": str(exc)})
        except json.JSONDecodeError:
            return self._json(400, {"error": "invalid JSON"})
        except Exception as exc:              # keep the server up; report the class, not a traceback
            from core.api import PanosApiError
            msg = str(exc) if isinstance(exc, PanosApiError) else f"{type(exc).__name__}: {exc}"
            self._audit(f"error {msg}")
            return self._json(502 if isinstance(exc, PanosApiError) else 500, {"error": msg})


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, backend: Backend, password: Optional[str], tls: bool):
        super().__init__(addr, Handler)
        self.backend = backend
        self.password = password
        self.tls = tls
        self.token = secrets.token_urlsafe(24)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(args) -> AppServer:
    """Validate the exposure settings, load the data and bind the socket."""
    password = os.environ.get("PT_WEB_PASSWORD") or None
    tls = bool(args.tls_cert)
    if not _is_loopback(args.listen):
        if not password:
            raise SystemExit("refusing to listen on a network address without a password: set PT_WEB_PASSWORD")
        if not tls and not args.allow_plain_http:
            raise SystemExit("refusing to send passwords over plain HTTP: pass --tls-cert/--tls-key "
                             "(or --allow-plain-http on a trusted network)")
        if len(password) < 12:
            raise SystemExit("PT_WEB_PASSWORD must be at least 12 characters")
    backend = Backend(args)
    srv = AppServer((args.listen, args.port), backend, password, tls)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def cmd_serve(args) -> int:
    if args.demo:
        from .cli import DEMO_DIR
        args.config = str(DEMO_DIR / "branch-fw.xml")
        args.logs = [str(p) for p in sorted(DEMO_DIR.glob("*-logs.*"))]
    elif not (args.host or args.config):
        raise SystemExit("serve needs --demo, --config FILE or --host HOST")
    if args.host:
        print(f"reading running config and routes from {args.host} (read-only) ...", file=sys.stderr)
    srv = make_server(args)
    scheme = "https" if srv.tls else "http"
    shown = "127.0.0.1" if args.listen in ("0.0.0.0", "::") else args.listen
    url = f"{scheme}://{shown}:{srv.server_address[1]}/"
    b = srv.backend
    print(f"Firewall Check is running for {b.policy.hostname or 'firewall'} ({b.mode}) at {url}", file=sys.stderr)
    print("read-only; press Ctrl+C to stop", file=sys.stderr)
    if not args.no_browser and _is_loopback(args.listen):
        import webbrowser
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
    finally:
        srv.server_close()
    return 0
