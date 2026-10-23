"""
Web app for pan-troubleshoot: a browser front end for helpdesk and network engineers.

    pan-troubleshoot serve --demo                                   # fictional data, http://127.0.0.1:8080
    pan-troubleshoot serve --host fw01.example.net --ca-bundle mgmt.pem
    pan-troubleshoot serve --inventory inventory/firewalls.yaml     # all sites, picked from a drop-down
    PT_WEB_PASSWORD=... pan-troubleshoot serve --host fw01 --listen 0.0.0.0 --tls-cert cert.pem --tls-key key.pem

Design
------
* **Read-only.** It reuses the same engine as the CLI; nothing it does can change the firewall.
  Fix plans are shown as text for the network team.
* **Secrets stay on the server.** API keys come from the process environment
  (``PANOS_API_KEY_<HOST>`` / ``PANOS_API_KEY``, or a keygen with ``PANOS_USERNAME`` and
  ``PANOS_PASSWORD``) and are never sent to a browser.
* **Many firewalls.** With an inventory, each firewall is read the first time someone picks it
  and has its own lock, so a slow site doesn't hold up the others.
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
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from .engine import Troubleshooter, log_summary
from .helpdesk import (NETWORK_TEAM, HelpdeskAnswer, bypass_answer, combine, parse_destination, parse_device,
                       summarize)
from .inventory import FirewallEntry, load_inventory
from .inventory import to_dict as inventory_dict
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
# One firewall: its connection, cached config and lock
# ---------------------------------------------------------------------------

class Firewall:
    """A firewall from the inventory. Its config is read on first use and kept until Refresh."""

    def __init__(self, entry: FirewallEntry, args):
        self.entry = entry
        self.args = args
        self.lock = threading.Lock()          # one conversation with this firewall at a time
        self.client = None
        self.policy = None
        self.loaded_at: Optional[str] = None
        self.active_host: Optional[str] = None   # which HA member answered
        self.error: Optional[str] = None
        self.mode = "live" if entry.host and not entry.config else ("demo" if args.demo else "offline")
        self.offline_logs = []

    def _make_client(self, host: Optional[str] = None):
        from core.api import PanosApiClient, PanosAuthError
        e, a = self.entry, self.args
        host = host or e.host
        verify = e.ca_bundle or a.ca_bundle or (False if (e.insecure or a.insecure) else True)
        user = a.username or os.environ.get("PANOS_USERNAME")
        client = PanosApiClient(host, username=user, verify=verify)
        if not client.has_key:
            if not (user and os.environ.get("PANOS_PASSWORD")):
                raise PanosAuthError(f"no API key for {e.name}: set PANOS_API_KEY_<HOST> or PANOS_API_KEY, or "
                                     f"PANOS_USERNAME and PANOS_PASSWORD on the server", host=host)
            client.generate_key()             # key kept in memory only
        return client

    def _connect(self):
        """Talk to the active HA member: traffic, threat and URL logs live only on the one passing traffic."""
        if not self.entry.ha_peer:
            return self._make_client(), self.entry.host
        first_error, standby = None, None
        for host in (self.entry.host, self.entry.ha_peer):
            try:
                client = self._make_client(host)
                state = ha_state(client)
            except Exception as exc:          # unreachable or refused: try the partner
                first_error = first_error or exc
                continue
            if state in ("", "active", "active-primary", "active-secondary"):
                return client, host
            standby = standby or (client, host)
        if standby:                           # neither says active: config is synced, use what answered
            return standby
        raise first_error


    def ensure_loaded(self) -> None:
        if self.policy is None:
            self.refresh()

    def refresh(self) -> None:
        with self.lock:
            try:
                if self.mode == "live":
                    from .live import pull_config, pull_routes
                    if self.client is None or self.entry.ha_peer:   # HA: re-check who is active
                        self.client, self.active_host = self._connect()
                    policy, _ = pull_config(self.client, vsys=self.entry.vsys)
                    pull_routes(self.client, policy)
                else:
                    from .cli import _load_logs
                    policy = load_policy(self.entry.config, vsys=self.entry.vsys)
                    self.offline_logs = _load_logs(self.entry.logs)
                self.policy = policy
                self.loaded_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.error = None
            except Exception as exc:
                self.error = str(exc)
                raise

    def ha_health(self):
        """HA health from the member we talk to; doesn't need the config to be loaded."""
        from .ha import HA_COMMAND, HaHealth, evaluate, parse_ha
        e = self.entry
        if self.mode != "live":
            return HaHealth(e.name, "unknown", "Not checked: this firewall is loaded from a config file",
                            ["HA state is only available from a live firewall."])
        try:
            with self.lock:
                if self.client is None:
                    self.client, self.active_host = self._connect()
                root = self.client.op(HA_COMMAND)
        except Exception as exc:
            return HaHealth(e.name, "unknown", "Couldn't ask the firewall", [str(exc)[:300]])
        return evaluate(e.name, parse_ha(root), e.ha)

    def verify_active(self) -> Optional[dict]:
        """Before a check (caller holds the lock): make sure we're reading the active HA member.

        Logs exist only on the member that passed the traffic, so a passive member is swapped for its
        partner (``ha_peer``, else the peer address the firewall reports). None when HA is off or offline.
        """
        if self.mode != "live" or self.client is None or self.entry.ha is False:   # standalone: nothing to verify
            return None
        from .ha import ACTIVE_STATES, HA_COMMAND, parse_ha
        name, host = self.entry.name, self.active_host or self.entry.host
        try:
            info = parse_ha(self.client.op(HA_COMMAND))
        except Exception as exc:
            return {"level": "warn", "text": f"HA: couldn't confirm whether {name} ({host}) is the active member: "
                                             f"{str(exc)[:200]}"}
        if not info.enabled:
            return None
        if info.local in ACTIVE_STATES:
            return {"level": "ok", "host": host, "text": f"HA: checked on the active member of {name} ({host}); "
                                                         f"its peer is {info.peer or 'unknown'}."}
        for partner in dict.fromkeys(p for p in (self.entry.ha_peer, info.peer_ip) if p and p != host):
            try:
                client = self._make_client(partner)
                state = parse_ha(client.op(HA_COMMAND)).local
            except Exception:
                continue
            if state in ACTIVE_STATES:
                self.client, self.active_host = client, partner
                return {"level": "ok", "host": partner,
                        "text": f"HA: {host} is {info.local or 'not active'}, so the check ran on the active member "
                                f"of {name} ({partner})."}
        return {"level": "warn", "host": host,
                "text": f"HA: {name} at {host} is {info.local or 'not active'} and the active member couldn't be "
                        f"reached. Rules and routes are synchronized, so the verdict holds, but recent logs live on "
                        f"the active member and may be missing here."}

    def logs(self, target, peer, port, since, nlogs=500):
        """Live: query the firewall. Offline: the loaded files. Returns (entries, capped kinds)."""
        if self.mode != "live":
            return list(self.offline_logs), []
        from .logs import fetch_logs
        entries, raw = fetch_logs(self.client, target, peer, port, since, nlogs=nlogs)
        return entries, [k for k, el in raw.items() if len(el) >= nlogs]

    def networks(self, other_hosts: Optional[List[str]] = None) -> List[str]:
        """The site's address space: from the inventory, else derived from the loaded config."""
        if self.entry.networks or self.policy is None:
            return self.entry.networks
        from .inventory import _internal_networks, drop_other_sites
        return drop_other_sites(_internal_networks(self.policy), other_hosts or [])

    def summary(self) -> dict:
        return dict(inventory_dict(self.entry), mode=self.mode, loaded=self.policy is not None,
                    loaded_at=self.loaded_at, active_host=self.active_host, error=self.error)


# ---------------------------------------------------------------------------
# Backend: the firewalls, recent reports and the API endpoints
# ---------------------------------------------------------------------------

def ha_state(client) -> str:
    """This member's HA state ('active', 'passive', ...), or '' when HA isn't configured."""
    root = client.op("<show><high-availability><state></state></show>")
    if (root.findtext(".//enabled") or "").strip().lower() == "no":
        return ""
    return (root.findtext(".//local-info/state") or "").strip().lower()


def _label(f: "Firewall") -> str:
    return f"{f.entry.name} ({f.entry.site})" if f.entry.site else f.entry.name


class Backend:
    def __init__(self, args, entries: List[FirewallEntry]):
        self.args = args
        self.firewalls: "OrderedDict[str, Firewall]" = OrderedDict((e.name, Firewall(e, args)) for e in entries)
        self.reports: "OrderedDict[str, str]" = OrderedDict()
        self.ha_results: Dict[str, dict] = {}   # last HA check per firewall, for notes on connection checks
        self.reports_lock = threading.Lock()

    @property
    def default(self) -> Optional[str]:
        """The first non-lab firewall (lab/test firewalls are never pre-selected)."""
        return next((n for n, f in self.firewalls.items() if not f.entry.lab), None)

    def fw(self, params: dict) -> Firewall:
        name = params.get("fw") or (self.default if len(self.firewalls) == 1 else None)
        if name == "auto" and len(self.firewalls) == 1:
            name = next(iter(self.firewalls))
        if name == "auto":                   # logs / matrix: the site of the device (or source) IP
            raw = params.get("device") or params.get("source")
            try:
                ip = parse_device(raw)[0] if raw else None
            except ValueError as exc:
                raise UserError(str(exc)) from None
            found = self._site_of(ip)[0] if ip else None
            if found is None:
                raise UserError("Automatic needs an IP that's in one site's networks: pick the firewall at the top")
            found.ensure_loaded()
            return found
        if not name:
            raise UserError("pick a firewall first")
        f = self.firewalls.get(str(name))
        if f is None:
            raise UserError(f"unknown firewall {name!r}")
        f.ensure_loaded()
        return f

    # -- endpoints -----------------------------------------------------------------
    def list_firewalls(self, params: dict) -> dict:
        return {"firewalls": [f.summary() for f in self.firewalls.values()], "default": self.default}

    def status(self, params: dict) -> dict:
        f = self.fw(params)
        p = f.policy
        return dict(f.summary(), hostname=p.hostname, source=p.source, vsys=p.vsys, zones=sorted(p.zones),
                    rules=len(p.security_rules), nat_rules=len(p.nat_rules), verify_available=f.mode == "live")

    def refresh(self, params: dict) -> dict:
        f = self.firewalls.get(str(params.get("fw") or self.default))
        if f is None:
            raise UserError("unknown firewall")
        f.refresh()
        return self.status({"fw": f.entry.name})

    def locate(self, params: dict) -> dict:
        """Which firewall(s) a device sits behind, from the inventory networks (and any loaded configs)."""
        try:
            ip, _ = parse_device(params.get("device", ""))
        except ValueError as exc:
            raise UserError(str(exc)) from None
        probe = FirewallEntry(name="probe", host="x")
        hits = []
        for f in self.firewalls.values():
            probe.networks = f.networks()
            n = probe.match_len(ip)
            if n >= 0:
                hits.append({"name": f.entry.name, "site": f.entry.site, "lab": f.entry.lab, "prefix": n})
        hits.sort(key=lambda m: -m["prefix"])        # the most specific network wins (a /24 beats a /8 summary)
        return {"device": ip, "matches": hits}

    @staticmethod
    def _since(params: dict) -> Optional[str]:
        minutes = _int(params, "minutes", 1, 7 * 24 * 60)
        if minutes is None:
            return None
        return (datetime.now() - timedelta(minutes=minutes)).strftime("%Y/%m/%d %H:%M:%S")

    # -- which firewall(s) a connection passes ----------------------------------------
    def _site_of(self, ip: str):
        """(firewall, prefix length, tied firewalls) for the most specific inventory network holding *ip*."""
        probe = FirewallEntry(name="probe", host="x")
        best, best_len = [], -1
        hosts = [x.entry.host for x in self.firewalls.values() if x.entry.host]
        for f in self.firewalls.values():
            if f.entry.lab:
                continue
            probe.networks = f.networks([h for h in hosts if h != f.entry.host])
            n = probe.match_len(ip)
            if n > best_len:
                best, best_len = [f], n
            elif n == best_len and n >= 0:
                best.append(f)
        if best_len < 0:
            return None, -1, []
        return (best[0] if len(best) == 1 else None), best_len, best

    def _bypass(self, f: Firewall, src: str, dst: str) -> Optional[dict]:
        """Traffic that never reaches *f*: east-west inside a switched site, or two hosts on one subnet."""
        e = f.entry
        if e.east_west and e.covers(src) and e.covers(dst) and not (e.in_firewalled(src) or e.in_firewalled(dst)):
            net = next((n for n in e.networks if FirewallEntry("p", host="x", networks=[n]).covers(src)
                        and FirewallEntry("p", host="x", networks=[n]).covers(dst)), "")
            return {"reason": "east-west", "carried_by": e.east_west, "network": net}
        try:
            f.ensure_loaded()
        except Exception:
            return None                  # unreachable: _check_one reports it
        s, d = parse_target(src), parse_target(dst)
        for routes in f.policy.routes.routes.values():
            for r in routes:
                if r.nexthop_type == "connected" and r.prefixlen < 31 and \
                        r.destination[0] == s[0] == d[0] and r.destination[1] <= s[1] <= r.destination[2] \
                        and r.destination[1] <= d[1] <= r.destination[2] and s[1] == s[2] and d[1] == d[2]:
                    from .objects import interval_str
                    return {"reason": "same-subnet", "carried_by": "", "network": interval_str(r.destination)}
        return None

    def _plan_hops(self, params: dict, src: str, dst: Optional[str]):
        """[(firewall, role)] for this connection, and a note on how they were chosen."""
        chosen = params.get("fw") or "auto"
        if chosen != "auto" or len(self.firewalls) == 1:
            f = self.fw(params if chosen != "auto" else {"fw": next(iter(self.firewalls))})
            return [(f, "selected")], ""
        s_fw, s_len, s_ties = self._site_of(src)
        d_fw, d_len, d_ties = self._site_of(dst) if dst else (None, -1, [])
        for ip, ties in ((src, s_ties), (dst, d_ties)):
            if len(ties) > 1:
                raise UserError(f"{ip} is in more than one site ({', '.join(t.entry.name for t in ties)}): pick the "
                                f"firewall at the top")
        if s_fw is None and d_fw is None:
            raise UserError(f"Can't tell which firewall handles {src}" + (f" or {dst}" if dst else "")
                            + ": it isn't in any site's networks in the inventory. Pick the firewall at the top.")
        if s_fw is not None and s_fw is d_fw:
            return [(s_fw, "both ends")], f"both addresses are in {_label(s_fw)}"
        hops = []
        if s_fw is not None:
            hops.append((s_fw, "source side"))
        if d_fw is not None:
            hops.append((d_fw, "destination side"))
        how = "; ".join(f"{ip} is in {_label(f)}" for ip, f in ((src, s_fw), (dst, d_fw)) if f is not None)
        return hops, how

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
        src, dst = (device_ip, dest.ip if dest else None) if direction == "out" else (dest.ip if dest else None,
                                                                                     device_ip)
        if src is None:
            raise UserError("an inbound check needs the destination (the side that starts the connection)")
        hops, how = self._plan_hops(params, src, dst)
        device_label = params.get("device", "").strip() if device_note else device_ip
        dest_label = dest.label if dest else None
        notes = [n for n in (device_note, dest.note if dest else "") if n]
        if how:
            notes.insert(0, f"Firewall picked automatically: {how}.")

        if dst and len(hops) == 1:
            bypass = self._bypass(hops[0][0], src, dst)
            if bypass:
                f = hops[0][0]
                ans = bypass_answer(device_label, dest_label or dst, f.entry.name, f.entry.site, bypass["reason"],
                                    bypass["carried_by"], bypass["network"])
                return {"answer": ans.to_dict(), "hops": [], "notes": notes, "bypass": bypass,
                        "path": [{"name": f.entry.name, "site": f.entry.site, "role": "not involved",
                                  "status": "bypass", "lab": f.entry.lab}]}

        results = [self._check_one(f, role, params, device_ip, device_label, dest, dest_label, port, proto,
                                   direction, single=len(hops) == 1) for f, role in hops]
        overall = combine([{"name": r["name"], "site": r["site"], "role": r["role"], "answer": r.pop("_answer")}
                           for r in results], device_label, dest_label, port)
        ha_lines = [r["ha"]["text"] for r in results if r.get("ha")]
        if ha_lines:
            overall.ticket_text = overall.ticket_text.rstrip("\n") + "\n" + "\n".join(ha_lines)
        for f, _ in hops:
            ha = self.ha_results.get(f.entry.name)
            if ha and ha["level"] in ("fail", "warn"):
                notes.append(f"{f.entry.name}'s HA pair was unhealthy when last checked ({ha['checked_at']}): "
                             f"{ha['headline']}. This doesn't change the result above, but tell the network team.")
        return {"answer": overall.to_dict(), "hops": results, "notes": notes, "auto": bool(how),
                "path": [{"name": r["name"], "site": r["site"], "role": r["role"], "status": r["answer"]["status"],
                          "lab": r["lab"]} for r in results]}

    def _check_one(self, f: Firewall, role: str, params: dict, device_ip: str, device_label: str, dest, dest_label,
                   port, proto, direction: str, single: bool) -> dict:
        base = {"name": f.entry.name, "site": f.entry.site, "role": role, "lab": f.entry.lab, "notes": []}
        try:
            f.ensure_loaded()
        except Exception as exc:
            ans = HelpdeskAnswer("unknown", f"Couldn't reach {f.entry.name}",
                                 f"The checker couldn't read {f.entry.name}: {exc}",
                                 ["Try again in a minute.", "If it keeps failing, escalate to the network team."],
                                 NETWORK_TEAM)
            return dict(base, answer=ans.to_dict(), _answer=ans, diagnosis=None, log_summary="", report_id=None,
                        error=str(exc))
        fz = tz = None
        hints = Hints()
        if single:                       # zone overrides and fix-plan hints only make sense for one firewall
            fz, tz = _text(params, "from_zone"), _text(params, "to_zone")
            for z in (fz, tz):
                if z and z not in f.policy.zones:
                    raise UserError(f"unknown zone {z!r} on {f.entry.name}")
            hints = Hints(*(self._addr(params, k) for k in ("next_hop", "return_next_hop", "dnat_to")))
        since = self._since(params)
        with f.lock:
            ha = f.verify_active()
            target = parse_target(device_ip)
            peer = parse_target(dest.ip) if dest else None
            logs, capped = f.logs(target, peer, port, since)
            live = None
            if params.get("verify") and f.mode == "live":
                from .live import LiveVerifier
                live = LiveVerifier(f.client, f.policy)
            ts = Troubleshooter(f.policy, logs, live=live, logs_queried=f.mode == "live")
            d = ts.diagnose(device_ip, dest.ip if dest else None, port=port, proto=proto,
                            app=_text(params, "app"), direction=direction, from_zone=fz, to_zone=tz,
                            user=_text(params, "user"), url_category=_text(params, "url_category"), hints=hints)
        for k in capped:
            d.log_counts[k + "_capped"] = 1
        answer = summarize(d, device_label, dest_label, port, firewall=f.entry.name, policy=f.policy)
        rid = secrets.token_urlsafe(12)
        with self.reports_lock:
            self.reports[rid] = render_html(d, f.policy, answer)
            while len(self.reports) > 50:
                self.reports.popitem(last=False)
        notes = []
        if f.entry.lab:
            notes.append(f"{f.entry.name} is a TEST/LAB firewall" + (f": {f.entry.note}" if f.entry.note else ""))
        if capped:
            notes.append(f"Only the newest 500 {', '.join(capped)} log entries were checked on {f.entry.name}; pick "
                         f"a shorter time window for a complete picture.")
        if since:
            notes.append(f"Logs checked since {since} (this computer's clock).")
        return dict(base, answer=answer.to_dict(), _answer=answer, diagnosis=d.to_dict(), log_summary=log_summary(d),
                    report_id=rid, notes=notes, ha=ha, error=None)

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
        f = self.fw(params)
        try:
            src, _ = parse_device(params.get("source", ""))
            dst = parse_destination(params.get("destination", "")).ip
        except ValueError as exc:
            raise UserError(str(exc)) from None
        pairs = [(src, dst)] + ([] if params.get("one_way") else [(dst, src)])
        return {"matrices": [build_matrix(f.policy, s, t).to_dict() for s, t in pairs]}

    def audit(self, params: dict) -> dict:
        from .advisor import audit_policy
        p = self.fw(params).policy
        items = audit_policy(p)
        counts = Counter(a.severity for a in items)
        flagged = {a.rule for a in items if a.rule and a.severity in ("HIGH", "MEDIUM")}
        total = len(p.security_rules) or 1
        return {"items": [a.to_dict() for a in items], "counts": counts,
                "score": round(100 * (1 - len(flagged) / total)),
                "rules": [{"name": r.name, "label": r.label, "action": r.action,
                           "zones": f"{','.join(r.from_zones)} -> {','.join(r.to_zones)}"}
                          for r in p.security_rules]}

    def ha(self, params: dict) -> dict:
        """HA health of every firewall (lab ones last), asked in parallel."""
        from concurrent.futures import ThreadPoolExecutor
        from .ha import CLI_COMMAND
        fws = sorted(self.firewalls.values(), key=lambda f: (f.entry.lab, f.entry.group, f.entry.name))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda f: f.ha_health(), fws))
        out = []
        for f, r in zip(fws, results):
            d = dict(r.to_dict(), site=f.entry.site, group=f.entry.group, lab=f.entry.lab, host=f.entry.host,
                     active_host=f.active_host, checked_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            self.ha_results[f.entry.name] = d
            out.append(d)
        return {"firewalls": out, "counts": Counter(d["level"] for d in out if not d["lab"]), "command": CLI_COMMAND}

    def rules(self, params: dict) -> dict:
        p = self.fw(params).policy
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
        p = self.fw(params).policy
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
        f = self.fw(params)
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
        with f.lock:
            entries, capped = f.logs(target, peer, port, self._since(params), nlogs=300)
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
            params = {k: v[0] for k, v in query.items() if k != "t"}
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
            routes = {("GET", "/api/firewalls"): lambda: b.list_firewalls(params),
                      ("GET", "/api/status"): lambda: b.status(params),
                      ("POST", "/api/locate"): lambda: b.locate(params),
                      ("POST", "/api/check"): lambda: b.check(params),
                      ("POST", "/api/matrix"): lambda: b.matrix(params),
                      ("GET", "/api/audit"): lambda: b.audit(params),
                      ("GET", "/api/rules"): lambda: b.rules(params),
                      ("GET", "/api/ha"): lambda: b.ha(params),
                      ("GET", "/api/profiles"): lambda: b.profiles(params),
                      ("POST", "/api/logs"): lambda: b.logs(params),
                      ("POST", "/api/refresh"): lambda: b.refresh(params)}
            fn = routes.get((method, path))
            if fn is None:
                return self._json(404, {"error": "unknown endpoint"})
            if path not in ("/api/status", "/api/firewalls", "/api/locate"):
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

    def handle_error(self, request, client_address):
        """Browsers open spare connections and drop them unused: not worth a traceback."""
        import sys
        if isinstance(sys.exc_info()[1], (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _entries(args) -> List[FirewallEntry]:
    if getattr(args, "inventory", None):
        return load_inventory(args.inventory)
    if args.host:
        return [FirewallEntry(name=args.host, host=args.host, vsys=args.vsys)]
    return [FirewallEntry(name=Path(args.config).stem, config=args.config, logs=list(args.logs or []), vsys=args.vsys)]


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
    backend = Backend(args, _entries(args))
    if args.host:                         # single firewall from the command line: connect now (may prompt)
        from .cli import _client
        only = next(iter(backend.firewalls.values()))
        only.client = _client(args)
        only.refresh()
    elif not args.inventory:
        next(iter(backend.firewalls.values())).refresh()
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
        args.inventory = str(DEMO_DIR / "firewalls.yaml")
    elif not (args.host or args.config or getattr(args, "inventory", None)):
        raise SystemExit("serve needs --inventory FILE, --host HOST, --config FILE or --demo")
    if getattr(args, "inventory", None):
        from .inventory import InventoryError
        try:
            n = len(load_inventory(args.inventory))
        except (InventoryError, OSError) as exc:
            raise SystemExit(f"inventory: {exc}")
        print(f"inventory: {n} firewall(s) from {args.inventory}; each is read the first time someone picks it",
              file=sys.stderr)
    if args.host:
        print(f"reading running config and routes from {args.host} (read-only) ...", file=sys.stderr)
    srv = make_server(args)
    scheme = "https" if srv.tls else "http"
    shown = "127.0.0.1" if args.listen in ("0.0.0.0", "::") else args.listen
    url = f"{scheme}://{shown}:{srv.server_address[1]}/"
    names = list(srv.backend.firewalls)
    print(f"Firewall Check is running for {names[0] if len(names) == 1 else f'{len(names)} firewalls'} at {url}",
          file=sys.stderr)
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
