"""Self-contained HTML report for one diagnosis (no external assets; everything is escaped)."""

from __future__ import annotations

import html
import os
from datetime import datetime, timezone
from pathlib import Path

from .engine import Diagnosis, log_summary
from .policy import PolicyConfig

_CSS = """
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;--code:#f5f5f4;
--err:#b91c1c;--warn:#b45309;--ok:#15803d;--info:#0369a1}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;
--line:#44403c;--code:#0c0a09;--err:#f87171;--warn:#fbbf24;--ok:#4ade80;--info:#38bdf8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:12px 16px;margin:8px 0}
.verdict{font-size:20px;font-weight:700}.BLOCKED{color:var(--err)}.ALLOWED{color:var(--ok)}
.other{color:var(--warn)}
.step{display:grid;grid-template-columns:52px 120px minmax(0,1fr);gap:8px;padding:3px 0;border-top:1px solid var(--line)}
.card,main{min-width:0;overflow-wrap:anywhere}h1,h2{overflow-wrap:anywhere}
.tag{font-weight:700;font-size:12px}.ok{color:var(--ok)}.fail,.ERROR{color:var(--err)}
.warn,.WARNING{color:var(--warn)}.info,.INFO{color:var(--info)}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:8px 10px;
overflow-x:auto;max-width:100%;overflow-wrap:normal;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;margin:6px 0}
ul{margin:4px 0 4px 18px;padding:0}.alt{border-style:dashed}
@media (max-width:600px){.step{grid-template-columns:44px minmax(0,1fr)}.step .stage{display:none}}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""))


def render_html(d: Diagnosis, policy: PolicyConfig) -> str:
    vclass = "BLOCKED" if d.verdict.startswith("BLOCKED") else "ALLOWED" if d.verdict.startswith("ALLOWED") else "other"
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>Firewall diagnosis {_e(d.target)}</title><style>{_CSS}</style></head><body><main>",
           f"<h1>{_e(d.hostname or 'firewall')}: {_e(d.target)}{(' ↔ ' + _e(d.peer)) if d.peer else ''}</h1>",
           f"<div class='muted'>{_e(policy.source)} · generated "
           f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by pan-troubleshoot</div>",
           f"<div class='card'><div class='verdict {vclass}'>{_e(d.verdict)}</div>",
           f"<div>{_e('; '.join(d.reasons))}</div><div class='muted'>logs: " + _e(log_summary(d)) + "</div></div>"]
    for i, t in enumerate(d.traces):
        out.append(f"<h2>Flow {i + 1}: {_e(t.flow)}</h2><div class='card'>")
        for s in t.steps:
            out.append(f"<div class='step'><span class='tag {s.status}'>{_e(s.status.upper())}</span>"
                       f"<span class='stage muted'>{_e(s.stage)}</span><span>{_e(s.text)}</span></div>")
        out.append(f"<p><b>{_e(t.verdict)}</b> {_e(t.reason)}</p></div>")
        if i < len(d.plans):
            plan = d.plans[i]
            out.append(f"<h2>Fix plan</h2><p>{_e(plan.summary)}</p>")
            for s in plan.steps:
                out.append(f"<div class='card{' alt' if s.alternative else ''}'><b>{'Alternative: ' if s.alternative else ''}"
                           f"[{_e(s.area)}] {_e(s.title)}</b><div class='muted'>{_e(s.why)}</div>")
                if s.commands:
                    out.append("<pre>" + _e("\n".join(s.commands)) + "</pre>")
                if s.notes:
                    out.append("<ul>" + "".join(f"<li>{_e(n)}</li>" for n in s.notes) + "</ul>")
                out.append("</div>")
        if i < len(d.commands):
            out.append("<h2>Verify on the firewall</h2>")
            for title, cmds in d.commands[i].groups:
                out.append(f"<div class='muted'>{_e(title)}</div><pre>{_e(chr(10).join(cmds))}</pre>")
    out.append("<h2>Findings</h2>")
    for f in d.findings:
        out.append(f"<div class='card'><span class='tag {f.severity}'>{_e(f.severity)}</span> "
                   f"<b>{_e(f.category)}/{_e(f.code)}</b><div>{_e(f.message)}</div>")
        if f.details:
            out.append("<ul>" + "".join(f"<li>{_e(x)}</li>" for x in f.details if x) + "</ul>")
        out.append("</div>")
    out.append("<p class='muted'>Proposed commands are for review only; nothing was changed on the firewall.</p>")
    out.append("</main></body></html>")
    return "\n".join(out)


def write_html(d: Diagnosis, policy: PolicyConfig, path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(render_html(d, policy))
    return path
