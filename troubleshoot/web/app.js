"use strict";
// Firewall Check: front end for pan-troubleshoot serve. All data comes from the local server's
// read-only API; every request carries the page token. DOM is built with textContent only.

const TOKEN = document.querySelector('meta[name="pt-token"]').content;
const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

let FW = null;                 // name of the selected firewall
async function api(path, body) {
  const opts = { headers: { "X-PT-Token": TOKEN } };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(Object.assign({ fw: FW }, body));
  } else if (FW && path !== "/api/firewalls") {
    path += (path.includes("?") ? "&" : "?") + "fw=" + encodeURIComponent(FW);
  }
  const resp = await fetch(path, opts);
  let data = {};
  try { data = await resp.json(); } catch (e) { /* non-JSON error */ }
  if (!resp.ok) throw new Error(data.error || `request failed (${resp.status})`);
  return data;
}

function formData(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    out[el.name] = el.type === "checkbox" ? el.checked : el.value.trim();
  }
  return out;
}

function copyButton(getText, label = "Copy") {
  const b = h("button", { class: "btn small copy", type: "button" }, label);
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(getText()); b.textContent = "Copied"; }
    catch (e) { b.textContent = "Select & copy manually"; }
    setTimeout(() => (b.textContent = label), 1600);
  });
  return b;
}

function cmdBlock(lines) {
  const text = lines.join("\n");
  return h("div", { class: "cmd" }, h("pre", {}, text), copyButton(() => text));
}

function section(title, open, ...body) {
  return h("details", { class: "sec", open: open || null }, h("summary", {}, title), h("div", { class: "body" }, ...body));
}

function setBusy(on, btn, busyEl) {
  if (btn) btn.disabled = on;
  if (busyEl) busyEl.hidden = !on;
}

function showError(el, err) {
  el.hidden = false;
  el.textContent = err.message || String(err);
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------
const loaders = {};
function show(view) {
  document.querySelectorAll(".nav").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  if (loaders[view]) loaders[view]();
  window.scrollTo(0, 0);
}
document.querySelectorAll(".nav").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

// ---------------------------------------------------------------------------
// Firewall picker and status
// ---------------------------------------------------------------------------
let STATUS = null;
let FIREWALLS = [];
const store = {
  get() { try { return localStorage.getItem("pt-fw"); } catch (e) { return null; } },
  set(v) { try { localStorage.setItem("pt-fw", v); } catch (e) { /* private mode */ } },
};
const cache = {};

function banner(text, kind) {
  const b = $("#fw-banner");
  b.hidden = !text;
  b.className = `banner ${kind || ""}`;
  b.textContent = text || "";
}

function fwEntry(name) { return FIREWALLS.find((f) => f.name === name); }

async function loadFirewalls() {
  try {
    const r = await api("/api/firewalls");
    FIREWALLS = r.firewalls;
    const sel = $("#fw-select");
    const groups = {};
    for (const f of FIREWALLS) {
      const g = f.lab ? "Test / lab – don't use" : (f.group || "Firewalls");
      (groups[g] = groups[g] || []).push(f);
    }
    const isLab = (g) => (g.startsWith("Test") ? 1 : 0);
    const order = Object.keys(groups).sort((a, b) => isLab(a) - isLab(b) || a.localeCompare(b));
    const opts = [];
    if (FIREWALLS.length > 1) opts.push(h("option", { value: "" }, "Pick a firewall…"));
    for (const g of order) {
      const items = groups[g].sort((a, b) => a.name.localeCompare(b.name)).map((f) =>
        h("option", { value: f.name }, f.name + (f.site ? ` · ${f.site}` : "") + (f.lab ? " (TEST – don't use)" : "")));
      if (order.length > 1 || g !== "Firewalls") opts.push(h("optgroup", { label: g }, items));
      else opts.push(...items);
    }
    sel.replaceChildren(...opts);
    const saved = store.get();
    const pick = FIREWALLS.length === 1 ? FIREWALLS[0].name
      : saved && fwEntry(saved) && !fwEntry(saved).lab ? saved : "";
    sel.value = pick;
    await selectFirewall(pick);
  } catch (e) {
    banner(`Can't load the firewall list: ${e.message}`, "err");
  }
}

async function selectFirewall(name) {
  FW = name || null;
  STATUS = null;
  Object.keys(cache).forEach((k) => delete cache[k]);
  ["#check-result", "#logs-result", "#matrix-result", "#rules-result", "#profiles-result", "#audit-result"]
    .forEach((sel) => $(sel).replaceChildren());
  $("#check-error").hidden = true;
  $("#fw-dot").className = "dot";
  if (!FW) {
    $("#fw-name").textContent = "";
    banner("Pick the firewall for the user's site at the top, then check the connection.", "");
    return;
  }
  store.set(FW);
  const entry = fwEntry(FW) || {};
  banner(entry.lab ? `${FW} is a TEST / LAB firewall` + (entry.note ? `: ${entry.note}` : "") +
    ". Don't use it for user checks." : "", entry.lab ? "lab" : "");
  await loadStatus();
  const visible = document.querySelector(".view:not([hidden])");
  const view = visible ? visible.id.replace("view-", "") : "check";
  if (loaders[view]) loaders[view]();
  locate();
}

async function loadStatus() {
  const name = FW;
  $("#fw-name").textContent = `connecting to ${name}…`;
  try {
    const st = await api("/api/status");
    if (name !== FW) return;                     // the user switched while we were loading
    STATUS = st;
    $("#fw-dot").className = `dot ${st.mode}`;
    const mode = { live: "Live", demo: "Demo data", offline: "Saved config" }[st.mode];
    $("#fw-name").textContent = `${mode} · loaded ${st.loaded_at.slice(11, 16)}`;
    document.querySelectorAll("select.zones").forEach((sel) => {
      sel.replaceChildren(h("option", { value: "" }, "automatic"), ...st.zones.map((z) => h("option", {}, z)));
    });
    const verify = $('#check-form [name="verify"]');
    verify.disabled = !st.verify_available;
    verify.checked = st.verify_available;
  } catch (e) {
    if (name !== FW) return;
    $("#fw-dot").className = "dot";
    $("#fw-name").textContent = "not reachable";
    banner(`Can't read ${name}: ${e.message}`, "err");
  }
}

$("#fw-select").addEventListener("change", (ev) => selectFirewall(ev.target.value));
$("#refresh").addEventListener("click", async (ev) => {
  if (!FW) return;
  ev.target.disabled = true;
  try { await api("/api/refresh", {}); Object.keys(cache).forEach((k) => delete cache[k]); await loadStatus(); }
  catch (e) { banner(`Refresh failed: ${e.message}`, "err"); }
  ev.target.disabled = false;
});

// Suggest the right firewall for a device IP (from the inventory's networks)
let locateTimer = null;
async function locate() {
  const hint = $("#locate-hint");
  const device = $('#check-form [name="device"]').value.trim();
  hint.hidden = true;
  if (!device || FIREWALLS.length < 2) return;
  try {
    const r = await api("/api/locate", { device });
    const m = r.matches.filter((x) => !x.lab);
    if (!m.length) return;
    if (m.some((x) => x.name === FW)) {
      hint.className = "hint ok";
      hint.replaceChildren(`✓ ${device} is on ${FW}'s network`);
    } else {
      hint.className = "hint";
      hint.replaceChildren(`${device} looks like it's at ${m[0].name}${m[0].site ? ` (${m[0].site})` : ""}.`,
        h("button", { class: "btn small", type: "button",
          onclick: () => { $("#fw-select").value = m[0].name; selectFirewall(m[0].name); } }, `Switch to ${m[0].name}`));
    }
    hint.hidden = false;
  } catch (e) { /* the hint is optional */ }
}
$('#check-form [name="device"]').addEventListener("input", () => {
  clearTimeout(locateTimer);
  $("#locate-hint").hidden = true;
  locateTimer = setTimeout(locate, 500);
});

// ---------------------------------------------------------------------------
// Check a connection
// ---------------------------------------------------------------------------
const ICON = { blocked: "✕", allowed: "✓", check: "?", unknown: "?" };
const STATUS_WORD = { blocked: "Blocked", allowed: "Not blocked by the firewall", check: "Needs a closer look", unknown: "Unclear" };

function renderAnswer(r) {
  const a = r.answer;
  const card = h("div", { class: `card answer ${a.status}` },
    h("div", { class: "answer-head" },
      h("div", { class: "badge-icon", "aria-hidden": "true" }, ICON[a.status] || "?"),
      h("div", {},
        h("div", { class: "status" }, STATUS_WORD[a.status] || a.status),
        h("div", { class: "headline" }, a.headline),
        h("div", {}, a.explanation))),
    h("h3", {}, "What to do next"),
    h("ol", {}, a.next_steps.map((s) => h("li", {}, s))),
    a.escalate_to ? h("span", { class: "escalate" }, `Escalate to the ${a.escalate_to}`) : null,
    h("div", { class: "btnrow" },
      copyButton(() => a.ticket_text, "Copy for ticket"),
      h("a", { class: "btn small", href: `/api/report/${encodeURIComponent(r.report_id)}?t=${encodeURIComponent(TOKEN)}` },
        "Download report")),
    r.notes.length ? h("div", { class: "notes" }, r.notes.join(" · ")) : null,
    h("div", { class: "notes" }, `Logs checked: ${r.log_summary}`));
  return card;
}

function renderFlows(d) {
  if (!d.traces.length) return h("div", { class: "empty" }, "No connection to trace: add a destination, or nothing was blocked in the time window.");
  return d.traces.map((t, i) => h("div", { class: "flow" },
    h("h3", {}, `Connection ${i + 1}: ${t.flow}`),
    t.steps.map((s) => h("div", { class: "step" },
      h("span", { class: `chip ${s.status}` }, { ok: "OK", fail: "FAIL", warn: "WARN", info: "INFO" }[s.status]),
      h("span", { class: "stage" }, s.stage), h("span", {}, s.text))),
    h("div", { class: "verdict-line" }, `${t.verdict}: ${t.reason}`)));
}

function renderPlans(d) {
  const plans = d.fix_plans.filter((p) => p.steps.length);
  if (!plans.length) return h("div", { class: "empty" }, d.fix_plans[0] ? d.fix_plans[0].summary : "Nothing to change.");
  return plans.map((p) => h("div", {},
    h("h3", {}, `${p.flow}: ${p.summary}`),
    p.steps.map((s) => h("div", { class: `fix${s.alternative ? " alt" : ""}` },
      h("div", {}, h("b", {}, (s.alternative ? "Alternative: " : "") + s.title)),
      h("div", { class: "why" }, s.why),
      s.commands.length ? cmdBlock(s.commands) : null,
      s.notes.length ? h("ul", {}, s.notes.map((n) => h("li", {}, n))) : null)),
    h("p", { class: "muted" }, "Review before applying, then commit. This tool never changes the firewall.")));
}

function renderCommands(d) {
  return d.verification_commands.map((cs) => h("div", {},
    h("h3", {}, cs.flow),
    cs.groups.map((g) => h("div", {}, h("div", { class: "muted" }, g.title), cmdBlock(g.commands)))));
}

function renderFindings(findings) {
  if (!findings.length) return h("div", { class: "empty" }, "No findings.");
  return findings.map((f) => h("div", { class: "finding" },
    h("span", { class: `sev ${f.severity}` }, f.severity), h("b", {}, f.code), h("div", {}, f.message),
    f.details.length ? h("ul", {}, f.details.filter(Boolean).map((x) => h("li", {}, x))) : null));
}

async function runCheck(params) {
  const err = $("#check-error"), out = $("#check-result");
  err.hidden = true;
  if (!FW) { showError(err, new Error("Pick a firewall at the top first.")); return; }
  out.replaceChildren();
  setBusy(true, $("#check-btn"), $("#check-busy"));
  try {
    const r = await api("/api/check", params);
    const d = r.diagnosis;
    const important = d.findings.filter((f) => f.severity !== "INFO");
    out.append(
      renderAnswer(r),
      section("What the firewall did, step by step", false, renderFlows(d)),
      section("For the network team: how to fix it", false, renderPlans(d)),
      section("Commands to confirm on the firewall", false, renderCommands(d)),
      section(`Technical findings (${important.length} important, ${d.findings.length} total)`, false,
        renderFindings(d.findings)));
  } catch (e) {
    showError(err, e);
  } finally {
    setBusy(false, $("#check-btn"), $("#check-busy"));
  }
}

$("#check-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  runCheck(formData(ev.target));
});

function prefillCheck(values) {
  const form = $("#check-form");
  for (const [k, v] of Object.entries(values)) if (form.elements[k]) form.elements[k].value = v ?? "";
  show("check");
  runCheck(formData(form));
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------
$("#logs-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#logs-result");
  out.replaceChildren(h("div", { class: "busy" }, h("span", { class: "spinner" }), "Reading logs…"));
  try {
    const params = formData(ev.target);
    const r = await api("/api/logs", params);
    const rows = r.entries.map((e) => h("tr", { class: e.blocked ? "blocked" : null },
      h("td", { class: "mono" }, e.time || ""), h("td", {}, e.kind), h("td", { class: "mono" }, e.src || ""),
      h("td", { class: "mono" }, `${e.dst || ""}${e.dport ? ":" + e.dport : ""}`), h("td", {}, e.app || ""),
      h("td", {}, e.rule || ""), h("td", {}, e.action || ""),
      h("td", {}, e.kind === "url" ? `${e.category || ""} ${e.url || ""}` : e.kind === "threat" ? `${e.threat || ""} (${e.severity || ""})` : e.session_end_reason || ""),
      h("td", {}, h("button", { class: "btn small", type: "button",
        onclick: () => prefillCheck({ device: e.src, destination: e.dst, port: e.dport || "", minutes: params.minutes }) }, "Check this"))));
    out.replaceChildren(h("div", { class: "card" },
      h("div", { class: "muted" }, `${r.total} matching entr${r.total === 1 ? "y" : "ies"}` +
        (r.capped.length ? ` (only the newest were read for: ${r.capped.join(", ")})` : "")),
      rows.length ? h("div", { class: "tablewrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Time", "Type", "Source", "Destination", "App", "Rule", "Action", "Detail", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows))) : h("div", { class: "empty" }, "Nothing found for this filter.")));
  } catch (e) {
    out.replaceChildren(h("div", { class: "error" }, e.message));
  }
});

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------
function matrixTable(rows) {
  if (!rows.length) return h("div", { class: "empty" }, "(none)");
  return h("div", { class: "tablewrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["Application", "Ports / service", "Rule", "Match"].map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.map((r) => h("tr", {},
      h("td", {}, r.application), h("td", { class: "mono" }, r.ports), h("td", {}, `${r.position} ${r.action}`),
      h("td", {}, r.match === "full" ? "full" : `${r.match}: ${r.note}`,
        r.conflict ? h("div", { class: "error" }, `App-ID/port conflict: ${r.conflict}`) : null))))));
}

$("#matrix-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#matrix-result");
  out.replaceChildren(h("div", { class: "busy" }, h("span", { class: "spinner" }), "Working…"));
  try {
    const r = await api("/api/matrix", formData(ev.target));
    out.replaceChildren(...r.matrices.map((m) => h("div", { class: "card" },
      h("h2", {}, `${m.src} → ${m.dst}  (${m.from_zone || "?"} → ${m.to_zone || "?"})`),
      m.error ? h("div", { class: "error" }, m.error) : [
        h("h3", {}, "Allowed"), matrixTable(m.permitted),
        h("h3", {}, "Blocked"), matrixTable(m.blocked),
        h("p", { class: "muted" }, m.default)])));
  } catch (e) {
    out.replaceChildren(h("div", { class: "error" }, e.message));
  }
});

// ---------------------------------------------------------------------------
// Rules, profiles, audit (loaded once, refreshed with the Refresh button)
// ---------------------------------------------------------------------------
async function once(key, path, el, render) {
  if (cache[key]) return;
  if (!FW) { el.replaceChildren(h("div", { class: "card empty" }, "Pick a firewall at the top first.")); return; }
  el.replaceChildren(h("div", { class: "busy" }, h("span", { class: "spinner" }), "Loading…"));
  try { cache[key] = await api(path); el.replaceChildren(render(cache[key])); }
  catch (e) { el.replaceChildren(h("div", { class: "error" }, e.message)); }
}
const list = (xs) => (xs || []).join(", ");

function rulesView(r) {
  const tabs = {
    "Security rules": () => h("table", {},
      h("thead", {}, h("tr", {}, ["#", "Name", "From → To", "Source", "Destination", "Application", "Service", "Action", "Profiles"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.security.concat(r.defaults).map((x) => h("tr", { class: x.disabled ? "disabled" : null },
        h("td", {}, x.rulebase === "default" ? "default" : x.position), h("td", {}, x.name, x.disabled ? " (disabled)" : ""),
        h("td", {}, `${list(x.from_zones)} → ${list(x.to_zones)}`), h("td", {}, (x.negate_source ? "NOT " : "") + list(x.source)),
        h("td", {}, (x.negate_destination ? "NOT " : "") + list(x.destination)), h("td", {}, list(x.application)),
        h("td", {}, list(x.service)), h("td", {}, h("span", { class: `pill ${x.action === "allow" ? "allow" : "deny"}` }, x.action)),
        h("td", {}, x.profile_group ? `group ${x.profile_group}` : Object.keys(x.profiles_effective || {}).length ? "individual" : "none"))))),
    "NAT rules": () => h("table", {},
      h("thead", {}, h("tr", {}, ["#", "Name", "From → To", "Source", "Destination", "Service", "Translation"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.nat.map((x) => h("tr", { class: x.disabled ? "disabled" : null },
        h("td", {}, x.position), h("td", {}, x.name), h("td", {}, `${list(x.from_zones)} → ${list(x.to_zones)}`),
        h("td", {}, list(x.source)), h("td", {}, list(x.destination)), h("td", {}, x.service), h("td", {}, x.translation))))),
    "Interfaces & zones": () => h("table", {},
      h("thead", {}, h("tr", {}, ["Interface", "Type", "Addresses", "Zone", "Router", "Comment"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.interfaces.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.kind),
        h("td", { class: "mono" }, x.dhcp && !x.ips.length ? "DHCP" : list(x.ips)), h("td", {}, x.zone || "(none)"),
        h("td", {}, x.vr || ""), h("td", {}, x.comment || ""))))),
    "Routes": () => h("table", {},
      h("thead", {}, h("tr", {}, ["Router", "Route"].map((t) => h("th", {}, t)))),
      h("tbody", {}, r.routes.map((x) => h("tr", {}, h("td", {}, x.vr), h("td", { class: "mono" }, x.route))))),
  };
  const body = h("div", { class: "tablewrap" });
  const bar = h("div", { class: "tabs" });
  const pick = (name) => {
    bar.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.textContent === name));
    body.replaceChildren(tabs[name]());
  };
  Object.keys(tabs).forEach((name) => bar.append(h("button", { class: "tab", type: "button", onclick: () => pick(name) }, name)));
  const card = h("div", { class: "card" }, h("h1", {}, "Rules, NAT & routes"),
    h("p", { class: "muted" }, r.routes_live ? "Routes are the live routing table." : "Routes come from the configuration (static and connected)."),
    bar, body);
  pick("Security rules");
  return card;
}

function profilesView(r) {
  const label = { virus: "Antivirus", spyware: "Anti-spyware", vulnerability: "Vulnerability", "url-filtering": "URL filtering",
    "file-blocking": "File blocking", "wildfire-analysis": "WildFire", "data-filtering": "Data filtering" };
  return h("div", {},
    h("div", { class: "card" }, h("h1", {}, "Security profile groups"),
      r.groups.length ? r.groups.map((g) => h("div", { class: "fix" },
        h("b", {}, g.name), h("span", { class: "muted" }, g.used_by.length ? `  used by ${g.used_by.join(", ")}` : "  not used by any rule"),
        h("div", {}, r.types.map((t) => h("span", { class: `pill ${g.profiles[t] ? "allow" : ""}` },
          `${label[t]}: ${g.profiles[t] || "none"}`))))) : h("div", { class: "empty" }, "No profile groups.")),
    h("div", { class: "card" }, h("h1", {}, "URL filtering profiles"),
      r.url_profiles.map((u) => h("div", { class: "fix" }, h("b", {}, u.name),
        Object.entries(u.actions).map(([act, cats]) => h("div", {}, h("span", { class: `pill ${act === "block" ? "deny" : act === "alert" ? "alert" : ""}` }, act),
          " ", cats.join(", ")))))));
}

function auditView(r) {
  const sevs = ["HIGH", "MEDIUM", "LOW"];
  let filter = "MEDIUM";
  const body = h("div");
  const draw = () => {
    const keep = (a) => sevs.indexOf(a.severity) <= sevs.indexOf(filter);
    const device = r.items.filter((a) => !a.rule && keep(a));
    const byRule = r.rules.map((rule) => [rule, r.items.filter((a) => a.rule === rule.name && keep(a))]).filter(([, xs]) => xs.length);
    const item = (a) => h("div", { class: "finding" }, h("span", { class: `sev ${a.severity}` }, a.severity), h("b", {}, a.message),
      h("div", { class: "muted" }, `→ ${a.recommendation}`));
    body.replaceChildren(...[
      device.length ? h("div", { class: "card" }, h("h2", {}, "Whole firewall"), device.map(item)) : null,
      ...byRule.map(([rule, xs]) => h("div", { class: "card" }, h("h2", {}, `Rule ${rule.label}  `, h("span", { class: "muted" }, `${rule.action} · ${rule.zones}`)), xs.map(item))),
      !device.length && !byRule.length ? h("div", { class: "card empty" }, "Nothing at this level.") : null].filter(Boolean));
    bar.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.sev === filter));
  };
  const bar = h("div", { class: "tabs" }, sevs.map((s) => h("button", { class: "tab", type: "button", "data-sev": s,
    onclick: () => { filter = s; draw(); } }, s === "HIGH" ? "High only" : s === "MEDIUM" ? "High + medium" : "Everything")));
  const card = h("div", {},
    h("div", { class: "card" }, h("h1", {}, "Best-practice audit"),
      h("div", { class: "counters" },
        sevs.map((s) => h("div", { class: "counter" }, h("b", {}, r.counts[s] || 0), h("span", { class: `sev ${s}` }, s))),
        h("div", { class: "counter" }, h("b", {}, `${r.score}%`), "rules without high/medium issues")),
      bar),
    body);
  draw();
  return card;
}

loaders.rules = () => once("rules", "/api/rules", $("#rules-result"), rulesView);
loaders.profiles = () => once("profiles", "/api/profiles", $("#profiles-result"), profilesView);
loaders.audit = () => once("audit", "/api/audit", $("#audit-result"), auditView);

loadFirewalls();
