/* GUARDRAIL-X dashboard SPA — all data from /api/v1 (no fabricated values). */
"use strict";

const API = "/api/v1";
let TOKEN = sessionStorage.getItem("gx_token") || "";
let ROLE = sessionStorage.getItem("gx_role") || "";
let EMAIL = sessionStorage.getItem("gx_email") || "";
const state = { refreshTimer: null, esTimer: null };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => "&#" + c.charCodeAt(0) + ";");
}
function badge(v) { return `<span class="badge b-${esc(String(v).replace(/\s+/g, "_"))}">${esc(v)}</span>`; }

async function api(path, opts = {}) {
  const headers = Object.assign({"Content-Type": "application/json"},
    TOKEN ? {"Authorization": "Bearer " + TOKEN} : {});
  const r = await fetch(API + path, {...opts, headers});
  if (r.status === 401 && TOKEN) { setSession("", "", ""); route(); throw new Error("session expired"); }
  if (!r.ok) {
    let detail = r.statusText;
    try { const j = await r.json(); detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch {}
    throw new Error(`${r.status}: ${detail}`);
  }
  return r.json();
}

function setSession(token, role, email) {
  TOKEN = token; ROLE = role; EMAIL = email;
  if (token) { sessionStorage.setItem("gx_token", token); sessionStorage.setItem("gx_role", role); sessionStorage.setItem("gx_email", email); }
  else { sessionStorage.clear(); }
  renderSession();
}

function renderSession() {
  document.getElementById("logout-btn").classList.toggle("hidden", !TOKEN);
  document.getElementById("whoami").textContent = TOKEN ? `${EMAIL} (${ROLE})` : "";
}

const NAV = [
  ["dashboard", "Dashboard"], ["targets", "Target Registry"], ["lab", "Scenario Lab"],
  ["explorer", "Live Explorer"], ["findings", "Findings"], ["benchmarks", "Benchmark Studio"],
  ["policy", "Policy & Permissions"], ["approvals", "Approvals"], ["audit", "Audit & Reports"],
];

function renderNav(active) {
  const nav = document.getElementById("nav");
  if (!TOKEN) { nav.innerHTML = ""; return; }
  nav.innerHTML = NAV.map(([k, label]) =>
    `<a href="#/${k}" class="${active === k ? "active" : ""}">${label}</a>`).join("");
}

/* ------------------------------------------------------------------ views */

async function viewDashboard(el) {
  const [stats, exps, events, benchmarks] = await Promise.all([
    api("/admin/stats"), api("/experiments"),
    api("/events?limit=12"), api("/benchmarks"),
  ]);
  el.innerHTML = `
    <h1>Dashboard</h1>
    <div class="cards">
      <div class="card ok"><div class="num">${stats.targets_operational}/${stats.targets}</div><div class="lbl">Operational targets</div></div>
      <div class="card"><div class="num">${stats.experiments_running}</div><div class="lbl">Running experiments</div></div>
      <div class="card"><div class="num">${stats.findings_total}</div><div class="lbl">Findings (all)</div></div>
      <div class="card crit"><div class="num">${stats.findings_by_severity?.critical || 0}</div><div class="lbl">Critical findings</div></div>
      <div class="card"><div class="num">${stats.benchmarks}</div><div class="lbl">Benchmark runs</div></div>
      <div class="card"><div class="num">${stats.approvals_pending}</div><div class="lbl">Pending approvals</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>Recent experiments</h3>
        <table><tr><th>ID</th><th>Title</th><th>Status</th><th>Findings</th></tr>
        ${exps.slice(0, 8).map(e => `<tr>
          <td><a class="link" href="#/explorer/${e.id}">${esc(e.id.slice(0, 14))}…</a></td>
          <td>${esc(e.title)}</td><td>${badge(e.status)}</td>
          <td>${e.stats?.findings ?? 0}</td></tr>`).join("") || "<tr><td colspan=4 class=muted>none</td></tr>"}
        </table></div>
      <div class="panel"><h3>Latest security events</h3><div class="timeline">
        ${events.map(ev => `<div class="tl-item ${ev.level === "warning" ? "warn" : ""}">
          <span class="type">${esc(ev.type)}</span> <span class="t">${esc((ev.created_at || "").slice(0, 19))}</span>
          <div class="t mono">${esc(JSON.stringify(ev.payload).slice(0, 120))}</div></div>`).join("") || '<span class="muted">no events</span>'}
      </div></div>
    </div>
    <div class="panel"><h3>Benchmark trend (policy violation rate)</h3>
      ${benchmarks.length ? `<table><tr><th>Run</th><th>Suite</th><th>Status</th><th>Policy violation rate</th><th>Injection success</th><th>False refusal</th></tr>
      ${benchmarks.slice(0, 8).map(b => {
        const m = b.metrics?.metrics || {};
        const pv = m.policy_violation_rate, pi = m.prompt_injection_success_rate, fr = m.false_refusal_rate;
        const pct = v => v == null ? "—" : (100 * v).toFixed(1) + "%";
        return `<tr><td>${esc(b.id.slice(0, 12))}…</td><td>${esc(b.suite_key)}</td><td>${badge(b.status)}</td>
          <td>${pct(pv?.value)}</td><td>${pct(pi?.value)}</td><td>${pct(fr?.value)}</td></tr>`;
      }).join("")}</table>` : '<span class="muted">no benchmark runs yet</span>'}
    </div>`;
}

async function viewTargets(el) {
  const [targets, adapters, projects] = await Promise.all([
    api("/targets"), api("/adapters"), api("/projects")]);
  el.innerHTML = `
    <h1>Target Registry</h1>
    <div class="panel"><h3>Registered targets</h3>
      <table><tr><th>Name</th><th>Adapter</th><th>Model</th><th>Status</th><th>Health detail</th><th></th></tr>
      ${targets.map(t => `<tr>
        <td>${esc(t.name)} ${t.is_demo ? '<span class="badge b-info">DEMO DATA</span>' : ""}</td>
        <td class="mono">${esc(t.adapter_name)}</td><td class="mono">${esc(t.model)}</td>
        <td>${badge(t.status)}</td>
        <td class="muted">${esc(t.last_health?.detail || "not tested")}</td>
        <td class="row">
          <button class="btn small" data-test="${esc(t.id)}">Test connection</button>
          <button class="btn small danger" data-del="${esc(t.id)}">Delete</button>
        </td></tr>`).join("") || '<tr><td colspan=6 class="muted">no targets registered</td></tr>'}
      </table></div>
    <div class="panel"><h3>Available adapters</h3>
      <table><tr><th>Adapter</th><th>Version</th><th>Modalities</th><th>Tool calling</th><th>Auth (env)</th><th>Configured</th></tr>
      ${adapters.map(a => `<tr><td class="mono">${esc(a.name)}</td><td>${esc(a.version)}</td>
        <td>${a.modalities.map(esc).join(", ")}</td><td>${a.supports_tool_calling ? "yes" : "no"}</td>
        <td class="mono">${a.auth_requirements.map(esc).join(", ") || "—"}</td>
        <td>${a.auth_requirements.length === 0 ? "ready" : "needs env credentials"}</td></tr>`).join("")}
      </table></div>
    <div class="panel"><h3>Register new target</h3>
      <div class="form-grid">
        <div><label>Project</label><select id="t-project">${projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}${p.is_demo ? " (demo)" : ""}</option>`).join("")}</select></div>
        <div><label>Name</label><input id="t-name" placeholder="my-target"></div>
        <div><label>Adapter</label><select id="t-adapter">${adapters.map(a => `<option value="${esc(a.name)}">${esc(a.name)}</option>`).join("")}</select></div>
        <div><label>Model</label><input id="t-model" placeholder="model id"></div>
        <div><label>Config JSON (behavior / base_url; never paste API keys)</label><input id="t-config" value='{}'></div>
      </div>
      <div class="row mt8"><button class="btn" id="t-create">Register</button><span id="t-msg" class="muted"></span></div>
    </div>`;
  el.querySelectorAll("[data-test]").forEach(b => b.onclick = async () => {
    b.disabled = true; b.textContent = "Testing…";
    try { const r = await api(`/targets/${b.dataset.test}/test-connection`, {method: "POST"});
      b.textContent = r.status; b.className = "btn small " + (r.status === "operational" ? "" : "danger");
      viewTargets(el); } catch (e) { b.textContent = "failed"; }
  });
  el.querySelectorAll("[data-del]").forEach(b => b.onclick = async () => {
    if (!confirm("Delete target?")) return;
    await api(`/targets/${b.dataset.del}`, {method: "DELETE"}); viewTargets(el);
  });
  el.querySelector("#t-create").onclick = async () => {
    const msg = el.querySelector("#t-msg");
    try {
      await api("/targets", {method: "POST", body: JSON.stringify({
        project_id: el.querySelector("#t-project").value,
        name: el.querySelector("#t-name").value,
        adapter_name: el.querySelector("#t-adapter").value,
        model: el.querySelector("#t-model").value,
        config: JSON.parse(el.querySelector("#t-config").value || "{}"),
      })});
      msg.textContent = "registered (run connection test to mark operational)";
      viewTargets(el);
    } catch (e) { msg.textContent = e.message; msg.className = "error-text"; }
  };
}

async function viewLab(el) {
  const [scenarios, targets, policies, projects] = await Promise.all([
    api("/scenarios"), api("/targets"), api("/policies"), api("/projects")]);
  const byCat = {};
  scenarios.forEach(s => (byCat[s.category] = byCat[s.category] || []).push(s));
  el.innerHTML = `
    <h1>Scenario Laboratory</h1>
    <div class="panel"><h3>Run new experiment</h3>
      <div class="form-grid">
        <div><label>Target (operational only)</label><select id="x-target">
          ${targets.filter(t => t.status === "operational").map(t => `<option value="${esc(t.id)}">${esc(t.name)} — ${esc(t.adapter_name)}</option>`).join("") || "<option value=''>— none operational —</option>"}
        </select></div>
        <div><label>Policy</label><select id="x-policy">
          ${policies.map(p => `<option value="${esc(p.id)}">${esc(p.name)} v${p.version} ${p.active ? "(active)" : ""}</option>`).join("")}
        </select></div>
        <div><label>Project</label><select id="x-project">${projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}</select></div>
        <div><label>Replays per scenario</label><input id="x-replays" type="number" value="1" min="1" max="5"></div>
      </div>
      <label>Scenarios</label>
      <div class="panel" style="max-height: 320px; overflow-y:auto">
        ${Object.entries(byCat).map(([cat, list]) => `<h3>${esc(cat)}</h3>` +
          list.map(s => `<label style="display:flex;gap:8px;align-items:center;margin:4px 0">
            <input type="checkbox" class="x-scen" value="${esc(s.key)}" style="width:auto" ${s.source === "builtin" ? "checked" : ""}>
            <span>${esc(s.title)}</span> <span class="muted mono">${esc(s.key)}</span> ${badge(s.risk <= 10 ? "low" : s.risk <= 45 ? "medium" : "high")}
            <span class="muted">${esc((s.description || "").slice(0, 80))}</span></label>`).join("")).join("")}
      </div>
      <div class="row mt8">
        <button class="btn" id="x-run">Create & run experiment</button>
        <button class="btn ghost" id="x-variations">Generate red-team variations</button>
        <span id="x-msg" class="muted"></span>
      </div>
    </div>
    <div class="panel"><h3>Experiments</h3>
      <table><tr><th>Title</th><th>Status</th><th>Cases</th><th>Outcomes</th><th></th></tr>
      ${(await api("/experiments")).slice(0, 15).map(e => `<tr>
        <td>${esc(e.title)}</td><td>${badge(e.status)}</td>
        <td>${e.stats?.cases_done ?? 0}/${e.stats?.cases_total ?? 0}</td>
        <td class="mono" style="font-size:11px">${esc(JSON.stringify(e.stats?.outcomes || {}))}</td>
        <td><a class="link" href="#/explorer/${e.id}">inspect</a>
            ${["created", "running", "paused"].includes(e.status) ? ` · <a class="link" data-cancel="${esc(e.id)}">cancel</a>` : ""}</td>
      </tr>`).join("")}</table></div>`;
  el.querySelector("#x-run").onclick = async () => {
    const keys = [...el.querySelectorAll(".x-scen:checked")].map(c => c.value);
    const msg = el.querySelector("#x-msg");
    if (!keys.length) { msg.textContent = "select at least one scenario"; return; }
    try {
      const created = await api("/experiments", {method: "POST", body: JSON.stringify({
        project_id: el.querySelector("#x-project").value,
        target_id: el.querySelector("#x-target").value,
        policy_id: el.querySelector("#x-policy").value,
        scenario_keys: keys,
        title: "Lab run " + new Date().toISOString().slice(0, 16).replace("T", " "),
        authorization: {authorized_by: EMAIL, acknowledged: true, scope: "scenario lab selection"},
        config: {replays: parseInt(el.querySelector("#x-replays").value || "1")},
      })});
      await api(`/experiments/${created.id}/start`, {method: "POST"});
      msg.textContent = "started " + created.id;
      location.hash = "#/explorer/" + created.id;
    } catch (e) { msg.textContent = e.message; msg.className = "error-text"; }
  };
  el.querySelector("#x-variations").onclick = async () => {
    const keys = [...el.querySelectorAll(".x-scen:checked")].slice(0, 5).map(c => c.value);
    const msg = el.querySelector("#x-msg");
    if (!keys.length) { msg.textContent = "select base scenarios first"; return; }
    try {
      const r = await api("/redteam/variations", {method: "POST", body: JSON.stringify({
        base_scenario_keys: keys.filter(k => !k.startsWith("rt.")), variations_per_base: 2})});
      msg.textContent = `registered ${r.variation_keys.length} bounded variations (reselect to see them)`;
    } catch (e) { msg.textContent = e.message; msg.className = "error-text"; }
  };
  el.querySelectorAll("[data-cancel]").forEach(a => a.onclick = async () => {
    await api(`/experiments/${a.dataset.cancel}/cancel`, {method: "POST"});
    viewLab(el);
  });
}

async function viewExplorer(el, expId) {
  if (!expId) {
    const exps = await api("/experiments");
    el.innerHTML = `<h1>Live Execution Explorer</h1>
      <div class="panel"><h3>Experiments</h3><table>
      <tr><th>ID</th><th>Title</th><th>Status</th><th>Started</th></tr>
      ${exps.map(e => `<tr><td><a class="link" href="#/explorer/${e.id}">${esc(e.id)}</a></td>
        <td>${esc(e.title)}</td><td>${badge(e.status)}</td><td class="muted">${esc((e.started_at || "").slice(0, 19))}</td></tr>`).join("")}
      </table></div>`;
    return;
  }
  const exp = await api(`/experiments/${expId}`);
  const events = await api(`/experiments/${expId}/events?limit=400`);
  el.innerHTML = `
    <h1>Execution ${esc(exp.id)} ${badge(exp.status)}</h1>
    <p class="muted">${esc(exp.title)} · adapter v${esc(exp.adapter_version)} · policy v${exp.policy_version} ·
       ${exp.config?.dry_run ? "DRY-RUN" : "gateway mode: " + esc(exp.config?.gateway_mode || "simulated")}</p>
    <div class="toolbar">
      <select id="case-filter"><option value="">All cases</option>
        ${exp.cases.map(c => `<option value="${esc(c.id)}">case ${c.seq}: ${esc(c.scenario_key)} (${esc(c.status)})</option>`).join("")}
      </select>
      ${["created", "running", "paused"].includes(exp.status) ? `<button class="btn danger small" id="x-cancel">Cancel</button>` : ""}
      <span class="muted">${events.length} events</span>
    </div>
    <div class="grid2">
      <div class="panel"><h3>Cases</h3><table>
        <tr><th>#</th><th>Scenario</th><th>Replay</th><th>Outcome</th><th>Finding</th></tr>
        ${exp.cases.map(c => `<tr><td>${c.seq}</td><td class="mono">${esc(c.scenario_key)}</td><td>${c.replay}</td>
          <td>${badge(c.status)}</td><td>${c.finding_id ? `<a class="link" href="#/findings/${esc(c.finding_id)}">${esc(c.finding_id.slice(0, 12))}…</a>` : "—"}</td></tr>`).join("")}
      </table></div>
      <div class="panel"><h3>Event timeline</h3><div class="timeline" id="tl" style="max-height: 560px; overflow-y:auto">
        ${events.map(ev => `<div class="tl-item ${ev.level === "warning" ? "warn" : ev.level === "error" ? "err" : ""}" data-case="${esc(ev.case_id || "")}">
          <span class="type">${esc(ev.type)}</span> <span class="t">${esc((ev.created_at || "").slice(11, 19))} · ${esc(ev.actor)}</span>
          <div class="t mono">${esc(JSON.stringify(ev.payload).slice(0, 220))}</div></div>`).join("")}
      </div></div>
    </div>`;
  el.querySelector("#case-filter").onchange = e => {
    const v = e.target.value;
    el.querySelectorAll("#tl .tl-item").forEach(item =>
      item.style.display = (!v || item.dataset.case === v) ? "" : "none");
  };
  const cancelBtn = el.querySelector("#x-cancel");
  if (cancelBtn) cancelBtn.onclick = async () => { await api(`/experiments/${expId}/cancel`, {method: "POST"}); viewExplorer(el, expId); };
  if (exp.status === "running") setTimeout(() => { if (location.hash.includes(expId)) viewExplorer(el, expId); }, 3000);
}

async function viewFindings(el, findingId) {
  if (findingId) {
    const f = await api(`/findings/${findingId}`);
    el.innerHTML = `<h1>${esc(f.title)}</h1>
      <p>${badge(f.severity)} ${badge(f.confidence)} ${badge(f.status)} <span class="muted">layer: ${esc(f.failure_layer)} · class: ${esc(f.vuln_class)}</span></p>
      <div class="grid2">
        <div class="panel"><h3>Expected</h3><pre>${esc(JSON.stringify(f.expected, null, 2))}</pre>
          <h3>Observed</h3><pre>${esc(JSON.stringify(f.observed, null, 2))}</pre></div>
        <div class="panel"><h3>Impact</h3><p>${esc(f.impact)}</p>
          <h3>Remediation</h3><p>${esc(f.remediation)}</p>
          <h3>Reproduction (authorized environment)</h3><pre>${esc(JSON.stringify(f.reproduction, null, 2))}</pre>
          <h3>Limitations</h3><ul>${(f.limitations || []).map(l => `<li>${esc(l)}</li>`).join("")}</ul>
          <h3>Evidence</h3><p class="mono">${(f.evidence_event_ids || []).length} correlated events · reproducible: ${f.reproducible ?? "unknown"}</p>
          ${f.regression_scenario_key ? `<p>Regression scenario: <span class="mono">${esc(f.regression_scenario_key)}</span></p>` : ""}
          <button class="btn small" id="f-verify">Re-verify</button> <span id="f-msg" class="muted"></span></div>
      </div>`;
    el.querySelector("#f-verify").onclick = async () => {
      try { await api(`/findings/${findingId}/verify`, {method: "POST"});
        el.querySelector("#f-msg").textContent = "verification pass complete"; viewFindings(el, findingId);
      } catch (e) { el.querySelector("#f-msg").textContent = e.message; }
    };
    return;
  }
  const fs = await api("/findings");
  el.innerHTML = `<h1>Findings Center</h1>
    <div class="panel"><table>
    <tr><th>Title</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Layer</th><th>Reproducible</th><th></th></tr>
    ${fs.map(f => `<tr><td>${esc(f.title)}</td><td>${badge(f.severity)}</td><td>${badge(f.confidence)}</td>
      <td>${badge(f.status)}</td><td>${esc(f.failure_layer)}</td><td>${f.reproducible ?? "—"}</td>
      <td><a class="link" href="#/findings/${esc(f.id)}">inspect</a></td></tr>`).join("") || '<tr><td colspan=7 class=muted>no findings</td></tr>'}
    </table></div>`;
}

async function viewBenchmarks(el) {
  const [suites, runs, targets, projects] = await Promise.all([
    api("/benchmarks/suites"), api("/benchmarks"), api("/targets"), api("/projects")]);
  const policies = await api("/policies");
  el.innerHTML = `<h1>Benchmark Studio</h1>
    <div class="panel"><h3>Suites</h3><table>
      <tr><th>Suite</th><th>Version</th><th>Description</th></tr>
      ${Object.entries(suites.suites).map(([k, s]) => `<tr><td class="mono">${esc(k)}</td><td>v${s.version}</td><td>${esc(s.description)}</td></tr>`).join("")}
      ${suites.dynamic.map(k => `<tr><td class="mono">${esc(k)}</td><td>—</td><td>auto-generated from confirmed findings (regression pack)</td></tr>`).join("")}
    </table></div>
    <div class="panel"><h3>Run suite</h3>
      <div class="form-grid">
        <div><label>Suite</label><select id="b-suite">${[...Object.keys(suites.suites), ...suites.dynamic].map(k => `<option>${esc(k)}</option>`).join("")}</select></div>
        <div><label>Target</label><select id="b-target">${targets.filter(t => t.status === "operational").map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("")}</select></div>
        <div><label>Project</label><select id="b-project">${projects.map(p => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join("")}</select></div>
        <div><label>Policy</label><select id="b-policy">${policies.filter(p => p.active).map(p => `<option value="${esc(p.id)}">${esc(p.name)} v${p.version}</option>`).join("")}</select></div>
      </div>
      <div class="row mt8"><button class="btn" id="b-run">Run benchmark</button><span id="b-msg" class="muted"></span></div>
    </div>
    <div class="panel"><h3>Runs</h3><table>
      <tr><th>Run</th><th>Suite</th><th>Status</th><th>Violation rate</th><th>Enforcement failures</th><th>Task completion</th><th>False refusal</th><th>Coverage</th></tr>
      ${runs.map(b => { const m = b.metrics?.metrics || {}; const pct = v => v == null ? "—" : (100 * v).toFixed(1) + "%";
        return `<tr><td class="mono">${esc(b.id.slice(0, 12))}…</td><td>${esc(b.suite_key)}</td><td>${badge(b.status)}</td>
        <td>${pct(m.policy_violation_rate?.value)}</td><td>${pct(m.guardrail_enforcement_failure_rate?.value)}</td>
        <td>${pct(m.benign_task_completion_rate?.value)}</td><td>${pct(m.false_refusal_rate?.value)}</td>
        <td>${pct(b.metrics?.coverage_rate)}</td></tr>`; }).join("") || '<tr><td colspan=8 class=muted>no runs</td></tr>'}
    </table></div>`;
  el.querySelector("#b-run").onclick = async () => {
    const msg = el.querySelector("#b-msg");
    msg.textContent = "running suite (blocking — may take a minute)…";
    try {
      const r = await api("/benchmarks/run", {method: "POST", body: JSON.stringify({
        project_id: el.querySelector("#b-project").value,
        target_id: el.querySelector("#b-target").value,
        policy_id: el.querySelector("#b-policy").value,
        suite_key: el.querySelector("#b-suite").value,
        authorization: {authorized_by: EMAIL, acknowledged: true, scope: "benchmark run"},
        config: {}})});
      msg.textContent = "completed " + r.benchmark_id;
      viewBenchmarks(el);
    } catch (e) { msg.textContent = e.message; msg.className = "error-text"; }
  };
}

async function viewPolicy(el) {
  const [policies, conflicts] = await Promise.all([api("/policies"), Promise.resolve(null)]);
  el.innerHTML = `<h1>Policy & Permissions</h1>
    <div class="panel"><h3>Policies</h3><table>
      <tr><th>Name</th><th>Version</th><th>Active</th><th>Hash</th><th>Rules</th><th></th></tr>
      ${policies.map(p => `<tr><td>${esc(p.name)}</td><td>v${p.version}</td><td>${p.active ? badge("active") : badge("inactive")}</td>
        <td class="mono">${esc(p.document_hash)}</td><td>${p.document.rules.length}</td>
        <td class="row">
          ${!p.active ? `<button class="btn small" data-act="${esc(p.id)}">Activate</button>` : ""}
          <button class="btn small ghost" data-view="${esc(p.id)}">View</button>
          <button class="btn small ghost" data-test="${esc(p.id)}">Dry-run test</button>
        </td></tr>`).join("")}
    </table>
    <div class="row mt8">
      <input id="p-name" placeholder="policy name" style="max-width:220px">
      <button class="btn small" id="p-clone-default">Clone default policy</button>
      <span class="muted">editing a policy creates a new version; activation requires admin</span>
    </div>
    <div id="p-editor" class="hidden mt8"><textarea id="p-doc" rows="16"></textarea>
      <div class="row mt8"><button class="btn small" id="p-save">Save as new version</button><span id="p-msg" class="muted"></span></div></div>
    <div id="p-dryrun" class="hidden mt8">
      <h3>Dry-run decision test</h3>
      <div class="form-grid">
        <div><label>Tool</label><select id="d-tool">
          <option>sim_fs.read</option><option>sim_fs.write</option><option>sim_fs.delete</option>
          <option>sim_net.http</option><option>sim_marker.echo</option><option>unknown.tool</option>
        </select></div>
      </div>
      <button class="btn small mt8" id="d-run">Evaluate (no execution)</button>
      <pre id="d-out"></pre></div>
    </div>`;
  let editing = null;
  el.querySelectorAll("[data-view]").forEach(b => b.onclick = () => {
    const p = policies.find(x => x.id === b.dataset.view);
    editing = p;
    el.querySelector("#p-editor").classList.remove("hidden");
    el.querySelector("#p-doc").value = JSON.stringify(p.document, null, 2);
  });
  el.querySelectorAll("[data-act]").forEach(b => b.onclick = async () => {
    try { await api(`/policies/${b.dataset.act}/activate`, {method: "POST"}); viewPolicy(el); }
    catch (e) { alert(e.message); }
  });
  el.querySelectorAll("[data-test]").forEach(b => b.onclick = () => {
    el.querySelector("#p-dryrun").classList.remove("hidden");
    el.querySelector("#p-dryrun").dataset.policy = b.dataset.test;
  });
  el.querySelector("#p-clone-default").onclick = () => {
    const def = policies.find(p => p.name === "default");
    if (def) { el.querySelector("#p-editor").classList.remove("hidden");
      el.querySelector("#p-name").value = def.name + "-copy";
      el.querySelector("#p-doc").value = JSON.stringify(def.document, null, 2); editing = null; }
  };
  el.querySelector("#p-save").onclick = async () => {
    const msg = el.querySelector("#p-msg");
    try {
      await api("/policies", {method: "POST", body: JSON.stringify({
        name: el.querySelector("#p-name").value || (editing?.name + "-copy"),
        document: JSON.parse(el.querySelector("#p-doc").value)})});
      msg.textContent = "saved as new version (inactive until activated)";
      viewPolicy(el);
    } catch (e) { msg.textContent = e.message; msg.className = "error-text"; }
  };
  el.querySelector("#d-run").onclick = async () => {
    try {
      const r = await api("/policies/evaluate", {method: "POST", body: JSON.stringify({
        policy_id: el.querySelector("#p-dryrun").dataset.policy,
        tool_name: el.querySelector("#d-tool").value, arguments: {}})});
      el.querySelector("#d-out").textContent = JSON.stringify(r, null, 2);
    } catch (e) { el.querySelector("#d-out").textContent = e.message; }
  };
}

async function viewApprovals(el) {
  const pending = await api("/approvals/pending");
  el.innerHTML = `<h1>Approvals</h1>
    <div class="panel"><h3>Pending approval requests</h3>
    <table><tr><th>Requested</th><th>Tool</th><th>Arguments</th><th>Reason</th><th>Experiment</th><th></th></tr>
    ${pending.map(a => `<tr><td class="muted">${esc((a.requested_at || "").slice(0, 19))}</td>
      <td class="mono">${esc(a.tool_name)}</td><td class="mono">${esc(JSON.stringify(a.arguments))}</td>
      <td class="muted">${esc(a.reason)}</td>
      <td><a class="link" href="#/explorer/${esc(a.experiment_id)}">${esc(a.experiment_id.slice(0, 12))}…</a></td>
      <td class="row">
        <button class="btn small" data-appr="${esc(a.id)}">Approve & execute</button>
        <button class="btn small ghost" data-deny="${esc(a.id)}">Deny</button></td></tr>`).join("")
      || '<tr><td colspan=6 class="muted">nothing pending</td></tr>'}
    </table>
    <p class="muted">Approval requires the admin role. Approved actions execute in the experiment's configured gateway mode (simulated by default) — the execution mode is recorded in the trace.</p></div>`;
  el.querySelectorAll("[data-appr]").forEach(b => b.onclick = async () => {
    try { const r = await api(`/approvals/${b.dataset.appr}/decide`, {method: "POST",
      body: JSON.stringify({decision: "approved", reason: "approved via dashboard"})});
      alert("executed: " + JSON.stringify(r.executed?.result)); viewApprovals(el);
    } catch (e) { alert(e.message); }
  });
  el.querySelectorAll("[data-deny]").forEach(b => b.onclick = async () => {
    await api(`/approvals/${b.dataset.deny}/decide`, {method: "POST",
      body: JSON.stringify({decision: "denied", reason: "denied via dashboard"})});
    viewApprovals(el);
  });
}

async function viewAudit(el) {
  let audit = [];
  try { audit = await api("/admin/audit?limit=100"); } catch { audit = null; }
  const events = await api("/events?limit=60");
  el.innerHTML = `<h1>Audit & Reports</h1>
    ${audit === null ? '<div class="panel muted">Audit log requires the admin role.</div>' :
    `<div class="panel"><h3>Administrative audit trail</h3><table>
      <tr><th>When</th><th>Actor</th><th>Action</th><th>Object</th><th>Detail</th></tr>
      ${audit.map(a => `<tr><td class="muted">${esc((a.created_at || "").slice(0, 19))}</td>
        <td>${esc(a.actor)}</td><td class="mono">${esc(a.action)}</td>
        <td class="mono">${esc(a.object_type)} ${esc(a.object_id.slice(0, 14))}</td>
        <td class="mono" style="font-size:11px">${esc(JSON.stringify(a.detail).slice(0, 100))}</td></tr>`).join("")}
    </table></div>`}
    <div class="panel"><h3>Recent platform events</h3><div class="timeline">
      ${events.map(ev => `<div class="tl-item"><span class="type">${esc(ev.type)}</span>
        <span class="t"> ${esc((ev.created_at || "").slice(0, 19))} · ${esc(ev.actor)}</span>
        <div class="t mono">${esc(JSON.stringify(ev.payload).slice(0, 140))}</div></div>`).join("")}
    </div></div>
    <div class="panel"><h3>Export</h3>
      <p class="muted">Machine-readable export via the API: <span class="mono">GET /api/v1/experiments/{id}</span>,
      <span class="mono">GET /api/v1/findings</span>, <span class="mono">GET /api/v1/events</span>,
      <span class="mono">GET /api/v1/benchmarks</span> (Bearer auth). OpenAPI: <a class="link" href="/api/docs">/api/docs</a>.</p></div>`;
}

/* ------------------------------------------------------------------ login */

function viewLogin(el) {
  el.innerHTML = `<div class="login-box panel">
    <h1 style="margin-top:0">Sign in to GUARDRAIL-X</h1>
    <label>Email</label><input id="l-email" value="admin@guardrailx.local">
    <label>Password</label><input id="l-pass" type="password">
    <div class="row mt8"><button class="btn" id="l-btn">Sign in</button></div>
    <div id="l-msg" class="error-text hidden"></div>
    <p class="muted" style="font-size:12px">First run: the generated admin password is printed to
    <span class="mono">data/initial_admin_password.txt</span>.</p></div>`;
  const doLogin = async () => {
    const msg = el.querySelector("#l-msg");
    try {
      const r = await api("/auth/login", {method: "POST", body: JSON.stringify({
        email: el.querySelector("#l-email").value, password: el.querySelector("#l-pass").value})});
      setSession(r.access_token, r.role, r.email);
      route();
    } catch (e) { msg.textContent = e.message; msg.classList.remove("hidden"); }
  };
  el.querySelector("#l-btn").onclick = doLogin;
  el.querySelector("#l-pass").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
}

/* ------------------------------------------------------------------ router */

async function route() {
  const el = document.getElementById("view");
  const hash = location.hash.replace(/^#\//, "");
  const [page, param] = hash.split("/");
  renderNav(TOKEN ? page : "");
  if (state.refreshTimer) { clearInterval(state.refreshTimer); state.refreshTimer = null; }
  el.innerHTML = '<div class="loading">Loading…</div>';
  try {
    if (!TOKEN) return viewLogin(el);
    switch (page || "dashboard") {
      case "dashboard": return await viewDashboard(el);
      case "targets": return await viewTargets(el);
      case "lab": return await viewLab(el);
      case "explorer": return await viewExplorer(el, param);
      case "findings": return await viewFindings(el, param);
      case "benchmarks": return await viewBenchmarks(el);
      case "policy": return await viewPolicy(el);
      case "approvals": return await viewApprovals(el);
      case "audit": return await viewAudit(el);
      default: return await viewDashboard(el);
    }
  } catch (e) {
    el.innerHTML = `<div class="panel error-text">Failed to load: ${esc(e.message)}</div>`;
  }
}

window.addEventListener("hashchange", route);
document.getElementById("logout-btn").onclick = async () => {
  try { await api("/auth/logout", {method: "POST"}); } catch {}
  setSession("", "", ""); location.hash = "#/dashboard"; route();
};

renderSession();
route();
setInterval(async () => {  // emergency-stop indicator poll
  if (!TOKEN) return;
  try { const r = await api("/ready"); document.getElementById("es-indicator").classList.toggle("hidden", !r.emergency_stop); }
  catch {}
}, 10000);
