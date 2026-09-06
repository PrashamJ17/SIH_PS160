// Split out of index.html so the dashboard can be served under a Content Security
// Policy with no 'unsafe-inline' at all. Loaded from the same origin; nothing here
// reaches the network except this service's own API.
"use strict";
const API = "/api/v1";
let report = null;
let reportId = null;
let captureFile = null;

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value == null ? "" : value)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// Every value below came out of a packet capture and is attacker-influenced. Nothing is
// inserted with innerHTML without passing through esc() first.
const row = (cells) => "<tr>" + cells.map((c) => `<td>${c}</td>`).join("") + "</tr>";

async function health() {
  try {
    const r = await fetch("/health");
    const b = await r.json();
    $("build").textContent = b.build || b.version;
  } catch (e) {
    $("build").textContent = "service unreachable";
  }
}

function show(view) {
  for (const button of document.querySelectorAll("#tabs button")) {
    button.setAttribute("aria-selected", String(button.dataset.view === view));
  }
  for (const id of ["overview","inventory","findings","exposure","threats","pqc",
                    "remediation","detail"]) {
    $(id).hidden = id !== view;
  }
}

async function upload(file) {
  captureFile = file;
  $("status").textContent = "analysing…";
  const body = new FormData();
  body.append("file", file);
  let response;
  try {
    response = await fetch(`${API}/analyse?baseline=default`, { method: "POST", body });
  } catch (e) {
    $("status").textContent = "the service could not be reached";
    return;
  }
  const payload = await response.json();
  if (!response.ok) {
    $("status").textContent = payload.detail || "the capture could not be analysed";
    return;
  }
  reportId = payload.report_id;
  $("status").textContent = "";
  $("source").textContent = `${payload.source} · classifier ${payload.classifier}`;
  report = await (await fetch(`${API}/reports/${reportId}`)).json();
  $("tabs").hidden = false;
  renderAll();
  show("overview");
}

function renderAll() {
  renderOverview();
  renderInventory();
  renderFindings();
  renderExposure();
  renderThreats();
  renderPQC();
  renderRemediation();
}

function renderOverview() {
  const e = report.executive;
  const bySeverity = Object.entries(e.findings_by_severity || {})
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `<div class="card"><div class="value sev-${esc(s)}">${n}</div>
      <div class="label">${esc(s)}</div></div>`).join("");
  $("overview").innerHTML = `
    <h2>Estate overview</h2>
    <p class="headline"><strong>${esc(e.headline)}</strong></p>
    <div class="cards">
      <div class="card"><div class="value grade-${esc(e.estate_grade)}">${esc(e.estate_grade)}</div>
        <div class="label">grade</div></div>
      <div class="card"><div class="value">${e.estate_score}</div>
        <div class="label">score / 100</div></div>
      <div class="card"><div class="value">${e.tunnels_assessed}</div>
        <div class="label">tunnels</div></div>
      <div class="card"><div class="value">${e.tunnels_undocumented}</div>
        <div class="label">undocumented</div></div>
      ${bySeverity}
    </div>
    <div class="note">
      <span class="tag verified">Section A — verified</span>
      ${e.verified_findings} finding(s) read directly from the negotiation. Facts; no
      confidence value applies.
      <br><br>
      <span class="tag inferred">Section B — inferred</span>
      ${e.inferred_findings} finding(s) estimated from traffic patterns by a statistical
      model. Every one states a confidence and none is compliance evidence.
    </div>
    <ul>${(e.key_points || []).map((p) => `<li>${esc(p)}</li>`).join("")}</ul>`;
}

function renderInventory() {
  const entries = report.inventory.entries || [];
  const rows = entries.map((entry) => `
    <tr data-tunnel="${esc(entry.tunnel_id)}">
      <td class="mono">${esc(entry.tunnel_id)}</td>
      <td class="mono">${esc(entry.endpoints[0])} &harr; ${esc(entry.endpoints[1])}</td>
      <td>${entry.status === "undocumented"
            ? '<span class="tag undocumented">undocumented</span>'
            : esc(entry.status)}</td>
      <td>${esc(entry.negotiated_suite || "—")}</td>
      <td>${entry.packet_count}</td>
    </tr>`).join("");
  const unobserved = (report.inventory.unobserved || []).map((k) =>
    `<li class="mono">${esc(k.endpoints[0])} &harr; ${esc(k.endpoints[1])}
      ${k.name ? "(" + esc(k.name) + ")" : ""}</li>`).join("");
  $("inventory").innerHTML = `
    <h2>Inventory</h2>
    ${entries.length ? `<table><thead><tr><th>Tunnel</th><th>Endpoints</th><th>Status</th>
      <th>Negotiated suite</th><th>Packets</th></tr></thead><tbody>${rows}</tbody></table>`
      : '<p class="empty">No tunnels were observed.</p>'}
    ${unobserved ? `<h2>Documented but not observed</h2><ul>${unobserved}</ul>` : ""}`;
  bindTunnelRows("inventory");
}

function findingCard(finding, section) {
  const confidence = finding.confidence
    ? `<dt>Confidence</dt><dd>${finding.confidence.value.toFixed(2)}
       (${esc(finding.confidence.method)})</dd>` : "";
  return `<div class="finding ${section}">
    <h4><span class="tag ${section}">Section ${section === "verified" ? "A — verified"
      : "B — inferred"}</span>
      <span class="sev-${esc(finding.severity)}">${esc(finding.severity)}</span>
      · ${esc(finding.rule_id)} — ${esc(finding.title)}</h4>
    <dl>
      ${finding.tunnel_id ? `<dt>Tunnel</dt><dd class="mono">${esc(finding.tunnel_id)}</dd>` : ""}
      ${confidence}
      <dt>Evidence</dt><dd>${esc(finding.evidence)}</dd>
      <dt>Standard</dt><dd>${esc(finding.standard_ref)}</dd>
      <dt>Remediation</dt><dd>${esc(finding.remediation_hint)}</dd>
    </dl></div>`;
}

function renderFindings() {
  const a = report.section_a_verified || [];
  const b = report.section_b_inferred || [];
  $("findings").innerHTML = `
    <h2>Section A — verified findings</h2>
    <p class="empty">Read from the negotiation. Deterministic; no confidence applies.</p>
    ${a.length ? a.map((f) => findingCard(f, "verified")).join("")
      : '<p class="empty">No verified findings.</p>'}
    <h2>Section B — inferred findings</h2>
    <p class="empty">Estimated from traffic patterns. Not compliance evidence.</p>
    ${b.length ? b.map((f) => findingCard(f, "inferred")).join("")
      : '<p class="empty">No inferred findings.</p>'}`;
}

// Widths come from a fixed set of classes rather than a style attribute. The dashboard
// is served under a Content Security Policy with no 'unsafe-inline', which blocks inline
// styles outright — so a style attribute here would render every bar at zero width, and
// only in the browser. Twenty 5% steps is more resolution than a contribution bar needs.
function contributionBar(value) {
  const step = Math.max(1, Math.min(20, Math.round(Math.abs(value) * 400 / 5)));
  return `<div class="bar ${value >= 0 ? "pos" : "neg"}"><span class="w${step}"></span></div>`;
}

function renderExposure() {
  const entries = report.metadata_exposure.entries || [];
  const rows = entries.map((entry) => `
    <tr data-tunnel="${esc(entry.tunnel_id)}">
      <td class="mono">${esc(entry.tunnel_id)}</td>
      <td class="mono">${esc(entry.endpoints[0])} &harr; ${esc(entry.endpoints[1])}</td>
      <td>${entry.total_bytes} bytes / ${entry.total_packets} packets</td>
      <td>${entry.session_count}</td>
      <td>${(entry.active_hours || []).map((h) => String(h).padStart(2, "0") + ":00")
            .join(", ") || '<span class="empty">none observed</span>'}</td>
      <td>${entry.inferred_traffic
            ? `${esc(entry.inferred_traffic)} <span class="tag inferred">inferred
               ${entry.inferred_traffic_confidence.value.toFixed(2)}</span>`
            : '<span class="empty">not stated</span>'}</td>
    </tr>`).join("");
  $("exposure").innerHTML = `
    <h2>What encryption does not hide</h2>
    <div class="note">${esc(report.metadata_exposure.note)}</div>
    ${entries.length ? `<table><thead><tr><th>Tunnel</th><th>Endpoints</th><th>Volume</th>
      <th>Sessions</th><th>Active hours</th><th>Inferred application</th></tr></thead>
      <tbody>${rows}</tbody></table>`
      : '<p class="empty">No tunnels were observed.</p>'}`;
  bindTunnelRows("exposure");
}

function renderThreats() {
  const rows = (report.threat_matrix.rows || []).map((r) => row([
    `${esc(r.technique)} — ${esc(r.technique_name)}` +
      (r.includes_inferred ? ' <span class="tag inferred">includes inferred</span>' : ""),
    `<span class="sev-${esc(r.severity)}">${esc(r.severity)}</span>`,
    r.tunnel_ids.map(esc).join(", "),
    r.rule_ids.map(esc).join(", "),
    r.cves.length ? r.cves.map((c) =>
      `<strong>${esc(c.cve_id)}</strong> (CVSS ${c.cvss_score})<br>${esc(c.summary)}
       <br><em>Scope:</em> ${esc(c.scope_note)}`).join("<hr>")
      : '<span class="empty">none catalogued</span>',
  ])).join("");
  const uncategorised = report.threat_matrix.uncategorised_rules || [];
  $("threats").innerHTML = `
    <h2>Threat matrix</h2>
    ${rows ? `<table><thead><tr><th>Technique</th><th>Severity</th><th>Tunnels</th>
      <th>Findings</th><th>Published vulnerabilities</th></tr></thead>
      <tbody>${rows}</tbody></table>`
      : '<p class="empty">No findings map to an adversary technique.</p>'}
    ${uncategorised.length ? `<p class="empty">Findings with no technique mapped, listed
      so the matrix is not read as complete: ${uncategorised.map(esc).join(", ")}.</p>` : ""}`;
}

function renderPQC() {
  const rows = (report.pqc.entries || []).map((e) => row([
    `<span class="mono">${esc(e.tunnel_id)}</span>`,
    esc(e.grade),
    esc(e.rationale),
  ])).join("");
  $("pqc").innerHTML = `
    <h2>Post-quantum readiness</h2>
    <div class="note">${esc(report.pqc.note)}</div>
    ${rows ? `<table><thead><tr><th>Tunnel</th><th>Grade</th><th>Reasoning</th></tr></thead>
      <tbody>${rows}</tbody></table>`
      : '<p class="empty">No post-quantum assessment in this report.</p>'}`;
}

function renderRemediation() {
  const tunnels = (report.inventory.entries || []).map((e) =>
    `<option value="${esc(e.tunnel_id)}">${esc(e.tunnel_id)}</option>`).join("");
  $("remediation").innerHTML = `
    <h2>Remediation</h2>
    <p>Generate a change package from the observed negotiation. The tool produces
       documents; a person applies them.</p>
    <p><select id="remediate-tunnel">${tunnels}</select>
       <button class="action" id="remediate-go">Generate</button>
       <span class="status" id="remediate-status"></span></p>
    <div id="remediate-output"></div>`;
  const button = $("remediate-go");
  if (button) button.addEventListener("click", generatePackage);
}

async function generatePackage() {
  const tunnelId = $("remediate-tunnel").value;
  $("remediate-status").textContent = "generating…";
  const body = new FormData();
  body.append("file", captureFile);
  const response = await fetch(
    `${API}/remediate/${encodeURIComponent(tunnelId)}?baseline=default`,
    { method: "POST", body });
  const payload = await response.json();
  $("remediate-status").textContent = "";
  if (!response.ok) {
    $("remediate-output").innerHTML =
      `<p class="empty">${esc(payload.detail || "no change package could be produced")}</p>`;
    return;
  }
  const p = payload.package;
  const steps = p.sequence.map((s) =>
    `<li><strong>[${esc(s.role)}]</strong> ${esc(s.description)}
     <br><span class="mono">${esc(s.action)}</span></li>`).join("");
  $("remediate-output").innerHTML = `
    <h2>${esc(p.tunnel_id)}</h2>
    <p>Addresses ${p.findings_addressed.map(esc).join(", ")}.
       Expected disruption ${p.blast_radius.estimated_disruption_s}s.
       ${p.requires_maintenance_window ? "A maintenance window is required." : ""}</p>
    <div class="note">${payload.assumptions.map(esc).join("<br><br>")}</div>
    <h2>Sequence</h2><ol>${steps}</ol>
    <h2>Local end — ${esc(p.local_config.filename)}</h2>
    <button class="action" data-copy="local">Copy</button>
    <pre id="config-local">${esc(p.local_config.content)}</pre>
    <h2>Peer end — ${esc(p.peer_config.filename)}</h2>
    <button class="action" data-copy="peer">Copy</button>
    <pre id="config-peer">${esc(p.peer_config.content)}</pre>`;
  for (const button of document.querySelectorAll("[data-copy]")) {
    button.addEventListener("click", () => {
      const text = $(`config-${button.dataset.copy}`).textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(text);
      button.textContent = "Copied";
    });
  }
}

function bindTunnelRows(container) {
  for (const tr of $(container).querySelectorAll("tr[data-tunnel]")) {
    tr.addEventListener("click", () => openTunnel(tr.dataset.tunnel));
  }
}

async function openTunnel(tunnelId) {
  const response = await fetch(
    `${API}/tunnels/${encodeURIComponent(tunnelId)}?report_id=${encodeURIComponent(reportId)}`);
  if (!response.ok) return;
  const detail = await response.json();
  const exposure = detail.exposure;
  const explanation = exposure && exposure.explanation;
  const shap = explanation ? `
    <h2>Why the model said that</h2>
    <div class="note" id="shap-sentence">${esc(explanation.sentence)}</div>
    <p class="empty">Based on ${explanation.windows} traffic window(s).</p>
    <table id="shap-table"><thead><tr><th>Feature</th><th>Contribution</th><th></th></tr>
      </thead><tbody>${explanation.contributions.map(([name, value]) => row([
        esc(name), value.toFixed(4), contributionBar(value)])).join("")}</tbody></table>`
    : '<p class="empty" id="shap-absent">No inference was made for this tunnel.</p>';

  $("detail").innerHTML = `
    <p><button class="action" id="back">&larr; Back</button></p>
    <h2 class="mono">${esc(tunnelId)}</h2>
    <table><tbody>
      <tr><th>Endpoints</th><td class="mono">${esc(detail.tunnel.endpoints[0])} &harr;
        ${esc(detail.tunnel.endpoints[1])}</td></tr>
      <tr><th>Status</th><td>${esc(detail.tunnel.status)}</td></tr>
      <tr><th>IKE version</th><td>${esc(detail.tunnel.ike_version || "—")}</td></tr>
      <tr><th>Exchange</th><td>${esc(detail.tunnel.exchange_type || "—")}</td></tr>
      <tr><th>Negotiated suite</th><td class="mono">
        ${esc(detail.tunnel.negotiated_suite || "—")}</td></tr>
      <tr><th>Packets</th><td>${detail.tunnel.packet_count}</td></tr>
      ${detail.pqc ? `<tr><th>Post-quantum</th><td>${esc(detail.pqc.grade)} —
        ${esc(detail.pqc.rationale)}</td></tr>` : ""}
    </tbody></table>
    <h2>Findings</h2>
    <div id="detail-findings">${detail.findings.length
      ? detail.findings.map((f) => findingCard(f, f.confidence ? "inferred" : "verified")).join("")
      : '<p class="empty">No findings for this tunnel.</p>'}</div>
    ${exposure ? `<h2>Inferred application</h2>
      <p>${exposure.inferred_traffic
        ? `${esc(exposure.inferred_traffic)} <span class="tag inferred">inferred
           ${exposure.inferred_traffic_confidence.value.toFixed(2)}</span>`
        : '<span class="empty">not stated</span>'}</p>` : ""}
    ${shap}`;
  $("back").addEventListener("click", () => show("inventory"));
  show("detail");
}

for (const button of document.querySelectorAll("#tabs button")) {
  button.addEventListener("click", () => show(button.dataset.view));
}
$("file").addEventListener("change", (event) => {
  if (event.target.files.length) upload(event.target.files[0]);
});
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);
});
health();
