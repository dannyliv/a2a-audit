/* a2a-audit — client-side static audit engine.
 * Mirrors the Python static checks. The LLM skill-intent classifier and
 * cryptographic signature verification run only in the CLI; in the browser the
 * skills check uses the heuristic gate and the signature check is presence-only.
 */
"use strict";

const ASI = {
  ASI01: "ASI01: Agent Goal Hijack",
  ASI02: "ASI02: Tool Misuse & Exploitation",
  ASI03: "ASI03: Agent Identity & Privilege Abuse",
  ASI04: "ASI04: Agentic Supply Chain Compromise",
  ASI05: "ASI05: Unexpected Code Execution",
  ASI06: "ASI06: Memory & Context Poisoning",
  ASI07: "ASI07: Insecure Inter-Agent Communication",
  ASI08: "ASI08: Cascading Agent Failures",
  ASI09: "ASI09: Human-Agent Trust Exploitation",
  ASI10: "ASI10: Rogue Agents",
};
const SEV_W = { INFO: 0, LOW: 3, MEDIUM: 8, HIGH: 18, CRITICAL: 30 };
const CHK_W = { auth: 1.4, signature: 1.2, transport: 1.3, skills: 1.5, exposure: 1.0, webhook: 1.1 };

const INJECTION = [
  /ignore\s+(all\s+|the\s+)?(previous|prior|above|earlier)\s+(instruction|prompt|message|guidance|guideline|context|question|rule)/i,
  /disregard\s+.{0,30}(instruction|rule|guideline|guidance|prompt|policy)/i,
  /forget\s+(everything|all|what|the|any|previous|prior)/i,
  /(override|overrides|supersede|take[s]?\s+priority\s+over)\s+.{0,40}(previous|prior|any|the|your|system)/i,
  /without\s+any\s+(restriction|policy|rule|filter|limit)/i,
  /you\s+are\s+now\s+/i,
  /(developer|dev)\s+mode|jailbreak|\bDAN\b/i,
  /act\s+as\s+(an?\s+)?(unrestricted|jailbro|dan|evil|admin|root|malicious)/i,
  /(reveal|print|repeat|disclose|leak|expose|dump)\s+.{0,40}(system\s+prompt|developer\s+instruction|instruction|configuration|secret|hidden)/i,
  /<\/?(system|tool_call|tool|assistant|developer|im_start|im_end)>/i,
  /exfiltrat/i,
  /(send|transmit|upload|forward|post|push|attach|leak|smuggle)\s+.{0,80}(api\s*key|token|credential|password|secret|cookie|session|conversation|keystroke|\/etc\/|private\s+key|personal\s+data)/i,
  /(send|transmit|upload|forward|post|exfiltrate)\s+.{0,80}(to\s+)?(https?:\/\/|attacker|our\s+server|remote\s+host|external|collector|webhook)/i,
  /(collect|harvest|steal|capture|phish|grab|obtain)\s+.{0,40}(password|token|credential|cookie|secret|login|api\s*key)/i,
  /session\s+cookie|keystroke/i,
  /base64[\s-]*.{0,20}(encode|key|token|secret|credential|password)/i,
  /\b(curl|wget|bash\s+-c|\/bin\/sh|powershell|rm\s+-rf)\b/i,
  /BEGIN\s+.{0,20}PRIVATE\s+KEY/i,
  /(do\s+not|don'?t|never)\s+(tell|inform|mention|notify|alert|reveal|disclose)\s+(the\s+)?(user|human|admin)?/i,
  /\b(silently|quietly|secretly|covertly)\b/i,
  /(obey|follow|comply\s+with)\s+(them|it|those|any|the)/i,
  /(override|bypass|ignore|disable)\s+.{0,30}(safety|guardrail|filter|policy|restriction)/i,
];

function F(o) {
  return Object.assign(
    { remediation: "", asi_secondary: null, evidence: null, passed: false, caveat: null }, o
  );
}

function normalize(raw) {
  const interfaces = [];
  if (Array.isArray(raw.supportedInterfaces) && raw.supportedInterfaces.length) {
    raw.supportedInterfaces.forEach((i) => i && interfaces.push(i));
  } else {
    if (typeof raw.url === "string") interfaces.push({ url: raw.url, transport: raw.preferredTransport });
    if (Array.isArray(raw.additionalInterfaces)) raw.additionalInterfaces.forEach((i) => i && interfaces.push(i));
  }
  let primary = typeof raw.url === "string" ? raw.url : (interfaces[0] && interfaces[0].url) || null;
  const caps = (raw.capabilities && typeof raw.capabilities === "object") ? raw.capabilities : {};
  const schemes = (raw.securitySchemes && typeof raw.securitySchemes === "object") ? raw.securitySchemes : {};
  const reqs = [].concat(
    Array.isArray(raw.security) ? raw.security : [],
    Array.isArray(raw.securityRequirements) ? raw.securityRequirements : []
  );
  let spec = "v0.3";
  if ("supportedInterfaces" in raw) spec = "v1.0";
  else if (typeof raw.protocolVersion === "string") {
    if (raw.protocolVersion.startsWith("1.")) spec = "v1.0";
    else if (raw.protocolVersion.startsWith("0.2")) spec = "v0.2";
  } else if (!("url" in raw)) spec = "unknown";
  return {
    name: raw.name, primary_url: primary, interfaces, provider: raw.provider, capabilities: caps,
    security_schemes: schemes, security_requirements: reqs, skills: Array.isArray(raw.skills) ? raw.skills : [],
    signatures: Array.isArray(raw.signatures) ? raw.signatures : [],
    supports_extended_card: !!(raw.supportsAuthenticatedExtendedCard || caps.extendedAgentCard),
    spec_version: spec,
  };
}

function schemeKind(s) {
  if (!s || typeof s !== "object") return "unknown";
  if (s.type) return s.type;
  if (s.flows) return "oauth2";
  if (s.openIdConnectUrl) return "openIdConnect";
  if (s.scheme) return "http";
  if (s.name && (s.in || s.location)) return "apiKey";
  return "unknown";
}
const isHttp = (u) => typeof u === "string" && u.toLowerCase().startsWith("http://");

function checkAuth(c) {
  const out = [];
  const schemes = c.security_schemes, reqs = c.security_requirements;
  const hasSchemes = Object.keys(schemes).length > 0;
  if (!hasSchemes && reqs.length === 0) {
    out.push(F({ check_id: "auth", title: "No authentication declared", severity: "MEDIUM", asi_primary: "ASI03",
      message: "The card declares no securitySchemes and no security requirements.",
      remediation: "If not an intentional public demo, declare a securityScheme and matching requirement.",
      caveat: "Public demo agents may leave auth undeclared intentionally." }));
    return out;
  }
  if (hasSchemes && reqs.length === 0)
    out.push(F({ check_id: "auth", title: "Security schemes defined but not required", severity: "LOW", asi_primary: "ASI03",
      message: "securitySchemes declared but no `security` requirement; auth may not be enforced." }));
  let strong = false;
  for (const [nm, s] of Object.entries(schemes)) {
    const k = schemeKind(s);
    if (["oauth2", "openIdConnect", "mutualTLS"].includes(k)) strong = true;
    if (k === "apiKey" && (s.in || s.location) === "query")
      out.push(F({ check_id: "auth", title: `API key in query string (${nm})`, severity: "MEDIUM", asi_primary: "ASI03",
        message: "API keys in the URL leak via logs, proxies, and Referer.", remediation: "Move the key to a header.", evidence: `${nm}: apiKey in=query` }));
    if (k === "http" && (s.scheme || "").toLowerCase() === "basic")
      out.push(F({ check_id: "auth", title: `HTTP Basic auth (${nm})`, severity: "MEDIUM", asi_primary: "ASI03",
        message: "HTTP Basic sends reusable credentials on every request.", remediation: "Prefer Bearer/OAuth2/OIDC/mTLS." }));
    if (k === "oauth2" && s.flows) {
      const dep = Object.keys(s.flows).filter((f) => f === "implicit" || f === "password");
      if (dep.length) out.push(F({ check_id: "auth", title: `Deprecated OAuth2 flow (${nm}: ${dep.join(", ")})`, severity: "LOW", asi_primary: "ASI03",
        message: "The implicit and password grants are deprecated.", remediation: "Use authorizationCode (PKCE) or clientCredentials." }));
    }
  }
  if (strong && reqs.length)
    out.push(F({ check_id: "auth", title: "Strong authentication required", severity: "INFO", asi_primary: "ASI03", message: "Requires OAuth2/OIDC/mTLS.", passed: true }));
  return out;
}

function checkSignature(c) {
  if (!c.signatures.length)
    return [F({ check_id: "signature", title: "Card is unsigned", severity: "MEDIUM", asi_primary: "ASI04",
      message: "No `signatures` present; the card cannot be cryptographically verified and can be tampered.",
      remediation: "Sign with a detached JWS (RFC 7515 + RFC 8785 JCS) per spec section 8.4." })];
  return [F({ check_id: "signature", title: "Card is signed (verify in CLI)", severity: "INFO", asi_primary: "ASI04",
    message: `${c.signatures.length} signature(s) present. Cryptographic verification runs in the CLI, not this static demo.`, passed: true,
    caveat: "Browser demo detects presence only; run `a2a-audit <url>` to verify the JWS." })];
}

function checkTransport(c) {
  const out = [];
  if (!c.interfaces.length && !c.primary_url)
    out.push(F({ check_id: "transport", title: "No service endpoint declared", severity: "MEDIUM", asi_primary: "ASI04",
      message: "No url / interface to reach or assess." }));
  const plain = [];
  c.interfaces.forEach((i) => { if (isHttp(i.url)) plain.push(i.url); });
  if (isHttp(c.primary_url) && !plain.includes(c.primary_url)) plain.push(c.primary_url);
  plain.forEach((u) => out.push(F({ check_id: "transport", title: "Plaintext (HTTP) endpoint", severity: "HIGH", asi_primary: "ASI04", asi_secondary: "ASI07",
    message: "An endpoint is served over plaintext HTTP; traffic and credentials are exposed.", remediation: "Serve all endpoints over HTTPS.", evidence: u })));
  const p = c.provider;
  if (!p || !(p.organization || p.url))
    out.push(F({ check_id: "transport", title: "No provider information", severity: "LOW", asi_primary: "ASI04", message: "No provider declared; reduced accountability.", remediation: "Add provider organization + url." }));
  else if (isHttp(p.url))
    out.push(F({ check_id: "transport", title: "Provider URL is plaintext HTTP", severity: "LOW", asi_primary: "ASI04", message: "Provider URL uses HTTP.", evidence: p.url }));
  if (!plain.length && c.primary_url)
    out.push(F({ check_id: "transport", title: "All endpoints use HTTPS", severity: "INFO", asi_primary: "ASI04", message: "Declared endpoints use HTTPS.", passed: true }));
  return out;
}

function checkSkills(c) {
  const out = [];
  let flagged = 0;
  c.skills.forEach((s) => {
    const text = [s.name, s.description, ...(s.examples || [])].filter(Boolean).join("\n");
    if (!text.trim()) return;
    const hit = INJECTION.find((re) => re.test(text));
    if (hit) {
      flagged++;
      out.push(F({ check_id: "skills", title: `Suspicious skill description (unverified): ${s.id || s.name || "skill"}`, severity: "LOW", asi_primary: "ASI01",
        message: "Heuristic gate matched possible injection intent. Model-backed verification (local DeBERTa or Qwen2.5) runs in the CLI.",
        evidence: "matched injection heuristic", caveat: "Heuristic-only demo: expect some false positives; the CLI model stage confirms or clears these." }));
    }
  });
  if (!flagged && c.skills.length)
    out.push(F({ check_id: "skills", title: "No injection patterns in skill descriptions", severity: "INFO", asi_primary: "ASI01", message: `Screened ${c.skills.length} skill(s) (heuristic).`, passed: true }));
  return out;
}

function checkExposure(c) {
  const out = [];
  const hasAuth = Object.keys(c.security_schemes).length > 0 || c.security_requirements.length > 0;
  if (c.supports_extended_card) {
    if (!hasAuth) out.push(F({ check_id: "exposure", title: "Extended card advertised without authentication", severity: "MEDIUM", asi_primary: "ASI03",
      message: "Advertises an authenticated extended card but declares no auth.", remediation: "Require a securityScheme before serving the extended card." }));
    else out.push(F({ check_id: "exposure", title: "Extended card present (audit it separately)", severity: "INFO", asi_primary: "ASI03", message: "Audit the authenticated extended card endpoint separately." }));
  }
  const noId = c.skills.filter((s) => !s.id).length;
  const noTag = c.skills.filter((s) => !(Array.isArray(s.tags) && s.tags.length)).length;
  if (noId) out.push(F({ check_id: "exposure", title: `${noId} skill(s) missing an id`, severity: "LOW", asi_primary: "ASI03", message: "Skills without a stable id are hard to govern.", remediation: "Give every skill a unique id." }));
  if (noTag) out.push(F({ check_id: "exposure", title: `${noTag} skill(s) without tags`, severity: "LOW", asi_primary: "ASI03", message: "Untagged skills obscure capability scope.", remediation: "Tag each skill." }));
  if (!c.supports_extended_card && !noId && !noTag && c.skills.length)
    out.push(F({ check_id: "exposure", title: "No over-exposure indicators", severity: "INFO", asi_primary: "ASI03", message: "No extended-card gap; skills carry ids and tags.", passed: true }));
  return out;
}

function checkWebhook(c) {
  const push = !!c.capabilities.pushNotifications;
  if (!push) return [F({ check_id: "webhook", title: "Push notifications not enabled", severity: "INFO", asi_primary: "ASI07", message: "No client-webhook SSRF surface advertised.", passed: true })];
  const hasAuth = Object.keys(c.security_schemes).length > 0 || c.security_requirements.length > 0;
  const cav = "OWASP ASI07 emphasizes inter-agent spoofing/AitM; SSRF is partial here (ASI05 secondary).";
  if (!hasAuth) return [F({ check_id: "webhook", title: "Push notifications enabled with no declared auth", severity: "MEDIUM", asi_primary: "ASI07", asi_secondary: "ASI05",
    message: "Accepts push-notification webhooks but declares no auth; an unvalidated webhook-config endpoint is an SSRF pivot.",
    remediation: "Require auth to register webhooks; validate/allowlist URLs; block private IP ranges.", caveat: cav })];
  return [F({ check_id: "webhook", title: "Push notifications enabled (verify webhook URL validation)", severity: "LOW", asi_primary: "ASI07",
    message: "Confirm the agent validates client-supplied webhook URLs against an SSRF allowlist.", caveat: cav })];
}

// Banker's rounding (round-half-to-even) to match Python's round(), keeping the
// browser score identical to the CLI score.
function bankersRound(x) {
  const floor = Math.floor(x);
  const diff = x - floor;
  if (diff > 0.5) return floor + 1;
  if (diff < 0.5) return floor;
  return floor % 2 === 0 ? floor : floor + 1;
}

function audit(raw) {
  const c = normalize(raw);
  const findings = [].concat(checkAuth(c), checkSignature(c), checkTransport(c), checkSkills(c), checkExposure(c), checkWebhook(c));
  let penalty = 0;
  findings.forEach((f) => { if (!f.passed) penalty += (SEV_W[f.severity] || 0) * (CHK_W[f.check_id] || 1); });
  const score = Math.max(0, Math.min(100, bankersRound(100 - penalty)));
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const sevRank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const max = findings.filter((f) => !f.passed).reduce((m, f) => (sevRank[f.severity] > sevRank[m] ? f.severity : m), "INFO");
  return { spec_version: c.spec_version, score, grade, max_severity: max, findings, name: c.name };
}

/* ---------- UI ---------- */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[m]));
const GRADE_COLOR = { A: "var(--grade-a)", B: "var(--grade-b)", C: "var(--grade-c)", D: "var(--grade-d)", F: "var(--grade-f)" };

function renderResult(res, target, scroll = true) {
  const issues = res.findings.filter((f) => !f.passed).sort((a, b) => ({ INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[b.severity] - { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[a.severity]));
  const passed = res.findings.filter((f) => f.passed);
  const gc = GRADE_COLOR[res.grade];
  let rows = issues.map((f) => `
    <tr>
      <td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td class="asi">${f.asi_primary}${f.asi_secondary ? "/" + f.asi_secondary.split(":")[0] : ""}</td>
      <td><div class="f-title">${esc(f.title)}</div>
        ${f.evidence ? `<div class="f-ev">${esc(f.evidence)}</div>` : ""}
        ${f.remediation ? `<div class="f-fix">→ ${esc(f.remediation)}</div>` : ""}
        ${f.caveat ? `<div class="f-ev">⚠ ${esc(f.caveat)}</div>` : ""}
      </td>
    </tr>`).join("");
  if (!issues.length) rows = `<tr><td colspan="3" style="color:var(--green);font-family:var(--mono)">No issues found.</td></tr>`;
  const passNames = [...new Set(passed.map((f) => f.check_id))].join(", ");
  $("#result").innerHTML = `
    <div class="scorecard">
      <div class="grade-dial" style="box-shadow: inset 0 0 60px -20px ${gc}">
        <div class="g" style="color:${gc}">${res.grade}</div>
        <div class="s">${res.score}/100</div>
      </div>
      <div class="sc-meta">
        <h3>${esc(target)}</h3>
        <div class="sub">spec ${res.spec_version} · ${issues.length} issue${issues.length === 1 ? "" : "s"} · max severity ${res.max_severity}</div>
        <div class="pills">
          <span class="pill">ASI 2026 mapped</span>
          ${passNames ? `<span class="pill pass">passed: ${esc(passNames)}</span>` : ""}
        </div>
      </div>
    </div>
    <table class="findings"><thead><tr><th>Severity</th><th>ASI</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="hint">Heuristic-only browser audit. Model-backed classification and JWS signature verification run in the CLI: <code>a2a-audit ${esc(target.startsWith("http") ? target : "&lt;url&gt;")} --backend deberta</code></p>`;
  if (scroll) $("#result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function showError(msg) { $("#result").innerHTML = `<div class="err">${esc(msg)}</div>`; }

function auditText(text, target) {
  let raw;
  try { raw = JSON.parse(text); } catch (e) { showError("Invalid JSON: " + e.message); return; }
  if (typeof raw !== "object" || Array.isArray(raw)) { showError("Card must be a JSON object."); return; }
  renderResult(audit(raw), target || raw.name || "(pasted card)");
}

/* tabs */
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.classList.remove("active"));
  document.querySelectorAll(".pane").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  $("#pane-" + b.dataset.pane).classList.add("active");
}));

$("#runPaste").addEventListener("click", () => auditText($("#pasteBox").value, "(pasted card)"));

$("#runUrl").addEventListener("click", async () => {
  const url = $("#urlBox").value.trim();
  if (!url) { showError("Enter a URL or domain."); return; }
  let origin = url.includes("://") ? url : "https://" + url;
  const base = origin.replace(/\/$/, "");
  const candidates = base.endsWith(".json") ? [base] : [base + "/.well-known/agent-card.json", base + "/.well-known/agent.json"];
  $("#result").innerHTML = `<p class="hint">fetching ${esc(candidates[0])} …</p>`;
  for (const u of candidates) {
    try {
      const r = await fetch(u, { headers: { Accept: "application/json" } });
      if (!r.ok) continue;
      const raw = await r.json();
      renderResult(audit(raw), u);
      return;
    } catch (e) { /* CORS or network; try next */ }
  }
  showError("Could not fetch the card from the browser (most agents block cross-origin requests / CORS). Copy the card JSON into the Paste tab, or run the CLI: a2a-audit " + url);
});

/* load examples + aggregate */
fetch("data/examples.json").then((r) => r.json()).then((d) => {
  const grid = $("#examples");
  d.examples.forEach((ex) => {
    const g = ex.report.grade, gc = GRADE_COLOR[g] || "var(--ink)";
    const el = document.createElement("button");
    el.className = "ex";
    el.innerHTML = `<span class="gd" style="color:${gc}">${g}</span><div class="nm">${esc(ex.name)}</div><small>${ex.report.spec_version} · ${ex.report.score}/100</small>`;
    el.addEventListener("click", () => renderResult(audit(ex.card), ex.name));
    grid.appendChild(el);
  });
  // auto-show the injected-skill example as a striking default (no scroll:
  // the page must load at the top, not jump down to the result).
  const def = d.examples.find((e) => e.name === "injected-skill") || d.examples[0];
  if (def) renderResult(audit(def.card), def.name, false);
});

/* ---- pre-tested dataset (results pre-computed on-device with full DeBERTa) ---- */
function renderPrecomputed(rep, target) {
  const issues = (rep.findings || []).filter((f) => !f.passed).sort((a, b) => (
    { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[b.severity] -
    { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[a.severity]));
  const passed = (rep.findings || []).filter((f) => f.passed);
  const gc = GRADE_COLOR[rep.grade] || "var(--ink)";
  const asiShort = (f) => {
    const p = (f.asi && f.asi.primary || "").split(":")[0];
    const s = f.asi && f.asi.secondary ? "/" + (f.asi.secondary.split(":")[0]) : "";
    return p + s;
  };
  let rows = issues.map((f) => `
    <tr><td><span class="sev ${f.severity}">${f.severity}</span></td>
      <td class="asi">${asiShort(f)}</td>
      <td><div class="f-title">${esc(f.title)}</div>
        ${f.evidence ? `<div class="f-ev">${esc(f.evidence)}</div>` : ""}
        ${f.remediation ? `<div class="f-fix">→ ${esc(f.remediation)}</div>` : ""}
        ${f.caveat ? `<div class="f-ev">⚠ ${esc(f.caveat)}</div>` : ""}
      </td></tr>`).join("");
  if (!issues.length) rows = `<tr><td colspan="3" style="color:var(--green);font-family:var(--mono)">No issues found.</td></tr>`;
  const passNames = [...new Set(passed.map((f) => f.check_id))].join(", ");
  $("#result").innerHTML = `
    <div class="scorecard">
      <div class="grade-dial" style="box-shadow: inset 0 0 60px -20px ${gc}">
        <div class="g" style="color:${gc}">${rep.grade}</div><div class="s">${rep.score}/100</div>
      </div>
      <div class="sc-meta">
        <h3>${esc(target)}</h3>
        <div class="sub">spec ${rep.spec_version} · ${issues.length} issue${issues.length === 1 ? "" : "s"} · max severity ${rep.max_severity} · classifier ${esc(rep.classifier_mode || "deberta")}</div>
        <div class="pills">
          <span class="pill">ASI 2026 mapped</span>
          ${passNames ? `<span class="pill pass">passed: ${esc(passNames)}</span>` : ""}
        </div>
        <div class="precalc-badge">⛁ Pre-calculated on-device with the full DeBERTa classifier (2026-05-29). Not run live.</div>
      </div>
    </div>
    <table class="findings"><thead><tr><th>Severity</th><th>ASI</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table>
    <p class="hint">This is a stored result from a real on-device audit. Public agent card, point-in-time snapshot, shown for demonstration (not an accusation). Re-run live anytime: <code>a2a-audit ${esc(target.startsWith("http") ? target : "&lt;url&gt;")} --backend deberta</code></p>`;
  $("#result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

let PRETESTED = [];
fetch("data/pretested.json").then((r) => r.json()).then((d) => {
  PRETESTED = d.entries || [];
  const urlSel = $("#urlPreset"), jsonSel = $("#jsonPreset");
  const jc = $("#jsonCount"); if (jc) jc.textContent = PRETESTED.length;
  PRETESTED.forEach((e, i) => {
    const g = e.report.grade;
    const label = `[${g}] ${e.name || e.url}`.slice(0, 70);
    if (urlSel) { const o = document.createElement("option"); o.value = String(i); o.textContent = `[${g}] ${(e.url || e.name).replace(/^https?:\/\//, "").slice(0, 60)}`; urlSel.appendChild(o); }
    if (jsonSel) { const o = document.createElement("option"); o.value = String(i); o.textContent = label; jsonSel.appendChild(o); }
  });
  if (urlSel) urlSel.addEventListener("change", () => {
    const e = PRETESTED[+urlSel.value]; if (!e) return;
    $("#urlBox").value = e.url || "";
    renderPrecomputed(e.report, e.url || e.name);
  });
  if (jsonSel) jsonSel.addEventListener("change", () => {
    const e = PRETESTED[+jsonSel.value]; if (!e) return;
    $("#pasteBox").value = JSON.stringify(e.card, null, 2);
    renderPrecomputed(e.report, e.name || e.url);
  });
}).catch(() => { /* dataset optional */ });

fetch("data/aggregate.json").then((r) => r.json()).then((a) => {
  const total = a.n;
  const order = ["A", "B", "C", "D", "F"];
  const bars = order.filter((g) => a.grades[g]).map((g) => {
    const n = a.grades[g], pct = Math.round((n / total) * 100);
    return `<div class="b"><span style="color:${GRADE_COLOR[g]};font-weight:800">${g}</span>
      <div class="track"><div class="fill" style="width:${pct}%;background:${GRADE_COLOR[g]}"></div></div><span>${n}</span></div>`;
  }).join("");
  const freq = a.top_findings.map(([t, n]) => `<li><span>${esc(t)}</span><span class="n">${n}</span></li>`).join("");
  $("#agg-bars").innerHTML = bars;
  $("#agg-mean").innerHTML = `${a.mean_score}<small>/100</small>`;
  $("#agg-freq").innerHTML = freq;
  $("#agg-n").textContent = total;
  $("#agg-specs").textContent = Object.entries(a.specs).map(([k, v]) => `${k}: ${v}`).join("  ·  ");
});
