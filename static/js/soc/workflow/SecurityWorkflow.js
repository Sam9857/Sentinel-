/**
 * SecurityWorkflow — animated explanation of how BitSentinel turns a raw event into a response.
 * Standalone component: knows nothing about the dashboard. Used by templates/workflow.html.
 *
 * Every stage lists the real file / endpoint that implements it in this repository.
 * Packets are moved with requestAnimationFrame along connector paths measured from the live layout.
 */
import { h, clear, reducedMotion } from "../core/dom.js";

export const STAGES = [
  { id: "event", layer: 0, title: "Security event", short: "A request, login attempt or log line arrives", tone: "src",
    what: "Anything observable: an HTTP request hitting the server, a line in an access log, an uploaded log file, or a file hash submitted for analysis.",
    where: ["utils/live_monitor.py (simulate / self-tap / log-tail)", "POST /api/scan/log", "POST /api/scan/ip"], out: "Raw request / log record" },
  { id: "collect", layer: 1, title: "Data collection", short: "Parse and group traffic per source IP", tone: "core",
    what: "Log lines are parsed (Apache, Nginx, simple formats) and aggregated per IP: request count, failed logins, unique paths, error rate, payload size.",
    where: ["utils/log_parser.py", "utils/traffic_tap.py", "utils/log_tailer.py"], out: "ip_stats { requests, failures, paths, error_rate }" },
  { id: "extract", layer: 2, title: "Indicator extraction", short: "Pull out IPs, file hashes and URLs", tone: "core",
    what: "The observable indicators are isolated so each can be enriched: source IPs for reputation, MD5/SHA-1/SHA-256 for files. Uploaded files are hashed locally; the file is never forwarded.",
    where: ["services/malware_service.py → hash_bytes()", "services/geo_service.py → parse_ip()"], out: "IP · hash" },
  { id: "vt", layer: 3, title: "VirusTotal", short: "Engine verdicts for IPs and files", tone: "intel",
    what: "Queries API v3 with the server-side key. Returns how many antivirus engines flag the indicator and its community reputation. Cached for an hour to respect the free 4 requests/min quota.",
    where: ["services/providers.py → virustotal_ip() / virustotal_file()", "GET /api/intel/ip/<ip>", "GET /api/intel/hash/<hash>", "env: VIRUSTOTAL_API_KEY"], out: "malicious / suspicious / harmless counts" },
  { id: "abuse", layer: 3, title: "AbuseIPDB", short: "Crowd-sourced abuse reports", tone: "intel",
    what: "Returns an abuse-confidence percentage and the number of reports over 90 days for an IP address.",
    where: ["services/providers.py → abuseipdb_check()", "env: ABUSEIPDB_API_KEY"], out: "confidence %, report count" },
  { id: "ipi", layer: 3, title: "IP intelligence", short: "Location, ASN, proxy / VPN / Tor", tone: "intel",
    what: "IPinfo supplies geolocation, ASN and organisation. IPQualityScore (optional) adds proxy, VPN and Tor flags. Private ranges are never sent out.",
    where: ["services/providers.py → ipinfo_lookup() / ipqs_lookup()", "services/ip_intelligence_service.py", "env: IPINFO_API_KEY, IPQS_API_KEY"], out: "country, city, ASN, flags" },
  { id: "mal", layer: 3, title: "Malware analysis", short: "Hash lookup and detection ratio", tone: "intel",
    what: "A file's SHA-256 is looked up on VirusTotal. The result is normalised into a detection ratio, a 0–100 threat score and a verdict.",
    where: ["services/malware_service.py → analyse_hash()", "POST /api/intel/file"], out: "ratio, threat score, family" },
  { id: "analysis", layer: 4, title: "Data analysis", short: "Pattern rules plus behavioural AI", tone: "core",
    what: "Regex rules detect SQL injection, XSS and path traversal. Behavioural rules catch brute force and high-frequency traffic. An IsolationForest model scores how unusual the pattern is.",
    where: ["models/threat_detector.py", "models/anomaly_model.py"], out: "threat_types[], anomaly score" },
  { id: "score", layer: 5, title: "Threat scoring", short: "Weighted 0–100 risk score", tone: "core",
    what: "Signals are combined with fixed weights — for example SQL injection 30, XSS 25, brute force 25 — plus error-rate and AI-anomaly terms, capped at 100. The dashboard also shows an intelligence score: the highest normalised score across available sources.",
    where: ["utils/risk_scoring.py → calculate_risk_score()", "services/ip_intelligence_service.py"], out: "risk_score 0–100" },
  { id: "sev", layer: 6, title: "Severity classification", short: "Critical · High · Medium · Low · Info", tone: "core",
    what: "The score maps to five SOC severities: 90+ critical, 61–89 high, 31–60 medium, 1–30 low, 0 informational. One function, reused everywhere so colours always agree.",
    where: ["services/severity.py → classify()", "static/js/soc/core/format.js"], out: "severity label + colour" },
  { id: "dash", layer: 7, title: "SOC dashboard", short: "Map, charts, events, tables", tone: "out",
    what: "The dashboard reads aggregated views of the threat history: KPIs, timeline, world map, live events and the threat table. Live data arrives over Server-Sent Events.",
    where: ["services/soc_service.py", "routes/soc_routes.py → /api/soc/*", "GET /stream/threats (SSE)"], out: "What you are looking at" },
  { id: "alert", layer: 8, title: "Alert and incident", short: "Auto-block decision, activity log", tone: "out",
    what: "When the score crosses the configurable threshold, the prevention engine auto-blocks the IP (unless it is whitelisted) and records the action. High and critical events raise notifications.",
    where: ["models/prevention_engine.py → evaluate_auto_block()", "data/blacklist.json", "GET /api/activity"], out: "Blocked IP, alert" },
  { id: "resp", layer: 9, title: "Analyst response", short: "Investigate, block, trust, report", tone: "out",
    what: "An analyst opens the IP investigation panel, reads the intelligence, then blocks or trusts the address, adjusts thresholds, or exports a report.",
    where: ["POST /api/block · /api/unblock", "POST /api/prevention/whitelist/add", "GET /api/report"], out: "Contained threat" },
];

const LAYERS = [...new Set(STAGES.map(s => s.layer))].sort((a, b) => a - b).map(l => STAGES.filter(s => s.layer === l));

export function mountSecurityWorkflow(host) {
  let selected = STAGES[0], paused = false, speed = 1, raf, stopped = false;
  const nodes = {};
  const flow = h("div", { class: "wf-flow" });
  const overlay = h("svg", { class: "wf-overlay", __svg: true, "aria-hidden": "true" });
  const detail = h("aside", { class: "wf-detail", "aria-live": "polite" });

  function card(s) {
    const el = h("button", { type: "button", class: `wf-node ${s.tone}`, "data-id": s.id, "aria-pressed": "false",
      onclick: () => select(s), onmouseenter: () => paintDetail(s), onmouseleave: () => paintDetail(selected), onfocus: () => paintDetail(s), onblur: () => paintDetail(selected) },
      h("span", { class: "wf-t" }, s.title), h("span", { class: "wf-s" }, s.short));
    nodes[s.id] = el; return el;
  }
  LAYERS.forEach((layer, i) => {
    const label = i === 3 ? h("div", { class: "wf-lane-label" }, "Threat intelligence — queried in parallel") : null;
    if (label) flow.append(label);
    flow.append(h("div", { class: `wf-row n${layer.length}` }, ...layer.map(card)));
  });

  function select(s) {
    selected = s;
    Object.values(nodes).forEach(n => n.setAttribute("aria-pressed", String(n.dataset.id === s.id)));
    paintDetail(s);
  }
  function paintDetail(s) {
    clear(detail).append(
      h("h2", {}, s.title),
      h("p", { class: "wf-what" }, s.what),
      h("h3", {}, "Implemented in"), h("ul", {}, ...s.where.map(w => h("li", {}, h("code", {}, w)))),
      h("h3", {}, "Produces"), h("p", { class: "wf-out" }, s.out));
  }

  // ── connectors ────────────────────────────────────────────────
  let edges = [];
  function measure() {
    clear(overlay); edges = [];
    const fr = flow.getBoundingClientRect();
    overlay.setAttribute("width", fr.width); overlay.setAttribute("height", fr.height); overlay.setAttribute("viewBox", `0 0 ${fr.width} ${fr.height}`);
    const pos = id => { const r = nodes[id].getBoundingClientRect(); return { x: r.left - fr.left + r.width / 2, top: r.top - fr.top, bottom: r.bottom - fr.top }; };
    for (let i = 0; i < LAYERS.length - 1; i++) {
      const group = [];
      for (const a of LAYERS[i]) for (const b of LAYERS[i + 1]) {
        const A = pos(a.id), B = pos(b.id), my = (A.bottom + B.top) / 2;
        const d = `M${A.x},${A.bottom} C${A.x},${my} ${B.x},${my} ${B.x},${B.top}`;
        const p = h("path", { d, class: "wf-edge", __svg: true }); overlay.append(p);
        const e = { path: p, len: p.getTotalLength(), from: a.id, to: b.id, layer: i }; group.push(e); edges.push(e);
      }
    }
    // one packet dot per edge, pooled
    edges.forEach(e => { e.dot = h("circle", { r: 4, class: "wf-packet", __svg: true, opacity: 0 }); overlay.append(e.dot); });
  }

  // ── packet animation ──────────────────────────────────────────
  const active = []; // {edge, t0, dur, done}
  function pulse(id) { const n = nodes[id]; n.classList.add("lit"); setTimeout(() => n.classList.remove("lit"), 700); }
  function runWave() {
    if (paused || stopped || document.hidden) return;
    pulse(LAYERS[0][0].id);
    let li = 0;
    const step = () => {
      if (paused || stopped) return;
      const es = edges.filter(e => e.layer === li);
      if (!es.length) return;
      const dur = 650 / speed, t0 = performance.now();
      es.forEach(e => active.push({ edge: e, t0, dur }));
      setTimeout(() => { LAYERS[li + 1].forEach(s => pulse(s.id)); li++; if (li < LAYERS.length - 1) step(); }, dur);
    };
    step();
  }
  function frame(now) {
    for (let i = active.length - 1; i >= 0; i--) {
      const a = active[i], p = Math.min(1, (now - a.t0) / a.dur), pt = a.edge.path.getPointAtLength(p * a.edge.len);
      a.edge.dot.setAttribute("cx", pt.x); a.edge.dot.setAttribute("cy", pt.y);
      a.edge.dot.setAttribute("opacity", p < .1 ? p * 10 : p > .9 ? (1 - p) * 10 : 1);
      if (p >= 1) { a.edge.dot.setAttribute("opacity", 0); active.splice(i, 1); }
    }
    raf = requestAnimationFrame(frame);
  }

  // ── controls ──────────────────────────────────────────────────
  const playBtn = h("button", { class: "btn", type: "button", onclick: () => { paused = !paused; playBtn.textContent = paused ? "Resume animation" : "Pause animation"; } }, "Pause animation");
  const speedSeg = h("div", { class: "seg", role: "group", "aria-label": "Animation speed" }, ...[[.5, "0.5×"], [1, "1×"], [2, "2×"]].map(([v, l]) =>
    h("button", { type: "button", "aria-pressed": String(v === 1), onclick: e => { speed = v; [...speedSeg.children].forEach(b => b.setAttribute("aria-pressed", b === e.currentTarget)); } }, l)));
  const tour = h("button", { class: "btn primary", type: "button", onclick: async () => {
    tour.disabled = true;
    for (const s of STAGES) { if (stopped) break; select(s); nodes[s.id].scrollIntoView({ block: "center", behavior: reducedMotion() ? "auto" : "smooth" }); pulse(s.id); await new Promise(r => setTimeout(r, 2200)); }
    tour.disabled = false;
  } }, "Walk me through it");

  host.append(h("div", { class: "wf-controls" }, tour, playBtn, speedSeg),
    h("div", { class: "wf-layout" }, h("div", { class: "wf-stage" }, flow), detail));
  flow.append(overlay);
  select(STAGES[0]);

  const ro = new ResizeObserver(() => { clearTimeout(ro._t); ro._t = setTimeout(measure, 80); });
  ro.observe(flow);
  requestAnimationFrame(() => { measure(); if (!reducedMotion()) { raf = requestAnimationFrame(frame); runWave(); } });
  const timer = reducedMotion() ? null : setInterval(runWave, 6200 / 1);

  return () => { stopped = true; cancelAnimationFrame(raf); clearInterval(timer); ro.disconnect(); };
}
