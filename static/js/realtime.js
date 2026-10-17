/* ============================================================
   ipwnedyou — realtime.js  |  Phase 3: Dashboard Integration
   Server-Sent Events + Live Chart + Activity Timeline + IP Modal
   ============================================================ */

// ─── SSE Connection Manager ───────────────────────────────────
class SSEManager {
  constructor() {
    this.es          = null;
    this.connected   = false;
    this.retryDelay  = 3000;
    this.maxRetry    = 30000;
    this._retryTimer = null;
    this.knownIds    = new Set();
  }

  connect() {
    if (this.es) this.es.close();

    this.es = new EventSource("/stream/threats");

    this.es.addEventListener("open", () => {
      this.connected  = true;
      this.retryDelay = 3000;
      setSSEStatus("connected");
      clearTimeout(this._retryTimer);
    });

    // New individual threat pushed
    this.es.addEventListener("threat", e => {
      try {
        const threat = JSON.parse(e.data);
        if (threat.scan_id && !this.knownIds.has(threat.scan_id)) {
          this.knownIds.add(threat.scan_id);
          onNewThreat(threat);
        }
      } catch (_) {}
    });

    // Stats snapshot tick
    this.es.addEventListener("stats", e => {
      try {
        const stats = JSON.parse(e.data);
        onStatsUpdate(stats);
      } catch (_) {}
    });

    // Heartbeat
    this.es.addEventListener("heartbeat", () => {
      setSSEStatus("connected");
    });

    this.es.addEventListener("error", () => {
      this.connected = false;
      setSSEStatus("disconnected");
      this.es.close();
      this._retryTimer = setTimeout(() => this.connect(), this.retryDelay);
      this.retryDelay  = Math.min(this.retryDelay * 1.5, this.maxRetry);
    });
  }

  disconnect() {
    clearTimeout(this._retryTimer);
    if (this.es) { this.es.close(); this.es = null; }
    setSSEStatus("disconnected");
  }
}

const sseManager = new SSEManager();


// ─── SSE Status Indicator ─────────────────────────────────────
function setSSEStatus(status) {
  const dot  = document.getElementById("sse-dot");
  const label = document.getElementById("sse-label");
  if (!dot || !label) return;
  const map = {
    connected:    { color: "#00ff88", text: "LIVE" },
    disconnected: { color: "#ff3333", text: "RECONNECTING…" },
    paused:       { color: "#ffdd00", text: "PAUSED" },
  };
  const cfg = map[status] || map.disconnected;
  dot.style.background  = cfg.color;
  dot.style.boxShadow   = `0 0 8px ${cfg.color}`;
  label.textContent      = cfg.text;
  label.style.color      = cfg.color;
}


// ─── New Threat Handler ───────────────────────────────────────
const _threatBuffer    = [];   // buffer for batch DOM updates
let   _renderScheduled = false;

function onNewThreat(threat) {
  _threatBuffer.push(threat);
  logActivity(threat);

  // Danger alert
  if (threat.risk_level === "danger") {
    showDangerAlert(threat);
  }

  if (!_renderScheduled) {
    _renderScheduled = true;
    requestAnimationFrame(flushThreatBuffer);
  }
}

function flushThreatBuffer() {
  _renderScheduled = false;
  if (!_threatBuffer.length) return;

  const feed = document.getElementById("threat-feed");
  if (!feed) { _threatBuffer.length = 0; return; }

  // Remove empty state
  const empty = feed.querySelector(".empty-state");
  if (empty) empty.remove();

  _threatBuffer.splice(0).forEach(threat => {
    const el = buildThreatItem(threat);
    feed.insertBefore(el, feed.firstChild);

    // Keep max 60 items in feed
    while (feed.children.length > 60) feed.removeChild(feed.lastChild);
  });
}

function buildThreatItem(t) {
  const level = t.risk_level || "safe";
  const color = t.risk_color || (level === "danger" ? "#ff3333" : level === "suspicious" ? "#ffdd00" : "#00ff88");
  const time  = t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : "";

  const types = (t.threat_types || []).map(type => {
    const cls = type.toLowerCase().includes("sql") ? "danger"
              : type.toLowerCase().includes("xss") ? "xss" : "";
    return `<span class="tag ${cls}">${type}</span>`;
  }).join("") || `<span class="tag">Clean</span>`;

  const item = document.createElement("div");
  item.className        = `threat-item ${level}`;
  item.dataset.scanId   = t.scan_id || "";
  item.style.cursor     = "pointer";
  item.title            = "Click for IP details";
  item.innerHTML = `
    <div class="threat-badge ${level}"></div>
    <div class="threat-ip">${t.ip}</div>
    <div class="threat-tags">${types}</div>
    <div class="threat-score" style="color:${color}">${t.risk_score || 0}</div>
    <div class="threat-time">${time}</div>
  `;
  item.addEventListener("click", () => openIPModal(t.ip));
  return item;
}


// ─── Stats Update Handler ─────────────────────────────────────
let _lastStats = null;

function onStatsUpdate(stats) {
  _lastStats = stats;

  // Header counters
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el && parseInt(el.textContent) !== val) animateCounter(el, val);
  };
  set("cnt-total",   stats.total_threats);
  set("cnt-blocked", stats.blocked_ips);
  set("cnt-scanned", stats.total_scanned);

  // Last scan
  const ls = document.getElementById("last-scan");
  if (ls && stats.last_scan && stats.last_scan !== "Never") {
    ls.textContent = new Date(stats.last_scan).toLocaleString();
  }

  // Live chart
  liveChart.push(stats.danger || 0, stats.suspicious || 0, stats.safe || 0);

  // Risk arc — avg score
  if (typeof drawRiskArc === "function") drawRiskArc(stats.avg_score || 0);

  // Rate limit warning
  if (stats.rl_at_limit > 0) {
    showRLBadge(stats.rl_at_limit);
  }
}


// ─── Danger Alert Overlay ─────────────────────────────────────
let _alertQueue  = [];
let _alertShown  = false;

function showDangerAlert(threat) {
  _alertQueue.push(threat);
  if (!_alertShown) drainAlertQueue();
}

function drainAlertQueue() {
  if (!_alertQueue.length) { _alertShown = false; return; }
  _alertShown = true;
  const t     = _alertQueue.shift();
  const overlay = document.getElementById("danger-alert-overlay");
  if (!overlay) { _alertShown = false; return; }

  document.getElementById("da-ip").textContent    = t.ip;
  document.getElementById("da-score").textContent = t.risk_score;
  document.getElementById("da-types").textContent =
    (t.threat_types || []).join(" | ") || "Anomaly";

  overlay.classList.add("show");
  setTimeout(() => {
    overlay.classList.remove("show");
    setTimeout(drainAlertQueue, 400);
  }, 5000);
}


// ─── Rate Limit Badge ─────────────────────────────────────────
function showRLBadge(count) {
  let badge = document.getElementById("rl-header-badge");
  if (!badge) {
    badge       = document.createElement("span");
    badge.id    = "rl-header-badge";
    badge.className = "rl-header-badge";
    document.querySelector(".header-status")?.appendChild(badge);
  }
  badge.textContent = `🚦 ${count} IPs rate-limited`;
}


// ─── Live Threat Chart ────────────────────────────────────────
const liveChart = (() => {
  const MAX_POINTS = 20;
  const history   = {
    danger:     new Array(MAX_POINTS).fill(0),
    suspicious: new Array(MAX_POINTS).fill(0),
    safe:       new Array(MAX_POINTS).fill(0),
  };

  function push(danger, suspicious, safe) {
    history.danger.push(danger);
    history.suspicious.push(suspicious);
    history.safe.push(safe);
    ["danger","suspicious","safe"].forEach(k => {
      if (history[k].length > MAX_POINTS) history[k].shift();
    });
    draw();
  }

  function draw() {
    const canvas = document.getElementById("live-chart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W   = canvas.width, H = canvas.height;
    const pad = { top: 14, right: 10, bottom: 24, left: 32 };
    const cW  = W - pad.left - pad.right;
    const cH  = H - pad.top - pad.bottom;
    const pts = history.danger.length;

    ctx.clearRect(0, 0, W, H);

    // Grid lines
    ctx.strokeStyle = "rgba(255,255,255,0.04)";
    ctx.lineWidth   = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (cH / 4) * i;
      ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(W - pad.right, y); ctx.stroke();
    }

    const maxVal = Math.max(
      ...history.danger, ...history.suspicious, ...history.safe, 1
    );

    const drawLine = (data, color) => {
      if (!data.length) return;
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth   = 2;
      ctx.shadowColor = color;
      ctx.shadowBlur  = 6;
      data.forEach((v, i) => {
        const x = pad.left + (i / (pts - 1)) * cW;
        const y = pad.top  + cH - (v / maxVal) * cH;
        i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
      });
      ctx.stroke();
      ctx.shadowBlur = 0;
    };

    drawLine(history.safe,       "#00ff88");
    drawLine(history.suspicious, "#ffdd00");
    drawLine(history.danger,     "#ff3333");

    // Y-axis label
    ctx.fillStyle  = "rgba(255,255,255,0.25)";
    ctx.font       = "10px Courier New";
    ctx.textAlign  = "right";
    ctx.fillText(maxVal, pad.left - 4, pad.top + 4);
    ctx.fillText(0,      pad.left - 4, pad.top + cH);

    // Legend
    const legend = [
      ["DANGER",     "#ff3333"],
      ["SUSPICIOUS", "#ffdd00"],
      ["SAFE",       "#00ff88"],
    ];
    let lx = pad.left;
    ctx.textAlign = "left";
    legend.forEach(([lbl, clr]) => {
      ctx.fillStyle = clr;
      ctx.fillRect(lx, H - 12, 8, 8);
      ctx.fillStyle = "rgba(255,255,255,0.4)";
      ctx.fillText(lbl, lx + 11, H - 4);
      lx += lbl.length * 7 + 22;
    });
  }

  return { push, draw };
})();


// ─── Activity Timeline ────────────────────────────────────────
function logActivity(threat) {
  const timeline = document.getElementById("activity-timeline");
  if (!timeline) return;

  const empty = timeline.querySelector(".empty-state");
  if (empty) empty.remove();

  const level = threat.risk_level || "info";
  const icon  = level === "danger" ? "🔴" : level === "suspicious" ? "🟡" : "🟢";
  const time  = new Date(threat.timestamp || Date.now()).toLocaleTimeString();
  const types = (threat.threat_types || []).join(", ") || "Clean";

  const item = document.createElement("div");
  item.className = `activity-item ${level}`;
  item.innerHTML = `
    <span class="act-icon">${icon}</span>
    <span class="act-time">${time}</span>
    <span class="act-ip">${threat.ip}</span>
    <span class="act-desc">${types} — Score: <strong>${threat.risk_score}</strong></span>
  `;
  timeline.insertBefore(item, timeline.firstChild);
  while (timeline.children.length > 40) timeline.removeChild(timeline.lastChild);
}

async function loadActivityFromAPI() {
  const timeline = document.getElementById("activity-timeline");
  if (!timeline) return;
  try {
    const data = await apiFetch("/api/activity");
    const acts = data.activity || [];
    if (!acts.length) return;
    timeline.innerHTML = "";
    acts.forEach(a => {
      const icon  = a.level === "danger" ? "🔴" : a.level === "warning" ? "🟡" : "🟢";
      const time  = new Date(a.timestamp).toLocaleTimeString();
      const item  = document.createElement("div");
      item.className = `activity-item ${a.level || "info"}`;
      item.innerHTML = `
        <span class="act-icon">${icon}</span>
        <span class="act-time">${time}</span>
        <span class="act-ip">${a.ip || ""}</span>
        <span class="act-desc">${a.message}</span>
      `;
      timeline.appendChild(item);
    });
  } catch (_) {}
}


// ─── IP Detail Modal ──────────────────────────────────────────
async function openIPModal(ip) {
  const modal = document.getElementById("ip-modal");
  if (!modal) return;
  document.getElementById("modal-ip-title").textContent = ip;
  document.getElementById("modal-body").innerHTML       =
    '<div class="spinner" style="margin:24px auto"></div>';
  modal.classList.add("show");

  try {
    const data = await apiFetch(`/api/ip/${ip}`);
    renderIPModal(data);
  } catch (e) {
    document.getElementById("modal-body").innerHTML =
      `<div style="color:var(--red)">Failed to load: ${e.message}</div>`;
  }
}

function renderIPModal(data) {
  const bl    = data.block_entry;
  const rl    = data.rate_limit || {};
  const vt    = data.virustotal || {};
  const hist  = data.threat_history || [];
  const pct   = rl.max ? Math.round(((rl.max - (rl.remaining || 0)) / rl.max) * 100) : 0;
  const fillCls = pct >= 100 ? "danger" : pct >= 70 ? "warn" : "";

  const histRows = hist.length
    ? hist.map(t => `
        <tr>
          <td style="color:var(--text-dim);font-size:.7rem">${new Date(t.timestamp).toLocaleTimeString()}</td>
          <td style="color:${t.risk_color || '#00ff88'};font-weight:700">${t.risk_score}</td>
          <td>${(t.threat_types || []).join(", ") || "Clean"}</td>
        </tr>
      `).join("")
    : `<tr><td colspan="3" class="empty-state">No history</td></tr>`;

  // VirusTotal section
  const vtSection = vt.enabled ? `
    <div style="margin:14px 0;padding:12px;background:rgba(0,229,255,0.07);
                border:1px solid rgba(0,229,255,0.2);border-radius:8px;font-size:.8rem">
      <div style="color:var(--cyan);font-weight:700;margin-bottom:6px">🦠 VirusTotal Report</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        <div>Reputation: <span style="color:${vt.reputation >= 0 ? 'var(--green)' : 'var(--red)'}">${vt.reputation || 'N/A'}</span></div>
        <div>Country: <span style="color:var(--text)">${vt.country || 'Unknown'}</span></div>
        <div>Malicious URLs: <span style="color:var(--red)">${vt.malicious || 0}</span></div>
        <div>Suspicious Samples: <span style="color:var(--yellow)">${vt.suspicious || 0}</span></div>
        <div>Undetected Samples: <span style="color:var(--text)">${vt.undetected || 0}</span></div>
        <div>Harmless Samples: <span style="color:var(--green)">${vt.harmless || 0}</span></div>
      </div>
      ${vt.as_owner && vt.as_owner !== 'Unknown' ? `<div style="margin-top:6px">ASN: <span style="color:var(--text-dim)">${vt.as_owner}</span></div>` : ''}
      ${vt.network && vt.network !== 'Unknown' ? `<div style="margin-top:2px">Network: <span style="color:var(--text-dim)">${vt.network}</span></div>` : ''}

      ${vt.details && vt.details.length > 0 ? `
        <div style="margin-top:8px">
          <div style="font-weight:600;margin-bottom:4px">Latest Detections:</div>
          ${vt.details.slice(0, 3).map(d => `
            <div style="font-size:.75rem;margin:2px 0">
              <span style="color:${d.detected ? 'var(--red)' : 'var(--green)'}">●</span>
              ${d.name}: ${d.result}
            </div>
          `).join('')}
        </div>
      ` : ''}

      ${vt.error ? `<div style="margin-top:6px;color:var(--red);font-weight:600">⚠️ Error: ${vt.error}</div>` : ''}
      ${vt.rate_limited ? `<div style="margin-top:6px;color:var(--yellow);font-weight:600">⏱️ Rate Limited - Try again later</div>` : ''}

      <div style="margin-top:8px">
        <a href="${vt.permalink || vt.link}" target="_blank" class="btn btn-ghost btn-sm" style="font-size:.7rem">
          🔍 View Full Report on VirusTotal
        </a>
      </div>
    </div>
  ` : `
    <div style="margin:14px 0;padding:12px;background:rgba(255,255,255,0.03);
                border:1px solid rgba(255,255,255,0.1);border-radius:8px;font-size:.8rem">
      <div style="color:var(--text-dim);font-weight:700;margin-bottom:6px">🦠 VirusTotal</div>
      <div style="color:var(--text-dim)">${vt.message || 'External threat intelligence not available'}</div>
      <div style="margin-top:8px">
        <a href="${vt.link}" target="_blank" class="btn btn-ghost btn-sm" style="font-size:.7rem">
          🔍 Check on VirusTotal
        </a>
      </div>
    </div>
  `;

  document.getElementById("modal-body").innerHTML = `
    <div class="modal-grid">
      <div class="modal-info-card ${data.is_blocked ? 'danger' : data.is_whitelisted ? 'safe' : ''}">
        <div class="mic-label">Status</div>
        <div class="mic-val">
          ${data.is_blocked    ? '<span style="color:var(--red)">⛔ BLOCKED</span>'
          : data.is_whitelisted ? '<span style="color:var(--green)">✅ TRUSTED</span>'
          :                       '<span style="color:var(--text-dim)">— Untracked</span>'}
        </div>
      </div>
      <div class="modal-info-card">
        <div class="mic-label">Rate Usage</div>
        <div class="mic-val">
          ${rl.total || 0} / ${rl.max || "—"}
          <div class="rl-bar" style="width:100%;margin-top:6px">
            <div class="rl-bar-fill ${fillCls}" style="width:${pct}%"></div>
          </div>
        </div>
      </div>
    </div>

    ${vtSection}

    ${bl ? `
    <div style="margin:14px 0;padding:12px;background:rgba(255,51,51,0.07);
                border:1px solid rgba(255,51,51,0.2);border-radius:8px;font-size:.8rem">
      <div style="color:var(--red);font-weight:700;margin-bottom:6px">Block Details</div>
      <div>Reason: <span style="color:var(--text)">${bl.reason}</span></div>
      <div>Score at block: <span style="color:var(--red)">${bl.risk_score}</span></div>
      <div>Method: <span>${bl.auto
        ? '<span class="auto-badge">AUTO</span>'
        : '<span class="manual-badge">MANUAL</span>'}</span></div>
      <div>Blocked at: <span style="color:var(--text-dim)">${new Date(bl.blocked_at).toLocaleString()}</span></div>
    </div>` : ""}

    <div style="margin-top:14px">
      <span class="section-label">Threat History (last 10)</span>
      <div style="overflow-x:auto;margin-top:8px">
        <table class="rl-table">
          <thead><tr><th>Time</th><th>Score</th><th>Types</th></tr></thead>
          <tbody>${histRows}</tbody>
        </table>
      </div>
    </div>

    <div style="display:flex;gap:10px;margin-top:18px">
      ${data.is_blocked
        ? `<button class="btn btn-ghost btn-sm" onclick="unblockIP('${data.ip}');closeIPModal()">Unblock</button>`
        : `<button class="btn btn-danger btn-sm" onclick="blockIP_modal('${data.ip}')">⛔ Block</button>`}
      ${data.is_whitelisted
        ? `<button class="btn btn-ghost btn-sm" onclick="removeWhitelist('${data.ip}');closeIPModal()">Remove from Whitelist</button>`
        : `<button class="btn btn-ghost btn-sm" onclick="addWhitelist_modal('${data.ip}')">✅ Whitelist</button>`}
      <button class="btn btn-primary btn-sm" onclick="printIPReport('${data.ip}')">
        🖨️ Print Report
      </button>
    </div>
  `;
}

function closeIPModal() {
  document.getElementById("ip-modal")?.classList.remove("show");
}

async function blockIP_modal(ip) {
  try {
    const data = await apiFetch("/api/block", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    toast(data.message || data.error, data.error ? "error" : "success");
    await openIPModal(ip);   // refresh modal
    await loadBlacklist();
    await loadStatus();
  } catch (e) { toast(e.message, "error"); }
}

async function addWhitelist_modal(ip) {
  try {
    const data = await apiFetch("/api/prevention/whitelist/add", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
    toast(data.message || data.error, data.error ? "error" : "success");
    await openIPModal(ip);
  } catch (e) { toast(e.message, "error"); }
}

// ─── Print IP Report ────────────────────────────────────────────
async function printIPReport(ip) {
  try {
    const data = await apiFetch(`/api/ip/${ip}`);
    const printWindow = window.open('', '_blank');
    
    const vt = data.virustotal || {};
    const bl = data.block_entry;
    const rl = data.rate_limit || {};
    const hist = data.threat_history || [];
    
    const histRows = hist.length
      ? hist.map(t => `
          <tr>
            <td>${new Date(t.timestamp).toLocaleString()}</td>
            <td style="color:${t.risk_level === 'danger' ? 'red' : t.risk_level === 'suspicious' ? 'orange' : 'green'};font-weight:bold">${t.risk_score}</td>
            <td>${(t.threat_types || []).join(", ") || "Clean"}</td>
            <td>${t.risk_level || 'Unknown'}</td>
          </tr>
        `).join("")
      : `<tr><td colspan="4" style="text-align:center;color:#666">No threat history available</td></tr>`;

    const vtSection = vt.enabled ? `
      <tr>
        <td colspan="4">
          <h3>🦠 VirusTotal Report</h3>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="width:30%;font-weight:bold">Reputation:</td><td>${vt.reputation || 'N/A'}</td></tr>
            <tr><td style="font-weight:bold">Country:</td><td>${vt.country || 'Unknown'}</td></tr>
            <tr><td style="font-weight:bold">Malicious:</td><td style="color:red">${vt.malicious || 0}</td></tr>
            <tr><td style="font-weight:bold">Suspicious:</td><td style="color:orange">${vt.suspicious || 0}</td></tr>
            <tr><td style="font-weight:bold">Harmless:</td><td style="color:green">${vt.harmless || 0}</td></tr>
            ${vt.as_owner ? `<tr><td style="font-weight:bold">ASN:</td><td>${vt.as_owner}</td></tr>` : ''}
            <tr><td style="font-weight:bold">Full Report:</td><td><a href="${vt.permalink || vt.link}" target="_blank">View on VirusTotal</a></td></tr>
          </table>
        </td>
      </tr>
    ` : `
      <tr>
        <td colspan="4">
          <h3>🦠 VirusTotal</h3>
          <p>${vt.message || 'External threat intelligence not available'}</p>
          <p><a href="${vt.link}" target="_blank">Check on VirusTotal</a></p>
        </td>
      </tr>
    `;

    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>IP Threat Report - ${ip}</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
          h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
          h2 { color: #34495e; margin-top: 30px; }
          h3 { color: #2980b9; margin-top: 20px; }
          table { width: 100%; border-collapse: collapse; margin: 15px 0; }
          th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
          th { background-color: #f2f2f2; font-weight: bold; }
          .status-blocked { color: #e74c3c; font-weight: bold; }
          .status-trusted { color: #27ae60; font-weight: bold; }
          .status-untracked { color: #95a5a6; }
          .risk-danger { color: #e74c3c; font-weight: bold; }
          .risk-suspicious { color: #f39c12; font-weight: bold; }
          .risk-safe { color: #27ae60; font-weight: bold; }
          .header-info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
          .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; font-size: 12px; color: #7f8c8d; }
          @media print { body { margin: 10px; } }
        </style>
      </head>
      <body>
        <h1>🛡️ BitSentinel IP Threat Report</h1>
        
        <div class="header-info">
          <h2>📋 Summary</h2>
          <table>
            <tr><td style="width:30%;font-weight:bold">IP Address:</td><td><strong>${ip}</strong></td></tr>
            <tr><td style="font-weight:bold">Status:</td><td class="${data.is_blocked ? 'status-blocked' : data.is_whitelisted ? 'status-trusted' : 'status-untracked'}">
              ${data.is_blocked ? '⛔ BLOCKED' : data.is_whitelisted ? '✅ TRUSTED' : '— Untracked'}
            </td></tr>
            <tr><td style="font-weight:bold">Report Generated:</td><td>${new Date(data.fetched_at).toLocaleString()}</td></tr>
            <tr><td style="font-weight:bold">Rate Limit Usage:</td><td>${rl.total || 0} / ${rl.max || 'N/A'} requests</td></tr>
          </table>
        </div>

        ${bl ? `
          <h2>🚫 Block Details</h2>
          <table>
            <tr><td style="width:30%;font-weight:bold">Reason:</td><td>${bl.reason}</td></tr>
            <tr><td style="font-weight:bold">Risk Score at Block:</td><td style="color:red;font-weight:bold">${bl.risk_score}</td></tr>
            <tr><td style="font-weight:bold">Block Method:</td><td>${bl.auto ? '🤖 AUTO-BLOCK' : '👤 MANUAL BLOCK'}</td></tr>
            <tr><td style="font-weight:bold">Blocked At:</td><td>${new Date(bl.blocked_at).toLocaleString()}</td></tr>
          </table>
        ` : ''}

        ${vtSection}

        <h2>📊 Threat History</h2>
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Risk Score</th>
              <th>Threat Types</th>
              <th>Risk Level</th>
            </tr>
          </thead>
          <tbody>
            ${histRows}
          </tbody>
        </table>

        <div class="footer">
          <p>Generated by BitSentinel AI Threat Detection System</p>
          <p>Report Date: ${new Date().toLocaleString()}</p>
          <p>This is an official security report. Handle with appropriate security clearance.</p>
        </div>
      </body>
      </html>
    `);
    
    printWindow.document.close();
    printWindow.focus();
    
    // Wait for content to load, then print
    setTimeout(() => {
      printWindow.print();
      printWindow.close();
    }, 500);
    
  } catch (e) {
    toast(`Failed to generate report: ${e.message}`, "error");
  }
}


// ─── Init ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Connect SSE
  sseManager.connect();

  // Close modal on backdrop click
  document.getElementById("ip-modal")?.addEventListener("click", e => {
    if (e.target.id === "ip-modal") closeIPModal();
  });

  // Dismiss danger alert manually
  document.getElementById("da-dismiss")?.addEventListener("click", () => {
    document.getElementById("danger-alert-overlay")?.classList.remove("show");
  });

  // Initial chart draw (empty)
  liveChart.draw();

  // Load initial activity
  loadActivityFromAPI();

  // Periodic chart redraw even when no SSE data (keeps it alive)
  setInterval(() => liveChart.draw(), 10000);
});