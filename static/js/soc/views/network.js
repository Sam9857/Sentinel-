import { h, clear } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { store } from "../core/store.js";
import { toast } from "../core/toast.js";
import { fmtNum } from "../core/format.js";
import { panel, pageHead, rangeSeg, sourceBanner } from "../components/ui.js";
import { createTimelineChart, SERIES } from "../components/timelineChart.js";
import { socService } from "../services/socService.js";
import { opsService } from "../services/opsService.js";

export function mountNetwork(root, ctx) {
  const range = rangeSeg();
  const chart = createTimelineChart({ height: 240, initial: ["requests", "events"], series: SERIES.filter(s => ["requests", "events", "threats"].includes(s.id)) });
  const mode = h("select", { class: "field", "aria-label": "Monitoring mode" },
    h("option", { value: "simulate" }, "Simulate traffic"), h("option", { value: "self_tap" }, "Self-tap (this server's real requests)"), h("option", { value: "log_tail" }, "Tail an access log"));
  const logPath = h("input", { class: "field mono", placeholder: "/var/log/nginx/access.log", "aria-label": "Access log path", style: { display: "none", width: "280px" } });
  mode.onchange = () => { logPath.style.display = mode.value === "log_tail" ? "" : "none"; };
  const stats = h("div", { class: "kv", style: { marginTop: "14px", gridTemplateColumns: "150px 1fr" } });
  const dot = h("span", { class: "dot idle" }); const stateTxt = h("span", {}, "Stopped");
  const btn = h("button", { class: "btn primary", type: "button" });
  const tap = h("tbody"), rl = h("tbody");
  let running = false;

  function paintStatus(s) {
    running = !!s.running; dot.className = `dot ${running ? "live" : "idle"}`; stateTxt.textContent = running ? `Running · ${s.mode}` : "Stopped";
    btn.replaceChildren(icon(running ? "stop" : "play"), running ? "Stop monitor" : "Start live monitor"); btn.className = `btn ${running ? "danger" : "primary"}`;
    clear(stats).append(...[["Events analysed", fmtNum(s.events_generated)], ["Threats found", fmtNum(s.threats_found)], ["Auto-blocked", fmtNum(s.auto_blocked)], ["Interval", `${s.interval_seconds}s`]].flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      if (running) { paintStatus(await opsService.monitorStop()); toast("Monitor stopped"); }
      else {
        if (mode.value === "log_tail") await opsService.setLogPath(logPath.value.trim());
        const r = await opsService.monitorStart(mode.value, 5); if (r.error) throw new Error(r.error); paintStatus({ ...r, running: true });
        toast("Monitor started — your dashboard will switch to live data after ~25 events");
      }
    } catch (e) { toast(e.message, "err"); } finally { btn.disabled = false; }
  };

  async function loadSide() {
    try {
      const [s, t, r, c] = await Promise.all([opsService.monitorStatus(), opsService.tapFeed(), opsService.rateLimits(), socService.timeline()]);
      paintStatus(s); chart.set(c);
      clear(tap); (t.requests || []).slice(0, 15).forEach(q => tap.append(h("tr", { style: { cursor: "default" } }, h("td", { class: "muted" }, String(q.timestamp || "").slice(11, 19)), h("td", { class: "mono" }, q.ip), h("td", {}, q.method), h("td", { class: "mono" }, q.path), h("td", {}, q.status))));
      if (!tap.children.length) tap.append(h("tr", {}, h("td", { colspan: 5, class: "empty" }, t.enabled ? "Waiting for requests…" : "Self-tap is off. Choose “Self-tap” and start the monitor.")));
      clear(rl); (r.tracked_ips || []).slice(0, 12).forEach(x => rl.append(h("tr", { style: { cursor: "default" } }, h("td", { class: "mono" }, x.ip), h("td", { class: "num" }, x.total), h("td", { class: "num" }, x.remaining), h("td", {}, x.at_limit ? h("span", { class: "sev critical" }, "At limit") : h("span", { class: "state trusted" }, "OK")))));
      if (!rl.children.length) rl.append(h("tr", {}, h("td", { colspan: 4, class: "empty" }, "No tracked IPs yet")));
    } catch (e) { toast(e.message, "err"); }
  }
  const th = a => h("thead", {}, h("tr", {}, ...a.map(t => h("th", {}, t))));
  root.append(pageHead("Network activity", "Traffic ingestion, request volume and rate limiting", range.el), sourceBanner(),
    h("div", { class: "stack" },
      h("div", { class: "grid g-12" },
        panel("Request volume", { cls: "c-8", tools: chart.legend }, chart.el),
        panel("Live monitor", { cls: "c-4", sub: "Feeds the same detection pipeline" },
          h("div", { style: { display: "flex", alignItems: "center", gap: "8px", marginBottom: "12px" } }, dot, stateTxt), h("div", { class: "stack", style: { gap: "10px" } }, mode, logPath, btn), stats)),
      h("div", { class: "grid g-12" },
        panel("Captured requests", { cls: "c-7", bodyCls: "flush", sub: "Self-tap mode" }, h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" }, th(["Time", "IP", "Method", "Path", "Status"]), tap))),
        panel("Rate limits", { cls: "c-5", bodyCls: "flush", tools: h("button", { class: "btn sm", type: "button", onclick: async () => { await opsService.resetRateLimits(); loadSide(); } }, "Reset all") }, h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" }, th(["IP", "Requests", "Remaining", "State"]), rl))))));
  loadSide();
  const t = setInterval(() => { if (!document.hidden) loadSide(); }, 6000);
  const un = store.subscribe((s, p) => { if ("range" in p || "source" in p) loadSide(); });
  return () => { clearInterval(t); un(); chart.destroy(); range.destroy(); };
}
