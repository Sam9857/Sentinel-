import { h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { store } from "../core/store.js";
import { on } from "../core/bus.js";
import { classify } from "../core/format.js";
import { socService } from "../services/socService.js";
import { panel, pageHead, rangeSeg, sourceBanner, stamp } from "../components/ui.js";
import { createKpiStrip } from "../components/kpiStrip.js";
import { ThreatMap } from "../components/threatMap.js";
import { createLiveEvents } from "../components/liveEvents.js";
import { createTimelineChart } from "../components/timelineChart.js";
import { createSeverityBreakdown, createBars } from "../components/breakdowns.js";
import { createThreatTable } from "../components/threatTable.js";

export function mountOverview(root, ctx) {
  const range = rangeSeg();
  const upd = h("span", { class: "updated" });
  const refreshBtn = h("button", { class: "btn", type: "button", onclick: () => refresh({ animate: true }) }, icon("refresh"), "Refresh");

  const kpi = createKpiStrip(hash => ctx.navigate(hash));
  const mapHost = h("div", { class: "map-stage" });
  const map = new ThreatMap(mapHost, { onInvestigate: p => ctx.openIp(p.ip) });
  const events = createLiveEvents({ onSelect: e => ctx.openIp(e.src_ip), capacity: 40 });
  const pauseBtn = h("button", { class: "btn sm", type: "button", onclick: () => { events.setPaused(!events.paused); pauseBtn.textContent = events.paused ? "Resume" : "Pause"; } }, "Pause");
  const chart = createTimelineChart({ height: 250 });
  const sev = createSeverityBreakdown(id => ctx.navigate(`#/threats?severity=${id}`));
  const types = createBars("type"); const countries = createBars("country");
  const table = createThreatTable({ compact: true, pageSize: 8, onOpen: ctx.openIp });

  const banner = h("div");
  root.append(
    pageHead("Security operations overview", "Real-time threat intelligence and incident monitoring", upd, range.el, refreshBtn),
    banner,
    h("div", { class: "stack" },
      kpi.el,
      h("div", { class: "grid g-12" },
        panel("Global threat map", { cls: "map-panel c-8", bodyCls: "flush", sub: "Attack paths to your monitored asset", tools: h("a", { href: "#/map", class: "dim", style: { fontSize: "12.5px" } }, "Open full map") }, mapHost),
        panel("Live security events", { cls: "c-4", bodyCls: "flush", sub: "Newest first", tools: pauseBtn }, h("div", { style: { height: "430px", overflow: "auto", marginTop: "12px", borderTop: "1px solid var(--line)" } }, events.el))),
      h("div", { class: "grid g-12" },
        panel("Threat activity", { cls: "c-8", tools: chart.legend }, chart.el),
        panel("Severity distribution", { cls: "c-4" }, sev.el)),
      h("div", { class: "grid g-12" },
        panel("Top threat techniques", { cls: "c-6" }, types.el),
        panel("Top source countries", { cls: "c-6", sub: "Sources with medium+ risk" }, countries.el)),
      panel("Highest-risk sources", { bodyCls: "flush", tools: h("a", { href: "#/threats", class: "dim", style: { fontSize: "12.5px" } }, "View all threats") }, table.el)));

  let first = true, busy = false;
  async function refresh({ animate = false } = {}) {
    if (busy) return; busy = true;
    try {
      const [o, t, e, m] = await Promise.all([socService.overview(), socService.timeline(), socService.events(40), socService.map()]);
      kpi.update(o); sev.update(o.severity); types.update(o.top_types); countries.update(o.top_countries.map(c => ({ country: c.country, count: c.count })));
      chart.set(t, { redraw: animate || first }); events.set(e.events);
      map.update(m, { animate: animate || first });
      banner.replaceChildren(...[sourceBanner()].filter(Boolean));
      ctx.setBadge?.(o.kpis.critical.value);
      table.load(); stamp(upd); first = false;
    } catch (err) { ctx.toast(err.message, "err"); } finally { busy = false; }
  }
  refresh({ animate: true });

  const offs = [
    store.subscribe((s, p) => { if ("range" in p || "source" in p) refresh({ animate: true }); }),
    on("event", ev => {
      events.push(ev);
      if (ev.geo) map.flash(ev.geo, ev.severity);
    }),
    on("refresh", () => refresh()),
  ];
  const timer = setInterval(() => { if (!document.hidden) refresh(); }, 20000);

  return () => { clearInterval(timer); offs.forEach(f => f()); map.destroy(); chart.destroy(); range.destroy(); };
}
