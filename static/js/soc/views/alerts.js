import { h, clear } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { on } from "../core/bus.js";
import { fmtClock } from "../core/format.js";
import { panel, pageHead, sourceBanner } from "../components/ui.js";
import { createLiveEvents } from "../components/liveEvents.js";
import { socService } from "../services/socService.js";
import { opsService } from "../services/opsService.js";

export function mountAlerts(root, ctx) {
  const feed = createLiveEvents({ onSelect: e => ctx.openIp(e.src_ip), capacity: 100 });
  const act = h("div", { style: { maxHeight: "560px", overflow: "auto" } });
  async function load() {
    try {
      const [e, a] = await Promise.all([socService.events(100, 61), opsService.activity(50)]);
      feed.set(e.events);
      clear(act);
      if (!a.activity.length) act.append(h("div", { class: "empty" }, "No response actions recorded yet. Actions such as auto-blocks appear here."));
      a.activity.forEach(x => act.append(h("div", { class: "ev", style: { gridTemplateColumns: "64px 1fr", cursor: "default" } },
        h("span", { class: "t" }, fmtClock(Date.parse(x.timestamp + "Z") / 1000)), h("div", { class: "m" }, h("b", {}, x.message), h("small", {}, x.ip && h("span", { class: "mono" }, x.ip), x.event_type)))));
    } catch (err) { ctx.toast(err.message, "err"); }
  }
  root.append(pageHead("Alerts", "High and critical events, plus automated response activity", h("button", { class: "btn", type: "button", onclick: load }, icon("refresh"), "Refresh")), sourceBanner(),
    h("div", { class: "grid g-12" },
      panel("High-priority events", { cls: "c-7", bodyCls: "flush", sub: "Score 61 and above" }, h("div", { style: { maxHeight: "620px", overflow: "auto", marginTop: "8px" } }, feed.el)),
      panel("Response activity", { cls: "c-5", bodyCls: "flush", sub: "From the prevention engine" }, act)));
  load();
  const offs = [on("event", ev => { if (ev.score >= 61) feed.push(ev); }), on("refresh", load)];
  return () => offs.forEach(f => f());
}
