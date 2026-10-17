import { h, clear } from "../core/dom.js";
import { store } from "../core/store.js";
import { on } from "../core/bus.js";
import { SEVERITIES, fmtAgo } from "../core/format.js";
import { socService } from "../services/socService.js";
import { panel, pageHead, rangeSeg, sourceBanner, stamp } from "../components/ui.js";
import { ThreatMap } from "../components/threatMap.js";
import { sevChip } from "../components/chips.js";

export function mountMapView(root, ctx) {
  const range = rangeSeg(); const upd = h("span", { class: "updated" });
  const mapHost = h("div", { class: "map-stage tall" });
  const map = new ThreatMap(mapHost, { onInvestigate: p => ctx.openIp(p.ip), maxParticles: 30 });
  const list = h("div", { style: { overflow: "auto", maxHeight: "calc(100vh - 290px)" } });
  const hide = new Set();
  let data = null;

  const filters = h("div", { class: "legend", role: "group", "aria-label": "Show severities" },
    ...SEVERITIES.slice(0, 4).map(s => h("button", { type: "button", style: { "--c": s.hex }, "aria-pressed": "true", onclick: e => { hide.has(s.id) ? hide.delete(s.id) : hide.add(s.id); e.currentTarget.setAttribute("aria-pressed", !hide.has(s.id)); apply(); } }, h("i"), s.label)));

  function apply() {
    if (!data) return;
    const pts = data.points.filter(p => !hide.has(p.severity));
    map.update({ ...data, points: pts });
    clear(list);
    if (!pts.length) list.append(h("div", { class: "empty" }, "No sources match"));
    pts.slice(0, 40).forEach(p => list.append(h("div", { class: "ev", style: { gridTemplateColumns: "1fr auto" }, tabindex: 0, role: "button", onclick: () => map.select(map.pts?.find(x => x.ip === p.ip) || p), onkeydown: e => { if (e.key === "Enter") ctx.openIp(p.ip); } },
      h("div", { class: "m" }, h("b", { class: "mono" }, p.ip), h("small", {}, p.country, " · ", p.types[0] || "Behavioural", " · ", fmtAgo(p.last_seen))), sevChip(p.severity))));
  }
  async function refresh(animate) { try { data = await socService.map(); apply(); stamp(upd); } catch (e) { ctx.toast(e.message, "err"); } }

  root.append(pageHead("Threat map", "Attacking sources and live attack paths", upd, range.el), h("div", { class: "banner-slot" }, sourceBanner()),
    h("div", { class: "grid g-12" },
      panel("World threat activity", { cls: "map-panel c-9", bodyCls: "flush", tools: filters }, mapHost),
      panel("Sources", { cls: "c-3", bodyCls: "flush", sub: "Highest risk first" }, list)));
  refresh(true);
  const offs = [store.subscribe((s, p) => { if ("range" in p || "source" in p) refresh(true); }), on("event", ev => ev.geo && map.flash(ev.geo, ev.severity)), on("refresh", () => refresh(false))];
  return () => { offs.forEach(f => f()); map.destroy(); range.destroy(); };
}
