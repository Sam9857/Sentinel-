/** Multi-series area/line chart with hover crosshair, series toggles. d3 is loaded globally (vendor). */
import { h, clear, reducedMotion } from "../core/dom.js";
import { fmtNum } from "../core/format.js";

const d3 = window.d3;
export const SERIES = [
  { id: "events",   label: "Events",           color: "#8796a8" },
  { id: "threats",  label: "Threats",          color: "#e8c14a" },
  { id: "alerts",   label: "High + critical",  color: "#f08a3c" },
  { id: "critical", label: "Critical",         color: "#f0525d" },
  { id: "requests", label: "Requests observed", color: "#35d0c0" },
];

export function createTimelineChart({ height = 260, initial = ["events", "threats", "alerts", "critical"], series = SERIES } = {}) {
  const on = new Set(initial);
  let data = null, drawn = false;
  const host = h("div", { class: "chart" });
  const tip = h("div", { class: "tip" });
  const legend = h("div", { class: "legend", role: "group", "aria-label": "Chart series" },
    ...series.map(s => h("button", { type: "button", style: { "--c": s.color }, "aria-pressed": on.has(s.id) ? "true" : "false",
      onclick: e => { on.has(s.id) ? on.delete(s.id) : on.add(s.id); e.currentTarget.setAttribute("aria-pressed", on.has(s.id)); if (!on.size) { on.add(s.id); e.currentTarget.setAttribute("aria-pressed", "true"); } draw(); } },
      h("i"), s.label)));
  document.body.append(tip);

  function draw() {
    if (!data) return;
    clear(host);
    const W = host.clientWidth || 600, m = { t: 10, r: 14, b: 26, l: 40 }, H = height;
    const pts = data.points, active = series.filter(s => on.has(s.id));
    const x = d3.scaleLinear().domain([0, pts.length - 1]).range([m.l, W - m.r]);
    const ymax = Math.max(1, d3.max(pts, p => d3.max(active, s => p[s.id])) || 1);
    const y = d3.scaleLinear().domain([0, ymax * 1.12]).nice().range([H - m.b, m.t]);
    const svg = d3.select(host).append("svg").attr("viewBox", `0 0 ${W} ${H}`).attr("height", H).attr("role", "img")
      .attr("aria-label", `Threat activity over ${data.range}`);
    svg.append("g").attr("class", "grid-l").attr("transform", `translate(${m.l},0)`).call(d3.axisLeft(y).ticks(4).tickSize(-(W - m.l - m.r)).tickFormat(""));
    svg.append("g").attr("class", "axis").attr("transform", `translate(${m.l - 8},0)`).call(d3.axisLeft(y).ticks(4).tickSize(0).tickFormat(d3.format("~s")));
    const step = Math.max(1, Math.ceil(pts.length / Math.floor(W / 78)));
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${H - m.b + 8})`)
      .call(d3.axisBottom(x).tickValues(d3.range(0, pts.length, step)).tickSize(0).tickFormat(i => pts[i]?.label ?? ""));
    const defs = svg.append("defs");
    active.forEach(s => {
      const g = defs.append("linearGradient").attr("id", `g-${s.id}`).attr("x1", 0).attr("x2", 0).attr("y1", 0).attr("y2", 1);
      g.append("stop").attr("offset", "0%").attr("stop-color", s.color).attr("stop-opacity", .28);
      g.append("stop").attr("offset", "100%").attr("stop-color", s.color).attr("stop-opacity", 0);
      const line = d3.line().x((_, i) => x(i)).y(p => y(p[s.id])).curve(d3.curveMonotoneX);
      const area = d3.area().x((_, i) => x(i)).y0(y(0)).y1(p => y(p[s.id])).curve(d3.curveMonotoneX);
      if (active.length <= 2 || s.id === "events") svg.append("path").datum(pts).attr("d", area).attr("fill", `url(#g-${s.id})`);
      const path = svg.append("path").datum(pts).attr("d", line).attr("fill", "none").attr("stroke", s.color).attr("stroke-width", 1.8);
      if (!drawn && !reducedMotion()) { const L = path.node().getTotalLength(); path.attr("stroke-dasharray", L).attr("stroke-dashoffset", L).transition().duration(900).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0).on("end", () => path.attr("stroke-dasharray", null)); }
    });
    drawn = true;
    const cross = svg.append("line").attr("class", "cross").attr("y1", m.t).attr("y2", H - m.b).style("display", "none");
    const dots = active.map(s => svg.append("circle").attr("r", 3.5).attr("fill", s.color).attr("stroke", "#0f1720").attr("stroke-width", 1.5).style("display", "none"));
    svg.append("rect").attr("x", m.l).attr("y", m.t).attr("width", W - m.l - m.r).attr("height", H - m.t - m.b).attr("fill", "transparent")
      .on("mousemove", ev => {
        const i = Math.max(0, Math.min(pts.length - 1, Math.round(x.invert(d3.pointer(ev)[0]))));
        const p = pts[i];
        cross.attr("x1", x(i)).attr("x2", x(i)).style("display", null);
        dots.forEach((d, k) => d.attr("cx", x(i)).attr("cy", y(p[active[k].id])).style("display", null));
        clear(tip).append(h("div", { class: "tt" }, h("b", {}, p.label)),
          ...active.map(s => h("div", { class: "tr" }, h("span", {}, h("span", { style: { color: s.color } }, "● "), s.label), h("b", { class: "num" }, fmtNum(p[s.id])))));
        tip.classList.add("on");
        const r = tip.getBoundingClientRect(); let tx = ev.clientX + 14; if (tx + r.width > innerWidth - 8) tx = ev.clientX - r.width - 14;
        tip.style.left = `${tx}px`; tip.style.top = `${ev.clientY - r.height / 2}px`;
      })
      .on("mouseleave", () => { cross.style("display", "none"); dots.forEach(d => d.style("display", "none")); tip.classList.remove("on"); });
  }

  const ro = new ResizeObserver(() => { clearTimeout(ro._t); ro._t = setTimeout(draw, 100); });
  ro.observe(host);
  return {
    el: host, legend,
    set(d, { redraw = false } = {}) { if (redraw) drawn = false; data = d; draw(); },
    destroy() { ro.disconnect(); tip.remove(); },
  };
}
