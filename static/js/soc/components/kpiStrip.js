import { h, clear } from "../core/dom.js";
import { fmtPct, classify, SEV } from "../core/format.js";
import { countTo } from "../core/motion.js";

const DEFS = [
  { id: "total_threats",  label: "Total threats",    tone: "",         nav: "#/threats" },
  { id: "active_threats", label: "Active threats",   tone: "high",     nav: "#/incidents" },
  { id: "critical",       label: "Critical threats", tone: "critical", nav: "#/threats?severity=critical" },
  { id: "resolved",       label: "Resolved threats", tone: "ok",       nav: "#/incidents" },
  { id: "suspicious_ips", label: "Suspicious IPs",   tone: "",         nav: "#/threats" },
  { id: "malware",        label: "Malware detected", tone: "",         nav: "#/malware" },
  { id: "alerts",         label: "Security alerts",  tone: "",         nav: "#/alerts" },
  { id: "incidents",      label: "Incidents",        tone: "",         nav: "#/incidents" },
];

/** Semicircle gauge for the mean risk score. */
function gaugeSVG() {
  const NS = "http://www.w3.org/2000/svg";
  const mk = (t, a) => { const e = document.createElementNS(NS, t); for (const k in a) e.setAttribute(k, a[k]); return e; };
  const svg = mk("svg", { viewBox: "0 0 200 118", role: "img", "aria-label": "Mean risk score" });
  const R = 78, cx = 100, cy = 100;
  const pt = (v, r = R) => { const a = Math.PI * (1 - v / 100); return [cx + r * Math.cos(a), cy - r * Math.sin(a)]; };
  const arc = (v0, v1, r = R) => { const [x0, y0] = pt(v0, r), [x1, y1] = pt(v1, r); return `M${x0},${y0} A${r},${r} 0 0 1 ${x1},${y1}`; };
  svg.append(mk("path", { d: arc(0, 100), fill: "none", stroke: "#1b2a39", "stroke-width": 10, "stroke-linecap": "round" }));
  const val = mk("path", { d: arc(0, .01), fill: "none", stroke: "#4aa3e8", "stroke-width": 10, "stroke-linecap": "round", style: "transition:stroke .4s" });
  svg.append(val);
  [31, 61, 90].forEach(v => { const [x0, y0] = pt(v, R - 9), [x1, y1] = pt(v, R + 9); svg.append(mk("line", { x1: x0, y1: y0, x2: x1, y2: y1, stroke: "#0f1720", "stroke-width": 2 })); });
  const num = mk("text", { x: cx, y: cy - 8, "text-anchor": "middle", fill: "#d7e0ea", "font-size": 36, "font-weight": 600, "font-family": "IBM Plex Sans" });
  num.textContent = "0"; svg.append(num);
  const lab = mk("text", { x: cx, y: cy + 12, "text-anchor": "middle", fill: "#7a8da1", "font-size": 11.5, "font-family": "IBM Plex Sans" });
  lab.textContent = "out of 100"; svg.append(lab);
  svg.update = v => {
    const to = Math.max(0.01, Math.min(100, v));
    const from = Number(svg.dataset.v || 0); svg.dataset.v = to;
    const t0 = performance.now();
    const step = now => { const p = Math.min(1, (now - t0) / 900), e = 1 - Math.pow(1 - p, 3), cur = from + (to - from) * e;
      val.setAttribute("d", arc(0, Math.max(.01, cur))); num.textContent = Math.round(cur);
      if (p < 1 && svg.isConnected) requestAnimationFrame(step); };
    requestAnimationFrame(step);
    val.setAttribute("stroke", SEV[classify(v)].hex);
  };
  return svg;
}

export function createKpiStrip(onNav) {
  const gauge = gaugeSVG();
  const gSub = h("div", { class: "g-sub" }, "Mean risk score");
  const cells = Object.fromEntries(DEFS.map(d => {
    const v = h("span", { class: "k-v num" }, "—"), dl = h("span", { class: "k-d" }, "");
    const el = h("button", { class: "kpi", type: "button", "data-tone": "", onclick: () => onNav?.(d.nav) },
      h("span", { class: "k-l" }, d.label), v, dl);
    return [d.id, { el, v, dl, d }];
  }));
  const root = h("section", { class: "panel kpi-wrap", "aria-label": "Key security metrics" },
    h("div", { class: "gauge-cell" }, h("div", { class: "t" }, "Threat posture"), gauge, gSub),
    h("div", { class: "kpis" }, ...DEFS.map(d => cells[d.id].el)));

  return {
    el: root,
    update(o) {
      gauge.update(o.mean_risk);
      gSub.textContent = `Mean risk · ${o.events_total.toLocaleString("en-US")} events`;
      for (const d of DEFS) {
        const k = o.kpis[d.id], c = cells[d.id];
        countTo(c.v, k.value);
        c.el.dataset.tone = k.value > 0 && d.tone ? d.tone : "";
        c.dl.className = "k-d";
        if (k.delta != null) { c.dl.textContent = `${fmtPct(k.delta)} vs previous`; c.dl.classList.add(k.delta > 0 && d.id !== "resolved" ? "up" : "down"); }
        else c.dl.textContent = k.note || "";
      }
    },
  };
}
