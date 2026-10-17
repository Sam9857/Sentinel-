/**
 * ThreatMap — interactive world map with animated attack paths.
 *
 *  • d3-geo natural-earth projection, country polygons from static/data/world-110m.json (TopoJSON)
 *  • d3-zoom for pan / zoom (wheel, drag, pinch, buttons, double-click)
 *  • each source IP → curved path to the monitored asset, drawn in once, then a particle travels it
 *  • critical / high sources pulse; hover = tooltip; click = detail card + highlighted path
 *  • flash() draws a short-lived path for events arriving in real time
 *
 * Data in:  { asset:{lat,lon,name,city}, points:[{ip,lat,lon,severity,score,country,...}] }
 */
import { h, clear, reducedMotion } from "../core/dom.js";
import { SEV, fmtAgo } from "../core/format.js";
import { sevChip, statusState } from "./chips.js";

const d3 = window.d3, topojson = window.topojson;
const SVGNS = "http://www.w3.org/2000/svg";
let worldPromise;
const loadWorld = () => (worldPromise ||= fetch("/static/data/world-110m.json").then(r => r.json()));

export class ThreatMap {
  constructor(host, { onInvestigate, showCard = true, maxParticles = 22 } = {}) {
    this.host = host; this.onInvestigate = onInvestigate; this.showCard = showCard; this.maxParticles = maxParticles;
    this.points = []; this.asset = null; this.selected = null; this.countryHits = new Map();
    this.tip = document.querySelector(".tip.map-tip") || document.body.appendChild(h("div", { class: "tip map-tip", role: "tooltip" }));
    this.build();
    this.ro = new ResizeObserver(() => { clearTimeout(this._rt); this._rt = setTimeout(() => this.layout(), 120); });
    this.ro.observe(host);
    this.vis = () => (document.hidden ? this.stopLoop() : this.startLoop());
    document.addEventListener("visibilitychange", this.vis);
  }

  build() {
    clear(this.host);
    this.svg = d3.select(this.host).append("svg").attr("role", "img").attr("aria-label", "World map of attacking sources and attack paths");
    this.root = this.svg.append("g");
    this.gSphere = this.root.append("path").attr("class", "sphere").attr("fill", "none");
    this.gGrat = this.root.append("path").attr("class", "grat");
    this.gLand = this.root.append("g");
    this.gArcs = this.root.append("g");
    this.gFlash = this.root.append("g");
    this.gParts = this.root.append("g").style("pointer-events", "none");
    this.gPts = this.root.append("g");
    this.gAsset = this.root.append("g");
    this.zoom = d3.zoom().scaleExtent([1, 8]).on("zoom", e => this.onZoom(e.transform));
    this.svg.call(this.zoom).on("dblclick.zoom", null);
    this.svg.on("dblclick", ev => { this.svg.transition().duration(300).call(this.zoom.scaleBy, 1.8, d3.pointer(ev)); });
    this.svg.on("click", ev => { if (ev.target === this.svg.node() || ev.target.classList.contains("land")) this.select(null); });

    // overlay controls
    this.host.append(
      h("div", { class: "map-zoom" },
        h("button", { type: "button", "aria-label": "Zoom in", onclick: () => this.svg.transition().duration(250).call(this.zoom.scaleBy, 1.6) }, "+"),
        h("button", { type: "button", "aria-label": "Zoom out", onclick: () => this.svg.transition().duration(250).call(this.zoom.scaleBy, 1 / 1.6) }, "−"),
        h("button", { type: "button", "aria-label": "Reset view", onclick: () => this.svg.transition().duration(350).call(this.zoom.transform, d3.zoomIdentity), style: { fontSize: "12px" } }, "⌂")),
      h("div", { class: "map-legend" },
        ...["critical", "high", "medium", "low"].map(s => h("span", {}, h("i", { style: { background: SEV[s].hex } }), SEV[s].label)),
        h("span", {}, h("i", { style: { background: "var(--accent)" } }), "Monitored asset")));
    this.noteEl = h("div", { class: "map-note", hidden: true }, "Locations are simulated");
    this.host.append(this.noteEl);
    this.cardEl = h("div", { class: "sel-card", hidden: true });
    this.host.append(this.cardEl);
    this.k = 1;
  }

  async layout() {
    const w = this.host.clientWidth, h_ = this.host.clientHeight;
    if (!w || !h_) return;
    this.w = w; this.h = h_;
    this.svg.attr("viewBox", `0 0 ${w} ${h_}`);
    this.zoom.translateExtent([[0, 0], [w, h_]]).extent([[0, 0], [w, h_]]);
    this.proj = d3.geoNaturalEarth1().fitExtent([[8, 8], [w - 8, h_ - 8]], { type: "Sphere" });
    const path = d3.geoPath(this.proj);
    this.gSphere.attr("d", path({ type: "Sphere" }));
    this.gGrat.attr("d", path(d3.geoGraticule10()));
    const world = await loadWorld();
    if (!this.features) this.features = topojson.feature(world, world.objects.countries).features.filter(f => f.properties.name !== "Antarctica");
    this.gLand.selectAll("path").data(this.features).join("path").attr("class", "land").attr("d", path)
      .on("mousemove", (ev, d) => this.showCountryTip(ev, d.properties.name))
      .on("mouseleave", () => this.hideTip());
    this.draw({ animate: !this._drawn });
  }

  /** Public: set data */
  update(data, { animate = false } = {}) {
    this.points = data.points || []; this.asset = data.asset;
    this.noteEl.hidden = !data.simulated_geo;
    this.countryHits = new Map();
    this.points.forEach(p => this.countryHits.set(p.country, (this.countryHits.get(p.country) || 0) + 1));
    if (this.selected && !this.points.find(p => p.ip === this.selected.ip)) this.select(null);
    if (this.proj) this.draw({ animate }); else this.layout();
  }

  project(lon, lat) { return this.proj([lon, lat]); }

  arcPath(a, b) {
    const dx = b[0] - a[0], dy = b[1] - a[1], dist = Math.hypot(dx, dy) || 1;
    const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
    const lift = Math.min(dist * 0.28, 140);
    // control point: perpendicular, biased upward so paths bow toward the north like flight arcs
    let nx = -dy / dist, ny = dx / dist; if (ny > 0) { nx = -nx; ny = -ny; }
    return `M${a[0]},${a[1]} Q${mx + nx * lift},${my + ny * lift} ${b[0]},${b[1]}`;
  }

  draw({ animate }) {
    if (!this.proj || !this.asset) return;
    this._drawn = true;
    const A = this.project(this.asset.lon, this.asset.lat);
    const pts = this.points.map(p => ({ ...p, xy: this.project(p.lon, p.lat) }));
    this.gArcs.selectAll("*").remove(); this.gPts.selectAll("*").remove(); this.gAsset.selectAll("*").remove(); this.gParts.selectAll("*").remove();
    this.parts = [];
    const rm = reducedMotion();
    // arcs — weakest first so critical ends up on top
    const ordered = [...pts].sort((a, b) => a.score - b.score);
    ordered.forEach((p, i) => {
      const d = this.arcPath(p.xy, A);
      const el = this.gArcs.append("path").attr("class", "arc").attr("d", d).attr("stroke", SEV[p.severity].hex).attr("data-ip", p.ip);
      const L = el.node().getTotalLength();
      if (animate && !rm) {
        el.attr("stroke-dasharray", L).attr("stroke-dashoffset", L)
          .transition().delay(i * 45).duration(900).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0)
          .on("end", function () { d3.select(this).attr("stroke-dasharray", null).attr("stroke-dashoffset", null); });
      }
      p._arc = el.node(); p._len = L;
    });
    // particles on the strongest paths
    if (!rm) {
      [...pts].sort((a, b) => b.score - a.score).slice(0, this.maxParticles).forEach((p, i) => {
        const c = this.gParts.append("circle").attr("r", 2.4).attr("fill", SEV[p.severity].hex).attr("opacity", 0);
        this.parts.push({ node: c.node(), arc: p._arc, len: p._len, dur: 2800 + (i % 5) * 450, off: (i * 397) % 2800, delay: animate ? 900 + i * 45 : 0 });
      });
    }
    // points
    pts.forEach(p => {
      const g = this.gPts.append("g").attr("transform", `translate(${p.xy[0]},${p.xy[1]})`).attr("class", "pt").attr("data-ip", p.ip);
      if (p.severity === "critical" || p.severity === "high")
        g.append("circle").attr("class", "pt-pulse").attr("r", 5).attr("stroke", SEV[p.severity].hex).style("animation-delay", `${(p.score % 7) * 0.3}s`);
      g.append("circle").attr("class", "pt-core").attr("r", 3.6).attr("fill", SEV[p.severity].hex)
        .attr("tabindex", 0).attr("role", "button").attr("aria-label", `${p.ip}, ${p.country}, ${SEV[p.severity].label}`)
        .on("mousemove", ev => this.showPointTip(ev, p)).on("mouseleave", () => this.hideTip())
        .on("click", ev => { ev.stopPropagation(); this.select(p); })
        .on("keydown", ev => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); this.select(p); } });
      p._g = g.node();
    });
    this.pts = pts;
    // asset
    const ag = this.gAsset.append("g").attr("transform", `translate(${A[0]},${A[1]})`);
    ag.append("circle").attr("class", "asset-ring").attr("r", 7);
    ag.append("circle").attr("class", "asset-core").attr("r", 5);
    ag.append("text").attr("class", "asset-label").attr("x", 10).attr("y", 4).text(this.asset.city || this.asset.name);
    this.A = A;
    this.applyScale(this.k);
    this.startLoop();
    if (this.selected) { const m = this.pts.find(p => p.ip === this.selected.ip); if (m) this.select(m, { keepZoom: true }); }
  }

  onZoom(t) { this.k = t.k; this.root.attr("transform", t); this.applyScale(t.k); }
  applyScale(k) {
    this.root.selectAll(".pt-core").attr("r", 3.6 / Math.sqrt(k));
    this.root.selectAll(".pt-pulse").attr("r", 5 / Math.sqrt(k));
    this.root.selectAll(".asset-core").attr("r", 5 / Math.sqrt(k));
    this.root.selectAll(".asset-ring").attr("r", 7 / Math.sqrt(k));
    this.gParts.selectAll("circle").attr("r", 2.4 / Math.sqrt(k));
    this.gAsset.select("text").attr("font-size", 11 / k).attr("x", 10 / k).attr("y", 4 / k).style("stroke-width", `${3 / k}px`);
  }

  // ── particle loop ─────────────────────────────────────────────
  startLoop() {
    if (this._raf || reducedMotion() || !this.parts?.length) return;
    const t0 = performance.now();
    const tick = now => {
      for (const p of this.parts) {
        const e = now - t0 - p.delay; if (e < 0) continue;
        const f = ((e + p.off) % p.dur) / p.dur;
        const pt = p.arc.getPointAtLength(f * p.len);
        p.node.setAttribute("cx", pt.x); p.node.setAttribute("cy", pt.y);
        p.node.setAttribute("opacity", f < .08 ? f / .08 : f > .9 ? (1 - f) / .1 : .95);
      }
      this._raf = requestAnimationFrame(tick);
    };
    this._raf = requestAnimationFrame(tick);
  }
  stopLoop() { cancelAnimationFrame(this._raf); this._raf = null; }

  /** Transient path for a real-time event */
  flash(geo, severity) {
    if (!this.proj || !this.A || geo?.lat == null) return;
    const a = this.project(geo.lon, geo.lat), col = SEV[severity].hex;
    const p = this.gFlash.append("path").attr("class", "arc hot").attr("d", this.arcPath(a, this.A)).attr("stroke", col);
    const ring = this.gFlash.append("circle").attr("cx", a[0]).attr("cy", a[1]).attr("r", 4 / Math.sqrt(this.k)).attr("fill", "none").attr("stroke", col).attr("stroke-width", 1.5);
    if (reducedMotion()) { setTimeout(() => { p.remove(); ring.remove(); }, 2500); return; }
    const L = p.node().getTotalLength();
    p.attr("stroke-dasharray", L).attr("stroke-dashoffset", L).transition().duration(1100).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0)
      .transition().delay(900).duration(900).style("opacity", 0).remove();
    ring.transition().duration(1400).attr("r", 22 / Math.sqrt(this.k)).style("opacity", 0).remove();
  }

  // ── selection / tooltip ───────────────────────────────────────
  select(p, { keepZoom } = {}) {
    this.selected = p;
    this.gArcs.selectAll(".arc").classed("hot", false).style("opacity", p ? 0.18 : null);
    if (!p) { this.cardEl.hidden = true; this.gArcs.selectAll(".arc").style("opacity", null); return; }
    this.gArcs.select(`.arc[data-ip="${CSS.escape(p.ip)}"]`).classed("hot", true).style("opacity", null).raise();
    if (!this.showCard) { this.onInvestigate?.(p); return; }
    clear(this.cardEl);
    this.cardEl.append(
      h("button", { class: "icon-btn x", type: "button", "aria-label": "Close", onclick: () => this.select(null), style: { width: "26px", height: "26px" } }, "×"),
      h("div", { style: { display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px" } }, sevChip(p.severity), statusState(p.status)),
      h("h3", { class: "mono" }, p.ip),
      h("div", { class: "row" }, h("span", {}, "Origin"), h("b", {}, `${p.city ? p.city + ", " : ""}${p.country}`)),
      h("div", { class: "row" }, h("span", {}, "Risk score"), h("b", { class: "num" }, p.score)),
      h("div", { class: "row" }, h("span", {}, "Events"), h("b", { class: "num" }, p.events)),
      h("div", { class: "row" }, h("span", {}, "Technique"), h("b", {}, p.types.join(", ") || "Behavioural")),
      h("div", { class: "row" }, h("span", {}, "Last seen"), h("b", {}, fmtAgo(p.last_seen))),
      h("button", { class: "btn primary sm", type: "button", style: { marginTop: "10px", width: "100%", justifyContent: "center" }, onclick: () => this.onInvestigate?.(p) }, "Investigate IP"));
    this.cardEl.hidden = false;
  }

  placeTip(ev) {
    const pad = 14, r = this.tip.getBoundingClientRect();
    let x = ev.clientX + pad, y = ev.clientY + pad;
    if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - pad;
    if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - pad;
    this.tip.style.left = `${x}px`; this.tip.style.top = `${y}px`;
  }
  showPointTip(ev, p) {
    clear(this.tip).append(
      h("div", { class: "tt" }, h("b", { class: "mono" }, p.ip), sevChip(p.severity)),
      h("div", { class: "tr" }, "Origin", h("b", {}, `${p.city ? p.city + ", " : ""}${p.country}`)),
      h("div", { class: "tr" }, "Risk score", h("b", {}, p.score)),
      h("div", { class: "tr" }, "Events", h("b", {}, p.events)),
      h("div", { class: "tr" }, "Technique", h("b", {}, p.types[0] || "Behavioural")));
    this.tip.classList.add("on"); this.placeTip(ev);
  }
  showCountryTip(ev, name) {
    const n = this.countryHits.get(name);
    clear(this.tip).append(h("div", { class: "tt" }, h("b", {}, name)), h("div", { class: "tr" }, "Attacking sources", h("b", {}, n || 0)));
    this.tip.classList.add("on"); this.placeTip(ev);
  }
  hideTip() { this.tip.classList.remove("on"); }

  destroy() { this.stopLoop(); this.ro.disconnect(); document.removeEventListener("visibilitychange", this.vis); this.hideTip(); }
}
