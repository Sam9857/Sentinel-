/** Small layout helpers shared by views. */
import { h } from "../core/dom.js";
import { store } from "../core/store.js";

export const RANGES = ["1H", "6H", "24H", "7D", "30D"];

export function panel(title, { sub, tools, cls = "", bodyCls = "" } = {}, ...body) {
  return h("section", { class: `panel ${cls}` },
    (title || tools) && h("div", { class: "panel-h" }, title && h("h2", {}, title), sub && h("span", { class: "sub" }, sub), tools && h("div", { class: "tools" }, tools)),
    h("div", { class: `panel-b ${bodyCls}` }, ...body));
}

export function pageHead(title, sub, ...tools) {
  return h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), sub && h("p", {}, sub)), h("div", { class: "page-tools" }, ...tools));
}

/** Segmented 1H…30D control bound to the global store. */
export function rangeSeg() {
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Time range" },
    ...RANGES.map(r => h("button", { type: "button", "aria-pressed": String(store.get().range === r), onclick: () => store.set({ range: r }) }, r)));
  const unsub = store.subscribe((s, patch) => { if ("range" in patch) [...seg.children].forEach((b, i) => b.setAttribute("aria-pressed", String(RANGES[i] === s.range))); });
  return { el: seg, destroy: unsub };
}

export function sourceBanner() {
  const s = store.get();
  if (s.resolvedSource !== "demo") return null;
  return h("div", { class: "banner info" }, h("span", {}, h("b", {}, "Showing the demo dataset. "),
    "Traffic is simulated and scored by BitSentinel's real detection engine. Start the Live Monitor (Network activity) or scan a log file and the dashboard switches to your own data automatically."));
}

export const updatedLabel = () => h("span", { class: "updated" }, "");
export function stamp(el) { el.textContent = `Updated ${new Date().toLocaleTimeString("en-GB")}`; }
