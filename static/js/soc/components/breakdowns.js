import { h, clear } from "../core/dom.js";
import { SEVERITIES, fmtNum } from "../core/format.js";

/** Stacked severity bar + clickable legend rows. */
export function createSeverityBreakdown(onPick) {
  const bar = h("div", { class: "sev-bar", role: "img", "aria-label": "Severity distribution" });
  const rows = h("div", { class: "sev-rows" });
  return {
    el: h("div", {}, bar, rows),
    update(sev) {
      const total = SEVERITIES.reduce((a, s) => a + (sev[s.id] || 0), 0) || 1;
      clear(bar); clear(rows);
      SEVERITIES.forEach(s => {
        const n = sev[s.id] || 0;
        bar.append(h("span", { style: { "--c": s.color, flex: `${n} 1 0`, display: n ? "" : "none" }, title: `${s.label}: ${n}` }));
        rows.append(h("button", { type: "button", style: { "--c": s.color }, onclick: () => onPick?.(s.id), "aria-label": `${s.label}: ${n} events. Open in threats` },
          h("i"), h("span", {}, s.label), h("span", { class: "n" }, fmtNum(n)), h("span", { class: "p" }, `${Math.round(n / total * 100)}%`)));
      });
    },
  };
}

/** Ranked horizontal bars. */
export function createBars(labelKey, onPick) {
  const root = h("div", { class: "bars" });
  return {
    el: root,
    update(items) {
      clear(root);
      if (!items?.length) return root.append(h("div", { class: "empty" }, "No data in this window"));
      const max = Math.max(...items.map(i => i.count), 1);
      items.forEach(i => root.append(h("div", { class: "bar-row" },
        h("span", { title: i[labelKey] }, i[labelKey]),
        h("div", { class: "tr" }, h("i", { style: { width: `${i.count / max * 100}%` } })),
        h("b", {}, fmtNum(i.count)))));
    },
  };
}
