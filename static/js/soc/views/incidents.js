import { h, clear } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { store } from "../core/store.js";
import { on } from "../core/bus.js";
import { toast } from "../core/toast.js";
import { fmtDateTime } from "../core/format.js";
import { panel, pageHead, rangeSeg, sourceBanner } from "../components/ui.js";
import { createThreatTable } from "../components/threatTable.js";
import { opsService } from "../services/opsService.js";

export function mountIncidents(root, ctx) {
  const range = rangeSeg();
  const table = createThreatTable({ severity: ["critical", "high"], pageSize: 10, onOpen: ctx.openIp });
  const list = h("div", { style: { maxHeight: "460px", overflow: "auto" } });
  const ipIn = h("input", { class: "field", placeholder: "IP to block", "aria-label": "IP to block", style: { flex: 1 } });

  async function loadBlocks() {
    try {
      const d = await opsService.blacklist();
      clear(list);
      if (!d.blocked_ips.length) list.append(h("div", { class: "empty" }, "No IPs are blocked"));
      d.blocked_ips.forEach(e => list.append(h("div", { class: "ev", style: { gridTemplateColumns: "1fr auto", cursor: "default" } },
        h("div", { class: "m" }, h("b", { class: "mono" }, e.ip), h("small", {}, e.auto ? "Auto-blocked" : "Manual", " · score ", e.risk_score ?? 0, " · ", e.blocked_at ? fmtDateTime(Date.parse(e.blocked_at + "Z") / 1000) : "")),
        h("button", { class: "btn sm", type: "button", onclick: async () => { try { await opsService.unblock(e.ip); toast(`Unblocked ${e.ip}`); loadBlocks(); table.load(); ctx.refreshData(); } catch (x) { toast(x.message, "err"); } } }, "Unblock"))));
    } catch (e) { clear(list).append(h("div", { class: "empty" }, e.message)); }
  }
  const blockBtn = h("button", { class: "btn danger", type: "button", onclick: async () => {
    const ip = ipIn.value.trim(); if (!ip) return;
    try { await opsService.block(ip, "Manual block from SOC dashboard"); toast(`Blocked ${ip}`); ipIn.value = ""; loadBlocks(); table.load(); ctx.refreshData(); } catch (e) { toast(e.message, "err"); }
  } }, icon("ban"), "Block");

  root.append(pageHead("Incidents", "High and critical sources, and the active blocklist", range.el), sourceBanner(),
    h("div", { class: "grid g-12" },
      h("div", { class: "c-8", style: { minWidth: 0 } }, table.el),
      panel("Blocklist", { cls: "c-4", bodyCls: "flush", sub: "Enforced by the prevention engine" },
        h("div", { style: { padding: "12px 16px" } }, h("div", { class: "field-row" }, ipIn, blockBtn)), list)));
  table.load(); loadBlocks();
  const offs = [store.subscribe((s, p) => { if ("range" in p || "source" in p) table.load(); }), on("refresh", () => { table.load(); loadBlocks(); })];
  return () => { offs.forEach(f => f()); range.destroy(); };
}
