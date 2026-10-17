import { h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { toast } from "../core/toast.js";
import { fmtNum, fmtDateTime } from "../core/format.js";
import { panel, pageHead } from "../components/ui.js";
import { createThreatTable } from "../components/threatTable.js";
import { opsService } from "../services/opsService.js";
import { rangeSeg } from "../components/ui.js";
import { store } from "../core/store.js";

export function mountReports(root, ctx) {
  const range = rangeSeg();
  const sum = h("div", { class: "kv", style: { gridTemplateColumns: "190px 1fr" } });
  const table = createThreatTable({ pageSize: 12, onOpen: ctx.openIp });
  let report = null;

  async function load() {
    try {
      report = await opsService.report();
      const s = report.summary;
      sum.replaceChildren(...[["Report ID", h("span", { class: "mono" }, report.report_id.slice(0, 13))], ["Generated", new Date(report.generated_at + "Z").toLocaleString("en-GB")], ["Threat records (stored)", fmtNum(s.total_threats)],
        ["Dangerous", fmtNum(s.danger)], ["Suspicious", fmtNum(s.suspicious)], ["Safe", fmtNum(s.safe)], ["Blocked IPs", fmtNum(s.blocked_ips)], ["Log lines scanned", fmtNum(s.total_scanned)]]
        .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
    } catch (e) { toast(e.message, "err"); }
  }
  const dl = () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
    const a = h("a", { href: url, download: `bitsentinel-report-${report.report_id.slice(0, 8)}.json` }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  };
  root.append(pageHead("Reports", "Export threat data for review and audit", range.el),
    h("div", { class: "stack" },
      h("div", { class: "grid g-12" },
        panel("Stored threat report", { cls: "c-7", sub: "From data/threats.json — your real scan history", tools: [h("button", { class: "btn", type: "button", onclick: dl }, icon("download"), "Download JSON"), h("a", { class: "btn", href: "/legacy", target: "_blank" }, icon("ext"), "Printable report")] }, sum),
        panel("About exports", { cls: "c-5" }, h("p", { class: "dim", style: { fontSize: "13px", lineHeight: 1.6 } }, "The JSON report covers the stored scan history. The table below exports the current dashboard view (including the demo dataset, if active) as CSV with the filters you set. The printable report is the original BitSentinel print view."))),
      table.el));
  load(); table.load();
  const un = store.subscribe((s, p) => { if ("range" in p || "source" in p) table.load(); });
  return () => { un(); range.destroy(); };
}
