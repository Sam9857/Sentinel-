import { h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { store } from "../core/store.js";
import { on } from "../core/bus.js";
import { toast } from "../core/toast.js";
import { panel, pageHead, rangeSeg, sourceBanner } from "../components/ui.js";
import { createThreatTable } from "../components/threatTable.js";
import { opsService } from "../services/opsService.js";

export function mountThreats(root, ctx, params) {
  const range = rangeSeg();
  const sevPreset = (params.get("severity") || "").split(",").filter(Boolean);
  const table = createThreatTable({ severity: sevPreset, q: params.get("q") || "", onOpen: ctx.openIp });

  const ipIn = h("input", { class: "field", placeholder: "IP found in the analysed log, e.g. 192.168.1.100", "aria-label": "IP to scan", style: { flex: 1 }, onkeydown: e => { if (e.key === "Enter") scanBtn.click(); } });
  const scanBtn = h("button", { class: "btn primary", type: "button", onclick: async () => {
    const ip = ipIn.value.trim(); if (!ip) return;
    scanBtn.disabled = true;
    try { const r = await opsService.scanIP(ip); toast(`${ip}: risk ${r.risk_score} (${r.risk_level})${r.auto_block_action?.action === "auto_blocked" ? " — auto-blocked" : ""}`); table.load(); ctx.refreshData(); }
    catch (e) { toast(e.message, "err"); } finally { scanBtn.disabled = false; }
  } }, icon("search"), "Scan IP");

  const fileIn = h("input", { type: "file", accept: ".log,.txt,.csv", hidden: true, onchange: () => upload(fileIn.files[0]) });
  const drop = h("div", { class: "drop", tabindex: 0, role: "button", "aria-label": "Upload a log file", onclick: () => fileIn.click(), onkeydown: e => { if (e.key === "Enter") fileIn.click(); },
    ondragover: e => { e.preventDefault(); drop.classList.add("over"); }, ondragleave: () => drop.classList.remove("over"),
    ondrop: e => { e.preventDefault(); drop.classList.remove("over"); upload(e.dataTransfer.files[0]); } },
    icon("upload"), h("div", {}, "Drop a log file or click to browse"), h("small", {}, ".log .txt .csv · Apache / Nginx / simple formats · max 5 MB"));
  drop.firstChild.style.cssText = "width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.7";
  const result = h("div", { style: { marginTop: "12px" } });

  async function upload(file) {
    if (!file) return;
    result.replaceChildren(h("div", { class: "muted" }, `Analysing ${file.name}…`));
    try {
      const r = await opsService.scanLog(file);
      result.replaceChildren(h("div", { class: "banner info", style: { marginBottom: 0 } }, h("span", {},
        h("b", {}, `${r.total_entries.toLocaleString()} entries · ${r.unique_ips} unique IPs. `), `${r.danger} dangerous, ${r.suspicious} suspicious, ${r.safe} safe. `,
        r.auto_blocked.length ? `Auto-blocked: ${r.auto_blocked.join(", ")}.` : "No IPs were auto-blocked.")));
      toast("Log analysed"); table.load(); ctx.refreshData();
    } catch (e) { result.replaceChildren(h("div", { class: "banner" }, e.message)); }
    fileIn.value = "";
  }

  root.append(pageHead("Threats", "Every source IP flagged by the detection engine", range.el), sourceBanner(),
    h("div", { class: "stack" },
      h("div", { class: "two" },
        panel("Scan an IP", { sub: "Looks up the IP in the sample log and scores it" }, h("div", { class: "field-row" }, ipIn, scanBtn)),
        panel("Analyse a log file", {}, drop, fileIn, result)),
      table.el));
  table.load();
  const offs = [store.subscribe((s, p) => { if ("range" in p || "source" in p) table.load(); }), on("refresh", () => table.load())];
  return () => { offs.forEach(f => f()); range.destroy(); };
}
