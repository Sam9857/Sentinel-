import { h, clear } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { store } from "../core/store.js";
import { toast } from "../core/toast.js";
import { panel, pageHead } from "../components/ui.js";
import { opsService } from "../services/opsService.js";
import { socService } from "../services/socService.js";

const CFG = [
  ["auto_block_threshold", "Auto-block threshold (0–100)", 0, 100], ["rate_limit_max_requests", "Max requests per window", 1, 10000],
  ["rate_limit_window_seconds", "Rate-limit window (seconds)", 5, 3600], ["brute_force_threshold", "Brute-force threshold (failures)", 1, 1000],
  ["high_freq_threshold", "High-frequency threshold (requests)", 1, 100000], ["max_threat_history", "Max stored threat records", 10, 100000],
];
const sw = (id, on, onchange) => h("label", { class: "sw" }, h("input", { type: "checkbox", id, checked: on, onchange }), h("span"));

export function mountSettings(root, ctx) {
  const form = h("div"), wl = h("div"), prov = h("div", { class: "prov" }), simOut = h("div", { style: { marginTop: "12px" } });
  let cfg = {};

  const seg = h("div", { class: "seg", role: "group", "aria-label": "Data source" },
    ...[["auto", "Auto"], ["live", "Live"], ["demo", "Demo"]].map(([id, l]) => h("button", { type: "button", "aria-pressed": String(store.get().source === id), onclick: e => { store.set({ source: id }); [...seg.children].forEach(b => b.setAttribute("aria-pressed", b === e.currentTarget)); } }, l)));

  async function loadCfg() {
    try {
      cfg = await opsService.config();
      clear(form).append(
        h("div", { class: "toggle" }, h("div", {}, h("b", {}, "Auto-block engine"), h("small", {}, "Block IPs that exceed the risk threshold")), sw("c-ab", cfg.auto_block_enabled)),
        h("div", { class: "toggle" }, h("div", {}, h("b", {}, "Rate limiting"), h("small", {}, "Track and limit requests per IP")), sw("c-rl", cfg.rate_limit_enabled)),
        h("div", { class: "form-grid", style: { marginTop: "16px" } }, ...CFG.map(([k, l, lo, hi]) => h("div", {}, h("label", { class: "lbl", for: `c-${k}` }, l), h("input", { class: "field num", style: { width: "100%" }, id: `c-${k}`, type: "number", min: lo, max: hi, value: cfg[k] })))),
        h("div", { style: { marginTop: "16px", display: "flex", gap: "8px" } }, h("button", { class: "btn primary", type: "button", onclick: save }, "Save configuration"), h("button", { class: "btn", type: "button", onclick: loadCfg }, icon("refresh"), "Reload")));
    } catch (e) { toast(e.message, "err"); }
  }
  async function save() {
    const body = { auto_block_enabled: form.querySelector("#c-ab").checked, rate_limit_enabled: form.querySelector("#c-rl").checked };
    CFG.forEach(([k]) => body[k] = Number(form.querySelector(`#c-${k}`).value));
    try { await opsService.saveConfig(body); toast("Configuration saved"); } catch (e) { toast(e.message, "err"); }
  }
  async function loadWl() {
    try {
      const d = await opsService.whitelist();
      clear(wl).append(...(d.trusted_ips.length ? d.trusted_ips.map(ip => h("span", { class: "chip mono", style: { margin: "0 6px 6px 0" } }, ip, h("button", { class: "icon-btn", type: "button", "aria-label": `Remove ${ip}`, style: { width: "18px", height: "18px", border: 0 }, onclick: async () => { await opsService.whitelistRemove(ip).catch(e => toast(e.message, "err")); loadWl(); } }, "×"))) : [h("span", { class: "muted" }, "No trusted IPs")]));
    } catch (e) { clear(wl).append(h("span", { class: "muted" }, e.message)); }
  }
  const wlIn = h("input", { class: "field", placeholder: "Trusted IP, e.g. 10.0.0.1", style: { flex: 1 }, "aria-label": "Trusted IP" });
  const sim = { ip: h("input", { class: "field", value: "203.0.113.9", "aria-label": "Simulation IP", style: { flex: 1 } }), score: h("input", { class: "field", type: "number", value: 80, min: 0, max: 100, style: { width: "90px" }, "aria-label": "Risk score" }) };

  const ENV = { virustotal: ["VirusTotal", "VIRUSTOTAL_API_KEY"], abuseipdb: ["AbuseIPDB", "ABUSEIPDB_API_KEY"], ipinfo: ["IPinfo", "IPINFO_API_KEY"], ipqualityscore: ["IPQualityScore", "IPQS_API_KEY"] };
  socService.meta().then(m => prov.replaceChildren(...Object.entries(ENV).map(([k, [n, env]]) => h("div", {}, h("span", {}, n, h("span", { class: "muted mono", style: { marginLeft: "8px", fontSize: "11.5px" } }, env)), h("span", { class: `pill ${m.providers[k] ? "ok" : ""}` }, m.providers[k] ? "Configured" : "Not set"))))).catch(() => {});

  root.append(pageHead("Settings", "Data source, prevention engine and integrations"),
    h("div", { class: "grid g-12" },
      h("div", { class: "c-7 stack", style: { minWidth: 0 } },
        panel("Prevention engine", { sub: "Applies immediately" }, form),
        panel("Trusted IPs", { sub: "Never auto-blocked" }, h("div", { class: "field-row", style: { marginBottom: "12px" } }, wlIn, h("button", { class: "btn", type: "button", onclick: async () => { try { await opsService.whitelistAdd(wlIn.value.trim()); wlIn.value = ""; loadWl(); toast("Added"); } catch (e) { toast(e.message, "err"); } } }, icon("trust"), "Trust")), wl)),
      h("div", { class: "c-5 stack", style: { minWidth: 0 } },
        panel("Dashboard data", { sub: "Auto uses your data once ≥25 events exist" }, seg,
          h("p", { class: "muted", style: { marginTop: "10px", fontSize: "12.5px" } }, "Demo data is simulated traffic scored by the real engine. It is never written to your threat history.")),
        panel("Integrations", { sub: "Set keys in the server's .env file" }, prov),
        panel("Test auto-block", { sub: "Dry run — nothing is blocked" }, h("div", { class: "field-row" }, sim.ip, sim.score, h("button", { class: "btn", type: "button", onclick: async () => {
          try { const r = await opsService.simulate({ ip: sim.ip.value.trim(), risk_score: +sim.score.value, risk_level: +sim.score.value >= 61 ? "danger" : "safe", threat_types: [] }); simOut.replaceChildren(h("div", { class: "banner info", style: { marginBottom: 0 } }, `Result: ${r.action} (score ${r.score}, threshold ${r.threshold})`)); }
          catch (e) { toast(e.message, "err"); } } }, "Run")), simOut),
        panel("Original dashboard", {}, h("a", { class: "btn", href: "/legacy" }, icon("ext"), "Open legacy dashboard")))));
  loadCfg(); loadWl();
  return () => {};
}
