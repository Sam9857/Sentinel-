/** Renders a normalised IP-intelligence payload (from /api/intel/ip/<ip>). Shared by the drawer and the IP Intelligence view. */
import { h } from "../core/dom.js";
import { SEV, fmtDateTime, fmtNum } from "../core/format.js";
import { sevChip, repBar } from "./chips.js";

const yn = v => (v === true ? "Yes" : v === false ? "No" : "Unknown");
const flag = (label, v) => h("div", { class: `flag${v === true ? " yes" : ""}` }, label, h("b", {}, yn(v)));
const kv = rows => h("dl", { class: "kv" }, rows.filter(r => r[1] != null && r[1] !== "").flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
const sec = (title, ...kids) => h("section", { class: "ip-sec" }, h("h3", {}, title), ...kids);

const PROVIDER_NAMES = { virustotal: "VirusTotal", abuseipdb: "AbuseIPDB", ipinfo: "IPinfo", ipqualityscore: "IPQualityScore" };
const PILL = { ok: ["ok", "Connected"], not_configured: ["", "No API key"], simulated: ["sim", "Simulated"], rate_limited: ["err", "Rate limited"], error: ["err", "Error"], not_found: ["", "No record"] };

export function renderProfile(d) {
  const sev = d.intel.severity;
  const out = [];
  if (d.mode === "simulated")
    out.push(h("div", { class: "banner" }, h("span", {}, h("b", {}, "Simulated profile. "), "This address is private or reserved, so no external lookup was made. Network, abuse and flag values are generated for the demo; the BitSentinel history below is real.")));

  out.push(sec("Intelligence score",
    h("div", { class: "score-hero" },
      h("div", { class: "big", style: { color: SEV[sev].color } }, d.intel.score),
      h("div", {}, sevChip(sev), h("div", { class: "muted", style: { fontSize: "12px", marginTop: "6px" } }, d.intel.method))),
    h("div", { class: "bars", style: { marginTop: "12px" } },
      Object.entries(d.intel.signals).map(([k, v]) => h("div", { class: "bar-row" }, h("span", {}, k), h("div", { class: "tr" }, h("i", { style: { width: `${v}%`, background: SEV[v >= 90 ? "critical" : v >= 61 ? "high" : v >= 31 ? "medium" : "low"].hex } })), h("b", {}, v))))));

  const g = d.geo, n = d.network;
  out.push(sec("Location and network", kv([
    ["IP address", h("span", { class: "mono" }, d.ip)],
    ["Country", g && `${g.country}${g.country_code ? ` (${g.country_code})` : ""}`],
    ["City", g?.city],
    ["ASN", n?.asn && h("span", { class: "mono" }, n.asn)],
    ["ISP", n?.isp],
    ["Organization", n?.org && n.org !== n.isp ? n.org : null],
    ["Geo source", g && (g.source === "simulated" ? h("span", { class: "tag sim" }, "simulated") : g.source)],
  ])));

  out.push(sec("Anonymity", h("div", { class: "flags" }, flag("Proxy", d.flags.proxy), flag("VPN", d.flags.vpn), flag("Tor", d.flags.tor))));

  if (d.abuse) out.push(sec("Abuse reports (AbuseIPDB)",
    h("div", { class: "bar-row", style: { gridTemplateColumns: "1fr 38px" } }, h("div", { class: "tr" }, h("i", { style: { width: `${d.abuse.confidence}%`, background: SEV[d.abuse.confidence >= 61 ? "high" : d.abuse.confidence >= 31 ? "medium" : "low"].hex } })), h("b", {}, `${d.abuse.confidence}%`)),
    kv([["Abuse score", `${d.abuse.confidence} / 100`], ["Reports (90 days)", fmtNum(d.abuse.reports)], ["Last reported", d.abuse.last_reported || "—"]])));

  if (d.vt) {
    const v = d.vt, tot = v.malicious + v.suspicious + v.harmless + v.undetected || 1;
    const seg = (n, c) => h("i", { style: { "--c": c, flex: `${n} 1 0`, display: n ? "" : "none" } });
    out.push(sec("Engine verdicts (VirusTotal)",
      h("div", { class: "stack-bar" }, seg(v.malicious, SEV.critical.hex), seg(v.suspicious, SEV.medium.hex), seg(v.harmless, "#3fcf8e"), seg(v.undetected, "#4a5b6e")),
      h("div", { class: "stack-leg" }, h("span", {}, "Malicious ", h("b", {}, v.malicious)), h("span", {}, "Suspicious ", h("b", {}, v.suspicious)), h("span", {}, "Harmless ", h("b", {}, v.harmless)), h("span", {}, "Undetected ", h("b", {}, v.undetected))),
      kv([["Community reputation", v.reputation]]),
      v.link && h("a", { href: v.link, target: "_blank", rel: "noopener noreferrer", class: "dim", style: { fontSize: "12.5px", display: "inline-block", marginTop: "8px" } }, "Open full report on VirusTotal ↗")));
  }

  const L = d.local;
  out.push(sec("BitSentinel history", L.events ? kv([
    ["Events observed", fmtNum(L.events)], ["Highest risk score", L.top_score],
    ["Techniques", L.types.join(", ") || "Behavioural anomaly"],
    ["First seen", fmtDateTime(L.first_seen)], ["Last seen", fmtDateTime(L.last_seen)],
    ["Response", L.whitelisted ? "Trusted (never auto-blocked)" : L.blocked ? "Blocked" : "No action taken"],
  ]) : h("div", { class: "muted" }, "This IP has not appeared in the analysed traffic.")));

  out.push(sec("Data sources", h("div", { class: "prov" },
    Object.entries(d.providers).map(([k, v]) => { const [cls, txt] = PILL[v.status] || ["", v.status];
      return h("div", { title: v.message }, h("span", {}, PROVIDER_NAMES[k] || k), h("span", { class: `pill ${cls}` }, txt)); }))));
  return h("div", {}, ...out);
}
