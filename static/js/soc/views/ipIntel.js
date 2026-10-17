import { h } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { toast } from "../core/toast.js";
import { looksLikeIP } from "../core/format.js";
import { panel, pageHead } from "../components/ui.js";
import { renderProfile } from "../components/intelProfile.js";
import { intelService } from "../services/intelService.js";

const recent = [];

export function mountIpIntel(root, ctx, params) {
  const input = h("input", { class: "field", placeholder: "Enter an IPv4 address, e.g. 8.8.8.8", "aria-label": "IP address", style: { flex: 1 }, value: params.get("ip") || "", onkeydown: e => { if (e.key === "Enter") go(); } });
  const out = h("div");
  const chips = h("div", { class: "legend", style: { marginTop: "10px" } });
  const provHost = h("div", { class: "prov" });

  async function go(ip = input.value.trim()) {
    if (!looksLikeIP(ip)) return toast("Enter a valid IPv4 address", "warn");
    input.value = ip;
    out.replaceChildren(h("div", { class: "skeleton", style: { height: "220px" } }));
    try {
      const d = await intelService.ip(ip);
      out.replaceChildren(panel(null, { bodyCls: "" }, renderProfile(d), h("div", { style: { marginTop: "14px", display: "flex", gap: "8px" } },
        h("button", { class: "btn", type: "button", onclick: () => ctx.openIp(ip) }, "Open in investigation panel"))));
      if (!recent.includes(ip)) { recent.unshift(ip); recent.length = Math.min(recent.length, 8); }
      drawChips();
    } catch (e) { out.replaceChildren(h("div", { class: "banner" }, e.message)); }
  }
  const drawChips = () => chips.replaceChildren(...recent.map(ip => h("button", { class: "chip mono", type: "button", onclick: () => go(ip) }, ip)));

  const ENV = { virustotal: ["VirusTotal", "VIRUSTOTAL_API_KEY", "Engine verdicts, reputation"], abuseipdb: ["AbuseIPDB", "ABUSEIPDB_API_KEY", "Abuse confidence, report count"], ipinfo: ["IPinfo", "IPINFO_API_KEY", "Geolocation, ASN, organisation"], ipqualityscore: ["IPQualityScore", "IPQS_API_KEY", "Proxy, VPN and Tor detection"] };
  intelService.providers().then(({ providers }) => provHost.replaceChildren(...Object.entries(ENV).map(([k, [n, env, what]]) =>
    h("div", {}, h("span", {}, h("b", { style: { fontWeight: 500, color: "var(--text)" } }, n), h("span", { class: "muted" }, ` · ${what}`)), providers[k] ? h("span", { class: "pill ok" }, "Key set") : h("span", { class: "pill", title: `Add ${env} to .env` }, env))))).catch(() => {});

  root.append(pageHead("IP intelligence", "Reputation, location and network ownership for any address"),
    h("div", { class: "grid g-12" },
      h("div", { class: "c-8 stack", style: { minWidth: 0 } },
        panel("Look up an IP", {}, h("div", { class: "field-row" }, input, h("button", { class: "btn primary", type: "button", onclick: () => go() }, icon("search"), "Investigate")), chips), out),
      panel("Intelligence providers", { cls: "c-4", sub: "Keys are stored server-side in .env" }, provHost,
        h("p", { class: "muted", style: { marginTop: "14px", fontSize: "12.5px" } }, "Private and documentation ranges (10.x, 192.168.x, 203.0.113.x) are never sent to third parties. They show a clearly labelled simulated profile."))));
  if (input.value) go();
  return () => {};
}
