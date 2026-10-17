import { h, clear, debounce } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { SEVERITIES, fmtDateTime, fmtNum } from "../core/format.js";
import { toast } from "../core/toast.js";
import { sevChip, statusState, repBar } from "./chips.js";
import { socService } from "../services/socService.js";

const COLS = [
  { id: "id", label: "Threat ID", sort: null, full: true },
  { id: "severity", label: "Severity", sort: "severity" },
  { id: "type", label: "Type", sort: "type" },
  { id: "ip", label: "Source IP", sort: "ip" },
  { id: "country", label: "Country", sort: "country" },
  { id: "asn", label: "ASN", sort: null, full: true },
  { id: "isp", label: "ISP", sort: null, full: true },
  { id: "reputation", label: "Reputation", sort: "score" },
  { id: "first", label: "First seen", sort: "first_seen", full: true },
  { id: "last", label: "Last seen", sort: "last_seen" },
  { id: "status", label: "Status", sort: "status" },
  { id: "action", label: "", sort: null },
];
const STATUSES = [["open", "Open"], ["investigating", "Investigating"], ["blocked", "Blocked"], ["trusted", "Trusted"]];

export function createThreatTable({ compact = false, pageSize = compact ? 8 : 12, severity = [], status = [], q = "", onOpen } = {}) {
  const st = { q, severity: new Set(severity), status: new Set(status), sort: "severity", dir: "desc", page: 1, pageSize };
  const cols = COLS.filter(c => !compact || !c.full);
  let last = null, req = 0;

  const search = h("input", { class: "field", type: "search", placeholder: "Search IP, ID, country, ASN, type…", "aria-label": "Search threats", value: q, style: { width: "260px" },
    oninput: debounce(e => { st.q = e.target.value.trim(); st.page = 1; load(); }, 250) });
  const sevChips = SEVERITIES.slice(0, 4).map(s => h("button", { class: "chip", type: "button", "aria-pressed": String(st.severity.has(s.id)),
    onclick: e => { toggle(st.severity, s.id); e.currentTarget.setAttribute("aria-pressed", st.severity.has(s.id)); st.page = 1; load(); } },
    h("span", { class: "dot", style: { background: s.hex, width: "7px", height: "7px" } }), s.label));
  const statChips = STATUSES.map(([id, label]) => h("button", { class: "chip", type: "button", "aria-pressed": String(st.status.has(id)),
    onclick: e => { toggle(st.status, id); e.currentTarget.setAttribute("aria-pressed", st.status.has(id)); st.page = 1; load(); } }, label));
  const sizeSel = h("select", { class: "field", "aria-label": "Rows per page", onchange: e => { st.pageSize = +e.target.value; st.page = 1; load(); } },
    ...[10, 12, 25, 50].map(n => h("option", { value: n, selected: n === st.pageSize }, `${n} rows`)));
  const bar = compact ? null : h("div", { class: "tbl-bar" },
    h("div", { class: "search", style: { flex: "none" } }, icon("search"), search),
    h("div", { class: "legend" }, ...sevChips), h("span", { class: "muted" }, "|"), h("div", { class: "legend" }, ...statChips),
    h("span", { style: { flex: 1 } }), sizeSel,
    h("button", { class: "btn sm", type: "button", onclick: exportCsv }, icon("download"), "Export CSV"));

  const thead = h("thead", {}, h("tr", {}, ...cols.map(c => {
    const th = h("th", { scope: "col", class: c.id === "action" ? "r" : "" });
    if (c.sort) { th.append(h("button", { type: "button", onclick: () => { st.dir = st.sort === c.sort && st.dir === "desc" ? "asc" : "desc"; st.sort = c.sort; st.page = 1; load(); } },
      c.label, h("svg", { class: "arr", viewBox: "0 0 24 24", __svg: true }, h("path", { d: "M12 5v14M6 13l6 6 6-6", __svg: true })))); th.dataset.sort = c.sort; }
    else th.textContent = c.label;
    return th;
  })));
  const tbody = h("tbody");
  const info = h("span"); const pager = h("div", { class: "pager" });
  const root = h("div", { class: compact ? "" : "panel" }, bar, h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" }, thead, tbody)), compact ? null : h("div", { class: "tbl-foot" }, info, pager));

  function toggle(set, v) { set.has(v) ? set.delete(v) : set.add(v); }
  const params = (extra = {}) => ({ q: st.q, severity: [...st.severity].join(","), status: [...st.status].join(","), sort: st.sort, dir: st.dir, page: st.page, page_size: st.pageSize, ...extra });

  async function load() {
    const my = ++req;
    try {
      const d = await socService.threats(params());
      if (my !== req) return;
      last = d; render(d);
    } catch (e) { if (my === req) { clear(tbody).append(h("tr", {}, h("td", { colspan: cols.length, class: "empty" }, e.message))); } }
  }

  function render(d) {
    thead.querySelectorAll("th[data-sort]").forEach(th => { th.removeAttribute("aria-sort"); if (th.dataset.sort === st.sort) th.setAttribute("aria-sort", st.dir === "asc" ? "ascending" : "descending"); });
    clear(tbody);
    if (!d.rows.length) tbody.append(h("tr", {}, h("td", { colspan: cols.length, class: "empty" }, "No threats match these filters in the selected time range.")));
    for (const r of d.rows) {
      const cell = {
        id: h("td", { class: "id" }, r.id), severity: h("td", {}, sevChip(r.severity)),
        type: h("td", {}, r.types[0] || "Behavioural anomaly", r.types.length > 1 && h("span", { class: "muted" }, ` +${r.types.length - 1}`)),
        ip: h("td", { class: "mono" }, r.ip),
        country: h("td", {}, r.country || "—", r.geo_source === "simulated" && h("span", { class: "muted", title: "Simulated geolocation" }, " ◦")),
        asn: h("td", { class: "mono" }, r.asn || "—"), isp: h("td", {}, r.isp || "—"),
        reputation: h("td", {}, repBar(r.reputation.value, `Source: ${r.reputation.from}`)),
        first: h("td", { class: "muted" }, fmtDateTime(r.first_seen)), last: h("td", { class: "muted" }, fmtDateTime(r.last_seen)),
        status: h("td", {}, statusState(r.status)),
        action: h("td", { class: "r" }, h("button", { class: "btn sm", type: "button", onclick: e => { e.stopPropagation(); onOpen?.(r.ip); } }, "Open")),
      };
      const tr = h("tr", { tabindex: 0, onclick: () => onOpen?.(r.ip), onkeydown: e => { if (e.key === "Enter") onOpen?.(r.ip); } }, ...cols.map(c => cell[c.id]));
      tbody.append(tr);
    }
    if (compact) return;
    const from = d.total ? (d.page - 1) * d.page_size + 1 : 0;
    info.textContent = `${fmtNum(from)}–${fmtNum(Math.min(d.total, d.page * d.page_size))} of ${fmtNum(d.total)} threat sources`;
    clear(pager);
    const go = p => () => { st.page = p; load(); };
    pager.append(h("button", { type: "button", disabled: d.page <= 1, onclick: go(d.page - 1), "aria-label": "Previous page" }, "‹"));
    const win = new Set([1, d.pages, d.page - 1, d.page, d.page + 1].filter(p => p >= 1 && p <= d.pages));
    let prev = 0;
    [...win].sort((a, b) => a - b).forEach(p => { if (p - prev > 1) pager.append(h("span", { class: "muted" }, "…")); pager.append(h("button", { type: "button", onclick: go(p), "aria-current": p === d.page ? "page" : null }, p)); prev = p; });
    pager.append(h("button", { type: "button", disabled: d.page >= d.pages, onclick: go(d.page + 1), "aria-label": "Next page" }, "›"));
  }

  async function exportCsv() {
    try {
      const d = await socService.threats(params({ page: 1, page_size: 500 }));
      const safe = v => { let s = String(v ?? ""); if (/^[=+\-@]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
      const head = ["threat_id", "severity", "score", "type", "source_ip", "country", "asn", "isp", "events", "first_seen", "last_seen", "status"];
      const lines = d.rows.map(r => [r.id, r.severity, r.score, r.types.join("; "), r.ip, r.country, r.asn, r.isp, r.events, new Date(r.first_seen * 1000).toISOString(), new Date(r.last_seen * 1000).toISOString(), r.status].map(safe).join(","));
      const url = URL.createObjectURL(new Blob([[head.join(","), ...lines].join("\n")], { type: "text/csv" }));
      const a = h("a", { href: url, download: `bitsentinel-threats-${Date.now()}.csv` }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      toast(`Exported ${d.rows.length} rows`);
    } catch (e) { toast(e.message, "err"); }
  }

  return { el: root, load, setQuery(v) { st.q = v; search.value = v; st.page = 1; return load(); }, setSeverity(list) { st.severity = new Set(list); sevChips.forEach((b, i) => b.setAttribute("aria-pressed", st.severity.has(SEVERITIES[i].id))); st.page = 1; return load(); } };
}
