/** BitSentinel SOC — app bootstrap, hash router and shell wiring. */
import { $, $$, h } from "./core/dom.js";
import { icon } from "./core/icons.js";
import { store } from "./core/store.js";
import { toast } from "./core/toast.js";
import { on, emit } from "./core/bus.js";
import { looksLikeIP, fmtClock } from "./core/format.js";
import { socService } from "./services/socService.js";
import { startLiveFeed } from "./services/liveFeed.js";
import { openIpDrawer } from "./components/ipDrawer.js";
import { sevChip } from "./components/chips.js";
import { mountOverview } from "./views/overview.js";
import { mountThreats } from "./views/threats.js";
import { mountIncidents } from "./views/incidents.js";
import { mountAlerts } from "./views/alerts.js";
import { mountIpIntel } from "./views/ipIntel.js";
import { mountMalware } from "./views/malware.js";
import { mountNetwork } from "./views/network.js";
import { mountMapView } from "./views/mapView.js";
import { mountReports } from "./views/reports.js";
import { mountSettings } from "./views/settings.js";

const ROUTES = { overview: mountOverview, threats: mountThreats, incidents: mountIncidents, alerts: mountAlerts, "ip-intelligence": mountIpIntel,
  malware: mountMalware, network: mountNetwork, map: mountMapView, reports: mountReports, settings: mountSettings };

const app = $(".app"), viewEl = $("#view"), badge = $("#nav-badge");
let cleanup = null, bell = { n: 0, items: [] };

const ctx = {
  navigate: hash => { location.hash = hash; },
  openIp: ip => openIpDrawer(ip, { onChanged: () => ctx.refreshData() }),
  toast,
  refreshData: () => emit("refresh", { reason: "action" }),
  setBadge: n => { badge.textContent = n > 99 ? "99+" : n; badge.hidden = !n; },
};

function route() {
  const raw = location.hash.replace(/^#\/?/, "") || "overview";
  const [name, query = ""] = raw.split("?");
  const mount = ROUTES[name] || ROUTES.overview;
  cleanup?.(); cleanup = null; viewEl.replaceChildren(); viewEl.scrollTop = 0;
  const inner = h("div", { class: "view-inner" }); viewEl.append(inner);
  cleanup = mount(inner, ctx, new URLSearchParams(query));
  $$(".nav a[data-route]").forEach(a => { const on_ = a.dataset.route === (ROUTES[name] ? name : "overview"); a.classList.toggle("active", on_); on_ ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current"); });
  document.title = `${(ROUTES[name] ? name : "overview").replace("-", " ")} · BitSentinel`;
  app.classList.remove("drawer-open");
}

// ── shell ───────────────────────────────────────────────────────
function applyCollapsed() { app.classList.toggle("collapsed", store.get().collapsed); }
$("#collapse")?.addEventListener("click", () => { store.set({ collapsed: !store.get().collapsed }); applyCollapsed(); });
$("#hamburger")?.addEventListener("click", () => app.classList.toggle("drawer-open"));
applyCollapsed();

const q = $("#global-search");
q?.addEventListener("keydown", e => {
  if (e.key !== "Enter") return;
  const v = q.value.trim(); if (!v) return;
  if (looksLikeIP(v)) ctx.openIp(v); else location.hash = `#/threats?q=${encodeURIComponent(v)}`;
  q.value = "";
});
document.addEventListener("keydown", e => { if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); q?.focus(); } });

// source chip
const srcChip = $("#src-chip"), srcDot = $("#src-dot"), srcTxt = $("#src-txt");
function paintSource() {
  const s = store.get().resolvedSource;
  srcTxt.textContent = s === "demo" ? "Demo data" : "Live data";
  srcDot.className = `dot ${s === "demo" ? "warn" : "live"}`;
  srcChip.title = s === "demo" ? "Simulated traffic scored by the real engine — click to change" : "Reading data/threats.json — click to change";
}
srcChip?.addEventListener("click", () => { location.hash = "#/settings"; });
store.subscribe((s, p) => { if ("resolvedSource" in p) paintSource(); });
paintSource();

// system status
const sysDot = $("#sys-dot"), sysTxt = $("#sys-txt");
async function pollStatus() {
  try { await socService.status(); sysDot.className = "dot live"; sysTxt.textContent = "System operational"; }
  catch { sysDot.className = "dot bad"; sysTxt.textContent = "Backend unreachable"; }
}
pollStatus(); setInterval(pollStatus, 20000);

// threat level chip (from overview)
const lvl = $("#lvl-txt"), lvlDot = $("#lvl-dot");
async function pollLevel() {
  try {
    const o = await socService.overview();
    const [t, c] = o.active_critical > 0 ? ["Elevated", "bad"] : o.kpis.active_threats.value > 0 ? ["Guarded", "warn"] : ["Low", ""];
    lvl.textContent = `Threat level: ${t}`; lvlDot.className = `dot ${c}`; ctx.setBadge(o.kpis.critical.value);
  } catch { /* shown by status chip */ }
}
setInterval(pollLevel, 30000);

// notifications
const bellBtn = $("#bell"), bellPip = $("#bell-pip"), menu = $("#bell-menu");
on("event", ev => {
  if (ev.severity !== "critical" && ev.severity !== "high") return;
  bell.n++; bell.items.unshift(ev); bell.items.length = Math.min(bell.items.length, 8);
  bellPip.textContent = bell.n; bellPip.hidden = false; paintMenu();
});
function paintMenu() {
  menu.replaceChildren(h("h3", {}, "New high-priority events"), ...(bell.items.length ? bell.items.map(e => h("div", { class: "ev", tabindex: 0, role: "button", onclick: () => { menu.classList.remove("on"); ctx.openIp(e.src_ip); } },
    h("div", { class: "m" }, h("b", {}, e.type), h("small", {}, sevChip(e.severity), h("span", { class: "mono" }, e.src_ip), h("span", {}, fmtClock(e.t)))))) : [h("div", { class: "empty" }, "No new alerts since you opened the dashboard")]));
}
bellBtn?.addEventListener("click", e => { e.stopPropagation(); paintMenu(); menu.classList.toggle("on"); bell.n = 0; bellPip.hidden = true; });
document.addEventListener("click", e => { if (!menu.contains(e.target)) menu.classList.remove("on"); });

// ── start ───────────────────────────────────────────────────────
window.addEventListener("hashchange", route);
route(); pollLevel(); startLiveFeed();
