import { h, clear } from "../core/dom.js";
import { icon } from "../core/icons.js";
import { toast } from "../core/toast.js";
import { store } from "../core/store.js";
import { sevChip } from "./chips.js";
import { renderProfile } from "./intelProfile.js";
import { intelService } from "../services/intelService.js";
import { opsService } from "../services/opsService.js";

let scrim, drawer, body, title, foot, lastFocus, token = 0;

function ensure() {
  if (drawer) return;
  scrim = h("div", { class: "scrim", onclick: close });
  title = h("h2", {}, "");
  body = h("div", { class: "drawer-b" });
  foot = h("div", { class: "drawer-f" });
  drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "IP investigation" },
    h("div", { class: "drawer-h" }, title, h("span", { style: { flex: 1 } }), h("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: close }, icon("x"))),
    body, foot);
  document.body.append(scrim, drawer);
  document.addEventListener("keydown", e => { if (e.key === "Escape" && drawer.classList.contains("on")) close(); });
}

export function close() {
  if (!drawer) return;
  drawer.classList.remove("on"); scrim.classList.remove("on");
  lastFocus?.focus?.();
}

export async function openIpDrawer(ip, { onChanged } = {}) {
  ensure();
  lastFocus = document.activeElement;
  const my = ++token;
  title.textContent = ip;
  clear(body).append(...[1, 2, 3, 4].map(() => h("div", { class: "skeleton", style: { height: "64px", marginBottom: "14px" } })));
  clear(foot);
  drawer.classList.add("on"); scrim.classList.add("on");
  drawer.querySelector("button")?.focus();
  try {
    const d = await intelService.ip(ip);
    if (my !== token) return;
    title.textContent = d.ip;
    clear(body).append(renderProfile(d));
    renderActions(d, onChanged);
  } catch (e) {
    if (my !== token) return;
    clear(body).append(h("div", { class: "banner" }, e.message));
  }
}

function renderActions(d, onChanged) {
  clear(foot);
  const demo = store.get().resolvedSource === "demo";
  const done = async (fn, msg) => { try { await fn(); toast(msg); onChanged?.(); openIpDrawer(d.ip, { onChanged }); } catch (e) { toast(e.message, "err"); } };
  if (d.local.blocked && !demo)
    foot.append(h("button", { class: "btn", type: "button", onclick: () => done(() => opsService.unblock(d.ip), `Unblocked ${d.ip}`) }, icon("check"), "Unblock"));
  else
    foot.append(h("button", { class: "btn danger", type: "button", disabled: demo, title: demo ? "Blocking is disabled while viewing simulated demo data" : "",
      onclick: () => done(() => opsService.block(d.ip, `Blocked from SOC dashboard (score ${d.intel.score})`), `Blocked ${d.ip}`) }, icon("ban"), "Block IP"));
  foot.append(h("button", { class: "btn", type: "button", disabled: demo, title: demo ? "Disabled for simulated demo data" : "",
    onclick: () => done(() => opsService.whitelistAdd(d.ip), `Added ${d.ip} to trusted list`) }, icon("trust"), "Trust IP"));
  if (demo) foot.append(h("span", { class: "muted", style: { fontSize: "12px", alignSelf: "center" } }, "Response actions are off for demo data."));
}
