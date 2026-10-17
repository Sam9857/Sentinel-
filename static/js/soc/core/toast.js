import { h } from "./dom.js";
let box;
export function toast(msg, kind = "ok", ms = 3200) {
  box ||= document.body.appendChild(h("div", { class: "toast-box", role: "status", "aria-live": "polite" }));
  const el = h("div", { class: `toast ${kind === "ok" ? "" : kind}` }, msg);
  box.append(el);
  setTimeout(() => { el.style.transition = "opacity .25s"; el.style.opacity = "0"; setTimeout(() => el.remove(), 260); }, ms);
}
