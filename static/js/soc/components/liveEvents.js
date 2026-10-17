import { h, clear } from "../core/dom.js";
import { fmtClock } from "../core/format.js";
import { sevChip, statusState } from "./chips.js";

/** Live security events list. `push()` prepends with a brief highlight; capacity-limited. */
export function createLiveEvents({ onSelect, capacity = 60 } = {}) {
  const list = h("ul", { class: "events", "aria-live": "off" });
  let paused = false, items = [];

  const row = (e, isNew) => h("li", { class: `ev${isNew ? " new" : ""}`, tabindex: 0, role: "button",
      onclick: () => onSelect?.(e), onkeydown: ev => { if (ev.key === "Enter") onSelect?.(e); } },
    h("span", { class: "t" }, fmtClock(e.t)),
    sevChip(e.severity),
    h("div", { class: "m" },
      h("b", {}, e.type),
      h("small", {}, h("span", { class: "mono" }, e.src_ip), e.src_country && h("span", {}, e.src_country), statusState(e.status))));

  const render = () => { clear(list); items.slice(0, capacity).forEach(e => list.append(row(e, false))); if (!items.length) list.append(h("li", { class: "empty" }, "No events in this window")); };

  return {
    el: list,
    set(events) { items = events; render(); },
    push(e) {
      if (paused) return;
      items.unshift(e); if (items.length > capacity) items.pop();
      list.querySelector(".empty")?.remove();
      list.prepend(row(e, true));
      while (list.children.length > capacity) list.lastChild.remove();
    },
    setPaused(p) { paused = p; },
    get paused() { return paused; },
  };
}
