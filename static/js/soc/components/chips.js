import { h } from "../core/dom.js";
import { SEV, STATUS_LABEL } from "../core/format.js";

export const sevChip = id => h("span", { class: `sev ${id}` }, SEV[id]?.label ?? id);
export const statusState = s => h("span", { class: `state ${s}` }, STATUS_LABEL[s] ?? s);

/** Small horizontal bar + number, coloured by severity band of the value. */
export function repBar(value, label) {
  const v = Math.max(0, Math.min(100, Number(value) || 0));
  const sev = v >= 90 ? "critical" : v >= 61 ? "high" : v >= 31 ? "medium" : v >= 1 ? "low" : "info";
  return h("span", { class: "rep", title: label || "", style: { "--c": SEV[sev].color } },
    h("i", {}, h("b", { style: { width: `${v}%` } })), h("span", {}, v));
}
