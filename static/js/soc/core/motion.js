import { reducedMotion } from "./dom.js";
/** Count a number up. Respects prefers-reduced-motion. */
export function countTo(el, to, { ms = 700, fmt = v => Math.round(v).toLocaleString("en-US") } = {}) {
  if (to == null || Number.isNaN(to)) { el.textContent = "—"; return; }
  const from = Number(el.dataset.v ?? 0);
  el.dataset.v = to;
  if (reducedMotion() || from === to) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const step = now => {
    const p = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(from + (to - from) * e);
    if (p < 1 && el.isConnected) requestAnimationFrame(step); else el.textContent = fmt(to);
  };
  requestAnimationFrame(step);
}
