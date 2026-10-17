/** Tiny pub/sub store for cross-view UI state. Only UI prefs are persisted (never secrets). */
const KEY = "bitsentinel.ui.v2";
const saved = (() => { try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch { return {}; } })();

const state = {
  range: saved.range || "24H",
  source: saved.source || "auto",         // auto | live | demo
  collapsed: !!saved.collapsed,
  resolvedSource: "demo",                  // what the server actually used
  meta: null,
};
const subs = new Set();

export const store = {
  get: () => state,
  set(patch) {
    Object.assign(state, patch);
    try { localStorage.setItem(KEY, JSON.stringify({ range: state.range, source: state.source, collapsed: state.collapsed })); } catch { /* private mode */ }
    subs.forEach(fn => fn(state, patch));
  },
  subscribe(fn) { subs.add(fn); return () => subs.delete(fn); },
};
