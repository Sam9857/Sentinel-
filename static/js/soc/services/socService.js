/**
 * socService — read-only dashboard data.
 * Each function maps 1:1 to an endpoint in routes/soc_routes.py.
 */
import { http, qs } from "./http.js";
import { store } from "../core/store.js";

const base = () => { const s = store.get(); return { range: s.range, source: s.source }; };
const track = d => { if (d?.data_source && d.data_source !== store.get().resolvedSource) store.set({ resolvedSource: d.data_source }); return d; };

export const socService = {
  meta:     () => http("/api/soc/meta"),
  overview: () => http(`/api/soc/overview?${qs(base())}`).then(track),
  timeline: () => http(`/api/soc/timeline?${qs(base())}`).then(track),
  events:   (limit = 40, min_score = 0) => http(`/api/soc/events?${qs({ ...base(), limit, min_score })}`).then(track),
  map:      () => http(`/api/soc/map?${qs(base())}`).then(track),
  threats:  (p = {}) => http(`/api/soc/threats?${qs({ ...base(), ...p })}`).then(track),
  demoTick: () => http("/api/soc/demo/tick"),
  status:   () => http("/api/status"),
};
