/** intelService — threat intelligence. Keys live on the server; the browser only ever calls /api/intel/*. */
import { http } from "./http.js";
import { store } from "../core/store.js";

export const intelService = {
  providers: () => http("/api/intel/providers"),
  ip: ip => http(`/api/intel/ip/${encodeURIComponent(ip)}?source=${store.get().source}`),
  hash: hsh => http(`/api/intel/hash/${encodeURIComponent(hsh)}`),
  file: file => { const f = new FormData(); f.append("file", file); return http("/api/intel/file", { method: "POST", body: f }); },
};
