/**
 * opsService — response & configuration actions.
 * Wraps the ORIGINAL BitSentinel endpoints unchanged (api_routes, prevention_routes, monitor_routes).
 */
import { http } from "./http.js";

export const opsService = {
  scanIP: ip => http("/api/scan/ip", { method: "POST", json: { ip } }),
  scanLog: file => { const f = new FormData(); f.append("file", file); return http("/api/scan/log", { method: "POST", body: f }); },
  clearHistory: () => http("/api/clear", { method: "POST" }),
  report: () => http("/api/report"),
  blacklist: () => http("/api/prevention/blacklist"),
  block: (ip, reason = "Blocked from SOC dashboard") => http("/api/block", { method: "POST", json: { ip, reason } }),
  unblock: ip => http("/api/unblock", { method: "POST", json: { ip } }),
  whitelist: () => http("/api/prevention/whitelist"),
  whitelistAdd: ip => http("/api/prevention/whitelist/add", { method: "POST", json: { ip } }),
  whitelistRemove: ip => http("/api/prevention/whitelist/remove", { method: "POST", json: { ip } }),
  config: () => http("/api/prevention/config"),
  saveConfig: cfg => http("/api/prevention/config", { method: "POST", json: cfg }),
  simulate: body => http("/api/prevention/simulate", { method: "POST", json: body }),
  rateLimits: () => http("/api/prevention/ratelimit"),
  resetRateLimits: ip => http("/api/prevention/ratelimit/reset", { method: "POST", json: ip ? { ip } : {} }),
  monitorStatus: () => http("/api/live-monitoring/status"),
  monitorStart: (mode, interval = 5) => http("/api/live-monitoring/start", { method: "POST", json: { mode, interval } }),
  monitorStop: () => http("/api/live-monitoring/stop", { method: "POST" }),
  tapFeed: () => http("/api/live-monitoring/tap-feed"),
  setLogPath: path => http("/api/live-monitoring/set-log-path", { method: "POST", json: { path } }),
  activity: (limit = 50) => http(`/api/activity?limit=${limit}`),
};
