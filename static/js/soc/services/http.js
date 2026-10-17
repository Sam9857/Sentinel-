/** The only place that talks HTTP. Throws Error(message) using the server's `error` text when available. */
export async function http(url, { method = "GET", json, body, signal } = {}) {
  const opts = { method, signal, headers: {} };
  if (json !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(json); }
  if (body) opts.body = body;
  let res;
  try { res = await fetch(url, opts); } catch (e) { if (e.name === "AbortError") throw e; throw new Error("Cannot reach the BitSentinel server"); }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (res.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
  if (!res.ok) throw new Error((data && (data.error || data.message)) || `Request failed (${res.status})`);
  return data;
}
export const qs = obj => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== undefined && v !== null && v !== "") p.set(k, v);
  return p.toString();
};
