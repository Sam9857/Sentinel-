/** Formatting + the SOC severity vocabulary (mirrors services/severity.py). */
export const SEVERITIES = [
  { id: "critical", label: "Critical", color: "var(--sev-critical)", hex: "#f0525d" },
  { id: "high",     label: "High",     color: "var(--sev-high)",     hex: "#f08a3c" },
  { id: "medium",   label: "Medium",   color: "var(--sev-medium)",   hex: "#e8c14a" },
  { id: "low",      label: "Low",      color: "var(--sev-low)",      hex: "#4aa3e8" },
  { id: "info",     label: "Informational", color: "var(--sev-info)", hex: "#8796a8" },
];
export const SEV = Object.fromEntries(SEVERITIES.map(s => [s.id, s]));

export function classify(score) {
  const s = Number(score) || 0;
  return s >= 90 ? "critical" : s >= 61 ? "high" : s >= 31 ? "medium" : s >= 1 ? "low" : "info";
}

export const STATUS_LABEL = { open: "Open", blocked: "Blocked", investigating: "Investigating", trusted: "Trusted", detected: "Detected" };

export const fmtNum = n => (n == null ? "—" : Number(n).toLocaleString("en-US"));
export const fmtPct = n => (n == null ? "" : `${n > 0 ? "+" : ""}${n}%`);

const pad = n => String(n).padStart(2, "0");
export function fmtClock(t) { const d = new Date(t * 1000); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; }
export function fmtDateTime(t) {
  if (!t) return "—";
  const d = new Date(t * 1000);
  return `${pad(d.getDate())} ${d.toLocaleString("en-US", { month: "short" })} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
export function fmtAgo(t) {
  if (!t) return "—";
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const fmtBytes = b => b == null ? "—" : b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`;
export const looksLikeIP = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s.trim());
