/**
 * liveFeed — one real-time stream for the whole app.
 *   live data → existing SSE endpoint /stream/threats (pushes when scans / the live monitor add records)
 *   demo data → /api/soc/demo/tick (one simulated event every few seconds, clearly labelled as demo)
 * Emits normalised events on the bus: on("event", ev)
 */
import { emit } from "../core/bus.js";
import { store } from "../core/store.js";
import { socService } from "./socService.js";

export function startLiveFeed() {
  let es, demoTimer, seen = new Set(), primed = false, debounceT, stopped = false;

  const mode = () => store.get().resolvedSource;

  async function pollNew() {
    if (mode() !== "live") return;
    try {
      const d = await socService.events(8);
      const fresh = d.events.filter(e => !seen.has(e.id));
      d.events.forEach(e => seen.add(e.id));
      if (primed) fresh.reverse().forEach(e => emit("event", e));
      primed = true;
      if (fresh.length && primed) emit("refresh", { reason: "live" });
    } catch { /* transient */ }
  }

  function connectSSE() {
    if (es || typeof EventSource === "undefined") return;
    es = new EventSource("/stream/threats");
    es.addEventListener("threat", () => { clearTimeout(debounceT); debounceT = setTimeout(pollNew, 1200); });
    es.addEventListener("error", () => { /* EventSource retries on its own */ });
  }

  function scheduleDemo() {
    clearTimeout(demoTimer);
    if (stopped) return;
    demoTimer = setTimeout(async () => {
      if (mode() === "demo" && !document.hidden) {
        try { emit("event", await socService.demoTick()); } catch { /* ignore */ }
      }
      scheduleDemo();
    }, 3200 + Math.random() * 2600);
  }

  connectSSE();
  scheduleDemo();
  pollNew();
  return () => { stopped = true; es?.close(); clearTimeout(demoTimer); clearTimeout(debounceT); };
}
