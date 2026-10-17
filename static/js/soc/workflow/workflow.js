import { $ } from "../core/dom.js";
import { store } from "../core/store.js";
import { mountSecurityWorkflow } from "./SecurityWorkflow.js";

const app = $("#app");
app.classList.toggle("collapsed", store.get().collapsed);
$("#collapse")?.addEventListener("click", () => { store.set({ collapsed: !store.get().collapsed }); app.classList.toggle("collapsed", store.get().collapsed); });
$("#hamburger")?.addEventListener("click", () => app.classList.toggle("drawer-open"));
$("#global-search")?.addEventListener("keydown", e => { if (e.key === "Enter" && e.target.value.trim()) location.href = `/#/threats?q=${encodeURIComponent(e.target.value.trim())}`; });
// status chips are decorative on this page
const dot = $("#sys-dot"), txt = $("#sys-txt");
fetch("/api/status").then(r => r.ok ? (txt.textContent = "System operational") : Promise.reject()).catch(() => { dot.className = "dot bad"; txt.textContent = "Backend unreachable"; });
$("#lvl-txt").textContent = "Workflow reference"; $("#src-chip").style.display = "none";

mountSecurityWorkflow($("#wf-host"));
