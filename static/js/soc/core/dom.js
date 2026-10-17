/** Minimal DOM helpers. Data is always inserted as text nodes — never as HTML. */
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const SVG_NS = "http://www.w3.org/2000/svg";

export function h(tag, attrs = {}, ...kids) {
  const svg = tag === "svg" || (attrs && attrs.__svg);
  const el = svg ? document.createElementNS(SVG_NS, tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "__svg" || v === false || v == null) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k === "style" && typeof v === "object") { for (const [sk, sv] of Object.entries(v)) { if (sv == null) continue; sk.startsWith("--") ? el.style.setProperty(sk, sv) : (el.style[sk] = sv); } }
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

export function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
export function mount(el, ...kids) { clear(el); append(el, kids); return el; }

/** Build a node from a trusted, hard-coded markup string (used only for icons). */
export function html(str) { const t = document.createElement("template"); t.innerHTML = str.trim(); return t.content.firstChild; }

export function debounce(fn, ms = 250) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
