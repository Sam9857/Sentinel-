/** App-wide event bus: 'event' (a live security event), 'refresh' (data changed — views may reload). */
export const bus = new EventTarget();
export const emit = (type, detail) => bus.dispatchEvent(new CustomEvent(type, { detail }));
export const on = (type, fn) => { const f = e => fn(e.detail); bus.addEventListener(type, f); return () => bus.removeEventListener(type, f); };
