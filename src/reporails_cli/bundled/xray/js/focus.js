// Keyboard focus across redraws: every region of the page is rebuilt from the view, so the focused control is recorded by
// the region it sits in and its identity attributes, and focus goes to its twin once the region is drawn again.
const REGIONS = ['#overlay', '#canvas', '#inspector', '#sources', '#view-calls', '#view-sources', '#side-calls', '#side-sources', '#view-file', '#parentstrip', '#header'];

const regionOf = e => REGIONS.find(r => e.closest(r)) || '';

const dataSelector = (tag, pairs) => tag + pairs.map(([name, value]) => `[${name}="${CSS.escape(value)}"]`).join('');

// The key of the element a region draws for an identity, as `keyOf` would write it once that element exists.
export const keyFor = (region, tag, pairs) => ({ region, selector: dataSelector(tag, pairs) });

// What finds an element again: its tag plus its id or data-* attributes, or its first class when it has none.
function selectorOf(e) {
  const tag = e.tagName.toLowerCase();
  if (e.id) return `${tag}[id="${CSS.escape(e.id)}"]`;
  const data = [...e.attributes].filter(a => a.name.startsWith('data-') && a.name !== 'data-slot');
  if (data.length) return dataSelector(tag, data.map(a => [a.name, a.value]));
  const slot = e.getAttribute('data-slot');
  if (slot) return `${tag}[data-slot="${CSS.escape(slot)}"]`;
  const cls = e.classList[0];
  return cls ? `${tag}.${CSS.escape(cls)}` : tag;
}

export function keyOf(e) {
  if (!e || e === document.body || !e.tagName) return null;
  return { region: regionOf(e), selector: selectorOf(e) };
}

export function find(key) {
  if (!key) return null;
  const root = key.region ? document.querySelector(key.region) : document;
  try { return root ? root.querySelector(key.selector) : null; } catch (_) { return null; }
}

let pending = null, depth = 0;

// True while a redraw runs: the focus and blur events it causes are not the user's.
export const redrawing = () => depth > 0;

// Gives focus back to the recorded control; false when it is not drawn any more.
export function restore() {
  const key = pending;
  pending = null;
  const target = find(key);
  if (!target) return false;
  if (document.activeElement !== target) target.focus({ preventScroll: true });
  return true;
}

// Runs a redraw and puts focus back on the control that had it, unless the redraw already placed it somewhere.
export function keepFocus(draw) {
  const outer = depth === 0;
  if (outer) pending = keyOf(document.activeElement);
  depth++;
  try { draw(); } finally { depth--; }
  if (!outer || !pending) return;
  const lost = !document.activeElement || document.activeElement === document.body || !document.activeElement.isConnected;
  if (lost) restore(); else pending = null;
}
