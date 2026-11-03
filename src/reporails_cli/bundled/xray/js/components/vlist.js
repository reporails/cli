// A virtualised list: fixed row height, only the rows in view plus a small overscan are in the DOM,
// inside a scroll container sized to the whole list. It is a grid: its header row (when given) is owned by the grid,
// every row carries its index, and the arrow keys move between rows whether or not the next one is drawn yet.
import { el } from '../dom.js';
import { keepFocus } from '../focus.js';

const OVERSCAN = 6;
const PAGE = 8;

let serial = 0;

// `rowH` px per row; `head` is the header element, drawn by the caller above the list.
// set(count, build, viewH) (re)draws; build(i) returns the row's element.
export function vlist(rowH, label, head) {
  const root = el('div', 'vl');
  root.setAttribute('aria-label', label);
  root.setAttribute('role', 'grid');
  root.tabIndex = 0;
  if (head) {
    head.id = `vl-head-${++serial}`;
    head.setAttribute('role', 'row');
    for (const c of head.children) c.setAttribute('role', 'columnheader');
    root.setAttribute('aria-owns', head.id);
  }
  const sizer = el('div', 'vl-sizer');
  sizer.setAttribute('role', 'rowgroup');
  root.append(sizer);
  let count = 0, build = null, shown = '';
  const draw = force => {
    const h = root.clientHeight || rowH * 12;
    const first = Math.max(0, Math.floor(root.scrollTop / rowH) - OVERSCAN);
    const last = Math.min(count, Math.ceil((root.scrollTop + h) / rowH) + OVERSCAN);
    const key = `${first}:${last}`;
    if (!force && key === shown) return;
    shown = key;
    const rows = [];
    for (let i = first; i < last; i++) {
      const r = build(i);
      r.setAttribute('role', 'row');
      r.setAttribute('aria-rowindex', String(i + 1));
      for (const c of r.children) c.setAttribute('role', 'gridcell');
      r.style.top = `${i * rowH}px`;
      r.style.height = `${rowH}px`;
      rows.push(r);
    }
    keepFocus(() => sizer.replaceChildren(...rows));
  };
  // Moves focus to row `at`, scrolling it into view and drawing it first when it is outside the drawn window.
  const goTo = at => {
    const i = Math.max(0, Math.min(count - 1, at));
    const h = root.clientHeight || rowH * 12;
    if (i * rowH < root.scrollTop) root.scrollTop = i * rowH;
    else if ((i + 1) * rowH > root.scrollTop + h) root.scrollTop = (i + 1) * rowH - h;
    draw(false);
    const row = sizer.querySelector(`[aria-rowindex="${i + 1}"]`);
    if (row) row.focus();
  };
  root.addEventListener('scroll', () => draw(false), { passive: true });
  root.addEventListener('keydown', e => {
    const row = e.target.closest ? e.target.closest('[aria-rowindex]') : null;
    if (!row || e.altKey || e.ctrlKey || e.metaKey) return;
    const at = Number(row.getAttribute('aria-rowindex')) - 1;
    const to = { ArrowDown: at + 1, ArrowUp: at - 1, PageDown: at + PAGE, PageUp: at - PAGE, Home: 0, End: count - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    goTo(to);
  });
  return {
    root,
    set(n, fn, viewH) {
      count = n;
      build = fn;
      root.setAttribute('aria-rowcount', String(n));
      sizer.style.height = `${n * rowH}px`;
      root.style.height = `${Math.min(n * rowH, viewH)}px`;
      draw(true);
    },
  };
}

// The scroll area's height for the window: tall enough to be useful, short enough to leave the toolbar in view.
export const viewHeight = () => Math.max(280, Math.min(640, window.innerHeight - 280));
