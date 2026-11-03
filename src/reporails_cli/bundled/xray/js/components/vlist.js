// A virtualised list: fixed row height, only the rows in view plus a small overscan are in the DOM,
// inside a scroll container sized to the whole list.
import { el } from '../dom.js';

const OVERSCAN = 6;

// `rowH` px per row. set(count, build, viewH) (re)draws; build(i) returns the row's element.
export function vlist(rowH, label) {
  const root = el('div', 'vl');
  root.setAttribute('aria-label', label);
  root.setAttribute('role', 'region');
  root.tabIndex = 0;
  const sizer = el('div', 'vl-sizer');
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
      r.style.top = `${i * rowH}px`;
      r.style.height = `${rowH}px`;
      rows.push(r);
    }
    sizer.replaceChildren(...rows);
  };
  root.addEventListener('scroll', () => draw(false), { passive: true });
  return {
    root,
    set(n, fn, viewH) {
      count = n;
      build = fn;
      sizer.style.height = `${n * rowH}px`;
      root.style.height = `${Math.min(n * rowH, viewH)}px`;
      draw(true);
    },
  };
}

// The scroll area's height for the window: tall enough to be useful, short enough to leave the toolbar in view.
export const viewHeight = () => Math.max(280, Math.min(640, window.innerHeight - 280));
