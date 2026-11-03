// The details frame: one open item ({kind, id}) drawn by the renderer registered for its kind. On the Graph tab the frame
// is a dialog over the canvas column; on the other tabs the same output fills a one-column side panel.
import { el, nk, sync } from '../dom.js';
import { find, keyOf, restore } from '../focus.js';

const renderers = new Map();
const listeners = [];

// render(env, id) -> { chip, kicker, title, tags[], main: Node[], side: Node[], actions: Node[] } | null
export function registerPeek(kind, render) {
  renderers.set(kind, render);
  for (const fn of listeners) fn();
}

export const onPeekRegister = fn => { listeners.push(fn); };

// "kind:id" as written in data-peek; the id may hold colons.
export function parsePeek(value) {
  const at = value.indexOf(':');
  return at < 0 ? null : { kind: value.slice(0, at), id: value.slice(at + 1) };
}

const peekKey = peek => (peek ? `${peek.kind}:${peek.id}` : '');

const asNode = (v, cls) => (typeof v === 'string' ? el('span', cls, v) : v);

function head(out, side) {
  const h = el('div', 'pk-h');
  if (out.chip != null) {
    const chip = asNode(out.chip, 'chip on');
    if (typeof out.chip === 'string') chip.setAttribute('aria-hidden', 'true');
    h.append(chip);
  }
  const titles = el('div', 'pk-t');
  if (out.kicker) titles.append(el('span', 'pk-k', out.kicker));
  const title = el('h2', 'pk-title', out.title);
  title.id = side ? 'peek-title-side' : 'peek-title';
  titles.append(title);
  h.append(titles);
  const tags = el('div', 'pk-tags');
  for (const t of out.tags || []) tags.append(asNode(t, 'tag'));
  h.append(tags);
  const acts = el('div', 'pk-acts');
  acts.append(...(out.actions || []));
  const x = el('button', 'pk-x', '×');
  x.type = 'button';
  x.dataset.closePeek = '1';
  x.setAttribute('aria-label', 'Close details');
  acts.append(x);
  h.append(acts);
  return { h, titleId: title.id };
}

// A scrolling box the keyboard can reach: focusable, named, and a region so a screen reader says what it scrolls.
export function scrollable(box, label) {
  box.tabIndex = 0;
  box.setAttribute('role', 'region');
  box.setAttribute('aria-label', label);
  return box;
}

function section(cls, nodes) {
  const d = el('div', cls);
  d.append(...(nodes || []));
  return d;
}

function content(env, side) {
  const peek = env.state.peek;
  const render = peek && renderers.get(peek.kind);
  const out = render ? render(env, peek.id) : null;
  if (!out) return null;
  const { h, titleId } = head(out, side);
  return { out, h, titleId };
}

// The Graph tab's overlay: a backdrop over the canvas column and the dialog on it.
export function renderOverlay(box, env) {
  const c = env.state.peek ? content(env, false) : null;
  box.hidden = !c;
  // The overlay covers the canvas only; behind it the canvas takes no focus and no clicks.
  document.querySelector('.canvaswrap').inert = !!c;
  if (!c) { sync(box); return; }
  const back = el('div', 'pk-back');
  back.dataset.closePeek = '1';
  const dlg = el('section', 'pk-dialog');
  dlg.setAttribute('role', 'dialog');
  dlg.setAttribute('aria-modal', 'false');
  dlg.setAttribute('aria-labelledby', c.titleId);
  const body = scrollable(el('div', 'pk-body'), 'Details content');
  body.append(section('pk-main', c.out.main), section('pk-side', c.out.side));
  dlg.append(c.h, body);
  sync(box, back, dlg);
}

// Another tab's side panel: the same output in one column, or a line saying nothing is open.
export function renderPanel(box, env) {
  const c = env.state.peek ? content(env, true) : null;
  if (!c) { sync(box, nk('Click a row for its details.')); return; }
  const wrap = el('section', 'pk-panel');
  wrap.setAttribute('role', 'region');
  wrap.setAttribute('aria-labelledby', c.titleId);
  const body = el('div', 'pk-body');
  body.append(section('pk-main', c.out.main), section('pk-side', c.out.side));
  wrap.append(c.h, body);
  sync(box, wrap);
}

// Focus: it goes to the × when details open, and back to the element that opened them when they close.
const focus = { shown: '', opener: null };

// What opened the details: its region and identity, which find its twin after a redraw.
export function remember(from) {
  focus.opener = keyOf(from);
}

export const hasFocusIn = () => !!document.activeElement && !!document.activeElement.closest('.pk-dialog, .pk-panel');

// Called after every draw. `fallback` takes focus when the opener is gone.
export function settle(env, fallback, hadFocusIn) {
  const key = peekKey(env.state.peek);
  const was = focus.shown;
  focus.shown = key;
  if (key === was && !(key && hadFocusIn)) return;
  if (key) {
    if (key === was && restore()) return;
    const x = document.querySelector('.pk-x');
    if (x) x.focus();
    return;
  }
  const o = focus.opener;
  focus.opener = null;
  (find(o) || fallback).focus();
}
