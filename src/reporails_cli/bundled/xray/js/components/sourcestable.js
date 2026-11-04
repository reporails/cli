// The Sources tab: every source and the coding agent's built-in context items in one virtualised table.
import { el } from '../dom.js';
import { k1 } from '../format.js';
import { UNRECORDED } from '../views.js';
import { vlist, viewHeight, revealRow } from './vlist.js';

const ROW_H = 36;
const scrolled = new WeakMap();

const inContext = (env, s, verb) => {
  if (s.availability === 'unrecorded') return UNRECORDED;
  const n = s.had_by ? s.had_by.length : 0;
  return n ? `${n} of ${env.ix.view.nodes.length} agents` : `never ${verb}`;
};

// Whether the open item is this row's: a source by its id, a built-in item by its key.
const isOpen = (peek, item) => !!peek && (item.s ? peek.kind === 'src' && peek.id === item.s.id : peek.kind === 'builtin' && peek.id === item.key);

function row(env, item) {
  const { state } = env, peek = state.peek;
  const b = el('button', 'vl-row tb-row tb-src-grid');
  b.type = 'button';
  const chip = el('span', item.s ? 'chip on' : 'chip', item.letter);
  chip.setAttribute('aria-hidden', 'true');
  b.append(chip, el('span', 'tb-trunc', item.name), el('span', 'tb-trunc tb-dim', item.kind), el('span', `tb-trunc${item.never ? ' tb-dim' : ''}`, item.who), el('span', 'tb-mono tb-r', item.tokens == null ? '–' : `~${k1(item.tokens)}`), el('span', item.finds ? 'tb-r tb-find' : 'tb-r tb-dim', item.finds ? String(item.finds) : '–'));
  if (item.s) b.dataset.source = item.s.id;
  else b.dataset.peek = `builtin:${item.key}`;
  if (isOpen(peek, item)) b.classList.add('on');
  if (item.never) b.classList.add('never');
  return b;
}

function items(env) {
  const { ix } = env, v = ix.view;
  const out = v.sources.map(s => {
    const k = ix.kinds.get(s.kind);
    return { s, letter: k ? k.letter : s.kind.charAt(0), name: s.label || s.name, kind: k ? k.label : s.kind, who: inContext(env, s, k ? k.verb : 'loaded'), never: s.availability === 'unrecorded' || !(s.had_by && s.had_by.length), tokens: s.tokens_est, finds: (s.findings && s.findings.count) || 0 };
  });
  for (const b of v.builtin || []) out.push({ key: b.key, letter: '·', name: b.label, kind: 'Session context', who: b.visible === 'hidden' ? 'every agent · not visible' : 'every agent', never: false, tokens: b.tokens_est, remainder: b.remainder, finds: 0 });
  return out;
}

const parts = new WeakMap();

export function render(box, env) {
  let p = parts.get(box);
  if (!p || !box.contains(p.list.root)) {
    const head = el('div', 'tb-head tb-src-grid');
    for (const h of ['', 'Name', 'Kind', 'In context', 'Tokens', 'Findings']) head.append(el('span', h === 'Tokens' || h === 'Findings' ? 'tb-r' : '', h));
    p = { list: vlist(ROW_H, 'Sources', head) };
    const table = el('div', 'tb-table');
    table.append(head, p.list.root);
    box.replaceChildren(table);
    parts.set(box, p);
  }
  const all = items(env);
  p.list.set(all.length, i => row(env, all[i]), viewHeight());
  const peek = env.state.peek, at = all.findIndex(it => isOpen(peek, it));
  const key = at >= 0 ? `${peek.kind}:${peek.id}` : '';
  if (scrolled.get(box) !== key) {
    scrolled.set(box, key);
    if (at >= 0) revealRow(p.list.root, at, ROW_H);
  }
}
