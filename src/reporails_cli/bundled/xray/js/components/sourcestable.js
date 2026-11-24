// The Sources tab: every source in one virtualised table.
import { el } from '../dom.js';
import { markOpen } from './details.js';
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

const openKey = item => `src:${item.s.id}`;
const isOpen = (peek, item) => !!peek && `${peek.kind}:${peek.id}` === openKey(item);

function row(env, item) {
  const b = el('button', 'vl-row tb-row tb-src-grid');
  b.type = 'button';
  const chip = el('span', 'chip on', item.letter);
  chip.setAttribute('aria-hidden', 'true');
  b.append(chip, el('span', 'tb-trunc', item.name), el('span', 'tb-trunc tb-dim', item.kind), el('span', `tb-trunc${item.never ? ' tb-dim' : ''}`, item.who), el('span', 'tb-mono tb-r', item.tokens == null ? '–' : `~${k1(item.tokens)}`), el('span', item.finds ? 'tb-r tb-find' : 'tb-r tb-dim', item.finds ? String(item.finds) : '–'));
  b.dataset.source = item.s.id;
  markOpen(b, env.state.peek, [openKey(item)], 'on');
  if (item.never) b.classList.add('never');
  return b;
}

function items(env) {
  const { ix } = env, v = ix.view;
  const out = v.sources.map(s => {
    const k = ix.kinds.get(s.kind);
    return { s, letter: k ? k.letter : s.kind.charAt(0), name: s.label || s.name, kind: k ? k.label : s.kind, who: inContext(env, s, k ? k.verb : 'loaded'), never: s.availability === 'unrecorded' || !(s.had_by && s.had_by.length), tokens: s.tokens_est, finds: (s.findings && s.findings.count) || 0 };
  });
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
