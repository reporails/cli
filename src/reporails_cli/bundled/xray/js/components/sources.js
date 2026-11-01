// The Sources panel: one section per source kind the adapter declares and the layers show.
import { el, tpl, slot } from '../dom.js';
import { k1 } from '../format.js';
import { hashFor } from '../state.js';

const MORE = { memory_unlinked: n => `${n.count} not linked`, repeated_instructions: n => `in ${n.contexts} contexts` };

// Facts that annotate a row: by path target; the kind-level ones are read by `kindCount`.
function rowNotes(facts) {
  const notes = new Map();
  for (const f of facts) {
    if (!f.target || f.target.kind !== 'path' || !MORE[f.kind]) continue;
    notes.set(f.target.value, [...(notes.get(f.target.value) || []), MORE[f.kind](f.numbers)]);
  }
  return notes;
}

// One statement per section from the funnel row: loaded of on disk, plus the listed count only when it differs.
function kindCount(ix, key, list) {
  const row = (ix.view.funnel || []).find(f => f.kind === key);
  if (!row) return list.length ? `${list.filter(s => s.availability === 'loaded').length} of ${list.length} loaded` : '';
  const listed = row.advertised != null && row.advertised !== row.on_disk ? ` · ${row.advertised} listed` : '';
  return `${row.loaded ?? 0} of ${row.on_disk} loaded${listed}`;
}

function who(ix, s) {
  if (s.availability === 'listed') return 'listed, never loaded';
  if (s.availability === 'on_disk') return 'on disk, never loaded';
  const all = ix.view.nodes.length;
  if (s.had_by.length === all) return 'every agent, every level';
  if (s.had_by.length === 1) return ix.nodes.get(s.had_by[0]).name;
  return `${s.had_by.length} of ${all} agents`;
}

function row(env, s, notes) {
  const never = s.availability !== 'loaded';
  const r = el('div', 'sr' + (never ? ' never' : '') + (env.focus && env.focus.id === s.id ? ' on' : ''));
  r.dataset.source = s.id;
  const finds = s.findings && s.findings.count > 0;
  r.append(el('span', 'sdot' + (finds ? ' find' : '')));
  const text = el('span', 'stx');
  text.append(el('b', 'sn', s.name));
  const bits = [who(env.ix, s), ...(notes.get(s.path) || [])];
  if (s.tokens_est != null && !never) bits.push(`${k1(s.tokens_est)} each`);
  text.append(el('span', 'sw', bits.join(' · ')));
  r.append(text);
  if (finds) {
    const p = el('a', 'pill', String(s.findings.count));
    p.href = hashFor(env.state.path, s.path);
    p.title = `${s.findings.count} findings in ${s.name}`;
    r.append(p);
  }
  if (s.path) {
    const open = el('a', 'sopen', '↗');
    open.href = hashFor(env.state.path, s.path);
    open.title = 'open ' + s.path;
    r.append(open);
  }
  return r;
}

export function render(box, env) {
  const { ix, state } = env;
  const facts = ix.view.facts;
  const notes = rowNotes(facts);
  box.replaceChildren();
  for (const k of ix.view.adapter.source_kinds) {
    if (!state.layers[k.key]) continue;
    const sec = tpl('t-source-section');
    const head = sec.firstElementChild;
    head.dataset.kind = k.key;
    slot(head, 'letter').textContent = k.letter;
    slot(head, 'label').textContent = k.label;
    const list = ix.view.sources.filter(s => s.kind === k.key);
    slot(head, 'count').textContent = kindCount(ix, k.key, list);
    const body = slot(head, 'rows');
    if (!list.length) body.append(el('div', 'nk', `No ${k.label.toLowerCase()} configured`));
    for (const s of list) body.append(row(env, s, notes));
    box.append(head);
  }
}
