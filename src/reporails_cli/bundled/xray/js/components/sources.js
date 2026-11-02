// The Sources panel: one section per source kind the adapter declares and the layers show.
import { el, tpl, slot } from '../dom.js';
import { fill, plural, tk } from '../format.js';
import { hashFor } from '../state.js';
import { SOURCES_SHOWN } from '../geometry.js';


// Facts that annotate a row: by path target; the kind-level ones are read by `kindCount`.
function rowNotes(facts, templates) {
  const notes = new Map();
  for (const f of facts) {
    if (!f.target || f.target.kind !== 'path' || !templates[f.kind]) continue;
    notes.set(f.target.value, [...(notes.get(f.target.value) || []), fill(templates[f.kind], f.numbers)]);
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

// A source of a kind the adapter marks as definitions says how often it was launched, not who held it.
const isDefinition = (ix, s) => !!(ix.kinds.get(s.kind) || {}).definitions;

function who(ix, s) {
  if (isDefinition(ix, s)) {
    return s.launches > 0
      ? `launched as ${plural(s.launches, 'subagent')} · passed down as its system prompt`
      : 'defined, never launched';
  }
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
  text.append(el('b', 'sn', isDefinition(env.ix, s) && s.path ? s.path : s.name));
  const bits = [who(env.ix, s), ...(notes.get(s.path) || [])];
  if (s.tokens_est != null && !never && !isDefinition(env.ix, s)) bits.push(`${tk(s.tokens_est, true)} each (estimated)`);
  if (typeof s.cost_usd_est === 'number') bits.push(`~$${s.cost_usd_est.toFixed(2)} estimated`);
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

const isOpen = (state, ix, key) => (key in state.sourceGroups ? state.sourceGroups[key] : key === ix.view.adapter.source_kinds[0].key);

// The focused source's group opens, and its list grows to reach it, once per change of focus.
function reveal(env, lists) {
  const { state, focus } = env;
  const id = focus ? focus.id : null;
  if (id !== null && state.revealed !== id) {
    state.sourceGroups[focus.kind] = true;
    const at = (lists.get(focus.kind) || []).findIndex(s => s.id === id);
    if (at >= SOURCES_SHOWN) state.more.add(focus.kind);
  }
  state.revealed = id;
}

// Called as focus moves: redraws only when the focused source is not on the panel yet.
export function follow(box, env) {
  const id = env.focus ? env.focus.id : null;
  if (id === null || env.state.revealed === id) { env.state.revealed = id; return; }
  const on = [...box.querySelectorAll('.sr')].some(r => r.dataset.source === id);
  if (on) env.state.revealed = id;
  else render(box, env);
}

// A click on a group header, a "show more" or the expand / collapse links; true when it was one of them.
export function click(t, env) {
  const { ix, state } = env;
  const head = t.closest('[data-source-group]');
  if (head) { state.sourceGroups[head.dataset.sourceGroup] = !isOpen(state, ix, head.dataset.sourceGroup); return true; }
  const more = t.closest('[data-more]');
  if (more) { if (!state.more.delete(more.dataset.more)) state.more.add(more.dataset.more); return true; }
  const all = t.closest('[data-groups]');
  if (all) {
    for (const k of ix.view.adapter.source_kinds) state.sourceGroups[k.key] = all.dataset.groups === 'open';
    return true;
  }
  return false;
}

function controls() {
  const bar = el('div', 'sctl');
  bar.append(el('b', 'stitle', 'Sources'));
  const all = el('span', 'sall');
  for (const [mode, label] of [['open', 'Expand all'], ['closed', 'Collapse all']]) {
    const b = el('button', 'slink', label);
    b.dataset.groups = mode;
    all.append(b);
  }
  bar.append(all);
  return bar;
}

export function render(box, env) {
  const { ix, state } = env;
  const facts = ix.view.facts;
  const templates = ix.view.adapter.fact_notes || {};
  const notes = rowNotes(facts, templates);
  const lists = new Map(ix.view.adapter.source_kinds.map(k => [k.key, ix.view.sources.filter(s => s.kind === k.key)]));
  reveal(env, lists);
  box.replaceChildren(controls());
  for (const k of ix.view.adapter.source_kinds) {
    if (!state.layers[k.key]) continue;
    const sec = tpl('t-source-section');
    const wrap = sec.firstElementChild;
    wrap.dataset.kind = k.key;
    const open = isOpen(state, ix, k.key);
    const head = slot(wrap, 'head');
    head.dataset.sourceGroup = k.key;
    head.setAttribute('aria-expanded', open);
    slot(head, 'chev').textContent = open ? '▾' : '▸';
    slot(head, 'letter').textContent = k.letter;
    slot(head, 'label').textContent = k.label;
    const list = lists.get(k.key);
    const finds = list.reduce((n, s) => n + ((s.findings && s.findings.count) || 0), 0);
    if (finds > 0) slot(head, 'finds').textContent = String(finds);
    slot(head, 'count').textContent = kindCount(ix, k.key, list);
    const body = slot(wrap, 'rows');
    body.hidden = !open;
    if (open) {
      const absent = facts.find(f => f.kind === 'kind_absent' && f.target && f.target.value === k.key);
      if (absent && templates.kind_absent) body.append(el('div', 'nk', fill(templates.kind_absent, { ...absent.numbers, label: k.label.toLowerCase() })));
      const all = state.more.has(k.key);
      for (const s of all ? list : list.slice(0, SOURCES_SHOWN)) body.append(row(env, s, notes));
      if (list.length > SOURCES_SHOWN) {
        const b = el('button', 'slink smore', all ? 'Show fewer' : `Show ${list.length - SOURCES_SHOWN} more`);
        b.dataset.more = k.key;
        body.append(b);
      }
      if (k.note) body.append(el('div', 'nk snote', k.note));
    }
    box.append(wrap);
  }
}
