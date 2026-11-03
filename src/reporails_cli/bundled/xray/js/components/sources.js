// The Sources panel: an inventory of everything the session had, whatever the graph shows. Built in first, then one group
// per source kind the adapter declares; each header says how many were used and carries the kind's eye for the graph.
import { el, svg } from '../dom.js';
import { costEst, fill, tk, plural } from '../format.js';
import { SOURCES_SHOWN } from '../geometry.js';

const BUILTIN = 'builtin';
const EYE = 'M2 12s4-7 10-7s10 7 10 7s-4 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z';

// Used of total from the funnel row (loaded of on disk); a kind with no funnel row counts its own list.
function counts(ix, key, list) {
  const row = (ix.view.funnel || []).find(f => f.kind === key);
  if (!row) return { used: list.filter(s => s.availability === 'loaded').length, total: list.length };
  return { used: row.loaded ?? 0, total: row.on_disk };
}

const findingsText = n => `${n} finding${n === 1 ? '' : 's'}`;
const findingsOf = s => (s.findings && s.findings.count) || 0;

// Line 2 of a row: its size, its cost and its findings, or that it never entered a context.
function facts(s, kind) {
  if (s.builtin) return [`built in · launched as ${plural(s.launches || 0, 'subagent')}`];
  const bits = [];
  const finds = findingsOf(s);
  if (s.availability !== 'loaded') bits.push(kind.definitions ? 'never launched' : 'not loaded');
  else {
    if (s.tokens_est != null) bits.push(`${tk(s.tokens_est, true)} tok`);
    const c = costEst(s.cost_usd_est);
    if (c) bits.push(c);
  }
  if (finds) bits.push(findingsText(finds));
  return bits;
}

function dot(ix, s) {
  const d = el('span', 'sdot' + (findingsOf(s) ? ' find' : ''));
  const t = s.agent_type ? ix.types.get(s.agent_type) : null;
  if (!t) return d;
  d.classList.add('sq');
  d.style.background = t.colour;
  return d;
}

function row(env, s) {
  const { ix } = env;
  const kind = ix.kinds.get(s.kind) || {};
  const never = s.availability !== 'loaded';
  const r = el('div', 'sr' + (never ? ' never' : '') + (env.focus && env.focus.id === s.id ? ' on' : ''));
  r.dataset.source = s.id;
  r.tabIndex = 0;
  r.setAttribute('role', 'button');
  const label = s.label || s.name;
  const finds = findingsOf(s);
  r.setAttribute('aria-label', `${label}${never ? ', not loaded' : ''}${finds ? `, ${findingsText(finds)}` : ''}. Open details.`);
  r.append(dot(ix, s));
  const text = el('span', 'stx');
  const top = el('span', 'sline');
  top.append(el('b', 'sn', label));
  if (s.scopes && s.scopes.length) top.append(el('span', 'scoped', 'scoped'));
  text.append(top, el('span', 'sw', facts(s, kind).join(' · ')));
  r.append(text);
  return r;
}

function builtinRow(item) {
  const r = el('div', 'sr');
  r.dataset.peek = `${BUILTIN}:${item.key}`;
  r.tabIndex = 0;
  r.setAttribute('role', 'button');
  r.setAttribute('aria-label', `${item.label}. Open details.`);
  r.append(el('span', 'sdot'));
  const text = el('span', 'stx');
  const top = el('span', 'sline');
  top.append(el('b', 'sn', item.label));
  text.append(top, el('span', 'sw', [`${tk(item.tokens_est, true)} tok`, item.visible === 'hidden' ? 'not in transcript' : null].filter(Boolean).join(' · ')));
  r.append(text);
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
    for (const key of [BUILTIN, ...ix.view.adapter.source_kinds.map(k => k.key)]) state.sourceGroups[key] = all.dataset.groups === 'open';
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

function eyeButton(k, on) {
  const b = el('button', 'sx-eye');
  b.type = 'button';
  b.dataset.eye = k.key;
  b.setAttribute('aria-pressed', String(on));
  b.setAttribute('aria-label', `${on ? 'Hide' : 'Show'} ${k.graph_label} on the graph`);
  b.title = b.getAttribute('aria-label');
  const s = svg('svg', { width: 16, height: 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
  s.append(svg('path', { d: on ? EYE : `${EYE} M3 3l18 18` }));
  b.append(s);
  return b;
}

// A group: its header (chevron, chip, name, used/total, findings line, hidden line, eye) and its items when open.
function group(env, spec) {
  const { state, ix } = env;
  const open = isOpen(state, ix, spec.key);
  const wrap = el('section', 'ssec' + (spec.hidden ? ' hidden' : ''));
  wrap.dataset.kind = spec.key;
  const head = el('div', 'sx-hd');
  const button = el('button', 'sh');
  button.type = 'button';
  button.dataset.sourceGroup = spec.key;
  button.setAttribute('aria-expanded', String(open));
  button.setAttribute('aria-label', [spec.label, spec.usage, spec.finds ? findingsText(spec.finds) : null].filter(Boolean).join(', '));
  button.append(el('span', 'chev', open ? '▾' : '▸'), el('span', 'chip on', spec.letter), el('span', 'sx-title', spec.label));
  const ct = el('span', 'ct');
  ct.title = spec.usage;
  ct.append(el('b', 'used', String(spec.used)));
  if (spec.total != null) ct.append(el('span', 'tot', `/${spec.total}`));
  button.append(ct);
  if (spec.finds) button.append(el('span', 'sx-sub gf', findingsText(spec.finds)));
  if (spec.hidden) button.append(el('span', 'sx-sub off', `${spec.graphLabel} hidden on the graph`));
  head.append(button);
  if (spec.eye) head.append(eyeButton(spec.eye, !spec.hidden));
  wrap.append(head);
  const body = el('div', 'sbody');
  body.hidden = !open;
  if (open) {
    if (spec.absent) body.append(el('div', 'nk', spec.absent));
    const all = state.more.has(spec.key);
    for (const r of all ? spec.rows : spec.rows.slice(0, SOURCES_SHOWN)) body.append(r);
    if (spec.rows.length > SOURCES_SHOWN) {
      const b = el('button', 'slink smore', all ? 'Show fewer' : `Show ${spec.rows.length - SOURCES_SHOWN} more`);
      b.dataset.more = spec.key;
      body.append(b);
    }
  }
  wrap.append(body);
  return wrap;
}

export function render(box, env) {
  const { ix, state } = env;
  const templates = ix.view.adapter.fact_notes || {};
  // Loaded items first, each group in the view's own order otherwise.
  const lists = new Map(ix.view.adapter.source_kinds.map(k => [k.key, ix.view.sources.filter(s => s.kind === k.key).sort((a, b) => (a.availability !== 'loaded') - (b.availability !== 'loaded'))]));
  reveal(env, lists);
  box.replaceChildren(controls());
  const builtin = ix.view.builtin || [];
  if (builtin.length) {
    box.append(group(env, {
      key: BUILTIN, label: 'Built in', letter: '·', used: builtin.length, total: null, usage: plural(builtin.length, 'item'),
      finds: 0, rows: builtin.map(builtinRow),
    }));
  }
  for (const k of ix.view.adapter.source_kinds) {
    const list = lists.get(k.key);
    const { used, total } = counts(ix, k.key, list);
    const absent = ix.view.facts.find(f => f.kind === 'kind_absent' && f.target && f.target.value === k.key);
    box.append(group(env, {
      key: k.key, label: k.label, letter: k.letter, used, total, usage: `${used} of ${total} ${k.verb}`,
      finds: list.reduce((n, s) => n + findingsOf(s), 0), hidden: !state.layers[k.key], graphLabel: k.graph_label, eye: k,
      absent: absent && templates.kind_absent ? fill(templates.kind_absent, { ...absent.numbers, label: k.label.toLowerCase() }) : null,
      rows: list.map(s => row(env, s)),
    }));
  }
}
