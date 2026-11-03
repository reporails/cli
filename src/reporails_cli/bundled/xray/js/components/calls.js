// The Tool calls tab: every call of every agent in one filterable, virtualised table with a timeline strip,
// and the `call` details renderer.
import { el, nk, err } from '../dom.js';
import { clock, k1 } from '../format.js';
import { typeOf, callIndex, subtreeIds } from '../views.js';
import { callDetail } from '../api.js';
import { registerPeek, scrollable } from './details.js';
import { vlist, viewHeight } from './vlist.js';

const ROW_H = 34;
const LIMIT = 150;
const STRIP_W = 1000;
const STRIP_H = 30;

// The agent the scope filters speak of: the selected one, else the one the page is looking at.
const subjectOf = env => env.ix.nodes.get(env.state.sel) || env.ix.nodes.get(env.state.path[env.state.path.length - 1]) || env.ix.view.nodes[0];

function filteredCalls(env) {
  const { ix, state } = env;
  const f = state.calls, subject = subjectOf(env);
  const scope = f.scope === 'sub' && !subject.children.length ? 'one' : f.scope;
  const within = scope === 'sub' ? subtreeIds(ix, subject.id) : null;
  return callIndex(ix).list.filter(({ call, node }) => {
    if (scope === 'one' && node.id !== subject.id) return false;
    if (within && !within.has(node.id)) return false;
    if (f.tool !== 'all' && call.tool !== f.tool) return false;
    return !f.failed || call.failed;
  });
}

const took = s => (s == null ? '–' : s < 1 ? `${Math.round(s * 1000)}ms` : `${s.toFixed(1)}s`);

function seg(attr, value, label, on, colour, title) {
  const b = el('button', 'seg');
  if (title) b.title = title;
  b.type = 'button';
  b.dataset[attr] = value;
  b.setAttribute('aria-pressed', String(on));
  if (colour) {
    const d = el('span', 'sdot2');
    d.style.background = colour;
    b.append(d);
  }
  b.append(...[].concat(label));
  return b;
}

function filterButtons(env, subject) {
  const { ix, state } = env, f = state.calls, idx = callIndex(ix);
  const scope = f.scope === 'sub' && !subject.children.length ? 'one' : f.scope;
  const scopes = el('div', 'seggrp');
  scopes.setAttribute('role', 'group');
  scopes.setAttribute('aria-label', 'Agents');
  // With one agent there is nothing to scope.
  if (ix.view.nodes.length > 1) {
    const only = el('span', 'segname', subject.name);
    scopes.append(seg('callsScope', 'all', 'All agents', scope === 'all'), seg('callsScope', 'one', [only, ' only'], scope === 'one', null, `${subject.name} only`));
    if (subject.children.length) scopes.append(seg('callsScope', 'sub', '+ its subagents', scope === 'sub'));
  }
  const tools = el('div', 'seggrp');
  tools.setAttribute('role', 'group');
  tools.setAttribute('aria-label', 'Tools');
  const seen = new Map();
  for (const { call } of idx.list) if (!seen.has(call.tool)) seen.set(call.tool, idx.colour(call.category));
  tools.append(seg('callsTool', 'all', 'All tools', f.tool === 'all'));
  for (const [tool, colour] of seen) tools.append(seg('callsTool', tool, tool, f.tool === tool, colour));
  const status = el('div', 'seggrp');
  status.append(seg('callsFailed', '1', 'Failed only', f.failed));
  return [scopes, tools, status];
}

function drawStrip(canvas, env, rows) {
  const { ix, state } = env, idx = callIndex(ix);
  const span = Math.max(ix.view.length_s || 0, ...idx.list.map(r => r.call.t), 1);
  const ctx = canvas.getContext('2d');
  canvas.width = STRIP_W;
  ctx.clearRect(0, 0, STRIP_W, STRIP_H);
  const css = getComputedStyle(document.documentElement);
  const bad = css.getPropertyValue('--find').trim() || '#F0883E';
  const open = state.peek && state.peek.kind === 'call' ? state.peek.id : null;
  const x = t => Math.min(STRIP_W - 2, (t / span) * STRIP_W);
  const byColour = new Map();
  const fails = [];
  let hot = null;
  for (const r of rows) {
    if (r.call.use_id === open) hot = r;
    else if (r.call.failed) fails.push(r);
    else {
      const c = idx.colour(r.call.category);
      if (!byColour.has(c)) byColour.set(c, []);
      byColour.get(c).push(r);
    }
  }
  ctx.globalAlpha = 0.65;
  for (const [c, list] of byColour) {
    ctx.fillStyle = c;
    for (const r of list) ctx.fillRect(x(r.call.t), 6, 1.5, 16);
  }
  ctx.globalAlpha = 1;
  ctx.fillStyle = bad;
  for (const r of fails) ctx.fillRect(x(r.call.t), 3, 2, 24);
  if (hot) {
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(x(hot.call.t) - 0.5, 1, 3, 28);
  }
  return span;
}

// What the Call column prints: the call's label; for a call with no file target (its label is its tool's name), the
// first line of its shell command once the server has answered. Only drawn rows reach this, so only they ask.
export function summaryOf(c) {
  if (c.category !== 'run' || c.label !== c.tool) return c.label;
  const line = (callDetail(c.use_id).text || '').split('\n').map(l => l.trim()).find(Boolean);
  return line || c.label;
}

function callRow(env, r) {
  const { ix, state } = env, c = r.call;
  const open = state.peek && state.peek.kind === 'call' && state.peek.id === c.use_id;
  const b = el('button', `vl-row tb-row tb-calls${c.failed ? ' bad' : ''}${open ? ' on' : ''}`);
  b.type = 'button';
  b.dataset.peek = `call:${c.use_id}`;
  const what = summaryOf(c);
  b.title = `${clock(c.t)} ${c.tool} ${what}${c.failed ? ', failed' : ''}`;
  const agent = el('span', 'tb-agent');
  const dot = el('span', 'tb-adot');
  dot.style.background = typeOf(ix, r.node).colour;
  agent.append(dot, el('span', 'tb-trunc', r.node.name));
  const tool = el('span', 'tb-tool tb-trunc', c.tool);
  tool.style.color = callIndex(ix).colour(c.category);
  b.append(
    el('span', 'tb-mono', clock(c.t)), agent, tool, el('span', 'tb-trunc', what),
    el('span', 'tb-mono tb-r', c.result_tokens_est == null ? '–' : `~${k1(c.result_tokens_est)}`),
    el('span', 'tb-mono tb-r', took(c.duration_s)),
    el('span', c.failed ? 'tb-fail' : 'tb-ok', c.failed ? 'failed' : 'ok'),
  );
  return b;
}

const parts = new WeakMap();

function skeleton(box) {
  const bar = el('div', 'tb-bar');
  const summary = el('span', 'tb-summary');
  summary.setAttribute('role', 'status');
  const filters = el('div', 'tb-filters');
  bar.append(summary, filters);
  const strip = el('div', 'tb-strip');
  const canvas = el('canvas', 'tb-canvas');
  canvas.setAttribute('role', 'img');
  const ticks = el('div', 'tb-ticks');
  strip.append(canvas, ticks);
  const head = el('div', 'tb-head tb-calls');
  for (const h of ['Time', 'Agent', 'Tool', 'Call', 'Result', 'Result after', 'Status']) head.append(el('span', h === 'Result' || h === 'Result after' ? 'tb-r' : '', h));
  const list = vlist(ROW_H, 'Tool calls', head);
  const empty = nk('No call matches these filters.');
  empty.hidden = true;
  const more = el('button', 'seg tb-more');
  more.type = 'button';
  more.dataset.callsAll = '1';
  more.hidden = true;
  const table = el('div', 'tb-table');
  table.append(head, list.root, empty, more);
  box.replaceChildren(bar, strip, table);
  return { summary, filters, canvas, ticks, list, empty, more };
}

export function render(box, env) {
  let p = parts.get(box);
  if (!p || !box.contains(p.summary)) { p = skeleton(box); parts.set(box, p); }
  const { state } = env, f = state.calls;
  const rows = filteredCalls(env);
  const subject = subjectOf(env);
  const total = callIndex(env.ix).list.length;
  const summary = `${rows.length} of ${total} calls · ${rows.filter(r => r.call.failed).length} failed`;
  if (p.summary.textContent !== summary) p.summary.textContent = summary;
  p.filters.replaceChildren(...filterButtons(env, subject));
  const span = drawStrip(p.canvas, env, rows);
  p.canvas.setAttribute('aria-label', `Timeline of ${rows.length} tool calls`);
  p.ticks.replaceChildren(...[0, 1, 2, 3, 4].map(i => {
    const s = el('span', 'tb-tick', clock((span * i) / 4));
    s.style.left = `${i * 25}%`;
    return s;
  }));
  const shown = f.all ? rows : rows.slice(0, LIMIT);
  p.empty.hidden = rows.length > 0;
  p.list.root.hidden = rows.length === 0;
  p.list.set(shown.length, i => callRow(env, shown[i]), viewHeight());
  const over = rows.length > LIMIT;
  p.more.hidden = !over;
  p.more.textContent = f.all ? `Show first ${LIMIT}` : `Show all ${rows.length} calls`;
}

// ---- the call's details

const block = (title, node) => {
  const d = el('div', 'tb-block');
  d.append(el('div', 'tb-bt', title), node);
  return d;
};

const pre = (text, bad) => scrollable(el('pre', `tb-pre${bad ? ' bad' : ''}`, text), bad ? 'Result excerpt' : 'Call text');

function inContext(env, r) {
  const { ix } = env, st = ix.stations.get(r.node.id);
  const seen = new Set(), out = [];
  for (const l of st ? st.loads : []) {
    const s = ix.sources.get(l.source);
    if (!s || l.t > r.call.t || !(ix.kinds.get(s.kind) || {}).instructions || seen.has(s.id)) continue;
    seen.add(s.id);
    const b = el('button', 'tb-src');
    b.type = 'button';
    b.dataset.source = s.id;
    b.append(el('span', 'tb-trunc', s.label || s.name), el('span', 'tb-find', s.findings && s.findings.count ? `${s.findings.count} findings` : ''));
    out.push(b);
  }
  return out;
}

// The agent's context total at the last reply at or before the call.
function contextThen(r) {
  const comp = r.node.detail && r.node.detail.composition;
  let total = null;
  for (const row of comp ? comp.replies : []) if (row[0] <= r.call.t) total = row[1];
  return total;
}

registerPeek('call', (env, id) => {
  const r = callIndex(env.ix).byId.get(id);
  if (!r) return null;
  const { call, node } = r, ty = typeOf(env.ix, node);
  const kv = el('div', 'tb-kv');
  const then = contextThen(r);
  for (const [k, v] of [['Agent', `${node.name} · ${ty.label}`], ['At', clock(call.t)], ['Result after', took(call.duration_s)], ['Context then', then == null ? '–' : `${k1(then)} · exact total that turn`]]) kv.append(el('span', 'tb-lb', k), el('span', 'tb-v', v));
  const d = callDetail(id);
  const main = [kv];
  if (d.loading) main.push(nk('Loading the call…'));
  else if (d.error) main.push(err(d.error));
  else {
    main.push(block('Input', pre(d.data.input || '–')), block('Result (excerpt)', pre(d.data.result || 'No result recorded.', call.failed)));
    if (d.data.truncated) main.push(nk('Shortened: the full text is longer than shown.'));
  }
  const files = inContext(env, r);
  const side = [block('Instructions in context at this call', files.length ? el('div', 'tb-srcs') : nk('None loaded yet.'))];
  if (files.length) side[0].lastChild.append(...files);
  const show = el('button', 'tb-act', 'Show in graph');
  show.type = 'button';
  show.dataset.showInGraph = node.id;
  const tags = [call.failed ? 'failed' : 'ok'];
  if (call.result_tokens_est != null) tags.push(`~${k1(call.result_tokens_est)} result · estimated`);
  return { chip: call.tool.charAt(0), kicker: `Tool call · ${node.name}`, title: summaryOf(call) || call.tool, tags, main, side, actions: [show] };
});
