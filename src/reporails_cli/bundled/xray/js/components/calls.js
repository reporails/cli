// The Tool calls tab: every call of every agent in one filterable, virtualised table with a timeline strip,
// and the `call` details renderer.
import { el, nk, err, sync } from '../dom.js';
import { clock, k1 } from '../format.js';
import { typeOf, callIndex, subtreeIds } from '../views.js';
import { callDetail } from '../api.js';
import { registerPeek, scrollable } from './details.js';
import { keepFocus, keyFor } from '../focus.js';
import { vlist, viewHeight, revealRow } from './vlist.js';

const ROW_H = 34;
const LIMIT = 150;
const STRIP_H = 34;
const MARK_W = 2;
// A click or hover this close (CSS px) to a mark belongs to it.
const REACH = 4;

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

const group = (label, cls = 'seggrp') => {
  const g = el('div', cls);
  g.setAttribute('role', 'group');
  g.setAttribute('aria-label', label);
  return g;
};

// The tools in the order of their calls, most called first, each with its colour.
function toolsByUse(idx) {
  const seen = new Map();
  for (const { call } of idx.list) {
    const t = seen.get(call.tool) || { tool: call.tool, colour: idx.colour(call.category), n: 0 };
    t.n++;
    seen.set(call.tool, t);
  }
  return [...seen.values()].sort((p, q) => q.n - p.n);
}

const scopeSegs = (env, subject, scope) => {
  const { ix } = env;
  // With one agent there is nothing to scope.
  if (ix.view.nodes.length <= 1) return [];
  const only = el('span', 'segname', subject.name);
  const out = [seg('callsScope', 'all', 'All agents', scope === 'all'), seg('callsScope', 'one', [only, ' only'], scope === 'one', null, `${subject.name} only`)];
  if (subject.children.length) out.push(seg('callsScope', 'sub', '+ its subagents', scope === 'sub'));
  return out;
};

const toolSeg = (f, t) => seg('callsTool', t.tool, t.tool, f.tool === t.tool, t.colour);

// The filters that are on, in words: "main agent only · Read · failed".
function activeFilters(env, subject, scope) {
  const f = env.state.calls, out = [];
  if (env.ix.view.nodes.length > 1 && scope !== 'all') out.push(scope === 'sub' ? `${subject.name} + subagents` : `${subject.name} only`);
  if (f.tool !== 'all') out.push(f.tool);
  if (f.failed) out.push('failed');
  return out;
}

const menuState = { open: false, refocus: false };
let last = null;

function menuButton(label, pressed) {
  const b = el('button', 'seg tb-menubtn', label);
  b.type = 'button';
  b.dataset.callsMenu = '1';
  b.setAttribute('aria-haspopup', 'true');
  b.setAttribute('aria-expanded', String(menuState.open));
  b.setAttribute('aria-pressed', String(pressed));
  return b;
}

// The filter bar's controls. Wide: the agent scope, the `shown` most-called tools with the rest in a menu, the failed
// filter. Beside open details: one button naming the active filters, its menu holding every group.
function filterNodes(env, subject, scope, tools, shown, narrow, withMenu) {
  const f = env.state.calls;
  const failed = seg('callsFailed', '1', 'Failed only', f.failed);
  const wrap = el('div', 'tb-menuwrap');
  if (narrow) {
    const on = activeFilters(env, subject, scope);
    wrap.append(menuButton(on.length ? on.join(' · ') : 'Filters', on.length > 0));
    if (withMenu) {
      const menu = el('div', 'tb-menu');
      const scopes = group('Agents', 'seggrp wrapgrp');
      scopes.append(...scopeSegs(env, subject, scope));
      const tg = group('Tools', 'seggrp wrapgrp');
      tg.append(seg('callsTool', 'all', 'All tools', f.tool === 'all'), ...tools.map(t => toolSeg(f, t)));
      const st = group('Status', 'seggrp wrapgrp');
      st.append(failed);
      menu.append(...(scopes.children.length ? [scopes] : []), tg, st);
      wrap.append(menu);
    }
    return [wrap];
  }
  const scopes = group('Agents');
  scopes.append(...scopeSegs(env, subject, scope));
  const tg = group('Tools');
  tg.append(seg('callsTool', 'all', 'All tools', f.tool === 'all'), ...tools.slice(0, shown).map(t => toolSeg(f, t)));
  const rest = tools.slice(shown);
  if (rest.length) {
    const hot = rest.find(t => t.tool === f.tool);
    wrap.append(menuButton(hot ? `${hot.tool} +${rest.length - 1}` : `+${rest.length}`, !!hot));
    if (withMenu) {
      const menu = el('div', 'tb-menu');
      const mg = group('More tools', 'seggrp wrapgrp');
      mg.append(...rest.map(t => toolSeg(f, t)));
      menu.append(mg);
      wrap.append(menu);
    }
    tg.append(wrap);
  }
  const status = group('Status');
  status.append(failed);
  return [...(scopes.children.length ? [scopes] : []), tg, status];
}

// Draws the controls, dropping the least-called tools into the menu until the bar fits on one line.
function drawFilters(p, env, subject) {
  const f = env.state.calls, idx = callIndex(env.ix), tools = toolsByUse(idx);
  const scope = f.scope === 'sub' && !subject.children.length ? 'one' : f.scope;
  // Beside open details the bar is one button; so it is when even the scope and status buttons leave no room for a tool.
  let narrow = p.box.classList.contains('narrow');
  let shown = tools.length;
  if (!narrow) {
    const room = () => {
      if (!p.bar.clientWidth) return true;
      const pad = parseFloat(getComputedStyle(p.bar).paddingRight) || 0;
      return p.filters.getBoundingClientRect().right <= p.bar.getBoundingClientRect().right - pad + 0.5;
    };
    for (; shown >= 0; shown--) {
      sync(p.filters, ...filterNodes(env, subject, scope, tools, shown, false, false));
      if (room()) break;
    }
    if (shown < 0) { narrow = true; shown = 0; }
  }
  if (narrow !== p.narrow) { p.narrow = narrow; menuState.open = false; }
  sync(p.filters, ...filterNodes(env, subject, scope, tools, shown, narrow, menuState.open));
  if (menuState.refocus) {
    menuState.refocus = false;
    const b = p.filters.querySelector('[data-calls-menu]');
    if (b) b.focus({ preventScroll: true });
  }
}

const redrawBar = () => { if (last) keepFocus(() => render(last.box, last.env)); };

// The menu opens on its button and closes on a pick, a click elsewhere or Escape, as the session switcher's list does.
document.addEventListener('click', e => {
  if (!last) return;
  const t = e.target;
  if (t.closest('[data-calls-menu]')) { menuState.open = !menuState.open; redrawBar(); return; }
  if (!menuState.open) return;
  menuState.open = false;
  menuState.refocus = !!t.closest('.tb-menu');
  redrawBar();
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape' || !menuState.open || !last) return;
  menuState.open = false;
  menuState.refocus = true;
  e.preventDefault();
  redrawBar();
});

// Draws one full-height mark per call, in its tool's colour, at the canvas's real pixel size; returns the time span and
// the marks (x in CSS px, sorted) a click or hover is matched against.
function drawStrip(canvas, env, rows) {
  const { ix, state } = env, idx = callIndex(ix);
  const span = Math.max(ix.view.length_s || 0, ...idx.list.map(r => r.call.t), 1);
  const w = Math.max(canvas.clientWidth, 1), dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(STRIP_H * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, STRIP_H);
  const bad = getComputedStyle(document.documentElement).getPropertyValue('--find').trim() || '#F0883E';
  const open = state.peek && state.peek.kind === 'call' ? state.peek.id : null;
  const at = r => (r.call.t / span) * (w - MARK_W);
  const marks = rows.map(r => ({ x: at(r), r })).sort((p, q) => p.x - q.x);
  for (const failed of [false, true]) {
    for (const m of marks) {
      if (!!m.r.call.failed !== failed || m.r.call.use_id === open) continue;
      ctx.fillStyle = failed ? bad : idx.colour(m.r.call.category);
      ctx.fillRect(m.x, 0, MARK_W, STRIP_H);
    }
  }
  const hot = marks.find(m => m.r.call.use_id === open);
  if (hot) {
    ctx.fillStyle = '#0D0E10';
    ctx.fillRect(hot.x - 2, 0, MARK_W + 4, STRIP_H);
    ctx.fillStyle = '#FFFFFF';
    ctx.fillRect(hot.x - 1, 0, MARK_W + 2, STRIP_H);
  }
  return { span, marks };
}

const strips = new WeakMap();

// What focus returns to when a call opened from the strip closes: that call's row.
export const openerOf = from => (from.classList.contains('tb-canvas') ? keyFor('#view-calls', 'button', [['data-peek', from.dataset.peek]]) : null);

// The mark nearest the pointer, within REACH px; it names itself as the canvas's tooltip and as the call a click opens.
function aim(canvas, clientX) {
  const marks = strips.get(canvas) || [];
  const x = clientX - canvas.getBoundingClientRect().left;
  let best = null;
  for (const m of marks) {
    const d = Math.abs(m.x + MARK_W / 2 - x);
    if (d <= REACH && (!best || d < best.d)) best = { d, m };
  }
  const c = best && best.m.r.call;
  if (!c) { canvas.removeAttribute('title'); delete canvas.dataset.peek; return; }
  canvas.title = `${clock(c.t)} ${c.tool} ${c.label}${c.failed ? ', failed' : ''}`;
  canvas.dataset.peek = `call:${c.use_id}`;
}

// What the Call column prints: the call's label; for a call with no file target (its label is its tool's name), the
// first line of its shell command once the server has answered. Only drawn rows reach this, so only they ask.
export function summaryOf(ix, c) {
  if (!callIndex(ix).hasCommand(c.category) || c.label !== c.tool) return c.label;
  const line = (callDetail(c.use_id).text || '').split('\n').map(l => l.trim()).find(Boolean);
  return line || c.label;
}

function callRow(env, r) {
  const { ix, state } = env, c = r.call;
  const open = state.peek && state.peek.kind === 'call' && state.peek.id === c.use_id;
  const b = el('button', `vl-row tb-row tb-calls${c.failed ? ' bad' : ''}${open ? ' on' : ''}`);
  b.type = 'button';
  b.dataset.peek = `call:${c.use_id}`;
  const what = summaryOf(ix, c);
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
  // The page opens what `data-peek` names, so the canvas names the call under the pointer before the click reaches the page.
  canvas.addEventListener('mousemove', e => aim(canvas, e.clientX));
  canvas.addEventListener('click', e => aim(canvas, e.clientX));
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
  return { box, bar, summary, filters, canvas, ticks, list, empty, more, narrow: false, scrolled: null };
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
  last = { box, env };
  drawFilters(p, env, subject);
  const { span, marks } = drawStrip(p.canvas, env, rows);
  strips.set(p.canvas, marks);
  p.canvas.setAttribute('aria-label', `Timeline of ${rows.length} tool calls`);
  sync(p.ticks, ...[0, 1, 2, 3, 4].map(i => {
    const s = el('span', 'tb-tick');
    s.append(el('span', 'tb-tl', clock((span * i) / 4)));
    s.style.left = `calc(${i / 4} * (100% - ${MARK_W}px) + ${MARK_W / 2}px)`;
    return s;
  }));
  // An open call past the first rows brings the whole list, as "Show all" does, and it stays so until a filter changes.
  const openId = state.peek && state.peek.kind === 'call' ? state.peek.id : null;
  const openAt = openId ? rows.findIndex(r => r.call.use_id === openId) : -1;
  if (openAt >= LIMIT) f.all = true;
  const shown = f.all ? rows : rows.slice(0, LIMIT);
  p.empty.hidden = rows.length > 0;
  p.list.root.hidden = rows.length === 0;
  p.list.set(shown.length, i => callRow(env, shown[i]), viewHeight());
  const over = rows.length > LIMIT;
  p.more.hidden = !over;
  if (!openId) p.scrolled = null;
  else if (openAt >= 0 && openId !== p.scrolled) { p.scrolled = openId; revealRow(p.list.root, openAt, ROW_H); }
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
  return { chip: call.tool.charAt(0), kicker: `Tool call · ${node.name}`, title: summaryOf(env.ix, call) || call.tool, tags, main, side, actions: [show] };
});
