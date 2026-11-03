import { el, nk } from './dom.js';
import { text, viewUrl, viewHeaders, xrayFetch, onTextArrived, forgetTexts } from './api.js';
import { index, focusSource, activeTab, TABS } from './views.js';
import { state, applyHash, hashFor } from './state.js';
import * as header from './components/header.js';
import * as parentstrip from './components/parentstrip.js';
import * as sources from './components/sources.js';
import * as canvas from './components/canvas.js';
import * as rail from './components/rail.js';
import * as inspector from './components/inspector.js';
import * as filepane from './components/filepane.js';
import * as details from './components/details.js';
import * as calls from './components/calls.js';
import * as sourcestable from './components/sourcestable.js';
import './components/peeks.js';
import { onRegister } from './components/nodes/index.js';

const $ = s => document.querySelector(s);
let ix = null, version = null, etag = null, inflight = false, lastAgentHash = '#/agent/main', afterHash = null;
const run = { busy: false, res: null, autoChecked: new Set() };
const opened = new Set();

const env = () => ({ ix, state, tab: activeTab(ix, state), focus: focusSource(ix, state), text, opened, busy: run.busy, res: run.res });

function renderNotices() {
  const v = ix.view, b = $('#banner');
  b.hidden = !v.refusals.length;
  if (v.refusals.length) {
    b.textContent = `${v.adapter.tool} wrote rows this reporails version does not read; parts of this page may be missing.`;
    b.title = v.refusals.join('\n');
  }
  const u = $('#picked');
  u.hidden = v.picked !== 'current_unknown';
  u.textContent = u.hidden ? '' : `Showing the folder's newest session because ${v.adapter.tool} did not say which session it is.`;
  const c = v.check, chk = $('#chk');
  chk.hidden = !c || c.state === 'done';
  chk.textContent = !c ? '' : c.state === 'running' ? 'checking the project…' : (c.message || 'The project check was refused.');
  $('#src').textContent = `Session ${v.session}. Numbers come from the session transcript and files on disk; ~ marks an estimate.`;
  $('#unknown').textContent = v.not_known.length ? `Not known: ${v.not_known.join(', ')}.` : '';
}

const BODIES = { graph: '#view-graph', calls: '#view-calls-body', sources: '#view-sources-body' };
const SIDES = { calls: '#side-calls', sources: '#side-sources' };

function renderTab(e) {
  for (const k of TABS) $(BODIES[k]).hidden = e.tab !== k;
  $('#hint').hidden = e.tab !== 'graph';
  const hadFocus = details.hasFocusIn();
  if (e.tab === 'graph') {
    canvas.render($('#canvas'), e);
    const cv = $('#canvas .cv');
    $('#canvas').style.setProperty('--cvh', `${cv ? cv.offsetHeight : 0}px`);
    inspector.render($('#inspector'), e);
    details.renderOverlay($('#overlay'), e);
  } else {
    $('#overlay').hidden = true;
    if (e.tab === 'calls') calls.render($('#view-calls'), e);
    else sourcestable.render($('#view-sources'), e);
    // With nothing open the side panel describes the agent, as the Graph tab's right column does.
    if (state.peek) details.renderPanel($(SIDES[e.tab]), e);
    else inspector.render($(SIDES[e.tab]), e);
  }
  details.settle(e, $(BODIES[e.tab]), hadFocus);
}

function render() {
  if (!ix) return;
  const e = env();
  renderNotices();
  header.render($('#header'), e);
  const filing = state.file != null;
  $('#view-agent').hidden = filing;
  $('#view-file').hidden = !filing;
  sources.render($('#sources'), e);
  if (filing) {
    parentstrip.render($('#parentstrip'), { ...e, state: { ...state, path: ['main'] } });
    filepane.render($('#view-file'), e);
    autoCheck();
    return;
  }
  $('#view-file').replaceChildren();
  parentstrip.render($('#parentstrip'), e);
  renderTab(e);
}

function renderFocus() {
  if (!ix || state.file != null) return;
  const e = env();
  if (e.tab === 'graph') canvas.render($('#canvas'), e);
  sources.follow($('#sources'), e);
  for (const r of document.querySelectorAll('#sources .sr')) r.classList.toggle('on', !!e.focus && r.dataset.source === e.focus.id);
}

function autoCheck() {
  const s = ix.view.sources.find(x => x.path === state.file);
  if (!s || !s.actionable || run.autoChecked.has(s.path) || run.busy) return;
  run.autoChecked.add(s.path);
  runAct('check', s.path);
}

async function runAct(kind, path) {
  if (run.busy || !path) return;
  run.busy = true;
  run.res = { path, running: true };
  render();
  const res = await xrayFetch(kind === 'check' ? 'check' : 'heal', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path }) });
  let part;
  if (!res) part = { error: 'The x-ray server did not answer.' };
  else if (res.j) part = !res.ok && !res.j.error ? { error: `request refused (${res.status})` } : res.j;
  else part = { error: `request failed (${res.status})` };
  if (kind === 'heal') forgetTexts();
  run.busy = false;
  run.res = { ...part, path };
  render();
}

const toggle = (set, v) => { if (!set.delete(v)) set.add(v); };

const closePeek = () => { state.peek = null; };

function openPeek(kind, id, from) {
  details.remember(from);
  state.peek = { kind, id };
}

// Draws the Graph tab's agent when a "show in graph" link names one: its parents become the path, it becomes the selection.
function showInGraph(id) {
  const chain = [];
  for (let n = ix.nodes.get(id); n; n = ix.nodes.get(n.parent)) chain.unshift(n.id);
  const here = chain.slice(0, -1);
  state.tab = 'graph';
  closePeek();
  if (!here.length || here.join('/') === state.path.join('/')) { state.sel = id; return render(); }
  afterHash = id;
  location.hash = hashFor(here);
}

// A changed filter starts the list at its first rows again.
const CALLS = {
  callsScope: (c, v) => { c.scope = v; c.all = false; },
  callsTool: (c, v) => { c.tool = v; c.all = false; },
  callsFailed: c => { c.failed = !c.failed; c.all = false; },
  callsAll: c => { c.all = !c.all; },
};

document.addEventListener('click', e => {
  if (!ix) return;
  const t = e.target;
  if (sources.click(t, env())) return render();
  const act = t.closest('[data-act]');
  if (act) return runAct(act.dataset.act, act.dataset.path);
  const tab = t.closest('[data-tab]');
  if (tab && TABS.includes(tab.dataset.tab)) {
    state.tab = tab.dataset.tab;
    if (tab.dataset.callsScope != null || tab.dataset.callsTool != null) {
      Object.assign(state.calls, { scope: tab.dataset.callsScope ?? state.calls.scope, tool: tab.dataset.callsTool ?? 'all', failed: false, all: false });
      closePeek();
    }
    if (state.file != null) location.hash = lastAgentHash;
    return render();
  }
  const jump = t.closest('[data-jump]');
  if (jump) return rail.jump(jump.dataset.jump);
  if (t.closest('a[href]')) return;
  if (t.closest('[data-back]')) { location.hash = lastAgentHash; return; }
  const open = t.closest('[data-open]');
  if (open) { toggle(opened, open.dataset.open); return render(); }
  if (t.closest('[data-clear]')) { state.pinned = null; return render(); }
  const eye = t.closest('[data-eye]');
  if (eye) { state.layers[eye.dataset.eye] = !state.layers[eye.dataset.eye]; return render(); }
  if (t.closest('[data-close-peek]')) { closePeek(); return render(); }
  const peek = t.closest('[data-peek]');
  const want = peek && details.parsePeek(peek.dataset.peek);
  if (want) { openPeek(want.kind, want.id, peek); return render(); }
  const show = t.closest('[data-show-in-graph]');
  if (show) return showInGraph(show.dataset.showInGraph);
  const drill = t.closest('[data-drill]');
  if (drill) { location.hash = hashFor([...state.path, drill.dataset.drill]); return; }
  if (t.closest('[data-unselect]')) { state.sel = null; return render(); }
  for (const [key, set] of Object.entries(CALLS)) {
    const c = t.closest(`[data-${key.replace(/[A-Z]/g, m => '-' + m.toLowerCase())}]`);
    if (!c) continue;
    set(state.calls, c.dataset[key]);
    return render();
  }
  const src = t.closest('[data-source]');
  if (src) { state.pinned = src.dataset.source; openPeek('src', src.dataset.source, src); return render(); }
  const group = t.closest('[data-group]');
  if (group) { state.groups[group.dataset.group] = group.getAttribute('aria-expanded') !== 'true'; return render(); }
  const card = t.closest('.card[data-node]');
  if (card && !card.classList.contains('top')) { state.sel = card.dataset.node; return render(); }
  if (card) { state.sel = null; render(); }
});

document.addEventListener('keydown', e => {
  if (!ix) return;
  const target = e.target.closest ? e.target : document.body;
  const card = target.closest('.card[data-node]');
  if (e.key === 'Enter' && card && !card.classList.contains('top')) { state.sel = card.dataset.node; render(); }
  if ((e.key === 'Enter' || e.key === ' ') && target.matches('[data-source], [data-peek]')) { e.preventDefault(); target.click(); return; }
  const tab = target.closest('[role="tab"]');
  if (tab && (e.key === 'ArrowRight' || e.key === 'ArrowLeft')) {
    const at = TABS.indexOf(tab.dataset.tab) + (e.key === 'ArrowRight' ? 1 : -1);
    state.tab = TABS[(at + TABS.length) % TABS.length];
    render();
    document.getElementById(`tab-${state.tab}`).focus();
    return;
  }
  if (e.key !== 'Escape' || e.defaultPrevented) return;
  if (state.peek) closePeek();
  else if (state.sel) state.sel = null;
  else if (state.pinned) state.pinned = null;
  else return;
  render();
});

// Hover and keyboard focus on a source highlight it; neither moves anything.
function lightSource(id) {
  if (id === state.hover) return;
  state.hover = id;
  renderFocus();
}

document.addEventListener('mouseover', e => {
  const src = e.target.closest && e.target.closest('[data-source]');
  lightSource(src ? src.dataset.source : null);
});

document.addEventListener('focusin', e => {
  const src = e.target.closest && e.target.closest('[data-source]');
  if (src) lightSource(src.dataset.source);
});

document.addEventListener('focusout', e => {
  const next = e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('[data-source]');
  if (e.target.closest && e.target.closest('[data-source]') && !next) lightSource(null);
});

window.addEventListener('hashchange', () => {
  if (!ix) return;
  applyHash(location.hash, ix.nodes);
  if (afterHash) { state.sel = ix.nodes.has(afterHash) ? afterHash : null; afterHash = null; }
  if (state.file == null) lastAgentHash = location.hash || lastAgentHash;
  render();
});

onTextArrived(render);
onRegister(render);
details.onPeekRegister(render);

function adopt(view) {
  ix = index(view);
  // The tab the page first opened on stays: a subagent showing up on a later poll does not move the user.
  if (state.tab == null) state.tab = activeTab(ix, state);
  if (!state.layers) state.layers = {};
  for (const k of view.adapter.source_kinds) if (!(k.key in state.layers)) state.layers[k.key] = true;
  applyHash(location.hash, ix.nodes);
  if (state.sel && !ix.nodes.has(state.sel)) state.sel = null;
  if (state.file == null && location.hash) lastAgentHash = location.hash;
}

async function poll() {
  if (document.hidden || inflight) return;
  inflight = true;
  try {
    const r = await fetch(viewUrl(), { headers: viewHeaders(etag), cache: 'no-store' });
    if (r.status === 304) return;
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    if (j.version === version) return;
    etag = r.headers.get('ETag') || String(j.version);
    version = j.version;
    forgetTexts();
    adopt(j);
    render();
  } catch (_) {
    if (!ix) {
      const n = el('div', 'nk', 'The x-ray server did not answer; retrying.');
      n.style.padding = '14px';
      $('#canvas').replaceChildren(n);
    }
  } finally { inflight = false; }
}

document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
poll();
setInterval(poll, 2000);
// A hidden tab does not read the view; it still tells the server once a minute that the page is open.
setInterval(() => { if (document.hidden) fetch('/launch', { cache: 'no-store' }).catch(() => {}); }, 60000);
