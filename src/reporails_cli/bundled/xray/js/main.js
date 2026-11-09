import { el, nk } from './dom.js';
import { text, viewUrl, viewHeaders, xrayFetch, onTextArrived, forgetTexts } from './api.js';
import { index, focusSource, activeTab, TABS } from './views.js';
import { state, applyHash, hashFor } from './state.js';
import { keepFocus, redrawing } from './focus.js';
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
let ix = null, version = null, etag = null, inflight = false, changed = false, lastAgentHash = '#/agent/main', afterHash = null;
const run = { busy: false, res: null, autoChecked: new Set() };
const opened = new Set();

const env = () => { const focus = focusSource(ix, state); return { ix, state, tab: activeTab(state), focus, graphFocus: focus && state.layers[focus.kind] ? focus : null, text, opened, busy: run.busy, res: run.res }; };

// The first view or a notice replaces the loading skeleton: its shapes go and the page stops reporting itself busy.
function endLoading() {
  for (const s of document.querySelectorAll('[data-skeleton]')) s.remove();
  $('main').removeAttribute('aria-busy');
}

function renderNotices() {
  const v = ix.view, b = $('#banner');
  b.hidden = !v.refusals.length;
  if (v.refusals.length) {
    b.textContent = `${v.adapter.tool} wrote rows this reporails version does not read; parts of this page may be missing.`;
    b.title = v.refusals.join('\n');
  }
  const u = $('#picked');
  u.hidden = v.picked !== 'current_unknown' && v.picked !== 'current_ambiguous';
  u.textContent = u.hidden ? '' : v.picked === 'current_ambiguous'
    ? 'More than one session started from a /clear of this one; showing the newest of them.'
    : `Showing the folder's newest session because ${v.adapter.tool} did not say which session it is.`;
  const c = v.check, chk = $('#chk');
  chk.hidden = !c || c.state === 'done';
  chk.textContent = !c ? '' : c.state === 'running' ? 'checking the project…' : (c.message || 'The project check was refused.');
  $('#src').textContent = `Session ${v.session}. Numbers come from the session transcript and files on disk; ~ marks an estimate.`;
  $('#unknown').textContent = v.not_known.length ? `Not known: ${v.not_known.join(', ')}.` : '';
}

const BODIES = { graph: '#view-graph', calls: '#view-calls-body', sources: '#view-sources-body' };
// Beside the table only on a screen wide enough for two panes; below it the details sit under the table.
const WIDE = window.matchMedia('(min-width:1101px)');
const TABLES = { calls: '#view-calls', sources: '#view-sources' };
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
    $('.canvaswrap').inert = false;
    // With nothing open the table has the whole width; an open item narrows it and its details fill the space beside it.
    const open = !!state.peek;
    for (const k of Object.keys(SIDES)) {
      $(BODIES[k]).classList.toggle('beside', open && k === e.tab);
      $(SIDES[k]).hidden = !(open && k === e.tab);
      $(TABLES[k]).classList.toggle('narrow', open && k === e.tab && WIDE.matches);
    }
    if (e.tab === 'calls') calls.render($('#view-calls'), e);
    else sourcestable.render($('#view-sources'), e);
    details.renderPanel($(SIDES[e.tab]), e);
  }
  details.settle(e, $(BODIES[e.tab]), hadFocus);
}

function render() { keepFocus(draw); }

function draw() {
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

function renderFocus() { keepFocus(drawFocus); }

function drawFocus() {
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
  details.remember(calls.openerOf(from) || from);
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
  const summary = t.closest('[data-summary]');
  if (summary) { state.sel = summary.dataset.summaryNode; opened.add(`summary:${summary.dataset.summary}`); return render(); }
  const open = t.closest('[data-open]');
  if (open) { toggle(opened, open.dataset.open); return render(); }
  if (t.closest('[data-clear]')) { state.pinned = null; return render(); }
  const eye = t.closest('[data-eye]');
  if (eye) { state.layers[eye.dataset.eye] = !state.layers[eye.dataset.eye]; return render(); }
  if (t.closest('[data-close-peek]')) { closePeek(); return render(); }
  const pin = t.closest('[data-pin]');
  if (pin) { state.pinned = pin.dataset.pin; closePeek(); return render(); }
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
  if (src) { openPeek('src', src.dataset.source, src); return render(); }
  const group = t.closest('[data-group]');
  if (group) { state.groups[group.dataset.group] = group.getAttribute('aria-expanded') !== 'true'; return render(); }
  const card = t.closest('.card[data-node]');
  if (card && !card.classList.contains('top')) { state.sel = card.dataset.node; return render(); }
  if (card) { state.sel = null; render(); }
});

// An element that acts like a button without being one: Enter and Space click it (a native button does that itself).
const isFakeButton = t => t.getAttribute('role') === 'button' && !['BUTTON', 'A', 'INPUT', 'SUMMARY'].includes(t.tagName);

document.addEventListener('keydown', e => {
  if (!ix) return;
  const target = e.target.closest ? e.target : document.body;
  if ((e.key === 'Enter' || e.key === ' ') && isFakeButton(target)) { e.preventDefault(); target.click(); return; }
  const tab = target.closest('[role="tab"]');
  if (tab && ['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) {
    const at = TABS.indexOf(tab.dataset.tab);
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : (at + (e.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length;
    e.preventDefault();
    state.tab = TABS[next];
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

// Hover and keyboard focus on a source highlight it; neither moves anything. Only keyboard focus also brings the source
// into the Sources panel: hovering never opens a group.
function lightSource(id, focused) {
  if (id === state.hover && (!focused || id === state.lit)) return;
  state.hover = id;
  if (focused) state.lit = id;
  renderFocus();
}

document.addEventListener('mouseover', e => {
  const src = e.target.closest && e.target.closest('[data-source]');
  lightSource(src ? src.dataset.source : null, false);
});

document.addEventListener('focusin', e => {
  const src = e.target.closest && e.target.closest('[data-source]');
  if (src) lightSource(src.dataset.source, true);
});

document.addEventListener('focusout', e => {
  const next = e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest('[data-source]');
  if (!redrawing() && e.target.closest && e.target.closest('[data-source]') && !next) { state.lit = null; lightSource(null, false); }
});

window.addEventListener('hashchange', () => {
  if (!ix) return;
  applyHash(location.hash, ix.nodes);
  if (afterHash) { state.sel = ix.nodes.has(afterHash) ? afterHash : null; afterHash = null; }
  if (state.file == null) lastAgentHash = location.hash || lastAgentHash;
  render();
});

// Several texts landing together draw once, on the next frame.
let textFrame = 0;
onTextArrived(() => { if (!textFrame) textFrame = requestAnimationFrame(() => { textFrame = 0; render(); }); });
onRegister(render);
details.onPeekRegister(render);

function adopt(view) {
  ix = index(view);
  if (!state.layers) state.layers = {};
  for (const k of view.adapter.source_kinds) if (!(k.key in state.layers)) state.layers[k.key] = true;
  applyHash(location.hash, ix.nodes);
  if (state.sel && !ix.nodes.has(state.sel)) state.sel = null;
  if (state.file == null && location.hash) lastAgentHash = location.hash;
}

async function poll() {
  if (document.hidden || inflight || changed) return;
  inflight = true;
  try {
    const r = await fetch(viewUrl(), { headers: viewHeaders(etag), cache: 'no-store' });
    if (r.status === 304) return;
    if (r.status === 409) {
      // The server's code is older than the page's: what it would send does not match what this page draws.
      changed = true;
      endLoading();
      const j = await r.json().catch(() => ({}));
      const b = $('#changed');
      b.hidden = false;
      b.textContent = j.error || 'ails changed since this page started; run `ails xray` again to open a current page.';
      if (!ix) $('#canvas').replaceChildren(nk('No view is shown: this page was started before ails changed.'));
      return;
    }
    if (r.status === 422) {
      // The project's config cannot be read: the server's words are the notice.
      endLoading();
      const j = await r.json().catch(() => ({}));
      const n = $('#chk');
      n.hidden = false;
      n.textContent = j.error || 'The project config cannot be read.';
      if (!ix) $('#canvas').replaceChildren(nk(n.textContent));
      return;
    }
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    if (j.version === version) return;
    etag = r.headers.get('ETag') || String(j.version);
    version = j.version;
    forgetTexts(j);
    endLoading();
    adopt(j);
    render();
  } catch (_) {
    endLoading();
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
// A changed width of the page redraws it: the strip's pixels, the filter bar's fit and the one-pane breakpoint follow it.
let pageWidth = 0;
new ResizeObserver(entries => {
  const w = Math.round(entries[0].contentRect.width);
  if (w === pageWidth) return;
  const first = pageWidth === 0;
  pageWidth = w;
  if (!first && ix) render();
}).observe(document.querySelector('main'));

// A hidden tab does not read the view; it still tells the server once a minute that the page is open.
setInterval(() => { if (document.hidden) fetch('/launch', { cache: 'no-store' }).catch(() => {}); }, 60000);
