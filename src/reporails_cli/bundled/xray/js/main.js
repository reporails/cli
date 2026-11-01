import { el } from './dom.js';
import { text, viewHeaders, xrayFetch, onTextArrived, forgetTexts } from './api.js';
import { index, focusSource } from './views.js';
import { state, applyHash, hashFor } from './state.js';
import * as header from './components/header.js';
import * as parentstrip from './components/parentstrip.js';
import * as toolbar from './components/toolbar.js';
import * as sources from './components/sources.js';
import * as canvas from './components/canvas.js';
import * as inspector from './components/inspector.js';
import * as filepane from './components/filepane.js';
import { render as renderFindings } from './components/findings.js';
import { onRegister } from './components/nodes/index.js';

const $ = s => document.querySelector(s);
let ix = null, version = null, etag = null, inflight = false, lastAgentHash = '#/agent/main';
const run = { busy: false, res: null, autoChecked: new Set() };
const opened = new Set();

const env = () => ({ ix, state, focus: focusSource(ix, state), text, opened, busy: run.busy, res: run.res });

function renderNotices() {
  const v = ix.view, b = $('#banner');
  b.hidden = !v.refusals.length;
  if (v.refusals.length) {
    b.textContent = `${v.adapter.tool} wrote rows this reporails version does not read; parts of this page may be missing.`;
    b.title = v.refusals.join('\n');
  }
  const c = v.check, chk = $('#chk');
  chk.hidden = !c || c.state === 'done';
  chk.textContent = !c ? '' : c.state === 'running' ? 'checking the project…' : (c.message || 'The project check was refused.');
  $('#src').textContent = `Session ${v.session}. Numbers come from the session transcript and files on disk; ~ marks an estimate.`;
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
    $('#toolbar').replaceChildren();
    filepane.render($('#view-file'), e);
    autoCheck();
    return;
  }
  parentstrip.render($('#parentstrip'), e);
  toolbar.render($('#toolbar'), e);
  canvas.render($('#canvas'), e);
  inspector.render($('#inspector'), e);
}

function renderFocus() {
  if (!ix || state.file != null) return;
  const e = env();
  canvas.render($('#canvas'), e);
  for (const r of document.querySelectorAll('#sources .sr')) r.classList.toggle('on', !!e.focus && r.dataset.source === e.focus.id);
}

function autoCheck() {
  const s = ix.view.sources.find(x => x.path === state.file);
  if (!s || !s.actionable || run.autoChecked.has(s.path)) return;
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

document.addEventListener('click', e => {
  if (!ix) return;
  const t = e.target;
  const act = t.closest('[data-act]');
  if (act) return runAct(act.dataset.act, act.dataset.path);
  if (t.closest('a[href]')) return;
  if (t.closest('[data-back]')) { location.hash = lastAgentHash; return; }
  const open = t.closest('[data-open]');
  if (open) { toggle(opened, open.dataset.open); return render(); }
  if (t.closest('[data-clear]')) { state.pinned = null; return render(); }
  const type = t.closest('[data-type]');
  if (type) { state.type = type.dataset.type; state.pinned = null; state.hover = null; return render(); }
  const layer = t.closest('[data-layer]');
  if (layer) { state.layers[layer.dataset.layer] = !state.layers[layer.dataset.layer]; return render(); }
  const src = t.closest('[data-source]');
  if (src) { state.pinned = state.pinned === src.dataset.source ? null : src.dataset.source; return render(); }
  const card = t.closest('.card[data-node]');
  if (card && !card.classList.contains('top')) { state.sel = card.dataset.node; return render(); }
  if (card) { state.sel = null; render(); }
});

document.addEventListener('dblclick', e => {
  const card = e.target.closest('.card[data-node]:not(.top)');
  if (!card || !ix) return;
  const node = ix.nodes.get(card.dataset.node);
  const kind = node && ix.nodeKinds.get(node.kind);
  if (kind && kind.opens) location.hash = hashFor([...state.path, node.id]);
});

document.addEventListener('keydown', e => {
  if (!ix) return;
  const card = e.target.closest && e.target.closest('.card[data-node]');
  if (e.key === 'Enter' && card && !card.classList.contains('top')) { state.sel = card.dataset.node; render(); }
  if (e.key === 'Escape' && state.pinned) { state.pinned = null; render(); }
});

document.addEventListener('mouseover', e => {
  const src = e.target.closest && e.target.closest('[data-source]');
  const id = src ? src.dataset.source : null;
  if (id === state.hover) return;
  state.hover = id;
  renderFocus();
});

window.addEventListener('hashchange', () => {
  if (!ix) return;
  applyHash(location.hash, ix.nodes);
  if (state.file == null) lastAgentHash = location.hash || lastAgentHash;
  render();
});

onTextArrived(render);
onRegister(render);

function adopt(view) {
  ix = index(view);
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
    const r = await fetch('view', { headers: viewHeaders(etag), cache: 'no-store' });
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
