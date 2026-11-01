import { dur, k1 } from './format.js';
import { el } from './dom.js';
import { derive, whereLoaded } from './model.js';
import * as chart from './components/chart.js';
import * as artifacts from './components/artifacts.js';
import * as loadorder from './components/loadorder.js';
import * as filepane from './components/filepane.js';
import * as harness from './components/harness.js';

const $ = s => document.querySelector(s);
const token = document.querySelector('meta[name="xray-token"]')?.content ?? '';

let model = null, version = null, etag = null, inflight = false;
const fetched = new Map();

async function xrayFetch(url, init) {
  try {
    const r = await fetch(url, { cache: 'no-store', ...init, headers: { 'X-Xray-Token': token, ...(init && init.headers) } });
    let j = null;
    try { j = await r.json(); } catch (_) { j = null; }
    return { ok: r.ok, status: r.status, j };
  } catch (_) { return null; }
}

// The text behind a key, fetched once per view version; the page draws again when it arrives.
function text(key, url) {
  if (fetched.has(key)) return fetched.get(key);
  const e = { loading: true };
  fetched.set(key, e);
  xrayFetch(url).then(res => {
    if (!res) fetched.set(key, { error: 'The x-ray server did not answer.' });
    else if (res.ok && res.j && typeof res.j.text === 'string') fetched.set(key, { text: res.j.text, truncated: !!res.j.truncated });
    else fetched.set(key, { error: (res.j && res.j.error) || `request refused (${res.status})` });
  }).then(render);
  return e;
}

const ctx = {
  sel: null, selTurn: null, openTurns: new Set(), startOpen: true, groupsOpen: new Set(['instructions']), busy: false, res: null,
  text, selectTurn, selectRun,
};

function renderHeader() {
  const d = model.started_at ? new Date(model.started_at) : null;
  const when = d && !isNaN(d) ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  const project = el('span');
  project.append(el('b', null, model.project));
  const spans = [project];
  if (when) spans.push(el('span', null, when));
  spans.push(el('span', null, `${model.length_s != null ? dur(model.length_s) + ', ' : ''}${model.turns.length} turns, ${model.runs.length} subagents, peak ${k1(model.peak)}`));
  $('#sess').replaceChildren(...spans);
  $('#src').textContent = `Session ${model.session}. Numbers come from the session transcript and files on disk; ~ marks an estimate.`;
}

function renderChart() {
  const m = model;
  chart.render($('#chartcard'), { turns: m.turns, runs: m.runs, first_context: m.first_context, length_s: m.length_s, window: m.window, peak: m.peak, comp: m.comp, stops: m.stops, starts: m.starts }, ctx);
}

function renderInfo() {
  const m = model, info = $('#info'), sel = ctx.sel;
  const a = sel && sel.file ? m.art.find(x => x.key === sel.file) : null;
  if (a) return filepane.render(info, { artifact: a, where: whereLoaded(m, a) }, ctx);
  if (sel && sel.harness != null && m.harness[sel.harness]) return harness.render(info, m.harness[sel.harness]);
  loadorder.render(info, { turns: m.turns, runs: m.runs, start: m.start, harness: m.harness, first_context: m.first_context, not_known: m.not_known, art: m.art, tokMax: m.tokMax, starts: m.starts, promptNo: m.promptNo }, ctx);
}

function render() {
  if (!model) return;
  const b = $('#banner');
  if (model.refusals.length) {
    b.hidden = false;
    b.textContent = 'Claude Code wrote rows this reporails version does not read; parts of this page may be missing.';
    b.title = model.refusals.join('\n');
  } else b.hidden = true;
  renderChart();
  artifacts.render($('#art'), { art: model.art, harness: model.harness }, ctx);
  renderInfo();
  renderHeader();
}

function scrollToIn(node) {
  const box = $('#info');
  if (node && box) box.scrollTop = node.offsetTop - box.offsetTop - 8;
}

function selectTurn(n, scroll) {
  ctx.selTurn = n;
  ctx.openTurns.add(n);
  if (ctx.sel && (ctx.sel.file || ctx.sel.harness != null)) ctx.sel = null;
  render();
  if (scroll) scrollToIn(document.getElementById('turn-' + n));
}

function selectRun(id) {
  const r = model.runs.find(x => x.id === id);
  if (!r) return;
  if (r.turn != null) { ctx.openTurns.add(r.turn); ctx.selTurn = r.turn; }
  ctx.sel = { run: r.id };
  render();
  scrollToIn(document.getElementById('turn-' + r.turn));
}

const toggle = (set, v) => { if (!set.delete(v)) set.add(v); };
const picked = (key, v) => ctx.sel && ctx.sel[key] === v ? null : { [key]: v };

async function runAct(kind, path) {
  if (ctx.busy || !path) return;
  ctx.busy = true;
  ctx.res = { path, running: true };
  render();
  const res = await xrayFetch(kind === 'check' ? 'check' : 'heal', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path }) });
  let part;
  if (!res) part = { error: 'The x-ray server did not answer.' };
  else if (res.j) part = !res.ok && !res.j.error ? { error: `request refused (${res.status})` } : res.j;
  else part = { error: `request failed (${res.status})` };
  if (kind === 'heal') fetched.clear();
  ctx.busy = false;
  ctx.res = { path, ...part };
  render();
}

document.addEventListener('click', e => {
  if (!model || e.target.closest('#chart')) return;
  const act = e.target.closest('[data-act]');
  if (act) return runAct(act.dataset.act, act.dataset.path);
  if (e.target.closest('pre.peek,.detail')) return;
  if (e.target.closest('[data-back]')) { ctx.sel = null; return render(); }
  const gr = e.target.closest('[data-group]');
  if (gr) { toggle(ctx.groupsOpen, gr.dataset.group); return render(); }
  const hv = e.target.closest('[data-harness]');
  if (hv) { ctx.sel = { harness: +hv.dataset.harness }; return render(); }
  if (e.target.closest('[data-expand]')) {
    if (ctx.openTurns.size) { ctx.openTurns.clear(); ctx.selTurn = null; } else model.turns.forEach(t => ctx.openTurns.add(t.n));
    return render();
  }
  if (e.target.closest('[data-startt]')) { ctx.startOpen = !ctx.startOpen; return render(); }
  const th = e.target.closest('[data-turnh]');
  if (th) {
    const n = +th.dataset.turnh;
    if (ctx.openTurns.has(n)) { ctx.openTurns.delete(n); if (ctx.selTurn === n) ctx.selTurn = null; } else { ctx.openTurns.add(n); ctx.selTurn = n; }
    return render();
  }
  const pr = e.target.closest('[data-prompt]');
  if (pr) { ctx.sel = picked('prompt', pr.dataset.prompt); return render(); }
  const run = e.target.closest('[data-run]');
  if (run) { ctx.sel = picked('run', run.dataset.run); return render(); }
  const fl = e.target.closest('[data-file]');
  if (fl) { ctx.sel = picked('file', fl.dataset.file); return render(); }
});

async function poll() {
  if (document.hidden || inflight) return;
  inflight = true;
  try {
    const headers = etag ? { 'X-Xray-Token': token, 'If-None-Match': etag } : { 'X-Xray-Token': token };
    const r = await fetch('view', { headers, cache: 'no-store' });
    if (r.status === 304) return;
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    if (j.version === version) return;
    etag = r.headers.get('ETag') || String(j.version);
    version = j.version;
    fetched.clear();
    model = derive(j);
    render();
  } catch (_) {
    if (!model) {
      const n = el('div', 'nk', 'The x-ray server did not answer; retrying.');
      n.style.padding = '14px';
      $('#info').replaceChildren(n);
    }
  } finally { inflight = false; }
}

function setTheme(t) {
  document.documentElement.dataset.theme = t;
  $('#lightBtn').setAttribute('aria-pressed', t === 'light');
  $('#darkBtn').setAttribute('aria-pressed', t === 'dark');
}
$('#lightBtn').addEventListener('click', () => setTheme('light'));
$('#darkBtn').addEventListener('click', () => setTheme('dark'));
setTheme(new URLSearchParams(location.search).get('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
let resizing = null;
window.addEventListener('resize', () => { clearTimeout(resizing); resizing = setTimeout(() => model && renderChart(), 120); });
poll();
setInterval(poll, 2000);
