'use strict';
const $ = s => document.querySelector(s);
const TOKEN = (document.querySelector('meta[name="xray-token"]') || {}).content || '';
const k1 = n => {
  if (n == null) return '';
  const a = Math.abs(n), s = n < 0 ? '−' : '';
  if (a >= 1e6) return s + (a / 1e6).toFixed(a >= 1e7 ? 0 : 2).replace(/\.?0+$/, '') + 'M';
  return s + (a >= 1000 ? (a / 1000).toFixed(a >= 10000 ? 0 : 1).replace(/\.0$/, '') + 'k' : String(a));
};
const tk = (n, est) => n == null ? '' : (est ? '~' : '') + k1(n);
const clock = t => { if (t == null) return ''; t = Math.max(0, Math.round(t)); const h = Math.floor(t / 3600), m = Math.floor(t % 3600 / 60), s = t % 60; return h ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${m}:${String(s).padStart(2, '0')}`; };
const dur = s => { s = Math.round(s || 0); return s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`; };
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const niceCeil = v => { if (!(v > 0)) return 1000; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p; return 10 * p; };
const plural = (n, w, ws) => `${n} ${n === 1 ? w : (ws || w + 's')}`;

const KIND_WORD = { project: 'project instructions', memory: 'auto memory', user: 'your user instructions', local: 'local instructions', managed: 'managed instructions', nested: 'loaded because a file in that folder was read' };
const CHIPS = [
  { k: 'instructions', label: 'Instruction files' }, { k: 'rule', label: 'Rules' }, { k: 'memory', label: 'Memory' },
  { k: 'skill', label: 'Skills' }, { k: 'agent', label: 'Agents' }, { k: 'command', label: 'Commands' }, { k: 'hook', label: 'Hooks' },
];
const HARNESS_KIND = {
  system_prompt: ['System prompt', 'Claude Code’s own instructions, sent every turn.'], deferred_tools: ['Deferred tools', 'Tool names listed; their schemas load on demand.'],
  agent_list: ['Agent listing', 'The subagent types Claude Code listed to the model.'], mcp_instructions: ['MCP instructions', 'Instructions the connected MCP servers added.'],
  skill_list: ['Skill listing', 'The skills Claude Code listed to the model: names and descriptions, not bodies.'], session_context: ['Session context', 'Account and environment facts added at session start.'],
  hook_note: ['Session-start hook notes', 'Text your SessionStart hooks added.'],
};
const LISTING_OF = { skill: 'skill_list', agent: 'agent_list' };
const GROUPS = [['instructions', 'Instruction files'], ['rule', 'Rules'], ['memory', 'Memory'], ['skill', 'Skills'], ['agent', 'Agents'], ['command', 'Commands'], ['hook', 'Hooks'], ['harness', 'Harness']];

let V = null, VERSION = null, ETAG = null;
let TURNS = [], ART = [], RUNS = [], PEAK = 0, TOK_MAX = 1;
let chipOpen = null, sel = null, openTurns = new Set(), selTurn = null, busy = false, RES = null;
let startOpen = true, groupsOpen = new Set(['instructions']), promptNo = new Map();


/* ---------- build ---------- */
function build(view) {
  V = view;
  TURNS = view.turns || [];
  RUNS = (view.subagents || []).map(s => {
    const pts = (s.series || []).filter(p => p && p[0] != null);
    return { id: String(s.id), type: s.type || 'subagent', turn: s.turn, sb: s, pts, start: s.start, end: s.end, miss: !(s.loads || []).some(l => l.kind === 'project') };
  });
  const comp = TURNS.find(t => t.compaction);
  PEAK = Math.max(0, view.first_context || 0, ...TURNS.map(t => t.context || 0), ...TURNS.flatMap(t => (t.series || []).map(p => p[1])), comp && comp.compaction.before || 0);
  ART = (view.artifacts || []).map(a => ({ ...a, key: a.kind + ':' + a.path }));
  const toks = [];
  TURNS.forEach(t => { (t.loads || []).forEach(l => toks.push(l.tokens_est || 0)); (t.notes || []).forEach(n => toks.push(n.tokens_est || 0)); });
  TOK_MAX = Math.max(1, ...toks, ...(view.harness || []).map(h => h.tokens_est || 0));
}
const artByPath = p => ART.find(a => a.path === p);
const nameOf = p => { const a = artByPath(p); return a ? a.label : p; };
const turnStart = (t, i) => (t.prompts && t.prompts.length) ? t.prompts[0].t : (t.series && t.series.length ? t.series[0][0] : (i ? TURNS[i - 1].t : 0));
const compTurn = () => TURNS.find(t => t.compaction);
const stopBlocks = () => TURNS.flatMap(t => (t.notes || []).filter(n => n.kind === 'stop_block').map(n => ({ ...n, turn: t.n })));

/* ---------- fetch ---------- */
async function xrayFetch(url, init) {
  try {
    const r = await fetch(url, { cache: 'no-store', ...init, headers: { 'X-Xray-Token': TOKEN, ...(init && init.headers) } });
    let j = null; try { j = await r.json(); } catch (_) { j = null; }
    return { ok: r.ok, status: r.status, j };
  } catch (_) { return null; }
}
const FETCHED = new Map();
function forgetFetched() { FETCHED.clear(); }
function want(key, url) {
  if (FETCHED.has(key)) return FETCHED.get(key);
  const e = { loading: true };
  FETCHED.set(key, e);
  xrayFetch(url).then(res => {
    if (!res) FETCHED.set(key, { error: 'The x-ray server did not answer.' });
    else if (res.ok && res.j && typeof res.j.text === 'string') FETCHED.set(key, { text: res.j.text, truncated: !!res.j.truncated });
    else FETCHED.set(key, { error: (res.j && res.j.error) || `request refused (${res.status})` });
  }).then(() => render());
  return e;
}
const textBlock = (key, url) => {
  const e = want(key, url);
  if (e.loading) return '<div class="nk">Loading…</div>';
  if (e.error) return `<div class="err">${esc(e.error)}</div>`;
  return `<pre class="peek" data-pk="${esc(key)}"></pre>${e.truncated ? '<div class="nk">text truncated</div>' : ''}`;
};

/* ---------- chart ---------- */
function chartModel(W) {
  const H = 214, L = 40, R = 10, T = 26, Bm = 22, pw = W - L - R, ph = H - T - Bm;
  const total = Math.max(V.length_s || 0, ...TURNS.map(t => t.t || 0), 1);
  const SCALE = V.window || niceCeil(PEAK);
  const x = t => L + Math.min(1, Math.max(0, t / total)) * pw, y = c => T + ph - Math.min(1, (c || 0) / SCALE) * ph;
  return { H, L, R, T, Bm, pw, ph, total, SCALE, x, y, W };
}
function mainPoints() {
  const pts = [];
  if (V.first_context != null) pts.push([0, V.first_context]);
  TURNS.forEach(t => (t.series || []).forEach(p => pts.push([p[0], p[1]])));
  pts.sort((a, b) => a[0] - b[0]);
  const c = compTurn();
  if (c && c.compaction.before != null && c.compaction.after != null) {
    const tc = c.compaction.t; let i = pts.findIndex(p => p[0] > tc); if (i < 0) i = pts.length;
    pts.splice(i, 0, [tc, c.compaction.before], [tc, c.compaction.after]);
  }
  return pts;
}
function renderChart() {
  const card = $('#chartcard');
  const W = Math.max(320, Math.round(card.clientWidth - 28));
  const m = chartModel(W), { x, y, H, L, T, ph, pw, W: _w } = m;
  const pts = mainPoints(), c = compTurn();
  let s = `<svg class="chart" id="chart" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`;
  // y grid
  [0, .25, .5, .75, 1].forEach(f => { const v = f * m.SCALE, yy = y(v); s += `<line class="grid" x1="${L}" x2="${W - m.R}" y1="${yy}" y2="${yy}"/>`; s += `<text class="ax" x="${L - 5}" y="${yy + 3}" text-anchor="end">${v ? k1(v) : '0'}</text>`; });
  // x ticks
  const steps = [30, 60, 120, 300, 600, 900, 1800, 3600], st = steps.find(q => m.total / q <= pw / 62) || 3600;
  for (let t = 0; t <= m.total; t += st) s += `<line class="grid" x1="${x(t)}" x2="${x(t)}" y1="${T + ph}" y2="${T + ph + 4}"/><text class="ax" x="${x(t)}" y="${H - 5}" text-anchor="${t === 0 ? 'start' : 'middle'}">${clock(t)}</text>`;
  // compaction band
  if (c) s += `<rect class="band" x="${x(c.compaction.t)}" y="${T}" width="${W - m.R - x(c.compaction.t)}" height="${ph}"/>`;
  // selected turn band
  if (selTurn != null) { const i = TURNS.findIndex(t => t.n === selTurn); if (i >= 0) { const a = x(turnStart(TURNS[i], i)), b = x(TURNS[i].t); s += `<rect class="selband" x="${a}" y="${T}" width="${Math.max(2, b - a)}" height="${ph}"/>`; } }
  // river
  if (pts.length) {
    s += `<polygon class="river" points="${x(pts[0][0])},${y(0)} ${pts.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ')} ${x(pts[pts.length - 1][0])},${y(0)}"/>`;
    s += `<polyline class="edge" points="${pts.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ')}"/>`;
  }
  TURNS.forEach(t => (t.series || []).forEach(p => { s += `<circle class="rp" data-turn="${t.n}" data-ctx="${p[1]}" cx="${x(p[0]).toFixed(1)}" cy="${y(p[1]).toFixed(1)}" r="1.2"/>`; }));
  // subagents
  RUNS.forEach(r => { if (r.pts.length > 1) s += `<polyline class="sub${sel && sel.run === r.id ? ' on' : ''}" data-run="${esc(r.id)}" style="${r.miss ? 'stroke:var(--red)' : ''}" points="${r.pts.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ')}"><title>${esc(r.type)} · peak ${k1(Math.max(...r.pts.map(p => p[1])))}</title></polyline>`; });
  if (c) s += `<line class="cmpl" x1="${x(c.compaction.t)}" x2="${x(c.compaction.t)}" y1="${T}" y2="${T + ph}"/>`;
  // stop ticks along the bottom axis
  stopBlocks().forEach(b => { s += `<line class="stop" x1="${x(b.t)}" x2="${x(b.t)}" y1="${T + ph - 7}" y2="${T + ph}"><title>Stop hook sent the reply back · turn ${b.turn}</title></line>`; });
  // turn markers and thinned labels
  const marks = TURNS.map((t, i) => ({ t, i, x: x(turnStart(t, i)) }));
  marks.forEach(mk => { s += `<line class="tm${mk.t.n === selTurn ? ' on' : ''}" x1="${mk.x}" x2="${mk.x}" y1="${T - 4}" y2="${T + ph}"/>`; });
  const placed = [];
  const prio = [...marks].sort((a, b) => (b.t.n === selTurn) - (a.t.n === selTurn) || !!b.t.compaction - !!a.t.compaction || (b.t.replies - a.t.replies));
  prio.forEach(mk => {
    const w = String(mk.t.n).length * 6.4 + 19, lo = Math.max(2, Math.min(W - w - 2, mk.x - w / 2)), hi = lo + w;
    if (placed.some(p => lo < p[1] + 3 && hi > p[0] - 3)) return;
    placed.push([lo, hi]);
    s += `<g class="tl${mk.t.n === selTurn ? ' on' : ''}" data-turn="${mk.t.n}"><rect x="${lo}" y="1" width="${w}" height="16" rx="4"/><text x="${lo + w / 2}" y="12.5" text-anchor="middle">T${mk.t.n}</text></g>`;
  });
  // peak + compaction labels
  const pk = pts.reduce((b, p) => p[1] > b[1] ? p : b, [0, 0]);
  if (pk[1]) { const flip = x(pk[0]) < L + 110; s += `<text class="lab" x="${x(pk[0]) + (flip ? 6 : -6)}" y="${y(pk[1]) + 11}" text-anchor="${flip ? 'start' : 'end'}">peak ${k1(pk[1])}</text>`; }
  if (c) s += `<text class="lab cmp" x="${W - m.R - 4}" y="${y(pk[1]) + 28}" text-anchor="end">/compact ${esc(c.compaction.trigger || '')} · ${k1(c.compaction.before)} → ${k1(c.compaction.after)}</text>`;
  const sr = RUNS.find(r => sel && sel.run === r.id);
  if (sr && sr.pts.length) { const mp = sr.pts.reduce((b, p) => p[1] > b[1] ? p : b, [0, 0]); s += `<text class="lab" x="${x(mp[0])}" y="${y(mp[1]) - 5}" text-anchor="middle" style="fill:var(--violet)">${esc(sr.type)} · ${k1(mp[1])}</text>`; }
  s += `<line class="hov" id="hovl" x1="0" x2="0" y1="${T}" y2="${T + ph}" style="display:none"/>`;
  s += '</svg>';
  const gl = (w, inner) => `<svg width="${w}" height="10" viewBox="0 0 ${w} 10" style="overflow:visible;margin-right:5px;vertical-align:-1px">${inner}</svg>`;
  const keys = `<div class="keys"><span>${gl(14, '<rect x="0" y="1" width="14" height="8" rx="1" fill="color-mix(in srgb,var(--blue) 22%,transparent)" stroke="var(--blue)"/>')}main session, context after each reply</span><span>${gl(14, '<rect x="0" y="0" width="12" height="9" rx="3" fill="var(--yellow-soft)" stroke="var(--yellow)"/>')}turn start</span><span>${gl(14, '<line x1="0" x2="14" y1="5" y2="5" stroke="var(--violet)" stroke-width="1.6"/>')}subagent</span><span>${gl(8, '<line x1="4" x2="4" y1="0" y2="10" stroke="var(--amber)" stroke-width="1.6"/>')}Stop hook sent the reply back</span><span>${gl(14, '<rect x="0" y="0" width="14" height="9" fill="var(--amber-soft)"/>')}after /compact</span></div>`;
  card.innerHTML = `<div class="ch"><b>Context window</b><span>tokens in context after each reply · ${TURNS.length} turns · ${RUNS.length} subagents</span><span class="scale">${V.window ? k1(V.window) + ' window' : 'scaled to the peak; the window is not known here'}</span></div>${s}${keys}<div class="tip" id="tip" hidden></div>`;
  card.style.position = 'relative';
  const svg = $('#chart'), hov = $('#hovl'), tip = $('#tip');
  const tAt = ev => { const r = svg.getBoundingClientRect(), px = ev.clientX - r.left; return Math.max(0, Math.min(1, (px - L) / pw)) * m.total; };
  const turnAt = t => { let n = TURNS.findIndex((q, i) => t <= q.t); return TURNS[n < 0 ? TURNS.length - 1 : n]; };
  svg.onmousemove = ev => { const r = svg.getBoundingClientRect(), px = ev.clientX - r.left, tt = tAt(ev), tn = turnAt(tt); hov.style.display = ''; hov.setAttribute('x1', px); hov.setAttribute('x2', px); tip.hidden = false; tip.textContent = `${clock(tt)} · turn ${tn.n}`; tip.style.left = Math.min(px + 24, W - 110) + 'px'; tip.style.top = '40px'; };
  svg.onmouseleave = () => { hov.style.display = 'none'; tip.hidden = true; };
  svg.onclick = ev => { const run = ev.target.closest('[data-run]'); if (run) return selectRun(run.dataset.run); const tl = ev.target.closest('[data-turn]'); selectTurn(tl ? +tl.dataset.turn : turnAt(tAt(ev)).n, true); };
}


/* ---------- left: the artifact list ---------- */
function kindStats(k) {
  const items = ART.filter(a => a.kind === k);
  const loaded = items.filter(a => a.loaded).length;
  const nl = k === 'memory' ? items.filter(a => a.linked === false).length : 0;
  const listed = LISTING_OF[k] ? ((V.harness || []).find(x => x.kind === LISTING_OF[k]) || {}).count : null;
  return { items, loaded, nl, listed };
}
const tagsOf = a => {
  let t = '';
  if (a.scope === 'plugin') t += `<span class="tag">${esc(a.plugin || a.scope)}</span>`;
  else if (a.scope !== 'project' && a.scope !== 'auto') t += `<span class="tag">${esc(a.scope)}</span>`;
  if (a.linked === false) t += '<span class="tag warn">not linked</span>';
  return t;
};
function fileRow(a) {
  const on = sel && sel.file === a.key;
  return `<div class="fr${on ? ' on' : ''}" data-file="${esc(a.key)}" title="${esc(a.path)}"><span class="sd ${a.loaded ? 'in' : 'not'}"></span><span class="p path">${esc(a.label)}</span>${tagsOf(a)}<span class="sp"></span>${a.findings != null ? `<span class="fc${a.findings ? '' : ' zero'}">${a.findings}</span>` : ''}<span class="tk">${tk(a.tokens_est, true)}</span></div>`;
}
function renderArt() {
  let h = '<div class="ah"><b>Artifacts</b></div><div class="alist" id="alist">';
  GROUPS.forEach(([k, label]) => {
    const open = groupsOpen.has(k);
    if (k === 'harness') {
      const hv = V.harness || [];
      h += `<div class="gh" data-group="${k}"><span class="cv">${open ? '▾' : '▸'}</span><span class="gt">${label}</span><span class="gc">${hv.length} at session start</span></div>`;
      if (open) h += hv.length ? hv.map((x, i) => `<div class="fr${sel && sel.harness === i ? ' on' : ''}" data-harness="${i}"><span class="sd hv"></span><span class="p" style="font-family:Geist,sans-serif">${esc(x.label)}${x.count != null ? ' · ' + x.count : ''}</span><span class="sp"></span><span class="tk">${tk(x.tokens_est, true)}</span></div>`).join('') : '<div class="nk" style="padding:4px 10px">not known here</div>';
      return;
    }
    const s = kindStats(k);
    h += `<div class="gh" data-group="${k}"><span class="cv">${open ? '▾' : '▸'}</span><span class="gt">${label}</span><span class="gc">${s.items.length} · ${s.loaded} loaded${s.nl ? ` · <b class="warn">${s.nl} not linked</b>` : ''}${s.listed != null ? ` · ${s.listed} listed` : ''}</span></div>`;
    if (!open) return;
    const loaded = s.items.filter(a => a.loaded).sort((a, b) => a.path.localeCompare(b.path));
    const rest = s.items.filter(a => !a.loaded).sort((a, b) => (b.linked === false) - (a.linked === false) || a.scope.localeCompare(b.scope) || a.label.localeCompare(b.label));
    h += loaded.map(fileRow).join('');
    if (rest.length) h += `<div class="ondisk">+${rest.length} on disk, not loaded</div>` + rest.map(fileRow).join('');
    if (!s.items.length) h += '<div class="nk" style="padding:4px 10px">none found on disk</div>';
  });
  $('#art').innerHTML = h + '</div>';
}

/* ---------- right: file, agent and prompt detail ---------- */
function actHtml(a) {
  let h = `<h4>reporails</h4><div class="act"><button data-act="check" data-path="${esc(a.path)}"${busy ? ' disabled' : ''}>Check this file</button><button data-act="heal" data-path="${esc(a.path)}"${busy ? ' disabled' : ''}>Fix this file</button></div>`;
  if (RES && RES.path === a.path) h += `<div>${RES.html}</div>`;
  return h;
}
const ranges = ns => { const out = []; let i = 0; while (i < ns.length) { let j = i; while (j + 1 < ns.length && ns[j + 1] === ns[j] + 1) j++; out.push(ns[i] === ns[j] ? lab(ns[i]) : `${lab(ns[i])}–${ns[j]}`); i = j + 1; } return out.join(', '); };
const lab = n => n === 0 ? 'start' : String(n);
function whereLoaded(a) {
  if (!a.loaded) return 'On disk, not loaded this session.';
  const ns = a.turns || [];
  const arrived = [V.start || [], ...TURNS.map(t => t.loads || [])].map((l, i) => l.some(x => x.path === a.path) ? (i === 0 ? 0 : TURNS[i - 1].n) : null).filter(x => x != null);
  const subs = RUNS.filter(r => (r.sb.loads || []).some(l => l.path === a.path));
  return `Arrived ${arrived.length ? (arrived[0] === 0 ? 'at session start' : 'in turn ' + arrived.join(', ')) : 'by a skill call'}; in context in ${ns.length ? 'turns ' + ranges(ns) : 'no turn recorded'}.${subs.length ? ` ${plural(subs.length, 'subagent')} got it too.` : ''}`;
}
function filePane(a) {
  let h = `<div class="oh"><button class="back" data-back>‹ Load order</button><b class="mono fn">${esc(a.label)}</b>${tagsOf(a)}</div><div class="pane">`;
  h += `<div class="dm">${esc(whereLoaded(a))}${a.tokens_est ? ` · ${tk(a.tokens_est, true)} tokens` : ''}<br><span class="rid">${esc(a.path)}</span></div>`;
  if (a.findings != null) h += `<h4>reporails findings, from the last check<span>${a.findings}</span></h4>`;
  if (a.actionable && a.kind !== 'hook') h += actHtml(a);
  else if (a.kind !== 'hook') h += '<div class="nk" style="margin:2px 0 4px">outside this project; run <code>ails check</code> on it</div>';
  if (a.kind !== 'hook') h += `<h4>Its text</h4>${textBlock('p:' + a.path, 'peek?path=' + encodeURIComponent(a.path))}`;
  else h += '<div class="nk">a hook configuration; its text is not shown</div>';
  return h + '</div>';
}
function harnessPane(x) {
  const d = HARNESS_KIND[x.kind] || [x.label, ''];
  return `<div class="oh"><button class="back" data-back>‹ Load order</button><b class="fn">${esc(x.label)}</b></div><div class="pane"><div class="dm">${esc(d[1])}<br>${x.count != null ? x.count + ' · ' : ''}${tk(x.tokens_est, true)} tokens${x.t != null ? ' · arrived at ' + clock(x.t) : ''}</div><div class="nk">Harness text is not stored in this view.</div></div>`;
}
function agentDetail(r) {
  const loads = r.sb.loads || [], first = loads.filter(l => l.kind !== 'nested'), later = loads.filter(l => l.kind === 'nested');
  let h = `<div class="detail"><div class="dm">${r.turn != null ? `started in turn ${r.turn}` : 'start turn not known'}${r.start != null ? ` at ${clock(r.start)}` : ''}${r.start != null && r.end != null ? `, ran ${dur(r.end - r.start)}` : ''}</div>`;
  h += `<h4>Started with<span>${first.length ? first.length : 'nothing'}</span></h4>` + (first.length ? first.map(l => `<div class="dl"><span style="color:var(--green)">+</span><span class="p">${esc(nameOf(l.path))}</span><span class="w">${tk(l.tokens_est, true)}</span></div>`).join('') : '<div class="dl"><span style="color:var(--red)">✕</span><span class="p">CLAUDE.md</span><span class="w" style="color:var(--red)">not given</span></div>');
  if (later.length) h += `<h4>Loaded during its run<span>${later.length}</span></h4>` + later.map(l => `<div class="dl"><span style="color:var(--green)">+</span><span class="p">${esc(nameOf(l.path))}</span><span class="w">${l.t != null ? 'at ' + clock(l.t) + ' · ' : ''}${tk(l.tokens_est, true)}</span></div>`).join('');
  const ran = r.sb.skill_runs || [];
  if (ran.length) h += `<h4>Skills it ran<span>${ran.length}</span></h4>` + ran.map(x => `<div class="dl"><span style="color:var(--green)">+</span><span class="p">${esc(x.name)}</span><span class="w">${x.t != null ? 'at ' + clock(x.t) + ' · ' : ''}${x.forked ? 'in its own subagent' : tk(x.tokens_est, true)}</span></div>`).join('');
  const ser = r.pts;
  if (ser.length > 1) { const mx = Math.max(1, ...ser.map(p => p[1])); h += `<h4>Its context<span>${k1(ser[0][1])} → ${k1(ser[ser.length - 1][1])}, peak ${k1(mx)}</span></h4><svg class="spk" viewBox="0 0 300 46" preserveAspectRatio="none"><path class="a" d="M0 46 ${ser.map((p, i) => `L${(i / (ser.length - 1) * 300).toFixed(1)} ${(46 - p[1] / mx * 42).toFixed(1)}`).join(' ')} L300 46Z"/></svg>`; }
  h += `<h4>Its brief</h4>${textBlock('b:' + r.id, 'brief?subagent=' + encodeURIComponent(r.id))}`;
  return h + '</div>';
}

/* ---------- right: load order ---------- */
const bar = (tok, cls) => `<span class="tc"><span class="num">${tok ? k1(tok) : ''}</span><span class="trk"><i class="${cls || ''}" style="width:${tok ? Math.max(3, Math.round(Math.min(1, tok / TOK_MAX) * 100)) : 0}%"></i></span></span>`;
const orow = (t, dotCls, name, why, tok, opts = {}) => `<div class="or${opts.attr ? ' link' : ''}${opts.on ? ' on' : ''}" ${opts.attr || ''}><span class="tm">${t == null ? '' : clock(t)}</span><span class="dt ${dotCls}"></span><span class="nm" title="${esc(opts.title || '')}">${name}</span><span class="why ${opts.whyCls || ''}" title="${esc(why)}">${esc(why)}</span>${bar(tok, opts.barCls)}</div>`;
function groupNotes(notes) {
  const g = new Map();
  notes.forEach(n => { const k = n.kind + '|' + n.label; const e = g.get(k) || { ...n, count: 0, tokens_est: 0 }; e.count++; e.tokens_est += n.tokens_est || 0; g.set(k, e); });
  return [...g.values()];
}
function loadRow(l, t) {
  const a = artByPath(l.path);
  return orow(l.t != null ? l.t : t, 'g', `<span class="p">${esc(nameOf(l.path))}</span>`, KIND_WORD[l.kind] || l.kind, l.tokens_est, { attr: a ? `data-file="${esc(a.key)}"` : '', title: l.path });
}
function runRow(r, t) {
  const a = r.path ? artByPath(r.path) : null;
  return orow(r.t != null ? r.t : t, 'g', `<span class="p">${esc(r.name)}</span>`, r.forked ? 'ran in a subagent' : 'ran', r.forked ? 0 : r.tokens_est, { attr: a ? `data-file="${esc(a.key)}"` : '', title: r.path || r.name });
}
function turnRows(t, i) {
  let h = '<div class="tb">';
  const t0 = turnStart(t, i);
  (t.prompts || []).forEach(p => {
    const on = sel && sel.prompt === p.id, no = promptNo.get(p.id);
    h += `<div class="pr${on ? ' on' : ''}" data-prompt="${esc(p.id)}"><span class="tm">${clock(p.t)}</span><span class="pn">${no}</span><span class="pt">${p.queued ? 'queued prompt' : 'your prompt'} · ${p.chars.toLocaleString('en')} chars</span><span class="open">${on ? 'close' : 'open'} ›</span></div>`;
    if (on) h += `<div class="detail">${textBlock('t:' + p.id, 'prompt?id=' + encodeURIComponent(p.id))}</div>`;
  });
  (t.loads || []).forEach(l => { h += loadRow(l, t0); });
  (t.skill_runs || []).forEach(r => { h += runRow(r, t0); });
  groupNotes((t.notes || []).filter(n => n.kind === 'hook_note')).forEach(n => { h += orow(n.t, 'm', `${esc(n.label)} hook note${n.count > 1 ? ' ×' + n.count : ''}`, `added by your ${n.event} hook`, n.tokens_est); });
  groupNotes((t.notes || []).filter(n => n.kind === 'stop_block')).forEach(n => { h += orow(n.t, 'a', `Stop hook sent the reply back${n.count > 1 ? ' ×' + n.count : ''}`, 'its message is added each time', n.tokens_est, { whyCls: 'warn', barCls: 's' }); });
  (t.subagents || []).forEach(id => {
    const r = RUNS.find(x => x.id === String(id)); if (!r) return;
    const on = sel && sel.run === r.id;
    h += orow(r.start, r.miss ? 'r' : 'v', `${esc(r.type)} subagent <a class="open">${on ? 'close' : 'open'} ›</a>`, r.miss ? 'started without CLAUDE.md' : 'its own context' + (r.start != null && r.end != null ? `, ran ${dur(r.end - r.start)}` : ''), r.pts.length ? Math.max(...r.pts.map(p => p[1])) : 0, { attr: `data-run="${esc(r.id)}"`, barCls: 'a', whyCls: r.miss ? 'red' : '', on });
    if (on) h += agentDetail(r);
  });
  if (t.compaction) { const c = t.compaction; h += orow(c.t, 'a', `/compact${c.trigger ? ' (' + esc(c.trigger) + ')' : ''}`, c.before != null && c.after != null ? `context ${k1(c.before)} → ${k1(c.after)}` : '', 0, { whyCls: 'warn' }); }
  if (!(t.loads || []).length && !(t.skill_runs || []).length && !(t.notes || []).length && !(t.subagents || []).length && !t.compaction && !(t.prompts || []).length) h += '<div class="or mute"><span class="tm"></span><span class="dt"></span><span class="nm" style="color:var(--ink-3)">nothing new loaded in this turn</span><span></span><span></span></div>';
  return h + '</div>';
}
function startRows() {
  let h = '<div class="tb">';
  (V.start || []).forEach(l => { h += loadRow(l, 0); });
  (V.harness || []).forEach(x => { h += orow(x.t != null ? x.t : 0, x.kind === 'hook_note' ? 'm' : 'g', esc(x.label) + (x.kind === 'hook_note' ? ' hook note' : '') + (x.count != null ? ` · ${x.count}` : ''), x.kind === 'hook_note' ? 'added by your hook' : 'Claude Code', x.tokens_est); });
  return h + '</div>';
}
function renderInfo() {
  if (sel && sel.file) { const a = ART.find(x => x.key === sel.file); if (a) return $('#info').innerHTML = filePane(a); }
  if (sel && sel.harness != null && (V.harness || [])[sel.harness]) return $('#info').innerHTML = harnessPane(V.harness[sel.harness]);
  let n = 0; TURNS.forEach(t => (t.prompts || []).forEach(p => promptNo.set(p.id, ++n)));
  let h = `<div class="oh"><b>Load order</b><span class="sub">what arrived, why, tokens</span><button data-expand>${openTurns.size ? 'Collapse all' : 'Expand all'}</button></div>`;
  h += `<div class="th${startOpen ? ' on' : ''}" data-startt><span class="cv">${startOpen ? '▾' : '▸'}</span><span class="tg quiet">turn 0</span><span class="tm0">0:00</span><span class="lbl">session start, before any prompt</span><span class="ln"></span><span class="rt">${V.first_context != null ? k1(V.first_context) + ' at the first reply' : ''}</span></div>`;
  if (startOpen) h += startRows();
  let prevCtx = V.first_context;
  TURNS.forEach((t, i) => {
    const open = openTurns.has(t.n), delta = t.context != null && prevCtx != null ? t.context - prevCtx : null;
    if (t.context != null) prevCtx = t.context;
    const stops = (t.notes || []).filter(x => x.kind === 'stop_block').length, np = (t.prompts || []).length;
    const lbl = np ? (np > 1 ? `your prompts ${promptNo.get(t.prompts[0].id)}–${promptNo.get(t.prompts[np - 1].id)}` : `your prompt ${promptNo.get(t.prompts[0].id)}`) : 'no prompt of yours';
    h += `<div class="th${open ? ' on' : ''}${selTurn === t.n ? ' selt' : ''}" data-turnh="${t.n}" id="turn-${t.n}"><span class="cv">${open ? '▾' : '▸'}</span><span class="tg${t.compaction ? ' cmp' : ''}">turn ${t.n}</span><span class="tm0">${clock(turnStart(t, i))}</span><span class="lbl">${lbl}</span><span class="ln"></span><span class="rt">${stops ? `<em class="st">${stops} Stop</em>` : ''}${t.compaction ? '<em class="st">/compact</em>' : ''}${plural(t.replies, 'reply', 'replies')}${delta != null ? ` · ${delta >= 0 ? '+' : '−'}${k1(Math.abs(delta))}` : ''}</span></div>`;
    if (open) h += turnRows(t, i);
  });
  if ((V.not_known || []).length) h += `<div class="nk" style="padding:10px 16px">Not known here: ${esc(V.not_known.join(', '))}</div>`;
  $('#info').innerHTML = h;
}

/* ---------- render ---------- */
function render() {
  if (!V) return;
  const b = $('#banner');
  if ((V.refusals || []).length) { b.hidden = false; b.textContent = 'Claude Code wrote rows this reporails version does not read; parts of this page may be missing.'; b.title = V.refusals.join('\n'); } else b.hidden = true;
  const keepL = $('#alist') ? $('#alist').scrollTop : 0, keepR = $('#info').scrollTop;
  renderChart(); renderArt(); renderInfo();
  if ($('#alist')) $('#alist').scrollTop = keepL;
  document.querySelectorAll('pre.peek[data-pk]').forEach(el => { el.textContent = (FETCHED.get(el.dataset.pk) || {}).text || ''; });
  const d = V.started_at ? new Date(V.started_at) : null;
  const when = d && !isNaN(d) ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  $('#sess').innerHTML = `<span><b>${esc(V.project)}</b></span>${when ? `<span>${esc(when)}</span>` : ''}<span>${V.length_s != null ? dur(V.length_s) + ', ' : ''}${TURNS.length} turns, ${RUNS.length} subagents, peak ${k1(PEAK)}</span>`;
  $('#src').textContent = `Session ${V.session}. Numbers come from the session transcript and files on disk; ~ marks an estimate.`;
}

/* ---------- selection ---------- */
function scrollToIn(el) { const box = $('#info'); if (!el || !box) return; box.scrollTop = el.offsetTop - box.offsetTop - 8; }
function selectTurn(n, scroll) {
  selTurn = n; openTurns.add(n); if (sel && (sel.file || sel.harness != null)) sel = null; render();
  if (scroll) scrollToIn(document.getElementById('turn-' + n));
}
function selectRun(id) {
  const r = RUNS.find(x => x.id === id); if (!r) return;
  if (r.turn != null) { openTurns.add(r.turn); selTurn = r.turn; }
  sel = { run: r.id }; render();
  scrollToIn(document.getElementById('turn-' + r.turn));
}
document.addEventListener('click', e => {
  if (!V || e.target.closest('#chart')) return;
  if (e.target.closest('pre.peek,.detail')) { const act = e.target.closest('[data-act]'); if (act) runAct(act.dataset.act, act.dataset.path); return; }
  const act = e.target.closest('[data-act]'); if (act) return runAct(act.dataset.act, act.dataset.path);
  if (e.target.closest('[data-back]')) { sel = null; return render(); }
  const gr = e.target.closest('[data-group]'); if (gr) { const k = gr.dataset.group; groupsOpen.has(k) ? groupsOpen.delete(k) : groupsOpen.add(k); return render(); }
  const hv = e.target.closest('[data-harness]'); if (hv) { sel = { harness: +hv.dataset.harness }; return render(); }
  if (e.target.closest('[data-expand]')) { if (openTurns.size) { openTurns.clear(); selTurn = null; } else TURNS.forEach(t => openTurns.add(t.n)); return render(); }
  if (e.target.closest('[data-startt]')) { startOpen = !startOpen; return render(); }
  const th = e.target.closest('[data-turnh]'); if (th) { const n = +th.dataset.turnh; if (openTurns.has(n)) { openTurns.delete(n); if (selTurn === n) selTurn = null; } else { openTurns.add(n); selTurn = n; } return render(); }
  const pr = e.target.closest('[data-prompt]'); if (pr) { sel = sel && sel.prompt === pr.dataset.prompt ? null : { prompt: pr.dataset.prompt }; return render(); }
  const run = e.target.closest('[data-run]'); if (run) { sel = sel && sel.run === run.dataset.run ? null : { run: run.dataset.run }; return render(); }
  const fl = e.target.closest('[data-file]'); if (fl) { sel = sel && sel.file === fl.dataset.file ? null : { file: fl.dataset.file }; return render(); }
});
/* check / fix */
const resLines = j => {
  if (j.error) return `<div class="err">${esc(j.error)}</div>`;
  if (Array.isArray(j.lines)) return j.lines.length ? j.lines.map(l => `<div class="fl"><span class="ln">line ${esc(l.line == null ? '—' : l.line)}</span><span class="rl">${esc(l.rule)}</span><span>${esc(l.message)}</span></div>`).join('') : '<div class="nk">no findings</div>';
  if (Array.isArray(j.receipt)) return j.receipt.length ? j.receipt.map(l => `<div class="rc">${esc(l)}</div>`).join('') : '<div class="nk">nothing to fix</div>';
  return '<div class="err">The reply had no result.</div>';
};
async function runAct(kind, path) {
  if (busy || !path) return;
  busy = true; RES = { path, html: '<div class="nk">Running…</div>' }; render();
  const res = await xrayFetch(kind === 'check' ? 'check' : 'heal', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path }) });
  let html;
  if (!res) html = '<div class="err">The x-ray server did not answer.</div>';
  else if (res.j) html = resLines(!res.ok && !res.j.error ? { error: `request refused (${res.status})` } : res.j);
  else html = `<div class="err">request failed (${res.status})</div>`;
  if (kind === 'heal') forgetFetched();
  busy = false; RES = { path, html }; render();
}

/* polling */
let inflight = false;
async function poll() {
  if (document.hidden || inflight) return;
  inflight = true;
  try {
    const h = ETAG ? { 'X-Xray-Token': TOKEN, 'If-None-Match': ETAG } : { 'X-Xray-Token': TOKEN };
    const r = await fetch('view', { headers: h, cache: 'no-store' });
    if (r.status === 304) return;
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    if (j.version === VERSION) return;
    ETAG = r.headers.get('ETag') || String(j.version); VERSION = j.version; forgetFetched();
    build(j); render();
  } catch (_) {
    if (!V) $('#info').innerHTML = '<div class="nk" style="padding:14px">The x-ray server did not answer; retrying.</div>';
  } finally { inflight = false; }
}
function setTheme(t) { document.documentElement.dataset.theme = t; $('#lightBtn').setAttribute('aria-pressed', t === 'light'); $('#darkBtn').setAttribute('aria-pressed', t === 'dark'); }
$('#lightBtn').addEventListener('click', () => setTheme('light'));
$('#darkBtn').addEventListener('click', () => setTheme('dark'));
setTheme(new URLSearchParams(location.search).get('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
let rz = null; window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => V && renderChart(), 120); });
poll();
setInterval(poll, 2000);
