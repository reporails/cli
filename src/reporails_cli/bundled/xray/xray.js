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
const shortPath = p => String(p).replace(/^~\/\.claude\/projects\/[^/]+\/memory\//, 'memory/');
const niceCeil = v => { if (!(v > 0)) return 1000; const p = Math.pow(10, Math.floor(Math.log10(v))); for (const m of [1, 2, 4, 8, 10]) if (m * p >= v) return m * p; return 10 * p; };

const STATE_WORD = { arr: 'arrived', in: 'in context', not: 'not loaded', listed: 'on disk, not loaded' };
const KIND_WORD = { project: 'project instructions', memory: 'auto memory', user: 'your user instructions', local: 'local instructions', managed: 'managed instructions', nested: 'loaded because a file in that folder was read' };
const KINDS = [{ k: 'instr', src: 'instructions', label: 'Instruction files' }, { k: 'mem', src: 'memory', label: 'Memory' }, { k: 'skill', src: 'skill', label: 'Skills' }, { k: 'agent', src: 'agent', label: 'Agents' }, { k: 'hook', src: 'hook', label: 'Hooks' }];
const KIND_TAG = { instr: 'instruction file', mem: 'memory', skill: 'skill', agent: 'agent', hook: 'hook' };

let V = null, VERSION = null, ETAG = null;
let ROWS = [], RUNS = [], ART = [], SCALE = 1000, PEAK = 0, F = { kind: 'turn', n: 0 };
let busy = false, RES = null;

const nk = s => ((V && V.not_known) || []).some(x => String(x).toLowerCase().includes(s));
const rowOfTime = t => { let r = 0; ROWS.forEach((x, i) => { if (x.t != null && t != null && x.t <= t) r = i; }); return r; };
const rowOfN = n => Math.max(0, ROWS.findIndex(r => r.n === n));
const compRow = () => ROWS.findIndex(r => r.compaction);
const defaultFocus = () => { const c = ROWS.find(r => r.compaction); return { kind: 'turn', n: c ? c.n : (ROWS[ROWS.length - 1] || { n: 0 }).n }; };
const fc = n => n == null ? '' : `<span class="fc ${n === 0 ? 'zero' : n >= 10 ? 'hi' : ''}">${n}</span>`;
const dotsOf = (a, i) => a.pres[i] === 'not' && a.listed ? 'listed' : a.pres[i];
const inCtx = p => p === 'in' || p === 'arr';
const isEvent = r => r.n && (r.compaction || (r.loads || []).length || (r.subagents || []).length);

/* ---------- build the page's arrays from the view ---------- */
function build(view) {
  V = view;
  const turns = view.turns || [];
  ROWS = [{ n: 0, t: 0, start: true, context: view.first_context, context_start: null, replies: 0, loads: view.start || [], reads: null, subagents: [], compaction: null }].concat(turns);
  PEAK = Math.max(0, ...turns.map(t => t.context || 0), view.first_context || 0);
  SCALE = view.window || niceCeil(PEAK);
  RUNS = (view.subagents || []).map((s, i) => {
    const pts = (s.series || []).filter(p => p && p[0] != null);
    const st = s.start != null ? s.start : (pts.length ? pts[0][0] : null);
    const en = s.end != null ? s.end : (pts.length ? pts[pts.length - 1][0] : st);
    const r0 = st == null && s.turn != null ? rowOfN(s.turn) : rowOfTime(st);
    return { id: String(s.id), type: s.type || 'subagent', turn: s.turn, sb: s, pts, start: st, end: en, r0, miss: !(s.loads || []).some(l => l.kind === 'project'), i };
  });
  const allLoads = [].concat(view.start || [], ...turns.map(t => t.loads || []), ...(view.subagents || []).map(s => s.loads || []));
  const tokOf = path => { const l = allLoads.find(x => x.path === path && x.tokens_est != null); return l ? l.tokens_est : null; };
  ART = (view.artifacts || []).map(a => {
    const set = new Set(a.turns || []);
    const pres = ROWS.map((r, i) => set.has(r.n) ? (i > 0 && set.has(ROWS[i - 1].n) ? 'in' : 'arr') : 'not');
    const K = KINDS.find(x => x.src === a.kind);
    return { key: a.kind + ':' + a.path, kind: K ? K.k : 'instr', label: a.path, path: a.path, canAct: a.kind !== 'hook', loaded: !!a.loaded, listed: !a.loaded, pres, fcount: a.findings, tok: tokOf(a.path) };
  });
  if (F.kind === 'turn' && !ROWS.some(r => r.n === F.n)) F = defaultFocus();
  if (F.kind === 'agent' && !RUNS.some(r => r.id === F.id)) F = defaultFocus();
  if (F.kind === 'art' && !ART.some(a => a.key === F.key)) F = defaultFocus();
}
const focusRow = () => F.kind === 'turn' ? rowOfN(F.n) : F.kind === 'agent' ? (RUNS.find(r => r.id === F.id) || { r0: 0 }).r0 : ROWS.length - 1;
const artByPath = p => ART.find(a => a.path === p && a.kind !== 'hook');

/* ---------- artifacts area: kind columns ---------- */
function renderArt() {
  const row = focusRow();
  const rowLab = F.kind === 'art' ? 'the end of the session' : row === 0 ? 'session start' : 'turn ' + ROWS[row].n;
  const checked = ART.filter(a => a.fcount != null);
  const total = checked.reduce((s, a) => s + a.fcount, 0);
  let h = `<div class="ah"><b>Artifacts</b><span class="sub">dots show ${esc(rowLab)}; numbers are reporails findings</span><span class="rp">${checked.length ? `${total} findings in ${checked.length} checked files` : 'no file checked yet'}</span></div><div class="cols">`;
  KINDS.forEach(K => {
    const items = ART.filter(a => a.kind === K.k);
    const runs = K.k === 'agent' ? RUNS : [];
    const inNow = items.filter(a => inCtx(a.pres[row]));
    const shownA = K.k === 'hook' ? items : items.filter(a => !a.listed);
    const shown = shownA.slice(0, 7 - Math.min(runs.length, 4));
    const more = items.length - shown.length;
    const fsum = items.reduce((s, a) => s + (a.fcount || 0), 0);
    const tsum = inNow.reduce((s, a) => s + (a.tok || 0), 0);
    const tot = K.k === 'agent' ? `${runs.length} ran, ${items.length} on disk` : K.k === 'hook' ? `${items.length} configured` : `${inNow.length}/${items.length} in context${tsum ? ', ~' + k1(tsum) : ''}`;
    h += `<div class="col"><h4>${K.label}${fsum ? fc(fsum) : ''}</h4><div class="tot">${esc(tot)}</div>`;
    if ((K.k === 'skill' && nk('skill')) || (K.k === 'hook' && nk('hook'))) h += `<div class="nk">${K.k === 'skill' ? 'skill loads' : 'hook notes'}: not known here</div>`;
    h += runs.slice(0, 4).map(r => `<div class="it${F.kind === 'agent' && F.id === r.id ? ' on' : ''}" data-run="${esc(r.id)}" title="subagent"><span class="sd ${r.miss ? 'miss' : 'ran'}"></span><span class="p">${esc(r.type)}${r.turn != null ? ` <span style="color:var(--ink-3)">T${r.turn}</span>` : ''}</span></div>`).join('');
    h += shown.map(a => {
      const s = dotsOf(a, row);
      return `<div class="it${F.kind === 'art' && F.key === a.key ? ' on' : ''}" data-art="${esc(a.key)}" title="${esc(STATE_WORD[s] || '')}"><span class="sd ${s}"></span><span class="p">${esc(shortPath(a.label))}</span>${fc(a.fcount)}</div>`;
    }).join('');
    if (more > 0) h += `<div class="more">+${more} on disk, not loaded</div>`;
    if (K.k === 'agent' && runs.length > 4) h += `<div class="more">+${runs.length - 4} more runs</div>`;
    h += '</div>';
  });
  $('#art').innerHTML = h + '</div>';
}

/* ---------- map, refined ---------- */
function renderMap() {
  const n = ROWS.length, rowH = Math.max(9, Math.min(13, Math.floor(600 / n)));
  const TOP = 46, loadX = 34, cx = 88, maxW = 190, lim = cx + maxW, stopX = lim + 14, LW = 52, lane0 = stopX + 22;
  const y = i => TOP + i * rowH + rowH / 2, H = TOP + n * rowH + 8;
  const wv = c => Math.min(1, (c || 0) / SCALE) * maxW, Rx = c => cx + wv(c);
  const pct = c => Math.round((c || 0) / SCALE * 100) + '%';
  const yT = t => { const ri = rowOfTime(t), t0 = ROWS[ri].t || 0, t1 = ROWS[ri + 1] && ROWS[ri + 1].t != null ? ROWS[ri + 1].t : t0 + 1; return y(ri) - rowH / 2 + Math.min(1, Math.max(0, (t - t0) / Math.max(1, t1 - t0))) * rowH; };
  const ci = compRow(), yb = ci > 0 ? y(ci) - rowH / 2 : 0, P = [];
  let prevC = 0;
  ROWS.forEach((t, i) => {
    const c = t.context != null ? t.context : prevC;
    if (i === ci && t.compaction.before != null && t.compaction.after != null) P.push([yb, t.compaction.before], [yb, t.compaction.after]);
    P.push([y(i), c]); prevC = c;
  });
  const riverX = v => { for (let j = 1; j < P.length; j++) { const [a, ca] = P[j - 1], [b, cb] = P[j]; if (v >= a && v <= b) return Rx(b === a ? Math.max(ca, cb) : ca + (cb - ca) * (v - a) / (b - a)); } return Rx(P[P.length - 1][1]); };
  const BR = RUNS.map(r => { const pts = r.pts.map(p => [yT(p[0]), p[1]]); const y0 = pts.length ? pts[0][0] : y(r.r0) - rowH / 2, y1 = pts.length ? pts[pts.length - 1][0] : y0 + 7; return { r, pts, y0, y1, stub: !pts.length, peak: pts.length ? Math.max(...pts.map(p => p[1])) : null }; });
  const lanes = [], fits = (l, a, b) => l.iv.every(([p, q]) => b + 3 < p || a > q + 3);
  [...BR.filter(b => !b.stub), ...BR.filter(b => b.stub)].forEach(b => { let L = lanes.findIndex(l => l.stub === b.stub && fits(l, b.y0, b.y1)); if (L < 0) { L = lanes.length; lanes.push({ iv: [], stub: b.stub }); } lanes[L].iv.push([b.y0, b.y1]); b.L = L; });
  let acc = lane0; const LX = lanes.map(l => { const x = acc; acc += l.stub ? 18 : LW; return x; });
  const labX = acc + 4, W = labX + 262;
  let s = `<svg class="map" id="map" viewBox="0 0 ${W} ${H}" style="height:${H}px">`;
  s += `<text class="colhead" x="24" y="13" text-anchor="end">turn</text><text class="colhead" x="${loadX - 2}" y="13">loaded</text><text class="colhead" x="${cx}" y="13">tokens in context</text><text class="colhead" x="${stopX}" y="13" text-anchor="middle">stop${nk('stop') ? '<title>Stop hook blocks: not known here</title>' : ''}</text>${nk('stop') ? `<text class="colhead nkh" x="${stopX}" y="23" text-anchor="middle" style="font-size:8px">n/k</text>` : ''}<text class="colhead" x="${lane0}" y="13">subagents, own window</text>`;
  [0, .25, .5, .75, 1].forEach(f => { const v = f * SCALE, x = Rx(v); s += `<text class="tick" x="${x}" y="33" text-anchor="middle">${v ? k1(v) : '0'}</text>`; if (f > 0 && f < 1) s += `<line class="gridv" x1="${x}" x2="${x}" y1="${TOP - 6}" y2="${H - 4}"/>`; });
  if (V.window) s += `<line class="lim" x1="${lim}" x2="${lim}" y1="${TOP - 6}" y2="${H - 4}"/>`;
  s += `<line class="spine" x1="${cx}" x2="${cx}" y1="${TOP - 6}" y2="${H - 4}"/>`;
  const fr = focusRow();
  if (F.kind === 'turn') s += `<rect class="selband" x="2" y="${y(fr) - rowH / 2}" width="${stopX + 8}" height="${rowH}" rx="3"/>`;
  if (F.kind === 'art') { const a = ART.find(x => x.key === F.key); if (a) a.pres.forEach((p, i) => { if (inCtx(p)) s += `<rect class="artline" x="${lim + 4}" y="${y(i) - rowH / 2 + 1}" width="3" height="${rowH - 2}" opacity="${p === 'in' ? .55 : 1}"/>`; }); }
  s += `<polygon class="river f" points="${cx},${P[0][0]} ${P.map(([yy, c]) => `${Rx(c)},${yy}`).join(' ')} ${cx},${P[P.length - 1][0]}"/><polyline class="edge" points="${P.map(([yy, c]) => `${Rx(c)},${yy}`).join(' ')}"/>`;
  ROWS.forEach((t, i) => {
    const yy = y(i);
    if (i === 0 || i === ci || i === n - 1 || (t.n % 5 === 0 && t.n)) s += `<text class="tick${i === ci ? ' cmp' : ''}" x="24" y="${yy + 3.5}" text-anchor="end">${t.n}</text>`;
    const g = t.loads || [];
    g.slice(0, 5).forEach((x, j) => { const gx = loadX + 2 + j * 7; s += `<circle class="g-file" cx="${gx}" cy="${yy}" r="3"><title>loaded: ${esc(shortPath(x.path))}</title></circle>`; });
    if (g.length > 5) s += `<text class="more" x="${loadX + 2 + 5 * 7 - 2}" y="${yy + 3}">+${g.length - 5}<title>${esc(g.slice(5).map(x => shortPath(x.path)).join(', '))}</title></text>`;
  });
  if (ci > 0) {
    const c = ROWS[ci].compaction, hasB = c.before != null;
    s += `<line class="cmpl" x1="${loadX - 4}" x2="${stopX + 6}" y1="${yb}" y2="${yb}"/>`;
    s += `<text class="cmpt" x="150" y="${yb - 3}">/compact${hasB ? (V.window ? ` at ${pct(c.before)} full` : ` at ${k1(c.before)}`) : ''}${c.trigger ? ` (${esc(c.trigger)})` : ''}</text>`;
    if (hasB && c.after != null) s += `<text class="cmpt2" x="150" y="${yb + 9.5}">${k1(c.before)} → ${k1(c.after)}</text>`;
  }
  ROWS.forEach((t, i) => { if (i && i !== ci && t.context != null && ROWS[i - 1].context != null && t.context - ROWS[i - 1].context >= SCALE * .2) s += `<text class="note" x="${Rx(t.context) - 5}" y="${y(i) + 3.5}" text-anchor="end">+${k1(t.context - ROWS[i - 1].context)}</text>`; });
  const last = ROWS[n - 1];
  if (last.context != null) s += `<text class="note" x="${Rx(last.context) - 5}" y="${y(n - 1) + 3.5}" text-anchor="end">ends at ${k1(last.context)}${V.window ? ', ' + pct(last.context) : ''}</text>`;
  let lastLab = -99;
  BR.slice().sort((a, b) => a.y0 - b.y0).forEach(({ r, pts, y0, y1, L, peak, stub }) => {
    const on = F.kind === 'agent' && F.id === r.id, x0 = LX[L], id = esc(r.id);
    s += `<path class="stemh" d="M${riverX(y0)} ${y0} H${x0}"/>`;
    if (pts.length) s += `<polygon class="branch${r.miss ? ' miss' : ''}${on ? ' on' : ''}" data-run="${id}" points="${pts.map(([yy]) => `${x0},${yy}`).join(' ')} ${pts.map(([yy, c]) => `${x0 + wv(c)},${yy}`).reverse().join(' ')}"><title>${esc(r.type)}</title></polygon>`;
    else s += `<circle class="nostub" data-run="${id}" cx="${x0 + 3.5}" cy="${y0}" r="3.5"><title>${esc(r.type)} (no context series)</title></circle>`;
    s += `<rect data-run="${id}" x="${x0 - 2}" y="${y0 - 4}" width="${stub ? 12 : LW - 4}" height="${Math.max(10, y1 - y0 + 8)}" fill="transparent" style="cursor:pointer"><title>${esc(r.type)}</title></rect>`;
    const ly = Math.max(y0, lastLab + 26); lastLab = ly;
    s += `<path class="labline" d="M${stub ? x0 + 9 : x0 + wv(pts[0][1]) + 3} ${y0} L${labX - 4} ${ly}"/>`;
    s += `<text class="brlab${on ? ' on' : ''}" data-run="${id}" x="${labX}" y="${ly + 3}">${esc(r.type)}</text>`;
    s += `<text class="brlab3" data-run="${id}" x="${labX}" y="${ly + 15}">${r.turn != null ? `turn ${r.turn}` : 'subagent'}${peak ? ` · peak ${k1(peak)}` : ''}${r.miss ? ' · <tspan class="bad">no CLAUDE.md</tspan>' : ''}</text>`;
  });
  s += `<rect class="hovband" id="hov" x="2" y="-50" width="${stopX + 8}" height="${rowH}" rx="3"/><text class="hovtxt" id="hovtxt" x="${W - 2}" y="13" text-anchor="end"></text></svg>`;
  const gl = (w, inner) => `<svg class="gl" width="${w}" height="10" viewBox="0 0 ${w} 10">${inner}</svg>`;
  const keys = '<div class="keys k8">' +
    `<span>${gl(14, '<rect x="0" y="1" width="14" height="8" rx="1" fill="color-mix(in srgb,var(--blue) 22%,transparent)" stroke="color-mix(in srgb,var(--blue) 75%,transparent)"/>')}tokens in context after each turn${V.window ? '' : ', scaled to the session’s peak'}</span>` +
    (V.window ? `<span>${gl(10, '<line x1="5" x2="5" y1="0" y2="10" stroke="var(--red)" stroke-dasharray="2 2" opacity=".6"/>')}${k1(V.window)} window limit</span>` : '') +
    `<span>${gl(14, '<line x1="0" x2="14" y1="5" y2="5" stroke="var(--amber)" stroke-width="2"/>')}/compact</span>` +
    `<span>${gl(8, '<circle cx="4" cy="5" r="3" fill="var(--green)"/>')}instruction file loaded</span>` +
    `<span>${gl(14, '<rect x="0" y="1" width="14" height="8" rx="1" fill="color-mix(in srgb,var(--violet) 22%,transparent)" stroke="color-mix(in srgb,var(--violet) 70%,transparent)"/>')}subagent, same scale</span>` +
    `<span>${gl(14, '<rect x="0" y="1" width="14" height="8" rx="1" fill="color-mix(in srgb,var(--red) 18%,transparent)" stroke="var(--red)"/>')}subagent started without CLAUDE.md</span>` +
    (F.kind === 'art' ? `<span>${gl(4, '<rect x="0" y="0" width="3" height="10" fill="var(--blue)"/>')}selected artifact in context</span>` : '') +
    (nk('stop') ? '<span class="nk">Stop hook blocks: not known here</span>' : '') + '</div>';
  const head = `<div class="mh2"><b>Context window, turn by turn</b><span>${esc(V.project)} · ${esc(String(V.started_at || '').slice(0, 10))} · ${V.length_s != null ? dur(V.length_s) + ' · ' : ''}${ROWS.length - 1} turns · ${RUNS.length} subagents</span></div>`;
  const foot = '<div class="mfoot"><span>One row per turn, time runs down. Click a row or a subagent to open it.</span><span class="bm"><i><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M5 7h8M5 12h14M5 17h10"/></svg></i>reporails <span>x-ray</span></span></div>';
  return { html: `<section class="card mapcard">${head}${s}${keys}${foot}</section>`, H, rowH, y, W, TOP };
}

/* ---------- focus pane ---------- */
const row = (ic, cls, name, why, tok, whyCls, attr) => `<div class="row${attr ? ' link' : ''}" ${attr || ''}><span class="ic ${cls}">${ic}</span><span class="nm">${name}</span><span class="why ${whyCls || ''}">${esc(why)}</span><span class="tk">${tok || ''}</span></div>`;
const loadRow = l => { const a = artByPath(l.path); return row('+', 'file', `<span class="p">${esc(shortPath(l.path))}</span>${l.findings != null ? ' ' + fc(l.findings) : ''}`, KIND_WORD[l.kind] || l.kind, tk(l.tokens_est, true), '', a ? `data-art="${esc(a.key)}"` : ''); };
const nkLine = () => (V.not_known || []).length ? `<div class="nk" style="padding:6px 0 2px">Not known here: ${esc(V.not_known.join(', '))}</div>` : '';

function turnDetail(t) {
  let h = '<div class="det">';
  (t.loads || []).forEach(l => { h += loadRow(l); });
  if (t.compaction) { const c = t.compaction; h += row('⟲', 'cmp', '/compact', c.before != null && c.after != null ? `context ${k1(c.before)} → ${k1(c.after)}` : (c.trigger || ''), '', 'warn'); }
  (t.subagents || []).forEach(id => { const r = RUNS.find(x => x.id === String(id)); if (r) h += row('⇣', r.miss ? 'miss' : 'agent', `${esc(r.type)} subagent`, r.miss ? 'started without CLAUDE.md' : 'started with project instructions', r.pts.length ? tk(Math.max(...r.pts.map(p => p[1]))) : '', r.miss ? 'red' : '', `data-run="${esc(r.id)}"`); });
  if (!(t.loads || []).length && !t.compaction && !(t.subagents || []).length) h += '<div class="row mute"><span class="ic mute">·</span><span class="nm">nothing new loaded in this turn</span></div>';
  if (!t.start) {
    if (t.reads == null) h += '<div class="nk" style="padding:4px 0 2px 32px">files read: not known here</div>';
    else if (t.reads.length) h += `<details class="reads"><summary>Read ${t.reads.length} file${t.reads.length > 1 ? 's' : ''} ›</summary>${t.reads.map(p => `<div>${esc(p)}</div>`).join('')}</details>`;
  }
  return h + nkLine() + '</div>';
}
function agentDetail(r) {
  const loads = r.sb.loads || [];
  const first = loads.filter(l => l.kind !== 'nested'), later = loads.filter(l => l.kind === 'nested');
  let h = `<div class="sec"><h3>Started with<span>${first.length ? '' : 'nothing'}</span></h3>${first.length ? first.map(loadRow).join('') : '<div class="row"><span class="ic miss">✕</span><span class="nm"><span class="p">CLAUDE.md</span></span><span class="why red">not given</span><span class="tk"></span></div>'}</div>`;
  if (later.length) h += `<div class="sec"><h3>Loaded during its run<span>${later.length}</span></h3>${later.map(l => row('+', 'file', `<span class="p">${esc(shortPath(l.path))}</span>`, (l.t != null ? `at ${clock(l.t)}, ` : '') + 'because it read a file in that folder', tk(l.tokens_est, true))).join('')}</div>`;
  const ser = r.pts;
  if (ser.length > 1) { const mx = Math.max(1, ...ser.map(p => p[1])); h += `<div class="sec"><h3>Its context<span>${k1(ser[0][1])} → ${k1(ser[ser.length - 1][1])}, peak ${k1(mx)}</span></h3><svg class="spk" viewBox="0 0 300 44" preserveAspectRatio="none"><path d="M0 44 ${ser.map((p, i) => `L${i / (ser.length - 1) * 300} ${44 - p[1] / mx * 40}`).join(' ')} L300 44Z"/></svg></div>`; }
  else h += '<div class="sec"><h3>Its context</h3><div class="nk">no context series recorded for this run</div></div>';
  return h;
}
function actHtml(a) {
  let h = `<div class="sec"><h3>reporails</h3><div class="act"><button data-act="check" data-path="${esc(a.path)}"${busy ? ' disabled' : ''}>Check this file</button><button data-act="heal" data-path="${esc(a.path)}"${busy ? ' disabled' : ''}>Fix this file</button></div>`;
  if (RES && RES.path === a.path) h += `<div class="res">${RES.html}</div>`;
  return h + '</div>';
}
function artDetail(a) {
  const fr = focusRow(), inN = a.pres.filter(inCtx).length;
  let h = `<div class="sec"><h3>In context, turn by turn<span>${inN} of ${ROWS.length}</span></h3><div class="strip2">${a.pres.map((p, i) => `<i class="${p === 'not' ? '' : p}${i === fr ? ' f' : ''}" data-row="${i}" title="${i === 0 ? 'session start' : 'turn ' + ROWS[i].n}: ${STATE_WORD[p] || ''}"></i>`).join('')}</div></div>`;
  const arr = ROWS.map((r, i) => ({ r, i })).filter(x => a.pres[x.i] === 'arr');
  if (arr.length) h += `<div class="sec"><h3>When it arrived</h3>${arr.map(x => { const l = (x.r.loads || []).find(y => y.path === a.path); return row('+', 'file', x.i === 0 ? 'session start' : `turn ${x.r.n}`, l ? KIND_WORD[l.kind] || '' : '', clock(x.r.t), '', `data-row="${x.i}"`); }).join('')}</div>`;
  const used = RUNS.filter(r => (r.sb.loads || []).some(l => l.path === a.path));
  if (used.length) h += `<div class="sec"><h3>Subagents that got it<span>${used.length}</span></h3>${used.map(r => row('⇣', 'agent', esc(r.type), (r.sb.loads || []).some(l => l.path === a.path && l.kind !== 'nested') ? 'at its start' : 'came with a read', r.turn != null ? `T${r.turn}` : '', '', `data-run="${esc(r.id)}"`)).join('')}</div>`;
  if (a.fcount != null) h += `<div class="sec"><h3>reporails findings, from the last check<span>${a.fcount}</span></h3></div>`;
  else if (a.canAct) h += '<div class="sec"><h3>reporails findings</h3><div class="nk">not checked yet</div></div>';
  if (a.canAct) h += actHtml(a);
  return h;
}
function renderFocus() {
  let head = '', body = '';
  if (F.kind === 'turn') {
    const t = ROWS[rowOfN(F.n)], ev = ROWS.filter(isEvent);
    const prevEv = [...ev].reverse().find(x => x.n < F.n), nextEv = ev.find(x => x.n > F.n);
    head = `<div class="fh"><span class="tg ${t.compaction ? 'cmp' : ''}">${t.start ? 'session start' : 'turn ' + t.n}</span><h2>${t.start ? 'Session start' : t.compaction ? '/compact' : 'turn ' + t.n}</h2><div class="nav"><button data-go="pe"${prevEv ? '' : ' disabled'}>‹ change</button><button data-go="pv">↑</button><button data-go="nx">↓</button><button data-go="ne"${nextEv ? '' : ' disabled'}>change ›</button></div></div>`;
    head += `<div class="fsub">${t.start ? (t.context != null ? `${k1(t.context)} at the first reply` : 'context at the first reply not known') : `${clock(t.t)}, ${t.replies} ${t.replies === 1 ? 'reply' : 'replies'}${t.context != null ? `, context ${t.context_start != null ? k1(t.context_start) + ' → ' : ''}${k1(t.context)}` : ''}`}</div>`;
    body = turnDetail(t);
  } else if (F.kind === 'agent') {
    const r = RUNS.find(x => x.id === F.id);
    head = `<div class="fh"><span class="tg agent">subagent</span><h2>${esc(r.type)}</h2><div class="nav"><button data-go="back">‹ main session</button></div></div><div class="fsub">${r.turn != null ? `started in turn ${r.turn}` : 'start turn not known'}${r.start != null ? ` at ${clock(r.start)}` : ''}${r.start != null && r.end != null ? `, ran ${dur(r.end - r.start)}` : ''}</div>`;
    body = agentDetail(r);
  } else {
    const a = ART.find(x => x.key === F.key);
    head = `<div class="fh"><span class="tg art">${KIND_TAG[a.kind]}</span><h2 class="mono">${esc(shortPath(a.label))}</h2><div class="nav"><button data-go="back">‹ turn</button></div></div><div class="fsub">${a.loaded ? 'loaded in this session' : 'on disk, not loaded this session'}${a.tok ? `, ${tk(a.tok, true)} tokens` : ''} <span class="rid">${esc(a.path)}</span></div>`;
    body = artDetail(a);
  }
  return `<section class="card focus">${head}${body}<div class="hint">↑ ↓ step through turns; click a turn on the map, an agent, or an artifact</div></section>`;
}
function step(d) {
  const i = F.kind === 'turn' ? rowOfN(F.n) : focusRow();
  F = { kind: 'turn', n: ROWS[Math.max(0, Math.min(ROWS.length - 1, i + d))].n }; render();
}

/* ---------- render ---------- */
function render() {
  if (!V) return;
  const b = $('#banner');
  if ((V.refusals || []).length) { b.hidden = false; b.textContent = 'Claude Code wrote rows this reporails version does not read; parts of this page may be missing.'; b.title = V.refusals.join('\n'); } else b.hidden = true;
  renderArt();
  const m = renderMap();
  document.documentElement.style.setProperty('--mapw', (m.W + 26) + 'px');
  $('#main').innerHTML = m.html + `<div class="rcol">${renderFocus()}</div>`;
  const map = $('#map'), pick = ev => { const r = map.getBoundingClientRect(), yy = (ev.clientY - r.top) * (m.H / r.height); return Math.max(0, Math.min(ROWS.length - 1, Math.floor((yy - m.TOP) / m.rowH))); };
  map.onmousemove = ev => { if (ev.target.dataset && ev.target.dataset.run) return; const i = pick(ev), c = ROWS[i].context; $('#hov').setAttribute('y', m.y(i) - m.rowH / 2); $('#hovtxt').textContent = `${i === 0 ? 'start' : 'turn ' + ROWS[i].n} · ${k1(c)}${V.window && c != null ? ' · ' + Math.round(c / SCALE * 100) + '%' : ''}`; };
  map.onmouseleave = () => { $('#hovtxt').textContent = ''; };
  map.onclick = ev => { const run = ev.target.closest('[data-run]'); if (run) { F = { kind: 'agent', id: run.dataset.run }; render(); return; } F = { kind: 'turn', n: ROWS[pick(ev)].n }; render(); };
  const d = V.started_at ? new Date(V.started_at) : null;
  const when = d && !isNaN(d) ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  $('#sess').innerHTML = `<span><b>${esc(V.project)}</b></span>${when ? `<span>${esc(when)}</span>` : ''}<span>${V.length_s != null ? dur(V.length_s) + ', ' : ''}${ROWS.length - 1} turns, ${RUNS.length} subagents, peak ${k1(PEAK)}</span>`;
  $('#src').textContent = `Session ${V.session}. Numbers come from the session transcript and the event log; ~ marks an estimate.`;
}

/* clicks outside the map */
document.addEventListener('click', e => {
  if (!V || e.target.closest('#map')) return;
  const g = e.target.closest('[data-go]');
  if (g) {
    const k = g.dataset.go, ev = ROWS.filter(isEvent);
    if (k === 'pv') return step(-1);
    if (k === 'nx') return step(1);
    if (k === 'pe') { const p = [...ev].reverse().find(x => x.n < F.n); if (p) { F = { kind: 'turn', n: p.n }; render(); } return; }
    if (k === 'ne') { const p = ev.find(x => x.n > F.n); if (p) { F = { kind: 'turn', n: p.n }; render(); } return; }
    if (k === 'back') { if (F.kind === 'agent') { const r = RUNS.find(x => x.id === F.id); F = r && r.turn != null && ROWS.some(x => x.n === r.turn) ? { kind: 'turn', n: r.turn } : defaultFocus(); } else F = defaultFocus(); render(); }
    return;
  }
  const act = e.target.closest('[data-act]');
  if (act) return runAct(act.dataset.act, act.dataset.path);
  const run = e.target.closest('[data-run]');
  if (run) { F = { kind: 'agent', id: run.dataset.run }; render(); return; }
  const art = e.target.closest('[data-art]');
  if (art) { if (ART.some(a => a.key === art.dataset.art)) { F = { kind: 'art', key: art.dataset.art }; render(); } return; }
  const rw = e.target.closest('[data-row]');
  if (rw) { F = { kind: 'turn', n: ROWS[+rw.dataset.row].n }; render(); }
});
document.addEventListener('keydown', e => {
  if (!V || e.target.closest('input,textarea')) return;
  if (e.key === 'ArrowDown') { e.preventDefault(); step(1); }
  if (e.key === 'ArrowUp') { e.preventDefault(); step(-1); }
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
  let html;
  try {
    const r = await fetch(kind === 'check' ? 'check' : 'heal', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Xray-Token': TOKEN }, body: JSON.stringify({ path }) });
    let j = null; try { j = await r.json(); } catch (_) { j = null; }
    html = j ? resLines(!r.ok && !j.error ? { error: `request refused (${r.status})` } : j) : `<div class="err">request failed (${r.status})</div>`;
  } catch (_) { html = '<div class="err">The x-ray server did not answer.</div>'; }
  busy = false; RES = { path, html }; render();
}

/* polling */
let inflight = false;
async function poll() {
  if (document.hidden || inflight) return;
  inflight = true;
  try {
    const h = ETAG ? { 'If-None-Match': ETAG } : {};
    const r = await fetch('view', { headers: h, cache: 'no-store' });
    if (r.status === 304) return;
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    if (j.version === VERSION) return;
    ETAG = r.headers.get('ETag') || String(j.version); VERSION = j.version;
    const first = !V; build(j); if (first) F = defaultFocus(); render();
  } catch (_) {
    if (!V) $('#main').innerHTML = '<section class="card mapcard"><div class="mh"><span>The x-ray server did not answer; retrying.</span></div></section>';
  } finally { inflight = false; }
}
function setTheme(t) { document.documentElement.dataset.theme = t; $('#lightBtn').setAttribute('aria-pressed', t === 'light'); $('#darkBtn').setAttribute('aria-pressed', t === 'dark'); }
$('#lightBtn').addEventListener('click', () => setTheme('light'));
$('#darkBtn').addEventListener('click', () => setTheme('dark'));
setTheme(new URLSearchParams(location.search).get('theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
poll();
setInterval(poll, 2000);
