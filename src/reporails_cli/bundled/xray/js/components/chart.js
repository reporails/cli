// part: turns, runs (subagents), context_line, length_s, window, peak, compactions (the view's), stops (where Stop blocks sit).
// ctx: selTurn, sel, selectTurn(n, scroll), selectRun(id).
import { k1, clock } from '../format.js';
import { svg, tpl, slot } from '../dom.js';

const niceCeil = v => {
  if (!(v > 0)) return 1000;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
};

const pointList = (pts, x, y) => pts.map(p => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ');

function draw(part, ctx, W) {
  const { turns, runs, compactions } = part;
  const compTurns = new Set(compactions.map(c => c.turn));
  const H = 214, L = 40, R = 10, T = 26, pw = W - L - R, ph = H - T - 22;
  const total = Math.max(part.length_s || 0, ...turns.map(t => t.t || 0), 1);
  const scale = part.window ? part.window.size : niceCeil(part.peak);
  const x = t => L + Math.min(1, Math.max(0, t / total)) * pw;
  const y = v => T + ph - Math.min(1, (v || 0) / scale) * ph;
  const pts = part.context_line;
  const root = svg('svg', { class: 'chart', id: 'chart', width: W, height: H, viewBox: `0 0 ${W} ${H}` });
  const add = (tag, attrs, text) => root.appendChild(svg(tag, attrs, text));

  [0, .25, .5, .75, 1].forEach(f => {
    const v = f * scale, yy = y(v);
    add('line', { class: 'grid', x1: L, x2: W - R, y1: yy, y2: yy });
    add('text', { class: 'ax', x: L - 5, y: yy + 3, 'text-anchor': 'end' }, v ? k1(v) : '0');
  });
  const st = [30, 60, 120, 300, 600, 900, 1800, 3600].find(q => total / q <= pw / 62) || 3600;
  for (let t = 0; t <= total; t += st) {
    add('line', { class: 'grid', x1: x(t), x2: x(t), y1: T + ph, y2: T + ph + 4 });
    add('text', { class: 'ax', x: x(t), y: H - 5, 'text-anchor': t === 0 ? 'start' : 'middle' }, clock(t));
  }
  compactions.forEach(c => add('rect', { class: 'band', x: x(c.t), y: T, width: Math.max(1, x(c.band_end) - x(c.t)), height: ph }));
  if (ctx.selTurn != null) {
    const i = turns.findIndex(t => t.n === ctx.selTurn);
    if (i >= 0) {
      const a = x(turns[i].start), b = x(turns[i].t);
      add('rect', { class: 'selband', x: a, y: T, width: Math.max(2, b - a), height: ph });
    }
  }
  if (pts.length) {
    add('polygon', { class: 'river', points: `${x(pts[0][0])},${y(0)} ${pointList(pts, x, y)} ${x(pts[pts.length - 1][0])},${y(0)}` });
    add('polyline', { class: 'edge', points: pointList(pts, x, y) });
  }
  turns.forEach(t => (t.series || []).forEach(p => add('circle', { class: 'rp', 'data-turn': t.n, 'data-ctx': p[1], cx: x(p[0]).toFixed(1), cy: y(p[1]).toFixed(1), r: 1.2 })));
  runs.forEach(r => {
    if (r.pts.length < 2) return;
    const line = svg('polyline', { class: 'sub' + (ctx.sel && ctx.sel.run === r.id ? ' on' : ''), 'data-run': r.id, points: pointList(r.pts, x, y) });
    if (!r.sb.has_project_instructions) line.style.stroke = 'var(--red)';
    line.append(svg('title', {}, `${r.type}${r.peak != null ? ' · peak ' + k1(r.peak) : ''}`));
    root.append(line);
  });
  compactions.forEach(c => add('line', { class: 'cmpl', x1: x(c.t), x2: x(c.t), y1: T, y2: T + ph }));
  part.stops.forEach(b => {
    const line = svg('line', { class: 'stop', x1: x(b.t), x2: x(b.t), y1: T + ph - 7, y2: T + ph });
    line.append(svg('title', {}, `Stop hook sent the reply back · turn ${b.turn}`));
    root.append(line);
  });
  const marks = turns.map(t => ({ t, x: x(t.start) }));
  marks.forEach(mk => add('line', { class: 'tm' + (mk.t.n === ctx.selTurn ? ' on' : ''), x1: mk.x, x2: mk.x, y1: T - 4, y2: T + ph }));
  const placed = [];
  const prio = [...marks].sort((a, b) => (b.t.n === ctx.selTurn) - (a.t.n === ctx.selTurn) || compTurns.has(b.t.n) - compTurns.has(a.t.n) || (b.t.replies - a.t.replies));
  prio.forEach(mk => {
    const w = String(mk.t.n).length * 6.4 + 19, lo = Math.max(2, Math.min(W - w - 2, mk.x - w / 2)), hi = lo + w;
    if (placed.some(p => lo < p[1] + 3 && hi > p[0] - 3)) return;
    placed.push([lo, hi]);
    const g = svg('g', { class: 'tl' + (mk.t.n === ctx.selTurn ? ' on' : ''), 'data-turn': mk.t.n });
    g.append(svg('rect', { x: lo, y: 1, width: w, height: 16, rx: 4 }), svg('text', { x: lo + w / 2, y: 12.5, 'text-anchor': 'middle' }, `T${mk.t.n}`));
    root.append(g);
  });
  // The peak is the view's; the plot only finds where that value sits.
  const pk = pts.find(p => p[1] === part.peak) || [0, 0];
  if (part.peak && pk[1]) {
    const flip = x(pk[0]) < L + 110;
    add('text', { class: 'lab', x: x(pk[0]) + (flip ? 6 : -6), y: y(pk[1]) + 11, 'text-anchor': flip ? 'start' : 'end' }, `peak ${k1(part.peak)}`);
  }
  compactions.forEach((c, i) => {
    const flip = x(c.t) > W - R - 170;
    add('text', { class: 'lab cmp', x: x(c.t) + (flip ? -4 : 4), y: T + 40 + 12 * (i % 2), 'text-anchor': flip ? 'end' : 'start' }, `/compact ${c.trigger || ''} · ${k1(c.before)} → ${k1(c.after)}`);
  });
  const sr = runs.find(r => ctx.sel && ctx.sel.run === r.id);
  if (sr && sr.pts.length) {
    const mp = sr.pts.find(p => p[1] === sr.peak) || sr.pts[0];
    const lab = svg('text', { class: 'lab', x: x(mp[0]), y: y(mp[1]) - 5, 'text-anchor': 'middle' }, `${sr.type}${sr.peak != null ? ' · ' + k1(sr.peak) : ''}`);
    lab.style.fill = 'var(--violet)';
    root.append(lab);
  }
  const hov = svg('line', { class: 'hov', id: 'hovl', x1: 0, x2: 0, y1: T, y2: T + ph });
  hov.style.display = 'none';
  root.append(hov);
  return { root, hov, L, pw, total };
}

export function render(card, part, ctx) {
  const W = Math.max(320, Math.round(card.clientWidth - 28));
  const { root, hov, L, pw, total } = draw(part, ctx, W);
  card.replaceChildren(tpl('t-chart'));
  slot(card, 'counts').textContent = `tokens in context after each reply · ${part.turns.length} turns · ${part.runs.length} subagents`;
  slot(card, 'scale').textContent = part.window ? `${k1(part.window.size)} window (${part.window.basis})` : 'scaled to the peak; the window is not known here';
  slot(card, 'plot').replaceWith(root);
  card.style.position = 'relative';
  const tip = card.querySelector('#tip');
  const tAt = ev => Math.max(0, Math.min(1, (ev.clientX - root.getBoundingClientRect().left - L) / pw)) * total;
  const turnAt = t => { const n = part.turns.findIndex(q => t <= q.t); return part.turns[n < 0 ? part.turns.length - 1 : n]; };
  root.addEventListener('mousemove', ev => {
    const px = ev.clientX - root.getBoundingClientRect().left, tt = tAt(ev), tn = turnAt(tt);
    hov.style.display = '';
    hov.setAttribute('x1', px);
    hov.setAttribute('x2', px);
    tip.hidden = false;
    tip.textContent = `${clock(tt)} · turn ${tn.n}`;
    tip.style.left = Math.min(px + 24, W - 110) + 'px';
    tip.style.top = '40px';
  });
  root.addEventListener('mouseleave', () => { hov.style.display = 'none'; tip.hidden = true; });
  root.addEventListener('click', ev => {
    const run = ev.target.closest('[data-run]');
    if (run) return ctx.selectRun(run.dataset.run);
    const tl = ev.target.closest('[data-turn]');
    ctx.selectTurn(tl ? +tl.dataset.turn : turnAt(tAt(ev)).n, true);
  });
}
