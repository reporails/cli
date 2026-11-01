// The canvas: the current agent's spine over time, its subagents as cards with arches, the stations on the spine and
// the side track of everyday calls. Card placement, scale, arches and ticks are geometry; every fact comes from the view.
import { el, svg } from '../dom.js';
import { clock, k1, tk } from '../format.js';
import { text, callUrl } from '../api.js';
import {
  BOT_H, BOT_W, CH, CW, SPX, TOP_W, TRACK_STEP, TRACK_X0, W, Y0,
  contextAt, lengthFor, placeCards, runningMarkers, spreadStations, tickTimes, timeScale,
} from '../geometry.js';
import { childrenOf, kindOfSource, typeOf } from '../views.js';
import { rendererFor } from './nodes/index.js';

const VIOLET = '#A594FF', BLUE = '#6EA8FF', WHITE = '#ECECEC', FIND = '#F0883E', NEUTRAL_EDGE = 'rgba(236,236,236,0.20)';
const TRIGGER = {
  session_start: 'at session start', path_match: 'loaded by a path match', agent: 'loaded by the agent',
  inherited: 'inherited from its parent', hook: 'a hook',
};

const abs = (cls, left, top, tag = 'div') => {
  const e = el(tag, cls);
  e.style.left = `${left}px`;
  e.style.top = `${top}px`;
  return e;
};

const hasIt = (focus, node) => !focus || focus.had_by.includes(node.id);

function banner(env, cur, kids) {
  const f = env.focus;
  const box = el('div', 'fbanner');
  if (!f) { box.hidden = true; return box; }
  box.append(el('b', null, f.name), ' ');
  if (!f.had_by.length) box.append('Never loaded by any agent in this session.');
  else {
    const n = kids.filter(c => f.had_by.includes(c.id)).length;
    const parts = [f.had_by.includes(cur.id) ? 'This agent had it' : 'This agent didn’t have it'];
    if (kids.length) parts.push(`${n} of ${kids.length} subagents here did`);
    if (f.tokens_est) parts.push(`${k1(f.tokens_est)} each`);
    box.append(parts.join(' · '));
  }
  if (env.state.pinned) {
    const clear = el('button', 'clear', 'Clear');
    clear.dataset.clear = '1';
    box.append(clear);
  }
  return box;
}

function spinePoints(cur, scale, cuts, series, isRoot, peak) {
  const times = [];
  for (let i = 0; i <= 60; i++) times.push(cur.start + (cur.end - cur.start) * i / 60);
  for (const c of cuts) times.push(c - 0.001, c);
  times.sort((a, b) => a - b);
  const half = t => Math.min(11, 1 + 10 * contextAt(series, cuts, t) / peak * (isRoot ? 1 : 2.4));
  const left = times.map(t => `${(SPX - half(t)).toFixed(1)},${scale.y(t).toFixed(1)}`);
  const right = times.map(t => `${(SPX + half(t)).toFixed(1)},${scale.y(t).toFixed(1)}`).reverse();
  return [...left, ...right].join(' ');
}

function ticks(cur, scale) {
  return tickTimes(cur).map(t => {
    const e = abs('tick', 0, scale.y(t) - 7);
    e.textContent = clock(t);
    return e;
  });
}

function breaks(scale) {
  return scale.marks.map(b => {
    const e = abs('brk', 0, b.y0);
    e.style.height = `${Math.max(6, b.y1 - b.y0)}px`;
    e.append(el('span', null, `no activity · ${Math.round((b.end - b.start) / 60)} min`));
    return e;
  });
}

function topNode(env, cur, focus) {
  const box = abs('card top' + (hasIt(focus, cur) ? '' : ' dim') + (focus && hasIt(focus, cur) ? ' ring' : ''), SPX - TOP_W / 2, 24);
  box.dataset.node = cur.id;
  box.style.width = `${TOP_W}px`;
  box.style.height = `${CH}px`;
  box.append(rendererFor(cur.kind).card(cur, { ...env, top: true }));
  return box;
}

function childCard(env, c, p, match, selected) {
  const focus = env.focus;
  const box = abs('card', p.left, p.top);
  box.dataset.node = c.id;
  box.dataset.kind = c.kind;
  box.tabIndex = 0;
  box.setAttribute('role', 'button');
  box.setAttribute('aria-label', `${c.kind} ${c.name}${c.descendants ? `, has ${c.descendants} nested` : ''}`);
  box.style.width = `${CW}px`;
  box.style.height = `${CH}px`;
  if (selected) box.classList.add('sel');
  if (c.descendants > 0) box.classList.add('stackcard');
  if (!match) box.classList.add('dim');
  if (focus && match) box.classList.add('ring');
  for (const [cls, y] of [['h1', 14], ['h2', CH - 22]]) {
    const h = el('i', 'hd ' + cls);
    h.style[p.side < 0 ? 'right' : 'left'] = '-4px';
    h.style.top = `${y}px`;
    box.append(h);
  }
  box.append(rendererFor(c.kind).card(c, { ...env, top: false }));
  return box;
}

function arches(env, kids, placedMap, scale, matchOf) {
  const g = svg('g', { class: 'arches' });
  const marks = svg('g', { class: 'marks' });
  const pills = [];
  for (const c of kids) {
    const p = placedMap.get(c.id);
    const edge = env.ix.edges.get(c.id);
    const on = env.state.sel === c.id;
    const match = matchOf(c);
    const outT = edge ? edge.out_t : c.start;
    const ys = scale.y(outT);
    const outcome = edge ? edge.outcome : null;
    const backT = edge && edge.back_t != null ? edge.back_t : outcome === 'running' || outcome === null ? null : c.end;
    const ye = backT == null ? null : scale.y(backT);
    const mx = (SPX + p.inner) / 2, ay = p.top + 18, by = p.top + CH - 18;
    const dim = match ? NEUTRAL_EDGE : 'rgba(236,236,236,0.05)';
    const down = edge ? edge.down : 0;
    const wOut = Math.min(3, (1.1 + down / 4500)) * (on ? 1.2 : 1);
    g.append(svg('path', {
      d: `M${SPX},${ys.toFixed(1)} C${mx.toFixed(1)},${ys.toFixed(1)} ${mx.toFixed(1)},${ay.toFixed(1)} ${p.inner.toFixed(1)},${ay.toFixed(1)}`,
      fill: 'none', 'data-node': c.id, stroke: on ? VIOLET : dim, 'stroke-width': wOut.toFixed(2), class: 'arch out' + (on ? ' flow' : ''),
    }));
    if (ye !== null) {
      const returned = outcome === 'returned';
      const wBack = Math.min(3, 0.9 + ((edge && edge.back) || 0) / 2600) * (on ? 1.2 : 1);
      const path = svg('path', {
        d: `M${p.inner.toFixed(1)},${by.toFixed(1)} C${mx.toFixed(1)},${by.toFixed(1)} ${mx.toFixed(1)},${ye.toFixed(1)} ${SPX},${ye.toFixed(1)}`,
        fill: 'none', 'data-node': c.id, stroke: returned ? (on ? BLUE : dim) : 'rgba(164,166,172,0.55)', 'stroke-width': returned ? wBack.toFixed(2) : 1,
        class: 'arch back' + (returned ? '' : ' dashed') + (on && returned ? ' flow' : ''),
      });
      g.append(path);
      marks.append(svg('circle', { cx: SPX, cy: ye.toFixed(1), r: on ? 4 : 2.5, fill: on && returned ? BLUE : '#8A8C92', opacity: on ? 1 : match ? 0.55 : 0.12 }));
    }
    marks.append(svg('circle', { cx: SPX, cy: ys.toFixed(1), r: on ? 4 : 2.5, fill: on ? VIOLET : '#8A8C92', opacity: on ? 1 : match ? 0.55 : 0.12 }));
    if (on) pills.push(...selectedPills(c, p, edge, ys, backT === null ? null : ye, outcome));
  }
  return { arches: g, marks, pills };
}

function selectedPills(c, p, edge, ys, ye, outcome) {
  const pill = (cls, label, y) => {
    const e = abs('pill-arch ' + cls + (p.side < 0 ? ' right' : ' left'), SPX, y);
    e.textContent = label;
    return e;
  };
  const out = [pill('down', `↓ ${tk(edge ? edge.down : null, true)} · ${clock(edge ? edge.out_t : c.start)}`, ys)];
  if (outcome === 'returned' && ye !== null) out.push(pill('up', `↑ ${tk(edge.back, true)} · ${clock(edge.back_t)}`, ye));
  return out;
}

function stationItems(env, cur, scale) {
  const { ix } = env;
  const st = ix.stations.get(cur.id);
  if (!st) return [];
  const shown = sid => { const k = kindOfSource(ix, sid); return !k || env.state.layers[k.key]; };
  const items = [];
  for (const l of st.loads) {
    if (!l.on_spine || !shown(l.source)) continue;
    const s = ix.sources.get(l.source);
    const k = kindOfSource(ix, l.source);
    items.push({
      type: 'load', source: l.source, y: scale.y(l.t ?? cur.start), small: l.small, letter: k ? k.letter : '?',
      tokens: l.tokens_est, find: !!(s && s.findings && s.findings.count > 0),
      title: `${k ? k.label : 'Source'} · ${s ? s.name : l.source} · ${l.tokens_est == null ? 'size unknown' : k1(l.tokens_est) + ' loaded'}` +
        ` · ${l.t == null ? 'time unknown, shown at the start' : 'at ' + clock(l.t)} · ${TRIGGER[l.trigger] || l.trigger}${l.event ? ' ' + l.event : ''}` +
        `${s && s.findings && s.findings.count ? ' · has findings' : ''}`,
      gap: l.small ? 12 : 22,
    });
  }
  for (const m of st.mcp) {
    if (!shown(m.server)) continue;
    const k = kindOfSource(ix, m.server);
    const s = ix.sources.get(m.server);
    const big = m.calls > 50;
    items.push({
      type: 'mcp', source: m.server, y: scale.y((m.first + m.last) / 2), letter: k ? k.letter : '?', calls: m.calls, big,
      tokens: m.back_tokens_est,
      title: `${s ? s.name : m.server} · ${m.calls} call${m.calls === 1 ? '' : 's'} ${clock(m.first)}–${clock(m.last)} · ${tk(m.back_tokens_est, true)} came back`,
      gap: 22,
    });
  }
  return items;
}

function stations(env, cur, scale) {
  const out = [];
  for (const it of spreadStations(stationItems(env, cur, scale))) {
    const hot = env.focus && env.focus.id === it.source;
    const dim = env.focus && !hot;
    const b = abs('station' + (it.type === 'mcp' ? ' mcp' : '') + (it.small && it.type === 'load' ? ' dot' : '') + (it.find ? ' find' : '') + (hot ? ' hot' : '') + (dim ? ' dim' : ''), SPX, it.drawY, 'button');
    b.dataset.source = it.source;
    b.dataset.station = it.type;
    b.title = it.title;
    if (!(it.small && it.type === 'load')) {
      const body = it.type === 'mcp' ? `⇄ ${it.calls}${it.big ? '' : ' · ' + tk(it.tokens, true)}` : `↓ ${tk(it.tokens, true)}`.trim();
      b.append(el('span', 'kl', it.letter), body);
    }
    out.push(b);
  }
  for (const c of (env.ix.stations.get(cur.id) || { compactions: [] }).compactions) {
    const m = abs('compact', 0, scale.y(c.t));
    const sizes = c.before != null && c.after != null ? ` · ${k1(c.before)} → ${k1(c.after)}` : '';
    m.append(el('span', null, `compacted${sizes}`));
    m.title = `context compacted at ${clock(c.t)}${c.trigger ? ' (' + c.trigger + ')' : ''}`;
    out.push(m);
  }
  return out;
}

function failureLabel(run) {
  const e = text(run.call_id, callUrl(run.call_id));
  const cmd = e.text ? e.text.split('\n')[0].slice(0, 44) : '';
  return `${cmd ? cmd + ' ' : ''}×${run.count} · failed every time${e.error ? ' (command text unavailable)' : ''}`;
}

function sideTrack(env, cur, scale, sel) {
  const { ix, focus } = env;
  const tr = ix.track.get(cur.id) || { calls: [], failure_runs: [], breaks: [] };
  const cols = ix.view.adapter.categories.filter(c => c.track);
  const colX = new Map(cols.map((c, i) => [c.key, TRACK_X0 + i * TRACK_STEP]));
  const out = [];
  const len = scale.end - Y0;
  cols.forEach(c => {
    const x = colX.get(c.key);
    const lab = abs('tlabel', x + 7, Y0 - 12);
    lab.textContent = c.label.toLowerCase();
    const line = abs('tline', x + 6, Y0);
    line.style.height = `${len}px`;
    out.push(lab, line);
  });
  if (sel) {
    const band = abs('selband', TRACK_X0 - 6, scale.y(sel.start));
    band.style.width = `${cols.length * TRACK_STEP + 10}px`;
    band.style.height = `${scale.y(sel.end) - scale.y(sel.start)}px`;
    out.push(band);
  }
  const inRun = c => tr.failure_runs.some(r => c.t >= r.first && c.t <= r.last) && c.failed;
  for (const c of tr.calls) {
    if (!colX.has(c.category)) continue;
    const hot = focus && c.source === focus.id;
    const t = abs('ctick' + (inRun(c) ? ' bad' : c.source ? ' src' : '') + (hot ? ' hot' : '') + (focus && !hot ? ' dim' : ''), colX.get(c.category) + 1, scale.y(c.t));
    t.title = `${clock(c.t)} · ${c.label}${c.failed ? ' · failed' : ''}`;
    out.push(t);
  }
  const runX = colX.get('run');
  if (runX !== undefined) {
    for (const r of tr.failure_runs) {
      const y0 = scale.y(r.first);
      const br = abs('bracket', runX - 5, y0);
      br.style.height = `${Math.max(6, scale.y(r.last) - y0)}px`;
      const lab = abs('blabel', TRACK_X0 + cols.length * TRACK_STEP + 8, y0 - 2);
      lab.dataset.call = r.call_id;
      lab.textContent = failureLabel(r);
      out.push(br, lab);
    }
  }
  return out;
}

export function render(box, env) {
  const { ix, state, focus } = env;
  const cur = ix.nodes.get(state.path[state.path.length - 1]);
  const isRoot = cur.parent === null;
  const kids = childrenOf(ix, cur);
  const tr = ix.track.get(cur.id) || { breaks: [] };
  const scale = timeScale(cur, tr.breaks, lengthFor(isRoot));
  const { placed, lowest } = placeCards(kids, scale.y);
  const placedMap = new Map(placed.map(p => [p.id, p]));
  const matchOf = c => (focus ? focus.had_by.includes(c.id) : state.type === 'all' || c.type === state.type);
  const station = ix.stations.get(cur.id) || { compactions: [] };
  const cuts = station.compactions.map(c => c.t);
  const sel = state.sel ? ix.nodes.get(state.sel) : null;
  const renderer = rendererFor(cur.kind);
  const hand = isRoot ? null : renderer.handback && renderer.handback(cur, env);
  const botY = Math.max(scale.end + 14, lowest + 10);
  const height = isRoot ? Math.max(scale.end + 40, lowest + 30) : botY + BOT_H + 40;

  const cv = el('div', 'cv');
  cv.style.width = `${W}px`;
  cv.style.height = `${height}px`;
  const s = svg('svg', { width: W, height, class: 'cvg' });
  s.append(svg('polygon', { points: spinePoints(cur, scale, cuts, cur.detail.series || [], isRoot, ix.peak), fill: typeOf(ix, cur).colour, 'fill-opacity': 0.1, class: 'band' }));
  s.append(svg('line', { x1: SPX, x2: SPX, y1: Y0, y2: scale.end, class: 'spine' }));
  const drawn = arches(env, kids, placedMap, scale, matchOf);
  s.append(drawn.arches, drawn.marks);
  cv.append(s, ...ticks(cur, scale), ...breaks(scale), ...sideTrack(env, cur, scale, sel), topNode(env, cur, focus));
  for (const c of kids) cv.append(childCard(env, c, placedMap.get(c.id), matchOf(c), state.sel === c.id));
  cv.append(...stations(env, cur, scale), ...drawn.pills);
  for (const m of runningMarkers(kids, scale.y)) {
    const e = abs('running', SPX - 22, m.y - 4);
    e.textContent = `+${m.more} running`;
    e.title = `${m.more} more subagents run at ${clock(m.t)} than the columns hold`;
    cv.append(e);
  }
  if (hand) {
    const b = abs('card bottom', SPX - BOT_W / 2, botY);
    b.style.width = `${BOT_W}px`;
    b.style.height = `${BOT_H}px`;
    b.textContent = hand;
    cv.append(b);
  }
  if (!kids.length) {
    const none = abs('nokids nk', SPX + 40, Y0 + 20);
    none.textContent = 'No subagents.';
    cv.append(none);
  }
  box.replaceChildren(banner(env, cur, kids), cv);
}
