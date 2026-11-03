// The canvas: the current agent's spine over time, its subagents as cards with arches, the stations on the spine and
// the side track of everyday calls. Card placement, scale, arches and ticks are geometry; every fact comes from the view.
import { el, svg } from '../dom.js';
import { clock, k1, range, tk } from '../format.js';
import { callText } from '../api.js';
import {
  BAND_OPACITY, BOT_H, BOT_W, CH, COLX, CW, GROUP_TILES, SH, SPINE_HALF_MAX, SPINE_HALF_MIN, SPX, STATION_EDGE, SW, TOP_W, TOP_Y, TRACK_STEP, TRACK_X0, W, Y0,
  bandColour, layoutTime, lengthFor, mergeStations, placeSources, replyAt, stationSide, tickMarks,
} from '../geometry.js';
import { groupOpen } from '../state.js';
import { childrenOf, kindOfSource, replyParts, typeOf } from '../views.js';
import { rendererFor } from './nodes/index.js';
import * as rail from './rail.js';
import { tile } from './nodes/agent.js';

const VIOLET = '#A594FF', BLUE = '#6EA8FF', WHITE = '#ECECEC', FIND = '#F0883E', NEUTRAL_EDGE = 'rgba(236,236,236,0.20)';

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
    if (f.agent_type) {
      const n = kids.filter(c => f.had_by.includes(c.id)).length;
      box.append(`${n} of ${kids.length} subagents here are ${f.label}${f.builtin ? ' (built in)' : ''}`);
    } else {
      const n = (cur.child_sources || {})[f.id] || 0;
      const parts = [f.had_by.includes(cur.id) ? 'This agent had it' : 'This agent didn’t have it'];
      if (kids.length) parts.push(`${n} of ${kids.length} subagents here did`);
      if (f.tokens_est) parts.push(`${tk(f.tokens_est, true)} each (estimated)`);
      box.append(parts.join(' · '));
    }
  }
  if (env.state.pinned) {
    const clear = el('button', 'clear', 'Clear');
    clear.dataset.clear = '1';
    box.append(clear);
  }
  return box;
}

// The spine: its outline follows the exact total of the replies (SPINE_HALF_MIN at zero up to SPINE_HALF_MAX at the agent's
// own peak) and the categories stack inside it, left to right in the adapter's order. A band's share of the width is its
// value over the reply's total; a negative remainder counts as 0, and when the estimates overshoot the total the shares are
// taken over their own sum so the bands never leave the spine. Each shape is sampled at the same times, so a band's points
// sit on the outline's.
function spineShapes(cur, scale, cuts, order) {
  const comp = cur.detail.composition;
  const rows = comp && comp.replies ? comp.replies : [];
  const peak = Math.max(1, ...rows.map(r => r[1]));
  const times = [];
  for (let i = 0; i <= 60; i++) times.push(cur.start + (cur.end - cur.start) * i / 60);
  for (const c of cuts) times.push(c - 0.001, c);
  for (const r of rows) if (r[0] >= cur.start && r[0] <= cur.end) times.push(r[0]);
  times.sort((a, b) => a - b);
  const samples = times.map(t => {
    const row = rows.length ? replyAt(rows, cuts, t) : null;
    const total = row ? row[1] : 0;
    const half = SPINE_HALF_MIN + (SPINE_HALF_MAX - SPINE_HALF_MIN) * total / peak;
    const parts = row ? replyParts(comp, row).map(v => Math.max(0, v)) : [];
    const denom = Math.max(1e-9, total, parts.reduce((a, b) => a + b, 0));
    return { y: scale.y(t), half, parts, denom };
  });
  const outline = ptsOf(samples, () => 0, () => 1);
  const bands = [];
  for (const c of order) {
    const i = comp ? comp.keys.indexOf(c.key) : -1;
    if (i < 0) continue;
    const before = sm => sm.parts.slice(0, i).reduce((a, b) => a + b, 0) / sm.denom;
    bands.push({ key: c.key, index: i, points: ptsOf(samples, before, sm => before(sm) + (sm.parts[i] || 0) / sm.denom) });
  }
  return { outline, bands };
}

// The polygon between two fractions of the spine's width at every sample, down the left edge and back up the right.
function ptsOf(samples, from, to) {
  const x = (sm, f) => (SPX - sm.half + 2 * sm.half * f).toFixed(1);
  const left = samples.map(sm => `${x(sm, from(sm))},${sm.y.toFixed(1)}`);
  const right = samples.map(sm => `${x(sm, to(sm))},${sm.y.toFixed(1)}`).reverse();
  return [...left, ...right].join(' ');
}

function ticks(cur, scale) {
  return tickMarks(cur, scale.y).map(m => {
    const e = abs('tick', 0, m.y - 7);
    e.textContent = clock(m.t);
    return e;
  });
}

// A 2 px bar beside the time labels wherever the scale was stretched, and the one-line note saying so.
function stretches(scale) {
  const link = abs('callslink', 0, 24, 'button');
  link.dataset.tab = 'calls';
  link.textContent = 'open in Tool calls →';
  if (!scale.stretches.length) return [link];
  const out = scale.stretches.map(s => {
    const e = abs('stretch', 40, s.y0);
    e.style.height = `${s.y1 - s.y0}px`;
    e.title = `Scale stretched ${s.factor.toFixed(1)}× between ${clock(s.t0)} and ${clock(s.t1)}`;
    return e;
  });
  const note = abs('scalenote mono', 0, 6);
  note.textContent = '▍ time scale stretched where agents fan out';
  return [...out, note, link];
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
  const box = abs('card top' + (hasIt(focus, cur) ? '' : ' dim') + (focus && hasIt(focus, cur) ? ' ring' : ''), SPX - TOP_W / 2, TOP_Y);
  box.dataset.node = cur.id;
  box.title = cur.name;
  box.style.width = `${TOP_W}px`;
  box.style.height = `${CH}px`;
  box.append(rendererFor(cur.kind).card(cur, { ...env, top: true }));
  return box;
}

function childCard(env, c, p, match, selected) {
  const focus = env.focus;
  const box = abs('card', p.left, p.top);
  box.dataset.node = c.id;
  box.title = c.name;
  if (p.launchY !== undefined) box.dataset.launchY = p.launchY.toFixed(1);
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
    h.style.left = '-4px';
    h.style.top = `${y}px`;
    box.append(h);
  }
  box.append(rendererFor(c.kind).card(c, { ...env, top: false }));
  return box;
}

// The y the child's way back lands on the spine, or null while it has not come back.
function backY(c, edge, scale) {
  const outcome = edge ? edge.outcome : null;
  const backT = edge && edge.back_t != null ? edge.back_t : outcome === 'running' || outcome === null ? null : c.end;
  return backT == null ? null : scale.y(backT);
}

// A collapsed group: one thick edge out at the first launch, one thin edge back from the card per member.
function groupEdges(env, grp, p, scale, matchOf, g, marks) {
  const match = grp.members.some(matchOf);
  const dim = match ? NEUTRAL_EDGE : 'rgba(236,236,236,0.05)';
  const ys = p.launchY;
  const mx = (SPX + p.inner) / 2, ay = p.top + 18, by = p.top + CH - 18;
  const w = Math.min(3, 1.1 + (grp.burst.down_tokens || 0) / 4500);
  g.append(svg('path', {
    d: `M${SPX},${ys.toFixed(1)} C${mx.toFixed(1)},${ys.toFixed(1)} ${mx.toFixed(1)},${ay.toFixed(1)} ${p.inner.toFixed(1)},${ay.toFixed(1)}`,
    fill: 'none', 'data-group': grp.key, stroke: match ? VIOLET : dim, 'stroke-width': w.toFixed(2), class: 'arch out',
  }));
  marks.append(svg('circle', { cx: SPX, cy: ys.toFixed(1), r: 2.5, fill: VIOLET, opacity: match ? 0.8 : 0.2 }));
  for (const c of grp.members) {
    const ye = backY(c, env.ix.edges.get(c.id), scale);
    if (ye === null) continue;
    g.append(svg('path', {
      d: `M${p.inner.toFixed(1)},${by.toFixed(1)} C${mx.toFixed(1)},${by.toFixed(1)} ${mx.toFixed(1)},${ye.toFixed(1)} ${SPX},${ye.toFixed(1)}`,
      fill: 'none', 'data-group': grp.key, stroke: dim, 'stroke-width': 0.9, class: 'arch back group-back',
    }));
    marks.append(svg('circle', { cx: SPX, cy: ye.toFixed(1), r: 2.5, fill: '#8A8C92', opacity: match ? 0.6 : 0.15 }));
  }
}

function groupCard(env, grp, p, match) {
  const picked = grp.members.find(m => m.id === env.state.sel);
  const box = abs('card group' + (match || picked ? '' : ' dim') + (env.focus && match ? ' ring' : '') + (picked ? ' picked' : ''), p.left, p.top, 'button');
  box.dataset.group = grp.key;
  box.dataset.launchY = p.launchY.toFixed(1);
  box.setAttribute('aria-expanded', 'false');
  box.setAttribute('aria-label', `${grp.members.length} subagents launched in parallel, ${range(grp.burst.first_launch, grp.burst.last_return)}. Expand to see them.`);
  box.style.width = `${CW}px`;
  box.style.height = `${CH}px`;
  const head = el('span', 'gh');
  head.append(el('span', 'gn mono', `⇉ ${grp.members.length}`), el('b', 'nm', picked ? `● ${picked.name}` : 'in parallel'));
  const tiles = el('span', 'gt');
  const shown = grp.members.length > GROUP_TILES ? GROUP_TILES - 1 : grp.members.length;
  for (const m of grp.members.slice(0, shown)) tiles.append(tile(env.ix, m, 16));
  if (shown < grp.members.length) tiles.append(el('span', 'gm mono', `+${grp.members.length - shown}`));
  const when = el('span', 'gs');
  when.append(el('span', 'sub mono', range(grp.burst.first_launch, grp.burst.last_return)), el('span', 'gx', 'expand ›'));
  box.append(head, when, tiles);
  return box;
}

// The dashed box and header of an expanded group.
function groupBox(grp, p) {
  const box = abs('gbox', p.box.left, p.box.top);
  box.style.width = `${p.box.width}px`;
  box.style.height = `${p.box.height}px`;
  const head = abs('ghead', COLX.R1, p.box.top + 4);
  const label = el('span', 'mono', `⇉ fan-out · ${grp.members.length} subagents in parallel · ${range(grp.burst.first_launch, grp.burst.last_return)}`);
  const btn = el('button', 'gcollapse', 'collapse');
  btn.dataset.group = grp.key;
  btn.setAttribute('aria-expanded', 'true');
  head.append(label, btn);
  return [box, head];
}

function arches(env, kids, placedMap, scale, matchOf, groups) {
  const g = svg('g', { class: 'arches' });
  const marks = svg('g', { class: 'marks' });
  const pills = [];
  for (const c of kids) {
    const p = placedMap.get(c.id);
    const edge = env.ix.edges.get(c.id);
    const on = env.state.sel === c.id;
    const match = matchOf(c);
    const outT = edge ? edge.out_t : c.start;
    const ys = p.launchY !== undefined ? p.launchY : scale.y(outT);
    const outcome = edge ? edge.outcome : null;
    const ye = backY(c, edge, scale);
    const backT = ye;
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
    if (on) pills.push(...selectedPills(c, p, edge, ys, ye, outcome));
  }
  for (const grp of groups) if (!grp.expanded) groupEdges(env, grp, placedMap.get(grp.key), scale, matchOf, g, marks);
  return { arches: g, marks, pills };
}

function selectedPills(c, p, edge, ys, ye, outcome) {
  const pill = (cls, label, y) => {
    const e = abs('pill-arch ' + cls + ' left', SPX, y);
    e.textContent = label;
    return e;
  };
  const out = [pill('down', `↓ ${tk(edge ? edge.down : null, true)} · ${clock(edge ? edge.out_t : c.start)}`, ys)];
  if (outcome === 'returned' && ye !== null) out.push(pill('up', `↑ ${tk(edge.back, true)} · ${clock(edge.back_t)}`, ye));
  return out;
}

const shownSource = (env, sid) => { const k = kindOfSource(env.ix, sid); return !k || env.state.layers[k.key]; };

// Hooks stay on the spine: a one-off hook load is a station and a repeated stretch of firings is one pill at its middle.
function stationItems(env, cur, scale) {
  const { ix } = env;
  const st = ix.stations.get(cur.id);
  if (!st) return [];
  const items = [];
  for (const l of st.loads) {
    if (l.event == null || !shownSource(env, l.source)) continue;
    const s = ix.sources.get(l.source);
    const k = kindOfSource(ix, l.source);
    items.push({
      type: 'load', source: l.source, name: s ? s.label : l.source, when: ix.triggers.get(l.trigger) || l.trigger, y: scale.y(l.t ?? cur.start), small: l.small, letter: k ? k.letter : '?',
      tokens: l.tokens_est, find: !!(s && s.findings && s.findings.count > 0),
      title: `${k ? k.label : 'Source'} · ${s ? s.label : l.source} · ${l.tokens_est == null ? 'size unknown' : tk(l.tokens_est, true) + ' loaded (estimated)'}` +
        ` · ${l.t == null ? 'time unknown, shown at the start' : 'at ' + clock(l.t)} · ${ix.triggers.get(l.trigger) || l.trigger}${l.event ? ' ' + l.event : ''}` +
        `${s && s.findings && s.findings.count ? ' · has findings' : ''}`,
    });
  }
  for (const h of st.hooks || []) {
    if (!shownSource(env, h.source)) continue;
    const k = kindOfSource(ix, h.source);
    const s = ix.sources.get(h.source);
    items.push({
      type: 'hook', source: h.source, y: scale.y((h.first + h.last) / 2), letter: k ? k.letter : '?', calls: h.count, tokens: h.tokens_est,
      name: s ? s.label : h.source,
      title: `${s ? s.label : h.source} · ${h.count} firing${h.count === 1 ? '' : 's'} ${clock(h.first)}–${clock(h.last)} · ${tk(h.tokens_est, true)} loaded (estimated)`,
    });
  }
  return items;
}

// Source nodes: one per source at its first load into this agent's context (hooks stay on the spine), one per MCP server
// with its round trips. An instruction file loaded with no time sits at the agent's start.
function sourceItems(env, cur, scale) {
  const { ix } = env;
  const st = ix.stations.get(cur.id);
  if (!st) return [];
  const first = new Map();
  for (const l of st.loads) {
    if (l.event != null || !shownSource(env, l.source)) continue;
    const t = l.t ?? cur.start;
    const prev = first.get(l.source);
    if (!prev || t < prev.t) first.set(l.source, { t, load: l });
  }
  const trips = new Map();
  for (const m of st.mcp) {
    if (!shownSource(env, m.server)) continue;
    trips.set(m.server, [...(trips.get(m.server) || []), m]);
    const prev = first.get(m.server);
    if (!prev) first.set(m.server, { t: m.first, load: null });
  }
  return [...first.entries()].map(([id, f]) => {
    const s = ix.sources.get(id);
    const k = kindOfSource(ix, id);
    const clusters = trips.get(id) || [];
    const calls = clusters.reduce((n, m) => n + m.calls, 0);
    const tokens = f.load ? f.load.tokens_est : null;
    const find = !!(s && s.findings && s.findings.count > 0);
    const label = s ? s.label : id;
    return {
      source: id, label, letter: k ? k.letter : '?', t: f.t, y: scale.y(f.t), tokens, find, clusters, calls,
      sub: calls ? `⇄ ${calls} call${calls === 1 ? '' : 's'}` : `↓ ${tokens == null ? 'size unknown' : tk(tokens, true)} · ${clock(f.t)}`,
      title: `${k ? k.label : 'Source'} · ${label} · ${tokens == null ? 'size unknown' : tk(tokens, true) + ' loaded (estimated)'} · ${f.load && f.load.t == null ? 'time unknown, shown at the start' : 'at ' + clock(f.t)}${f.load ? ' · ' + (ix.triggers.get(f.load.trigger) || f.load.trigger) : ''}` +
        `${calls ? ` · ${calls} call${calls === 1 ? '' : 's'}` : ''}${find ? ' · has findings' : ''}`,
    };
  }).sort((a, b) => a.y - b.y);
}

function sourceNode(env, it, p) {
  const hot = env.focus && env.focus.id === it.source;
  const dim = env.focus && !hot;
  const b = abs('snode' + (it.find ? ' find' : '') + (hot ? ' hot' : '') + (dim ? ' dim' : ''), p.left, p.top, 'button');
  b.dataset.source = it.source;
  b.title = it.title;
  b.setAttribute('aria-label', it.title);
  b.style.width = `${SW}px`;
  b.style.height = `${SH}px`;
  const text = el('span', 'sx');
  text.append(el('b', 'sn', it.label), el('span', 'ss mono', it.sub));
  b.append(el('span', 'kl', it.letter), text);
  return b;
}

// One group for every source node's edges: the edge into the spine ending in an arrowhead at the load time, and a round
// trip to every cluster of an MCP server's calls.
function sourceEdges(env, items, placed, scale) {
  const g = svg('g', { class: 'srcedges' });
  for (const it of items) {
    const p = placed.get(it.source);
    const hot = env.focus && env.focus.id === it.source;
    const dim = env.focus && !hot;
    const colour = hot ? WHITE : dim ? 'rgba(236,236,236,0.05)' : it.find ? 'rgba(242,166,110,0.55)' : 'rgba(236,236,236,0.28)';
    const ny = p.top + SH / 2, mx = (p.inner + SPX) / 2;
    g.append(svg('path', {
      d: `M${p.inner.toFixed(1)},${ny.toFixed(1)} C${mx.toFixed(1)},${ny.toFixed(1)} ${mx.toFixed(1)},${it.y.toFixed(1)} ${SPX - 6},${it.y.toFixed(1)}`,
      fill: 'none', stroke: colour, 'stroke-width': (1 + Math.min(2.4, (it.tokens || 400) / 2500)).toFixed(2), class: 'srcedge', 'data-source': it.source,
    }));
    g.append(svg('path', { d: `M${SPX - 7},${(it.y - 3.5).toFixed(1)} L${SPX - 1},${it.y.toFixed(1)} L${SPX - 7},${(it.y + 3.5).toFixed(1)} Z`, fill: colour, class: 'srcarrow', 'data-source': it.source }));
    for (const m of it.clusters) {
      const yt = scale.y((m.first + m.last) / 2);
      g.append(svg('path', {
        d: `M${p.inner.toFixed(1)},${(ny + 6).toFixed(1)} C${mx.toFixed(1)},${(ny + 6).toFixed(1)} ${mx.toFixed(1)},${yt.toFixed(1)} ${SPX},${yt.toFixed(1)}`,
        fill: 'none', stroke: hot ? WHITE : dim ? 'rgba(236,236,236,0.04)' : 'rgba(180,156,255,0.4)', 'stroke-width': (0.8 + Math.min(2, m.calls / 6)).toFixed(2), class: 'srctrip', 'data-source': it.source,
      }));
      g.append(svg('circle', { cx: SPX, cy: yt.toFixed(1), r: 3, fill: '#0D0E10', stroke: '#B49CFF', 'stroke-width': 1.5, opacity: dim ? 0.2 : 0.9, class: 'tripmark' }));
    }
  }
  return g;
}

// One pill for a lone station; for a run of stations that fall within MERGE_GAP, one button naming how many, whose tooltip
// lists each member and whose click and hover focus the first.
function stationPill(env, cl) {
  const [it] = cl.members;
  const many = cl.members.length > 1;
  const hot = env.focus && cl.members.some(m => m.source === env.focus.id);
  const dim = env.focus && !hot;
  const lone = !many && it.small && it.type === 'load';
  const cls = 'station' + (many ? ' merged' : it.type === 'hook' ? ' hook' : '') + (lone ? ' dot' : '')
    + (cl.members.some(m => m.find) ? ' find' : '') + (hot ? ' hot' : '') + (dim ? ' dim' : '');
  const b = abs(cls, SPX, cl.y, 'button');
  b.dataset.source = it.source;
  b.dataset.sources = cl.members.map(m => m.source).join(' ');
  b.dataset.station = many ? 'merged' : it.type;
  if (many) {
    const word = cl.members.every(m => m.type === 'load') ? 'hook loads' : 'stations';
    const label = `${cl.members.length} ${word}`;
    b.title = cl.members.map(m => [m.name, m.tokens == null ? 'size unknown' : tk(m.tokens, true), m.when].filter(Boolean).join(' · ')).join('\n');
    b.setAttribute('aria-label', `${label}: ${cl.members.map(m => m.name).join(', ')}`);
    b.append(label);
    return b;
  }
  b.title = it.title;
  if (!lone) {
    const body = it.type === 'hook' ? `↓×${it.calls}` : `↓ ${tk(it.tokens, true)}`.trim();
    b.append(el('span', 'kl', it.letter), body);
  }
  return b;
}

function stations(env, cur, scale) {
  const out = mergeStations(stationItems(env, cur, scale)).map(cl => stationPill(env, cl));
  for (const c of (env.ix.stations.get(cur.id) || { compactions: [] }).compactions) {
    const m = abs('compact', 0, scale.y(c.t));
    const sizes = c.before != null && c.after != null ? ` · ${k1(c.before)} → ${k1(c.after)}` : '';
    m.append(el('span', null, `compacted${sizes}`));
    m.title = `context compacted at ${clock(c.t)}${c.trigger ? ' (' + c.trigger + ')' : ''}`;
    out.push(m);
  }
  return out;
}

// Places each drawn station pill by `stationSide` among the cards, once the page has measured its width.
function settleStations(cv, rects) {
  for (const e of cv.querySelectorAll('.station')) {
    const where = stationSide(parseFloat(e.style.top), e.offsetWidth, rects);
    if (where === 'right') { e.style.left = `${SPX + STATION_EDGE}px`; e.classList.add('side-r'); }
    else if (where === 'left') { e.style.left = `${SPX - STATION_EDGE}px`; e.classList.add('side-l'); }
    else if (where === 'dot') {
      if (!e.getAttribute('aria-label')) e.setAttribute('aria-label', e.title);
      e.replaceChildren();
      e.classList.add('dot', 'squeezed');
    }
  }
}

function failureLabel(run) {
  const e = callText(run.call_id);
  const cmd = e.text ? e.text.split('\n')[0].slice(0, 44) : '';
  return `${cmd ? cmd + ' ' : ''}×${run.count} · failed every time${e.error ? ' (command text unavailable)' : ''}`;
}

const TICK_W = 11;

// The side track: per tracked category a label, a faint line and ONE path holding every tick; the ticks that belong to a
// failure run, to a source or to the focused source are drawn once more in their own path so they stand out.
function sideTrack(env, cur, scale, sel, height) {
  const { ix, focus } = env;
  const tr = ix.track.get(cur.id) || { calls: [], failure_runs: [], breaks: [] };
  const cols = ix.view.adapter.categories.filter(c => c.track);
  const colX = new Map(cols.map((c, i) => [c.key, TRACK_X0 + i * TRACK_STEP]));
  const out = [];
  const len = scale.end - Y0;
  const ticks = svg('svg', { width: TRACK_X0 + cols.length * TRACK_STEP + 4, height, class: 'trackg' });
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
  const inRun = c => c.failed && tr.failure_runs.some(r => c.t >= r.first && c.t <= r.last);
  const groups = new Map(cols.map(c => [c.key, { all: [], bad: [], src: [], hot: [] }]));
  for (const c of tr.calls) {
    const g = groups.get(c.category);
    if (!g) continue;
    const seg = `M${colX.get(c.category) + 1},${scale.y(c.t).toFixed(1)}h${TICK_W}`;
    g.all.push(seg);
    if (focus && c.source === focus.id) g.hot.push(seg);
    else if (inRun(c)) g.bad.push(seg);
    else if (c.source) g.src.push(seg);
  }
  for (const c of cols) {
    const g = groups.get(c.key);
    const add = (cls, list, stroke, extra = {}) => {
      if (list.length) ticks.append(svg('path', { d: list.join(''), stroke, 'stroke-width': 1.5, fill: 'none', class: cls, 'data-category': c.key, ...extra }));
    };
    add('tpath', g.all, c.colour || '#6E7076', { opacity: focus ? 0.35 : 0.8 });
    add('tmark src', g.src, '#A9C2FF');
    add('tmark bad', g.bad, FIND);
    add('tmark hot', g.hot, WHITE);
  }
  out.push(ticks);
  for (const r of tr.failure_runs) {
    const first = tr.calls.find(c => c.use_id === r.call_id) || tr.calls.find(c => c.failed && c.t >= r.first && c.t <= r.last);
    const runX = first ? colX.get(first.category) : undefined;
    if (runX === undefined) continue;
    const y0 = scale.y(r.first);
    const br = abs('bracket', runX - 5, y0);
    br.style.height = `${Math.max(6, scale.y(r.last) - y0)}px`;
    const lab = abs('blabel', TRACK_X0 + cols.length * TRACK_STEP + 8, y0 - 2);
    lab.dataset.call = r.call_id;
    lab.textContent = failureLabel(r);
    out.push(br, lab);
  }
  return out;
}

// The node's fan-out groups: its bursts with the members that are on this canvas, collapsed unless a member is selected
// or the user opened the group.
function groupsOf(cur, kids, state) {
  const byId = new Map(kids.map(c => [c.id, c]));
  const out = [];
  for (const burst of cur.bursts || []) {
    const members = burst.members.map(id => byId.get(id)).filter(Boolean).sort((a, b) => a.start - b.start);
    if (members.length < 2) continue;
    const key = `${cur.id}:${members[0].id}`;
    out.push({ key, burst, members, expanded: groupOpen(state, key, members.map(m => m.id)) });
  }
  return out;
}

// Whether subagents are drawn: the source kind whose vocabulary entry holds definitions is the one the eye hides them with.
function agentsShown(ix, state) {
  const k = ix.view.adapter.source_kinds.find(x => x.definitions);
  return !k || state.layers[k.key] !== false;
}

// Landmarks for the jump rail, each with an anchor on the canvas.
function railMarks(cur, tr, scale, groups, placedMap, sel, shownAgents) {
  const marks = [];
  for (const r of tr.failure_runs) marks.push({ y: scale.y(r.first), kind: 'fail', label: `Repeated failure · ${r.count} times at ${clock(r.first)}` });
  if (shownAgents) {
    for (const g of groups) {
      const p = placedMap.get(g.key);
      marks.push({ y: g.expanded ? p.box.top : p.top, kind: 'fan', label: `Fan-out · ${g.members.length} subagents at ${clock(g.burst.first_launch)}` });
    }
    const p = sel && placedMap.get(sel.id);
    if (p) marks.push({ y: p.top, kind: 'sel', label: `Selected · ${sel.name}` });
  }
  marks.push({ y: scale.end, kind: 'end', label: `End of ${cur.name}` });
  return marks.map((m, i) => ({ ...m, id: `xr-j-${i}` }));
}

export function render(box, env) {
  const { ix, state, focus } = env;
  const cur = ix.nodes.get(state.path[state.path.length - 1]);
  const isRoot = cur.parent === null;
  const kids = childrenOf(ix, cur);
  const shownAgents = agentsShown(ix, state);
  const tr = ix.track.get(cur.id) || { calls: [], failure_runs: [], breaks: [] };
  const groups = shownAgents ? groupsOf(cur, kids, state) : [];
  const drawnKids = shownAgents ? kids : [];
  const inGroup = new Set(groups.flatMap(g => g.members.map(m => m.id)));
  const units = [
    ...drawnKids.filter(c => !inGroup.has(c.id)).map(c => ({ key: c.id, t: c.start, members: 0, expanded: false })),
    ...groups.map(g => ({ key: g.key, t: g.burst.first_launch, members: g.members.length, expanded: g.expanded })),
  ];
  const scale = layoutTime(cur, tr.breaks, lengthFor(isRoot), units);
  const placedMap = new Map();
  for (const p of scale.placed) {
    const grp = groups.find(g => g.key === p.key);
    if (grp && grp.expanded) grp.members.forEach((m, i) => placedMap.set(m.id, p.slots[i]));
    placedMap.set(p.key, p);
  }
  const shownKids = drawnKids.filter(c => !groups.some(g => !g.expanded && g.members.includes(c)));
  const matchOf = c => (!focus || focus.had_by.includes(c.id));
  const station = ix.stations.get(cur.id) || { compactions: [] };
  const cuts = station.compactions.map(c => c.t);
  const sel = state.sel ? ix.nodes.get(state.sel) : null;
  const renderer = rendererFor(cur.kind);
  const hand = isRoot ? null : renderer.handback && renderer.handback(cur, env);
  const items = sourceItems(env, cur, scale);
  const placedSources = new Map(placeSources(items.map(it => ({ key: it.source, y: it.y }))).map(p => [p.key, p]));
  const sourcesBottom = Math.max(0, ...[...placedSources.values()].map(p => p.top + SH));
  const botY = Math.max(scale.end + 14, scale.lowest + 10);
  const height = Math.max(isRoot ? Math.max(scale.end + 40, scale.lowest + 30) : botY + BOT_H + 40, sourcesBottom + 30);

  const cv = el('div', 'cv');
  cv.style.width = `${W}px`;
  cv.style.height = `${height}px`;
  const s = svg('svg', { width: W, height, class: 'cvg' });
  const shapes = spineShapes(cur, scale, cuts, ix.view.adapter.composition || []);
  s.append(svg('polygon', { points: shapes.outline, fill: typeOf(ix, cur).colour, 'fill-opacity': 0.1, class: 'band' }));
  for (const b of shapes.bands) s.append(svg('polygon', { points: b.points, fill: bandColour(b.index), 'fill-opacity': BAND_OPACITY, class: 'cband', 'data-category': b.key }));
  s.append(svg('line', { x1: SPX, x2: SPX, y1: Y0, y2: scale.end, class: 'spine' }));
  const drawn = arches(env, shownKids, placedMap, scale, matchOf, groups);
  s.append(sourceEdges(env, items, placedSources, scale), drawn.arches, drawn.marks);
  cv.append(s, ...ticks(cur, scale), ...stretches(scale), ...breaks(scale), ...sideTrack(env, cur, scale, sel, height), topNode(env, cur, focus));
  for (const grp of groups) {
    const p = placedMap.get(grp.key);
    if (grp.expanded) cv.append(...groupBox(grp, p));
    else cv.append(groupCard(env, grp, p, grp.members.some(matchOf)));
  }
  for (const c of shownKids) cv.append(childCard(env, c, placedMap.get(c.id), matchOf(c), state.sel === c.id));
  for (const it of items) cv.append(sourceNode(env, it, placedSources.get(it.source)));
  cv.append(...stations(env, cur, scale), ...drawn.pills);
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
  const marks = railMarks(cur, tr, scale, groups, placedMap, sel, shownAgents);
  for (const m of marks) {
    const a = abs('jump-anchor', 0, m.y);
    a.id = m.id;
    cv.append(a);
  }
  box.replaceChildren(banner(env, cur, kids), cv);
  const rects = [{ left: SPX - TOP_W / 2, top: TOP_Y, width: TOP_W, height: CH }];
  for (const p of placedMap.values()) {
    for (const q of p.slots || [p]) if (q.left !== undefined && q.side !== undefined) rects.push({ left: q.left, top: q.top, width: CW, height: CH });
  }
  for (const p of placedSources.values()) rects.push({ left: p.left, top: p.top, width: SW, height: SH });
  if (hand) rects.push({ left: SPX - BOT_W / 2, top: botY, width: BOT_W, height: BOT_H });
  settleStations(cv, rects);
  const railBox = document.getElementById('rail');
  if (railBox) rail.render(railBox, { height, ys: tr.calls.map(c => scale.y(c.t)), marks });
}
