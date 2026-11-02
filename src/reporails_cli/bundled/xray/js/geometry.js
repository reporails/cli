// Canvas geometry: where times, cards, ticks and breaks sit. Pure functions of the view's numbers.
export const W = 780, SPX = 466, Y0 = 108, CW = 132, CH = 76, TOP_W = 148, BOT_W = 180, BOT_H = 48;
export const COLX = { L1: SPX - 26 - CW, L2: SPX - 26 - CW - 8 - CW, R1: SPX + 26, R2: SPX + 26 + CW + 8 };
export const TRACK_X0 = 52, TRACK_STEP = 15;
const CAP_S = 6 * 3600, GAP_PX = 28, LANE_GAP = 8;

// Pixels the root's whole duration spans on the unstretched scale, and a subagent's.
export const BASE_PX_ROOT = 1100, BASE_PX_SUB = 900;
export const lengthFor = isRoot => (isRoot ? BASE_PX_ROOT : BASE_PX_SUB);
// A segment drawn longer than this many times its unstretched length is marked; ticks keep this many pixels apart.
export const STRETCH_MARK = 1.6, TICK_GAP = 18;
// Space an expanded fan-out group keeps above its first row of members for its header, and around its box.
export const GROUP_HEAD = 30, GROUP_PAD = 8;
const CARD_RISE = 18, KNOT_STEP_S = 0.5, ROW_ORDER = ['L1', 'R1', 'L2', 'R2'];

// Time to y before any stretching. Idle breaks keep their linear length until the node is longer than the cap, then each
// shrinks to a fixed gap so the active stretches keep their scale.
function baseScale(node, breaks, len) {
  const span = Math.max(1, node.end - node.start);
  const inside = breaks
    .map(b => ({ start: Math.max(b.start, node.start), end: Math.min(b.end, node.end) }))
    .filter(b => b.end > b.start);
  const squeeze = span > CAP_S && inside.length > 0;
  const idle = squeeze ? inside.reduce((s, b) => s + (b.end - b.start), 0) : 0;
  const perSec = (len - (squeeze ? inside.length * GAP_PX : 0)) / Math.max(1, span - idle);
  const segs = [];
  let t = node.start, y = Y0;
  for (const b of squeeze ? inside : []) {
    segs.push({ t0: t, t1: b.start, y0: y, k: perSec });
    y += (b.start - t) * perSec;
    segs.push({ t0: b.start, t1: b.end, y0: y, k: GAP_PX / (b.end - b.start) });
    y += GAP_PX;
    t = b.end;
  }
  segs.push({ t0: t, t1: node.end, y0: y, k: squeeze ? perSec : len / span });
  const at = tt => {
    const c = Math.min(node.end, Math.max(node.start, tt));
    const s = segs.find(g => c <= g.t1) || segs[segs.length - 1];
    return s.y0 + (c - s.t0) * s.k;
  };
  const marks = inside.map(b => ({ start: b.start, end: b.end, squeezed: squeeze }));
  return { y: at, marks };
}

const cardSlot = (col, top) => {
  const side = col[0] === 'L' ? -1 : 1;
  const left = COLX[col];
  return { col, top, left, side, inner: side < 0 ? left + CW : left };
};

// The one time mapping of a node's canvas, and where its cards sit on it.
// `units` are the single child cards and the fan-out groups: { key, t, members, expanded } (members is the member count of
// a group, 0 for a single card). A unit's card top sits CARD_RISE above the y of its launch. When no column has room, that
// launch time is moved down to the earliest free slot; a knot (time, y) is recorded for every unit, so a card already
// placed never moves when a later one stretches the scale.
// Returns y(t), the y of the node's end, the idle breaks, the stretched segments, the placement of every unit and the
// lowest card bottom.
export function layoutTime(node, breaks, len, units) {
  const base = baseScale(node, breaks, len);
  const knots = [{ t: node.start, d: 0 }];
  const delta = t => {
    const last = knots[knots.length - 1];
    if (t >= last.t) return last.d;
    let i = 1;
    while (knots[i].t < t) i++;
    const a = knots[i - 1], b = knots[i];
    return a.d + (b.d - a.d) * (t - a.t) / (b.t - a.t);
  };
  const y = t => { const c = Math.min(node.end, Math.max(node.start, t)); return base.y(c) + delta(c); };
  const bottoms = { L1: -Infinity, R1: -Infinity, L2: -Infinity, R2: -Infinity };
  const placed = [];
  let lowest = 0;
  [...units].sort((a, b) => a.t - b.t).forEach((u, idx) => {
    const te = Math.max(u.t, knots[knots.length - 1].t + KNOT_STEP_S);
    let top = y(te) - CARD_RISE;
    const pref = idx % 2 === 0 ? ['R1', 'L1', 'R2', 'L2'] : ['L1', 'R1', 'L2', 'R2'];
    let col = null;
    if (u.expanded) {
      top = Math.max(top, Math.max(...Object.values(bottoms)) + LANE_GAP + GROUP_HEAD);
    } else {
      col = pref.find(c => bottoms[c] + LANE_GAP <= top);
      if (!col) {
        col = [...pref].sort((a, b) => bottoms[a] - bottoms[b])[0];
        top = bottoms[col] + LANE_GAP;
      }
    }
    knots.push({ t: te, d: top + CARD_RISE - base.y(te) });
    const unit = { key: u.key, top, launchY: top + CARD_RISE, launchT: te };
    if (u.expanded) {
      const rows = Math.ceil(u.members / ROW_ORDER.length);
      unit.slots = Array.from({ length: u.members }, (_, i) => cardSlot(ROW_ORDER[i % ROW_ORDER.length], top + Math.floor(i / ROW_ORDER.length) * (CH + LANE_GAP)));
      const bottom = top + rows * (CH + LANE_GAP) - LANE_GAP + GROUP_PAD;
      unit.box = { left: COLX.L2 - GROUP_PAD, top: top - GROUP_HEAD, width: COLX.R2 + CW - COLX.L2 + 2 * GROUP_PAD, height: bottom - top + GROUP_HEAD };
      for (const c of ROW_ORDER) bottoms[c] = bottom;
      lowest = Math.max(lowest, bottom);
    } else {
      Object.assign(unit, cardSlot(col, top));
      bottoms[col] = top + CH;
      lowest = Math.max(lowest, top + CH);
    }
    placed.push(unit);
  });
  const stretches = [];
  for (let i = 1; i < knots.length; i++) {
    const a = knots[i - 1], b = knots[i];
    const plain = base.y(b.t) - base.y(a.t);
    const factor = plain > 0 ? 1 + (b.d - a.d) / plain : 1;
    if (factor > STRETCH_MARK) stretches.push({ t0: a.t, t1: b.t, y0: y(a.t), y1: y(b.t), factor });
  }
  const marks = base.marks.map(m => ({ ...m, y0: y(m.start), y1: y(m.end) }));
  return { y, end: y(node.end), marks, stretches, placed, lowest };
}

// Tick times with their y, leaving out any tick closer than TICK_GAP to the one drawn before it.
export function tickMarks(node, y) {
  const span = node.end - node.start;
  const step = span >= 7200 ? 1800 : span > 1200 ? 300 : 120;
  const out = [];
  for (let t = Math.ceil(node.start / step) * step; t <= node.end; t += step) {
    const at = y(t);
    if (!out.length || at - out[out.length - 1].y >= TICK_GAP) out.push({ t, y: at });
  }
  return out;
}

// The spine: half-width in pixels at zero context and at the agent's own peak, and the opacity of the composition bands.
export const SPINE_HALF_MIN = 2, SPINE_HALF_MAX = 18, BAND_OPACITY = 0.5;
// Band colours for the composition, taken in the view's category order (a longer list wraps); the inspector bar uses the same.
export const BAND_COLOURS = ['#8A8C92', '#A9C2FF', '#A594FF', '#6EA8FF', '#7FD4B4', '#F2A66E', '#E6C86E', '#C79BE0'];
export const bandColour = i => BAND_COLOURS[i % BAND_COLOURS.length];
// Stations whose drawn y lie this close together merge into one pill.
export const MERGE_GAP = 14;

// The reply row at t, numbers interpolated between the two replies around t and read inside the stretch between
// compactions, so the spine narrows at the compaction itself. A reply row is [t, total, ...].
export function replyAt(rows, cuts, t) {
  const lo = cuts.filter(c => c <= t).pop() ?? -Infinity;
  const hi = cuts.find(c => c > t) ?? Infinity;
  const pts = rows.filter(p => p[0] >= lo && p[0] < hi);
  if (!pts.length) return null;
  if (t <= pts[0][0]) return pts[0];
  for (let i = 1; i < pts.length; i++) {
    if (t <= pts[i][0]) {
      const a = pts[i - 1], b = pts[i], f = (t - a[0]) / Math.max(1e-9, b[0] - a[0]);
      return a.map((v, j) => (typeof v === 'number' ? v + (b[j] - v) * f : v));
    }
  }
  return pts[pts.length - 1];
}

// Stations merge into pills: items (each with a y) sorted down the spine, and every run whose neighbours lie within
// MERGE_GAP of one another becomes one cluster at the run's mean y.
export function mergeStations(items) {
  const clusters = [];
  for (const it of [...items].sort((a, b) => a.y - b.y)) {
    const last = clusters[clusters.length - 1];
    if (last && it.y - last.members[last.members.length - 1].y <= MERGE_GAP) last.members.push(it);
    else clusters.push({ members: [it] });
  }
  return clusters.map(c => ({ members: c.members, y: c.members.reduce((s, m) => s + m.y, 0) / c.members.length }));
}

// The Sources panel shows this many items of a group before "Show N more".
export const SOURCES_SHOWN = 4;
