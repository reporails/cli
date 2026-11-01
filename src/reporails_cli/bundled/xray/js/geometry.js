// Canvas geometry: where times, cards, ticks and breaks sit. Pure functions of the view's numbers.
export const W = 780, SPX = 466, Y0 = 108, CW = 132, CH = 64, TOP_W = 148, BOT_W = 180, BOT_H = 48;
export const COLX = { L1: SPX - 26 - CW, L2: SPX - 26 - CW - 8 - CW, R1: SPX + 26, R2: SPX + 26 + CW + 8 };
export const TRACK_X0 = 52, TRACK_STEP = 15;
const CAP_S = 6 * 3600, GAP_PX = 28, LANE_GAP = 8, MAX_RUNNING_COLUMNS = 4;

export const lengthFor = isRoot => (isRoot ? 1480 : 980);

// Time to y. Idle breaks keep their linear length until the node is longer than the cap, then each shrinks to a
// fixed gap so the active stretches keep their scale.
export function timeScale(node, breaks, len) {
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
  const marks = inside.map(b => ({ start: b.start, end: b.end, y0: at(b.start), y1: at(b.end), squeezed: squeeze }));
  return { y: at, end: at(node.end), marks, span };
}

// Each card's top sits 18 px above its launch. Preferred side alternates; the preferred inner column first, then the
// other side, then the outer columns; with all four taken the card stacks under the preferred column's lowest card.
export function placeCards(children, y) {
  const bottoms = {};
  const placed = [];
  const ordered = [...children].sort((a, b) => a.start - b.start);
  ordered.forEach((child, idx) => {
    let top = Math.max(y(child.start) - 18, Y0 - 12);
    const pref = idx % 2 === 0 ? ['R1', 'L1', 'R2', 'L2'] : ['L1', 'R1', 'L2', 'R2'];
    let col = pref.find(c => bottoms[c] === undefined || bottoms[c] + LANE_GAP <= top);
    const stacked = !col;
    if (stacked) { col = pref[0]; top = bottoms[col] + LANE_GAP; }
    bottoms[col] = top + CH;
    const side = col[0] === 'L' ? -1 : 1;
    const left = COLX[col];
    placed.push({ id: child.id, col, top, left, side, inner: side < 0 ? left + CW : left, stacked });
  });
  const lowest = Object.values(bottoms).reduce((m, v) => Math.max(m, v), 0);
  return { placed, lowest };
}

// "+N running" where more than four children run at once: one marker per stretch, at the busiest launch.
export function runningMarkers(children, y) {
  const found = [];
  for (const c of children) {
    const n = children.filter(o => o.start <= c.start && o.end > c.start).length;
    if (n > MAX_RUNNING_COLUMNS) found.push({ y: y(c.start), t: c.start, more: n - MAX_RUNNING_COLUMNS });
  }
  const out = [];
  for (const m of found.sort((a, b) => a.y - b.y)) {
    const last = out[out.length - 1];
    if (last && m.y - last.y < 24) { if (m.more > last.more) Object.assign(last, m); } else out.push({ ...m });
  }
  return out;
}

export function tickTimes(node) {
  const span = node.end - node.start;
  const step = span >= 7200 ? 1800 : span > 1200 ? 300 : 120;
  const out = [];
  for (let t = Math.ceil(node.start / step) * step; t <= node.end; t += step) out.push(t);
  return out;
}

// Context size at t, read inside the stretch between compactions so the band narrows at the compaction itself.
export function contextAt(series, cuts, t) {
  const lo = cuts.filter(c => c <= t).pop() ?? -Infinity;
  const hi = cuts.find(c => c > t) ?? Infinity;
  const pts = series.filter(p => p[0] >= lo && p[0] < hi);
  if (!pts.length) return 0;
  if (t <= pts[0][0]) return pts[0][1];
  for (let i = 1; i < pts.length; i++) {
    if (t <= pts[i][0]) return pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * (t - pts[i - 1][0]) / Math.max(1e-9, pts[i][0] - pts[i - 1][0]);
  }
  return pts[pts.length - 1][1];
}


// Stations on the spine, nudged down just enough that their marks do not sit on one another.
export function spreadStations(items) {
  let last = -Infinity;
  return [...items].sort((a, b) => a.y - b.y).map(it => {
    const y = Math.max(it.y, last + it.gap);
    last = y;
    return { ...it, drawY: y };
  });
}
