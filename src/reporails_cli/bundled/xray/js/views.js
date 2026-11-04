// The view JSON indexed for the components, and the adapter's vocabulary as lookups.
const NEUTRAL = '#6E7076';
export const GENERIC_ICON = 'M12 4a8 8 0 1 0 0 16a8 8 0 1 0 0-16z';

export function index(view) {
  const nodes = new Map(view.nodes.map(n => [n.id, n]));
  const sources = new Map(view.sources.map(s => [s.id, s]));
  const edges = new Map(view.edges.map(e => [e.to, e]));
  const stations = new Map(view.stations.map(s => [s.node, s]));
  const track = new Map(view.track.map(t => [t.node, t]));
  const ad = view.adapter;
  const kinds = new Map(ad.source_kinds.map(k => [k.key, k]));
  const types = new Map(ad.agent_types.map(t => [t.key, t]));
  const nodeKinds = new Map(ad.node_kinds.map(k => [k.key, k]));
  const triggers = new Map((ad.triggers || []).map(t => [t.key, t.label]));
  return { view, triggers, nodes, sources, edges, stations, track, kinds, types, nodeKinds };
}

// The type's colour, icon and short label; a type the adapter does not list is grey with its raw name.
export function typeOf(ix, node) {
  const t = ix.types.get(node.type);
  return t ? { colour: t.colour, icon: t.icon, label: t.label } : { colour: NEUTRAL, icon: GENERIC_ICON, label: node.type };
}

// The one wording for a source the transcript does not show.
export const UNRECORDED = 'not recorded in this session';

export const kindOfSource = (ix, id) => {
  const s = ix.sources.get(id);
  return s ? ix.kinds.get(s.kind) || null : null;
};

export const visibleKinds = (ix, state) => ix.view.adapter.source_kinds.filter(k => state.layers[k.key]);

// The source whose focus is on: a pin holds until cleared, hover lights a source only while nothing is pinned. A kind's eye hides it on the graph only, so the list still highlights it.
export function focusSource(ix, state) {
  return ix.sources.get(state.pinned || state.hover) || null;
}

// The source the Sources panel scrolls and opens to: the one keyboard focus is on, else the pinned one. Hover never counts.
export function revealedSource(ix, state) {
  return ix.sources.get(state.lit || state.pinned) || null;
}

export const childrenOf = (ix, node) => node.children.map(id => ix.nodes.get(id)).filter(Boolean);

// A reply row is [t, total, input, cache write, cache read, ...one value per category key, over_estimate, measured].
export const replyParts = (comp, row) => row.slice(5, 5 + comp.keys.length);
export const replyOver = row => row[row.length - 2] === true;
export const replyMeasured = row => row[row.length - 1] === true;

export const TABS = ['graph', 'calls', 'sources'];

// The open tab: the one chosen, else the Graph.
export const activeTab = state => state.tab || 'graph';

// What each tab's count in the header says.
export function tabCounts(ix) {
  const v = ix.view;
  return {
    graph: v.nodes.length,
    calls: v.track.reduce((n, t) => n + t.calls.length, 0),
    sources: v.sources.length + (v.builtin || []).length,
  };
}

// Every call of the session with the node that made it, in time order; looked up by use id; each category's colour.
const callIndexes = new WeakMap();
export function callIndex(ix) {
  const have = callIndexes.get(ix);
  if (have) return have;
  const list = [];
  for (const t of ix.view.track) {
    const node = ix.nodes.get(t.node);
    for (const call of t.calls) list.push({ call, node });
  }
  list.sort((a, b) => a.call.t - b.call.t);
  const cats = new Map(ix.view.adapter.categories.map(c => [c.key, c]));
  const serverColour = new Map();
  for (const { call } of list) if (call.server && !serverColour.has(call.server) && cats.has(call.category)) serverColour.set(call.server, cats.get(call.category).colour);
  const made = { list, byId: new Map(list.map(r => [r.call.use_id, r])), colour: key => (cats.get(key) || {}).colour || NEUTRAL,
    hasCommand: key => !!(cats.get(key) || {}).command, serverColour: server => serverColour.get(server) || NEUTRAL };
  callIndexes.set(ix, made);
  return made;
}

// The ids of a node and every agent below it.
export function subtreeIds(ix, id) {
  const out = new Set();
  const walk = n => {
    if (!n || out.has(n.id)) return;
    out.add(n.id);
    for (const c of n.children) walk(ix.nodes.get(c));
  };
  walk(ix.nodes.get(id));
  return out;
}

// The agent's peak reply and its composition, or null when no reply was recorded.
export function peakOf(node) {
  const comp = node.detail && node.detail.composition;
  const reply = comp && comp.peak != null ? comp.replies[comp.peak] : null;
  return reply ? { comp, reply } : null;
}
