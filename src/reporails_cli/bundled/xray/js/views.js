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

export const kindOfSource = (ix, id) => {
  const s = ix.sources.get(id);
  return s ? ix.kinds.get(s.kind) || null : null;
};

export const visibleKinds = (ix, state) => ix.view.adapter.source_kinds.filter(k => state.layers[k.key]);

// The source whose focus is on: hover wins over a pin; a source of a hidden layer is no focus.
export function focusSource(ix, state) {
  const s = ix.sources.get(state.hover || state.pinned);
  return s && state.layers[s.kind] ? s : null;
}

export const childrenOf = (ix, node) => node.children.map(id => ix.nodes.get(id)).filter(Boolean);

// A reply row is [t, total, input, cache write, cache read, ...one value per category key, over_estimate].
export const replyParts = (comp, row) => row.slice(5, 5 + comp.keys.length);

export const TABS = ['graph', 'calls', 'sources'];

// The open tab: the one chosen, else Tool calls for a session with no subagents and Graph for the rest.
export const activeTab = (ix, state) => state.tab || (ix.view.nodes.length > 1 ? 'graph' : 'calls');

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
  const colours = new Map(ix.view.adapter.categories.map(c => [c.key, c.colour]));
  const made = { list, byId: new Map(list.map(r => [r.call.use_id, r])), colour: key => colours.get(key) || NEUTRAL };
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
