// Page state and its URL hash: the agent path (#/agent/<id>/<id>) and the findings drill-down (#/file/<path>).
export const state = {
  path: ['main'], sel: null, type: 'all', pinned: null, hover: null, layers: null, file: null, groups: {},
  // Inspector panes by key; open state lives here so it survives selecting another agent and the page's re-renders.
  panes: {},
  // Source kinds opened or closed by hand, the long kinds showing all, and the source last revealed by focus.
  sourceGroups: {}, more: new Set(), revealed: null,
};

const enc = s => encodeURIComponent(s);

export function hashFor(path, file) {
  if (file != null) return '#/file/' + file.split('/').map(enc).join('/');
  return '#/agent/' + path.map(enc).join('/');
}

export function readHash(hash) {
  const parts = hash.replace(/^#\/?/, '').split('/');
  if (parts[0] === 'file' && parts.length > 1) return { file: parts.slice(1).map(decodeURIComponent).join('/') };
  if (parts[0] === 'agent' && parts.length > 1) return { path: parts.slice(1).map(decodeURIComponent) };
  return {};
}

// Applies the hash to the state; an agent path with an unknown level keeps only its known levels.
export function applyHash(hash, nodes) {
  const got = readHash(hash);
  state.file = got.file ?? null;
  if (got.file != null) return;
  const want = got.path || ['main'];
  const keep = [];
  for (const id of want) {
    const node = nodes.get(id);
    if (!node || (keep.length && node.parent !== keep[keep.length - 1])) break;
    keep.push(id);
  }
  const next = keep.length ? keep : ['main'];
  const old = state.path;
  if (next.join('/') !== old.join('/')) {
    // Going up a level selects the child it came from, so that child's collapsed group opens.
    state.sel = next.length < old.length && next.every((id, i) => id === old[i]) ? old[next.length] : null;
    state.type = 'all';
  }
  state.path = next;
}

export const go = (path, file) => { location.hash = hashFor(path, file ?? null); };

// A fan-out group is open when the user said so; otherwise when the selected agent is one of its members.
export const groupOpen = (st, key, memberIds) => (key in st.groups ? st.groups[key] : memberIds.includes(st.sel));
