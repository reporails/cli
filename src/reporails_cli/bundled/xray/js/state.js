// Page state and its URL hash: the agent path (#/agent/<id>/<id>) and the findings drill-down (#/file/<path>).
export const state = {
  path: ['main'], sel: null, type: 'all', pinned: null, hover: null, layers: null, file: null,
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
  if (next.join('/') !== state.path.join('/')) { state.sel = null; state.type = 'all'; }
  state.path = next;
}

export const go = (path, file) => { location.hash = hashFor(path, file ?? null); };
