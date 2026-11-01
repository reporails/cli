// The header: logo, breadcrumb of the agent path, the session's date and length, and the adapter chip.
import { el, tpl, slot } from '../dom.js';
import { dur } from '../format.js';
import { hashFor } from '../state.js';

const MAX_SHOWN = 3;

function crumb(node, path, last) {
  if (last) return el('b', 'crumb here', node.name);
  const a = el('a', 'crumb', node.name);
  a.href = hashFor(path);
  return a;
}

// Past three levels the middle ones collapse to "…".
export function crumbs(ix, path) {
  const nodes = path.map(id => ix.nodes.get(id));
  const last = path.length - 1;
  const parts = path.length > MAX_SHOWN ? [0, -1, last] : path.map((_, i) => i);
  const out = [];
  for (const i of parts) {
    if (out.length) out.push(el('span', 'sep', '/'));
    if (i !== -1) { out.push(crumb(nodes[i], path.slice(0, i + 1), i === last)); continue; }
    const gap = el('span', 'crumb gap', '…');
    gap.title = nodes.slice(1, -1).map(n => n.name).join(' / ');
    out.push(gap);
  }
  return out;
}

export function render(box, env) {
  const { ix, state } = env;
  const v = ix.view;
  box.replaceChildren(tpl('t-header'));
  const d = v.started_at ? new Date(v.started_at) : null;
  const when = d && !isNaN(d) ? d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '';
  slot(box, 'crumbs').replaceChildren(...crumbs(ix, state.path));
  slot(box, 'session').textContent = [v.project, when, v.length_s != null ? dur(v.length_s) : ''].filter(Boolean).join(' · ');
  const n = v.adapter.nesting;
  slot(box, 'adapter').textContent = `adapter: ${v.adapter.tool} · nesting ${n.enabled ? 'on' : 'off'}`;
}
