// The floating toolbar: the agent-type filter for this level and one layer toggle per source kind.
import { el, tpl, slot } from '../dom.js';
import { childrenOf, typeOf } from '../views.js';

function typeButton(key, label, colour, on) {
  const b = el('button', 'tbtn');
  b.dataset.type = key;
  b.setAttribute('aria-pressed', on);
  if (key !== 'all') { const dot = el('i', 'dot'); dot.style.background = colour; b.append(dot); }
  b.append(label);
  return b;
}

export function render(box, env) {
  const { ix, state } = env;
  box.replaceChildren(tpl('t-toolbar'));
  const here = ix.nodes.get(state.path[state.path.length - 1]);
  const present = new Map();
  for (const c of childrenOf(ix, here)) {
    const t = typeOf(ix, c);
    if (!present.has(c.type)) present.set(c.type, t);
  }
  const types = slot(box, 'types');
  types.append(typeButton('all', 'All', '', state.type === 'all'));
  const order = ix.view.adapter.agent_types.map(t => t.key).filter(k => present.has(k));
  for (const k of [...order, ...[...present.keys()].filter(k => !order.includes(k))]) {
    types.append(typeButton(k, present.get(k).label, present.get(k).colour, state.type === k));
  }
  const layers = slot(box, 'layers');
  for (const k of ix.view.adapter.source_kinds) {
    const b = el('button', 'tbtn');
    b.dataset.layer = k.key;
    b.setAttribute('aria-pressed', !!state.layers[k.key]);
    b.append(el('span', 'chip on', k.letter), k.label);
    layers.append(b);
  }
}
