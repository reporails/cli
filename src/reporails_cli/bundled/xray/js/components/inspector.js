// The inspector: the selected child, or the current agent when nothing is selected.
import { el, nk } from '../dom.js';
import { clock, range } from '../format.js';
import { hashFor } from '../state.js';
import { childrenOf, typeOf } from '../views.js';
import { rendererFor } from './nodes/index.js';
import { tile } from './nodes/agent.js';

function slotLines(node, env) {
  const box = el('div', 'slotlines');
  for (const k of env.ix.view.adapter.source_kinds) {
    const s = node.slots && node.slots[k.key];
    if (!s || !env.state.layers[k.key]) continue;
    const total = env.ix.view.sources.filter(x => x.kind === k.key).length;
    const line = el('span', 'sl' + (s.count ? ' on' : ''));
    line.append(el('span', 'chip ' + (s.count ? (s.findings ? 'find' : 'on') : ''), k.letter), `${k.label} · ${s.count} of ${total}`);
    box.append(line);
  }
  return box;
}

export function render(box, env) {
  const { ix, state } = env;
  const here = ix.nodes.get(state.path[state.path.length - 1]);
  const node = state.sel ? ix.nodes.get(state.sel) : here;
  const t = typeOf(ix, node);
  const head = el('div', 'ih');
  const title = el('div', 'ititle');
  title.append(el('b', 'nm', node.name), el('span', 'sub', `${t.label} · ${range(node.start, node.end)} · depth ${node.depth}`));
  head.append(tile(ix, node, 32), title);
  box.replaceChildren(head, slotLines(node, env), rendererFor(node.kind).inspector(node, env));
  const kind = ix.nodeKinds.get(node.kind);
  if (node !== here && kind && kind.opens) {
    const open = el('a', 'open', node.descendants > 0 ? `Open — ${node.descendants} nested inside` : 'Open');
    open.href = hashFor([...state.path, node.id]);
    box.append(open);
  }
  if (node === here && !childrenOf(ix, node).length) box.append(nk('This agent launched no subagents.'));
  if (node === here && node.parent !== null) box.append(nk(`Started at ${clock(node.start)} in this session.`));
}
