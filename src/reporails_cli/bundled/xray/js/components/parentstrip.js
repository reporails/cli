// Below the root: the direct parent's subagents as bars on one line, the current one boxed.
import { el, tpl, slot, sync } from '../dom.js';
import { range } from '../format.js';
import { hashFor } from '../state.js';
import { childrenOf, typeOf } from '../views.js';

export function render(box, env) {
  const { ix, state } = env;
  if (state.path.length < 2) { box.hidden = true; box.replaceChildren(); return; }
  const cur = ix.nodes.get(state.path[state.path.length - 1]);
  const parent = ix.nodes.get(cur.parent);
  box.hidden = false;
  const strip = el('div');
  strip.append(tpl('t-parentstrip'));
  const up = slot(strip, 'up');
  up.href = hashFor(state.path.slice(0, -1));
  slot(strip, 'parent').textContent = parent.name;
  slot(strip, 'range').textContent = range(cur.start, cur.end);
  const lane = slot(strip, 'bars');
  const span = Math.max(1, parent.end - parent.start);
  for (const sib of childrenOf(ix, parent)) {
    const a = el('a', 'pbar' + (sib.id === cur.id ? ' cur' : ''));
    a.href = hashFor([...state.path.slice(0, -1), sib.id]);
    a.dataset.node = sib.id;
    a.title = `${sib.name} · ${range(sib.start, sib.end)}`;
    a.setAttribute('aria-label', a.title);
    a.dataset.name = sib.name;
    a.style.left = `${(sib.start - parent.start) / span * 100}%`;
    a.style.width = `${Math.max(0.6, (sib.end - sib.start) / span * 100)}%`;
    a.style.background = typeOf(ix, sib).colour;
    lane.append(a);
  }
  sync(box, ...strip.childNodes);
}
