// The node renderer registry: a node kind maps to its card, its inspector section and its hand-back line.
// A renderer is { card(node, env) -> Element, inspector(node, env) -> Element, handback?(node, env) -> string | null }.
import { el, nk } from '../../dom.js';

const renderers = new Map();
const listeners = [];

export function register(kind, renderer) {
  renderers.set(kind, renderer);
  for (const fn of listeners) fn();
}

export const onRegister = fn => { listeners.push(fn); };

// A kind with no renderer still draws: its name and its raw kind.
const fallback = {
  card: node => {
    const box = el('div', 'nc-fallback');
    box.append(el('b', 'nm', node.name), el('span', 'sub mono', node.kind));
    return box;
  },
  inspector: node => nk(`No details for a ${node.kind} node.`),
};

export const rendererFor = kind => renderers.get(kind) || fallback;
