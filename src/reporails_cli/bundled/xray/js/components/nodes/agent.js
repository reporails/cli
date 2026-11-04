// The agent node: its card on the canvas.
import { el, svg } from '../../dom.js';
import { clock, dur, k1, tk } from '../../format.js';
import { typeOf, visibleKinds } from '../../views.js';
import { register } from './index.js';

export function tile(ix, node, size) {
  const t = typeOf(ix, node);
  const box = el('span', 'tile');
  box.style.cssText = `width:${size}px;height:${size}px;border-radius:${Math.round(size * 0.28)}px;background:${t.colour}22`;
  const s = svg('svg', { width: size * 0.6, height: size * 0.6, viewBox: '0 0 24 24', fill: 'none', stroke: t.colour, 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
  s.append(svg('path', { d: t.icon }));
  box.append(s);
  return box;
}

// One chip per source kind the adapter declares and the layers show: filled when loaded, orange with findings, white when
// it matches the focused source.
export function slotChips(node, env) {
  const row = el('span', 'chips');
  const hot = env.focus;
  for (const k of visibleKinds(env.ix, env.state)) {
    const s = node.slots[k.key];
    if (!s) continue;
    const chip = el('span', 'chip', k.letter);
    chip.dataset.kind = k.key;
    if (hot && hot.kind === k.key && hot.had_by.includes(node.id)) chip.classList.add('hot');
    else if (s.count > 0 && s.findings > 0) chip.classList.add('find');
    else if (s.count > 0) chip.classList.add('on');
    chip.setAttribute('role', 'img');
    chip.setAttribute('aria-label', `${k.label}: ${s.count > 0 ? s.count + ' loaded' : 'none'}`);
    chip.title = `${k.label}: ${s.count > 0 ? s.count + ' loaded' : 'none'}${s.findings > 0 ? ` · ${s.findings} findings` : ''}`;
    row.append(chip);
  }
  return row;
}

function card(node, env) {
  const d = node.detail;
  const box = el('div', 'nc');
  const head = el('div', 'nh');
  head.append(tile(env.ix, node, env.top ? 26 : 24));
  head.append(el('b', 'nm', node.name));
  if (node.descendants > 0 && !env.top) {
    const badge = el('span', 'badge', String(node.descendants));
    badge.title = `${node.descendants} nested subagents`;
    head.append(badge);
  }
  const sub = env.top
    ? `${k1(d.context_start)} → ${k1(d.peak)}`
    : dur(node.end - node.start);
  box.append(head, el('span', 'sub mono', sub), slotChips(node, env));
  return box;
}

function handback(node, env) {
  const d = node.detail;
  if (d.outcome === 'returned') return `Handed back ↑ ${tk(d.back_tokens_est, true)} · ${clock(env.ix.edges.get(node.id)?.back_t ?? node.end)}`;
  return d.outcome ? { failed: 'Failed', stopped: 'Stopped, nothing handed back', no_handback: 'Ended with no hand-back', running: 'Still running' }[d.outcome] : null;
}

register('agent', { card, handback });
