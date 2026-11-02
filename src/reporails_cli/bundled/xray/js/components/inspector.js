// The inspector: the selected child, or the current agent when nothing is selected.
import { el, nk } from '../dom.js';
import { clock, k1, plural, range } from '../format.js';
import { hashFor } from '../state.js';
import { bandColour } from '../geometry.js';
import { childrenOf, replyParts, typeOf } from '../views.js';
import { rendererFor } from './nodes/index.js';
import { tile } from './nodes/agent.js';
import { pane, tag } from './pane.js';

function slotText(node, k, s, env) {
  const view = env.ix.view;
  if (k.definitions) {
    if (node.parent === null) return `${k.label} · ${s.count} defined, listed`;
    const def = s.count === 1 && view.sources.find(x => x.kind === k.key && x.had_by.includes(node.id));
    return `${k.label} · ${def ? def.path.split('/').pop() : 'built-in'}`;
  }
  const total = view.sources.filter(x => x.kind === k.key).length;
  return `${k.label} · ${s.count} of ${total}`;
}

function slotLines(node, env) {
  const box = el('div', 'slotlines');
  for (const k of env.ix.view.adapter.source_kinds) {
    const s = node.slots && node.slots[k.key];
    if (!s || !env.state.layers[k.key]) continue;
    const line = el('span', 'sl' + (s.count ? ' on' : ''));
    line.append(el('span', 'chip ' + (s.count ? (s.findings ? 'find' : 'on') : ''), k.letter), slotText(node, k, s, env));
    box.append(line);
  }
  return box;
}

const usd = n => '$' + (n >= 0.01 || n === 0 ? n.toFixed(2) : n.toFixed(4));
const row = (label, value, ...extra) => {
  const r = el('div', 'row');
  r.append(el('span', 'lb', label), el('span', 'v', value), ...extra);
  return r;
};
const note = text => el('p', 'note', text);

function stackBar(values, total) {
  const bar = el('div', 'stack');
  values.forEach((v, i) => {
    if (v <= 0 || total <= 0) return;
    const seg = el('i');
    seg.style.width = `${v / total * 100}%`;
    seg.style.background = bandColour(i);
    bar.append(seg);
  });
  return bar;
}

function contextPane(node, env) {
  const view = env.ix.view, comp = node.detail.composition;
  const title = el('b', null, 'Context at peak');
  const reply = comp && comp.peak != null ? comp.replies[comp.peak] : null;
  if (!reply) return pane('context', [title, el('span', 'note', 'not known here')], [note('Not known here: no replies were recorded for this agent.')]);
  const total = reply[1], parts = replyParts(comp, reply), over = reply[reply.length - 1];
  const remainder = view.adapter.composition_remainder;
  const labels = view.adapter.composition;
  const head = [title, el('span', 'big', k1(total)), tag('exact', 'exact'), stackBar(parts, total)];
  const body = [
    note(`At ${clock(reply[0])} · ${node.name}`),
    el('p', null, `input ${reply[2].toLocaleString('en-US')} + cache write ${reply[3].toLocaleString('en-US')} + cache read ${reply[4].toLocaleString('en-US')}`),
  ];
  let rest = null;
  for (const c of labels) {
    const i = comp.keys.indexOf(c.key);
    if (i < 0) continue;
    const isRest = c.key === remainder;
    if (isRest) rest = { c, v: parts[i] };
    const sw = el('span', 'swatch');
    sw.style.background = bandColour(i);
    const line = row(c.label, over && isRest ? 'see below' : `~${k1(parts[i])}`, isRest ? tag('est. + remainder', 'est') : tag('estimated', 'est'));
    line.prepend(sw);
    line.dataset.category = c.key;
    body.push(line);
  }
  const remLabel = (labels.find(c => c.key === remainder) || {}).label || remainder;
  if (over) body.push(note(`The estimates add up to more than the exact ${k1(total)}, so nothing is left for ${remLabel}; the split is approximate.`));
  else if (rest) body.push(note(`The estimates sum to ~${k1(total - rest.v)}; the rest of the exact ${k1(total)} went to ${remLabel}.`));
  return pane('context', head, body);
}

function costPane(node, env) {
  const view = env.ix.view, cost = node.detail.cost, list = view.price_list;
  const title = el('b', null, 'Cost');
  if (!cost || cost.total_usd == null) return pane('cost', [title, el('span', 'note', 'not known here'), tag('derived', 'derived')], [note('Not known here.')]);
  const pct = cost.cache_hit_rate == null ? null : `${Math.round(cost.cache_hit_rate * 100)}% cached`;
  const head = [title, el('span', 'big', usd(cost.total_usd))];
  if (pct) head.push(el('span', 'note', pct));
  head.push(tag('derived', 'derived'));
  const body = [row(`this agent, ${plural(cost.turns, 'turn')}`, usd(cost.total_usd))];
  if (cost.peak_turn_usd != null) body.push(row(`peak turn${cost.peak_turn_t != null ? ' at ' + clock(cost.peak_turn_t) : ''}`, usd(cost.peak_turn_usd)));
  if (cost.cache_hit_rate != null) body.push(row('cache hit rate', `${Math.round(cost.cache_hit_rate * 100)}%`, tag('exact', 'exact')));
  if (cost.instructions_usd_est != null) body.push(row('instruction files carried every turn', `~${usd(cost.instructions_usd_est)}`, tag('estimated', 'est')));
  if (cost.unpriced > 0) {
    const named = cost.unpriced_models.length ? `: ${cost.unpriced_models.join(', ')}` : ' (no model named)';
    body.push(note(`${plural(cost.unpriced, 'reply', 'replies')} not priced${named}`));
  }
  if (cost.split_assumed > 0) body.push(note(`${plural(cost.split_assumed, 'reply', 'replies')} had no 5-minute / 1-hour cache split and ${cost.split_assumed === 1 ? 'was' : 'were'} priced at the 5-minute rate.`));
  body.push(note(`Exact token counts × list price (${list.name}, ${list.as_of}). API-equivalent: on a subscription you don't pay per token.`));
  return pane('cost', head, body);
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
  const panes = [];
  if (node.detail && 'composition' in node.detail) panes.push(contextPane(node, env));
  if (node.detail && 'cost' in node.detail) panes.push(costPane(node, env));
  box.replaceChildren(head, slotLines(node, env), ...panes, rendererFor(node.kind).inspector(node, env));
  const kind = ix.nodeKinds.get(node.kind);
  if (node !== here && kind && kind.opens) {
    const open = el('a', 'open', node.descendants > 0 ? `Open — ${node.descendants} nested inside` : 'Open');
    open.href = hashFor([...state.path, node.id]);
    box.append(open);
  }
  if (node === here && !childrenOf(ix, node).length) box.append(nk('This agent launched no subagents.'));
  if (node === here && node.parent !== null) box.append(nk(`Started at ${clock(node.start)} in this session.`));
}
