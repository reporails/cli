// The right column: one agent, always. Nothing selected shows the agent whose view this is; a selected card shows that agent.
// Sections: header with slot chips, peak context and cost tiles, what was in context, activity, and the output of a subagent.
import { el, svg, sync } from '../dom.js';
import { clock, k1, tk, usd, range, plural } from '../format.js';
import { childrenOf, peakOf, typeOf } from '../views.js';
import { promptUrl } from '../api.js';
import { tile } from './nodes/agent.js';
import { textBlock } from './textblock.js';

const EXPAND = 'M4 9V4h5 M20 9V4h-5 M4 15v5h5 M20 15v5h-5';

const WHAT_HAPPENED = {
  failed: 'It failed: its parent’s call for it reported an error, so nothing was handed back.',
  stopped: 'You stopped it before it handed anything back.',
  no_handback: 'It ended without handing a result back.',
  running: 'It is still running; nothing has been handed back yet.',
};

const nodeLabel = node => (node.parent === null ? 'main agent' : node.name);

function chips(node, env) {
  const row = el('div', 'ix-chips');
  for (const k of env.ix.view.adapter.source_kinds) {
    const s = (node.slots && node.slots[k.key]) || { count: 0, findings: 0 };
    const chip = el('span', 'chip' + (s.count > 0 ? (s.findings > 0 ? ' find' : ' on') : ''), k.letter);
    const said = `${k.label}: ${s.count > 0 ? `${s.count} ${k.verb}` : 'none'}${s.findings > 0 ? ` · ${s.findings} findings` : ''}`;
    chip.setAttribute('role', 'img');
    chip.setAttribute('aria-label', said);
    chip.title = said;
    row.append(chip);
  }
  return row;
}

function header(node, env, selected, here) {
  const { ix } = env;
  const box = el('div', 'ix-head');
  box.append(el('div', 'ix-kicker', selected ? `Selected · depth ${node.depth}` : `Viewing · ${node.parent === null ? 'main agent' : `depth ${node.depth}`}`));
  if (selected) {
    const back = el('button', 'ix-back', `← ${nodeLabel(here)}`);
    back.type = 'button';
    back.dataset.unselect = '1';
    back.title = `Back to ${nodeLabel(here)} (clear selection)`;
    box.append(back);
  }
  const line = el('div', 'ih');
  const title = el('div', 'ititle');
  title.append(el('b', 'nm', nodeLabel(node)), el('span', 'sub', `${typeOf(ix, node).label} · ${range(node.start, node.end)}`));
  line.append(tile(ix, node, 32), title);
  box.append(line, chips(node, env));
  return box;
}

function expand(peek, label) {
  const b = el('button', 'ix-expand');
  b.type = 'button';
  b.dataset.peek = peek;
  b.setAttribute('aria-label', label);
  b.title = label;
  const s = svg('svg', { width: 14, height: 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' });
  s.append(svg('path', { d: EXPAND }));
  b.append(s);
  return b;
}

function stat(cls, label, value, lines, peek, open) {
  const box = el('div', `ix-tile ${cls}`);
  const top = el('div', 'ix-tl');
  top.append(el('span', 'lb', label));
  if (peek) top.append(expand(peek, open));
  box.append(top, el('b', 'big mono', value));
  for (const line of [].concat(lines)) box.append(el('span', 'ix-line', line));
  return box;
}

// The whole session's estimated cost against this agent's own: the lines the main agent's cost tile adds.
export function sessionCost(view, node) {
  const sc = view.session_cost;
  if (!sc || sc.total_usd == null || node.parent !== null || view.nodes.length < 2) return null;
  const others = sc.by_agent.filter(([id]) => id !== node.id);
  return { sc, subs: others.reduce((n, [, usd]) => n + usd, 0), n: view.nodes.length - 1, others };
}

const sessionLines = (view, node) => {
  const s = sessionCost(view, node);
  return s ? [`Session ~${usd(s.sc.total_usd)} · ${plural(s.n, 'subagent')} ~${usd(s.subs)}`] : [];
};

function tiles(node, env) {
  const box = el('div', 'ix-tiles');
  const hit = peakOf(node);
  const cost = node.detail && node.detail.cost;
  box.append(hit
    ? stat('peak', 'Peak context', k1(hit.reply[1]), `at ${clock(hit.reply[0])}`, `peak:${node.id}`, 'Open peak context details')
    : stat('peak', 'Peak context', '–', 'not known here', null));
  const known = cost && cost.total_usd != null;
  const costLabel = env.ix.view.nodes.length > 1 ? 'Est. cost · this agent' : 'Est. cost';
  box.append(known
    ? stat('cost', costLabel, usd(cost.total_usd), [[plural(cost.turns, 'turn'), cost.cache_hit_rate == null ? null : `${Math.round(cost.cache_hit_rate * 100)}% cached`].filter(Boolean).join(' · '), ...sessionLines(env.ix.view, node)], `cost:${node.id}`, 'Open est. cost details')
    : stat('cost', costLabel, '–', 'not known here', null));
  return box;
}

// The details a row of the in-context list opens: a source, the task prompt, a built-in item, how a measured row was worked out for this agent, or the composition at peak.
function opener(row, node, env) {
  const view = env.ix.view;
  if (row.key === 'source' || row.key === 'hooks') return row.source ? { source: row.source } : null;
  if (row.key === 'task') return { peek: `task:${node.id}` };
  if (row.key === 'builtin') {
    const item = (view.builtin || []).find(b => b.remainder) || (view.builtin || [])[0];
    return item ? { peek: `builtin:${item.key}` } : null;
  }
  if (row.measure) return { peek: `measured:${row.key}:${node.id}` };
  return { peek: `peak:${node.id}` };
}

function contextRow(row, node, env, measured) {
  const kind = row.kind ? env.ix.kinds.get(row.kind) : null;
  const b = el('button', 'ic');
  b.type = 'button';
  const go = opener(row, node, env);
  if (go && go.source) b.dataset.source = go.source;
  else if (go) b.dataset.peek = go.peek;
  const rem = !measured && (row.key === 'rest' || row.key === 'builtin');
  const time = row.t != null ? clock(row.t) : rem ? 'remainder' : 'always';
  b.setAttribute('aria-label', `${row.label}, ${row.reason}${row.findings ? `, ${row.findings} findings` : ''}, ${tk(row.tokens_est, true)}${rem ? ' remainder' : ''}. Open details.`);
  const text = el('span', 'ic-t');
  text.append(el('span', 'ic-n', row.label), el('span', 'ic-w', row.reason));
  b.append(el('span', 'chip on', kind ? kind.letter : '·'), text);
  if (row.findings) b.append(el('span', 'ic-f', String(row.findings)));
  b.append(el('span', 'ic-k mono', tk(row.tokens_est, true)), el('span', 'ic-s mono', time));
  return b;
}

function sectionHead(title) {
  const head = el('div', 'ix-sh');
  head.append(el('h4', null, title));
  return head;
}

function quiet(text) {
  return el('p', 'ix-quiet', text);
}

function inContext(node, env) {
  const sec = el('section', 'ix-sec ix-ctx');
  const ic = node.detail && node.detail.in_context;
  const head = el('div', 'ix-sh');
  head.append(el('h4', null, 'In context'));
  if (ic) head.append(el('span', 'ix-total mono', `${k1(ic.total)} at peak`));
  sec.append(head);
  if (!ic) { sec.append(quiet('Not known here: no replies were recorded for this agent.')); return sec; }
  for (const r of ic.rows) sec.append(contextRow(r, node, env, ic.measured));
  if (ic.note) sec.append(quiet(ic.note));
  if (ic.over) sec.append(quiet(`These estimates add up to more than the exact ${k1(ic.total)}, so the split is approximate.`));
  const w = node.withheld;
  if (node.parent !== null && w) {
    const names = w.sources.map(s => {
      const src = env.ix.sources.get(s.source);
      return src ? src.label || src.name : s.source;
    });
    if (w.conversation_tokens) names.push(`conversation (~${k1(w.conversation_tokens)})`);
    if (names.length) sec.append(quiet(`Parent had but didn't pass on: ${names.join(', ')}`));
  }
  return sec;
}

function toCalls(cls, label, scopeTool, aria) {
  const b = el('button', cls);
  b.type = 'button';
  b.dataset.tab = 'calls';
  b.dataset.callsScope = 'one';
  b.dataset.callsTool = scopeTool;
  b.setAttribute('aria-label', aria);
  b.append(...label);
  return b;
}

function activity(node, env) {
  const sec = el('section', 'ix-sec ix-act');
  sec.append(sectionHead('Activity'));
  const total = node.tools.reduce((n, t) => n + t.calls, 0);
  sec.append(toCalls('ix-all', [el('b', null, `${total} tool calls`), el('span', 'ix-go', '→')], 'all', `${total} tool calls, open in Tool calls`));
  const most = Math.max(1, ...node.tools.map(t => t.calls));
  const categories = new Map(env.ix.view.adapter.categories.map(c => [c.key, c]));
  for (const t of node.tools) {
    const colour = (categories.get(t.category) || {}).colour;
    const bar = el('span', 'ix-bar');
    const fillBar = el('i');
    fillBar.style.width = `${Math.max(4, Math.round(t.calls / most * 100))}%`;
    if (colour) fillBar.style.background = colour;
    bar.append(fillBar);
    const b = toCalls('ix-tool', [el('span', 'lb', t.tool), bar, el('span', 'n mono', String(t.calls))], t.tool, `${t.calls} ${t.tool} calls, open in Tool calls`);
    b.dataset.tool = t.tool;
    sec.append(b);
  }
  const prompts = node.detail.prompts || [];
  if (prompts.length) {
    sec.append(el('div', 'ix-sub', 'Prompts'));
    for (const p of prompts) {
      const key = `prompt:${p.id}`;
      const b = el('button', 'ix-kid');
      b.type = 'button';
      b.dataset.open = key;
      b.append(el('span', 'lb', `prompt at ${clock(p.t)}`), el('span', 'mono ix-s', tk(p.tokens_est, true)));
      sec.append(b);
      if (env.opened.has(key)) sec.append(textBlock(env.text, key, promptUrl(p.id)));
    }
  }
  const kids = childrenOf(env.ix, node);
  if (kids.length) {
    const below = node.descendants > kids.length ? ` · ${node.descendants} in total below` : '';
    sec.append(el('div', 'ix-sub', `Launched ${plural(kids.length, 'subagent')}${below}`));
    for (const kid of kids) {
      const b = el('button', 'ix-kid');
      b.type = 'button';
      b.dataset.showInGraph = kid.id;
      const dot = el('span', 'sdot sq');
      dot.style.background = typeOf(env.ix, kid).colour;
      b.append(dot, el('span', 'lb', kid.name), el('span', 'mono ix-s', clock(kid.start)));
      sec.append(b);
    }
  }
  return sec;
}

function output(node, env) {
  const d = node.detail;
  const sec = el('section', 'ix-sec ix-out');
  sec.append(sectionHead('Output'));
  if (d.outcome !== 'returned') {
    sec.append(el('p', 'ix-line', WHAT_HAPPENED[d.outcome] || 'It has no recorded outcome.'));
    return sec;
  }
  const edge = env.ix.edges.get(node.id);
  const parent = env.ix.nodes.get(node.parent);
  const at = edge && edge.back_t != null ? ` at ${clock(edge.back_t)}` : '';
  const back = d.back_tokens_est == null ? '; the size of its hand-back is not known' : `, summarised in ${k1(d.back_tokens_est)}${d.back_ratio ? ` (${Math.round(d.back_ratio)}× smaller)` : ''}`;
  sec.append(el('p', 'ix-line', `Returned to ${parent ? nodeLabel(parent) : 'its parent'}${at}. ${d.peak == null ? 'The size of its work is not known' : `${k1(d.peak - (d.context_start || 0))} of work`}${back}.`));
  return sec;
}

export function render(box, env) {
  const { ix, state } = env;
  const here = ix.nodes.get(state.path[state.path.length - 1]);
  const selected = !!state.sel && ix.nodes.has(state.sel);
  const node = selected ? ix.nodes.get(state.sel) : here;
  const parts = [header(node, env, selected, here), tiles(node, env), inContext(node, env), activity(node, env)];
  if (node.parent !== null) parts.push(output(node, env));
  const kind = ix.nodeKinds.get(node.kind);
  if (selected && kind && kind.opens) {
    const open = el('button', 'ix-open', node.descendants > 0 ? `Open — ${node.descendants} nested inside` : 'Open');
    open.type = 'button';
    open.dataset.drill = node.id;
    parts.push(open);
  }
  sync(box, ...parts);
}
