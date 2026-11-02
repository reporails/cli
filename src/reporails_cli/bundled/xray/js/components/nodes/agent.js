// The agent node: its card on the canvas and the passed down / worked / came back section of the inspector.
import { el, svg } from '../../dom.js';
import { clock, dur, k1, plural, tk } from '../../format.js';
import { typeOf, visibleKinds } from '../../views.js';
import { briefUrl, promptUrl } from '../../api.js';
import { textBlock } from '../textblock.js';
import { pane } from '../pane.js';
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

function item(env, label, tokens, sourceId, extra) {
  const row = el('div', 'it');
  row.append(el('span', 'lb', label), el('span', 'tk mono', tk(tokens, true)));
  const s = sourceId && env.ix.sources.get(sourceId);
  if (s && s.findings && s.findings.count > 0 && s.path) {
    const a = el('a', 'pill', String(s.findings.count));
    a.href = '#/file/' + s.path.split('/').map(encodeURIComponent).join('/');
    a.title = 'findings in ' + s.name;
    row.append(a);
  }
  if (extra) row.append(extra);
  return row;
}

// A line that shows a fetched text under it when clicked.
function opener(env, key, url, label, tokens) {
  const wrap = el('div', 'op');
  const head = el('button', 'it link', '');
  head.append(el('span', 'lb', label), el('span', 'tk mono', tk(tokens, true)));
  head.dataset.open = key;
  wrap.append(head);
  if (env.opened.has(key)) wrap.append(textBlock(env.text, key, url));
  return wrap;
}

function passedDown(node, env) {
  const d = node.detail;
  const step = el('section', 'step');
  step.append(el('h4', null, 'Passed down'));
  for (const g of d.given) {
    if (g.label === 'task prompt' && d.brief) step.append(opener(env, 'brief:' + node.id, briefUrl(node.id), g.label, g.tokens_est));
    else step.append(item(env, g.label, g.tokens_est, g.source));
  }
  for (const p of d.prompts) {
    step.append(opener(env, 'prompt:' + p.id, promptUrl(p.id), `prompt at ${clock(p.t)}`, p.tokens_est));
  }
  const w = node.withheld;
  if (w && w.sources.length) {
    const sum = w.sources.reduce((n, x) => n + (x.tokens_est || 0), 0);
    const body = [el('p', 'note', `Its parent held ${k1(w.context_tokens)} tokens of context and did not pass down:`)];
    for (const s of w.sources) {
      const src = env.ix.sources.get(s.source);
      body.push(item(env, src ? src.name : s.source, s.tokens_est, null));
    }
    step.append(pane('withheld', [el('b', null, `Not passed down: ${plural(w.sources.length, 'source')} · ~${k1(sum)}`)], body));
  } else if (w && w.context_tokens) {
    const box = el('div', 'withheld');
    box.append(el('span', null, `Its parent held ${k1(w.context_tokens)} tokens of context and passed down every source`));
    step.append(box);
  }
  return step;
}

function worked(node, env) {
  const d = node.detail;
  const step = el('section', 'step');
  step.append(el('h4', null, 'Worked'));
  const calls = Object.entries(node.tool_counts).filter(([k]) => k !== 'agent').reduce((s, [, n]) => s + n, 0);
  step.append(el('p', 'line', `Peak context ${k1(d.peak)} · ${calls} tool calls`));
  const launched = node.children.length;
  const below = node.descendants > launched ? ` · ${node.descendants} in total below` : '';
  step.append(el('p', 'line', launched ? `${launched} subagent${launched === 1 ? '' : 's'} launched${below}` : 'No subagents launched.'));
  const cats = env.ix.view.adapter.categories.filter(c => (node.tool_counts[c.key] || 0) > 0);
  const most = Math.max(1, ...cats.map(c => node.tool_counts[c.key]));
  for (const c of cats) {
    const n = node.tool_counts[c.key];
    const bar = el('div', 'bar');
    const fill = el('i');
    fill.style.width = `${Math.max(4, Math.round(n / most * 100))}%`;
    const track = el('span', 'trk');
    track.append(fill);
    bar.append(el('span', 'lb', c.label), track, el('span', 'n mono', String(n)));
    step.append(bar);
  }
  return step;
}

const WHAT_HAPPENED = {
  failed: 'It failed: its parent’s call for it reported an error, so nothing came back.',
  stopped: 'You stopped it before it handed anything back.',
  no_handback: 'It ended without handing a result back.',
  running: 'It is still running; nothing has come back yet.',
};

function cameBack(node, env) {
  const d = node.detail;
  const edge = env.ix.edges.get(node.id);
  const step = el('section', 'step');
  step.append(el('h4', null, d.outcome === 'returned' ? 'Came back' : 'What happened'));
  if (d.outcome !== 'returned') {
    step.append(el('p', 'line what', WHAT_HAPPENED[d.outcome] || 'It has no recorded outcome.'));
    return step;
  }
  const parent = env.ix.nodes.get(node.parent);
  const where = edge && edge.back_t != null ? ` · landed at ${clock(edge.back_t)}${parent ? ' in ' + parent.name : ''}` : '';
  step.append(el('p', 'line', d.back_tokens_est == null ? `Handed back${where}` : `${tk(d.back_tokens_est, true)} tokens${where}`));
  if (d.back_ratio != null) step.append(el('p', 'line muted', `${d.back_ratio}:1 from peak context to what came back`));
  return step;
}

function inspector(node, env) {
  const box = el('div', 'steps');
  box.append(passedDown(node, env), worked(node, env));
  if (node.detail.outcome !== null) box.append(cameBack(node, env));
  return box;
}

function handback(node, env) {
  const d = node.detail;
  if (d.outcome === 'returned') return `Handed back ↑ ${tk(d.back_tokens_est, true)} · ${clock(env.ix.edges.get(node.id)?.back_t ?? node.end)}`;
  return d.outcome ? { failed: 'Failed', stopped: 'Stopped, nothing handed back', no_handback: 'Ended with no hand-back', running: 'Still running' }[d.outcome] : null;
}

register('agent', { card, inspector, handback });
