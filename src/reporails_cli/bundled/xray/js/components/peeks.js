// The details renderers for a source, a built-in item, a task prompt, the peak context and the estimated cost.
import { el, nk, err } from '../dom.js';
import { clock, costEst, exclusionNote, k1, MCP_STATES, plural, tk, usd } from '../format.js';
import { briefUrl, hookOutputUrl, peekUrl, systemUrl } from '../api.js';
import { textBlock } from './textblock.js';
import { hashFor } from '../state.js';
import { bandColour } from '../geometry.js';
import { peakOf, replyMeasured, replyOver, replyParts, typeOf, UNRECORDED } from '../views.js';
import { nodeLabel, sessionCost } from './inspector.js';
import { render as renderFindings } from './findings.js';
import { registerPeek, scrollable } from './details.js';

const section = (title, ...nodes) => {
  const box = el('section', 'pk-sec');
  box.append(el('h4', null, title), ...nodes);
  return box;
};

const kv = pairs => {
  const box = el('div', 'pk-kv');
  for (const [k, v] of pairs) if (v != null && v !== '') box.append(el('span', 'lb', k), el('span', 'v', v));
  return box;
};

const pre = text => el('pre', 'pk-pre', text);
const action = (label, attrs, primary) => {
  const b = el('button', 'pk-act' + (primary ? ' primary' : ''), label);
  b.type = 'button';
  Object.assign(b.dataset, attrs);
  return b;
};

// A fetched text as a block: loading, the refusal, or the text itself.
function fetched(entry, pick) {
  if (entry.loading) return nk('Loading…');
  if (entry.error) return err(entry.error);
  const out = document.createDocumentFragment();
  out.append(scrollable(el('pre', 'peek', pick(entry)), 'File text'));
  if (entry.truncated) out.append(nk('text truncated'));
  return out;
}

// The reason an agent had the source, as the first recorded load words it.
function whyLoaded(view, id) {
  for (const n of view.nodes) {
    const rows = (n.detail && n.detail.in_context && n.detail.in_context.rows) || [];
    const hit = rows.find(r => r.source === id && r.reason);
    if (hit) return hit.reason;
  }
  return null;
}


// When the agent had the source: its first load into that agent, else the agent's start.
function loadTime(ix, node, s) {
  const st = ix.stations.get(node.id);
  const times = (st ? st.loads : []).filter(l => l.source === s.id && l.t != null).map(l => l.t);
  return times.length ? Math.min(...times) : node.start;
}

function findingsBlock(s, env) {
  const count = (s.findings && s.findings.count) || 0;
  const box = el('div');
  if (env.res && env.res.path === s.path) renderFindings(box, env.res);
  else if (s.actionable && s.path) {
    const b = action(count ? `Show the ${plural(count, 'finding')}` : 'Check this file');
    b.dataset.act = 'check';
    b.dataset.path = s.path;
    b.disabled = !!env.busy;
    box.append(b);
    const note = exclusionNote(s.excluded);
    if (note) box.append(el('div', 'nk excluded', note));
  } else {
    if (!s.excluded.outside) box.append(nk('Outside this project; run ails check on it.'));
    const why = exclusionNote(s.excluded);
    if (why) box.append(el('div', 'nk excluded', why));
  }
  return section(count ? `${plural(count, 'finding')}` : 'Findings', box);
}

const DECISIONS = { context_added: 'added to the context', message_shown: 'showed a message', blocked: 'blocked', ran: 'ran' };
const SCOPES = { project: 'project .mcp.json', user: 'your user settings', local: 'this project in your user settings', managed: 'managed settings', plugin: 'plugin' };

// A hook's commands with the file that declares each, and its firings: the output opens on request.
function hookSections(env, hook) {
  const out = [];
  const cmds = hook.commands.map(c => `${c.command}\n  declared in: ${c.declared_in || 'no hook config Claude Code reads holds this command'}`);
  out.push(section(plural(hook.commands.length, 'command'), cmds.length ? pre(cmds.join('\n\n')) : nk('No command is recorded for this hook.')));
  const list = el('div', 'pk-list');
  for (const f of hook.firings) {
    const key = `hook:${f.id}`;
    const b = el('button', 'pk-li');
    b.type = 'button';
    if (f.id) b.dataset.open = key;
    const bits = [DECISIONS[f.decision] || f.decision, f.exit_code != null ? `exit ${f.exit_code}` : null, `${f.chars} chars`, f.duration_ms != null ? `${f.duration_ms} ms` : null];
    b.append(el('span', 'lb', bits.filter(Boolean).join(' · ')), el('span', 'mono v', f.t != null ? clock(f.t) : ''));
    list.append(b);
    if (f.id && env.opened.has(key)) list.append(textBlock(env.text, key, hookOutputUrl(f.id)));
  }
  const more = hook.firing_count > hook.firings.length ? ` · latest ${hook.firings.length}` : '';
  out.push(section(`${plural(hook.firing_count, 'firing')}${more}`, hook.firings.length ? list : nk('No firing is recorded.')));
  return out;
}

registerPeek('src', (env, id) => {
  const { ix } = env;
  const s = ix.sources.get(id);
  if (!s) return null;
  const view = ix.view;
  const k = ix.kinds.get(s.kind);
  const count = (s.findings && s.findings.count) || 0;
  const unrecorded = s.availability === 'unrecorded';
  const entry = s.path ? env.text('p:' + s.path, peekUrl(s.path)) : null;
  const main = [];
  if (count || (s.actionable && s.path) || (s.path && s.excluded.outside)) main.push(findingsBlock(s, env));
  if (entry && entry.frontmatter) main.push(section('Configuration', pre(entry.frontmatter)));
  if (s.scopes && s.scopes.length) main.push(section('Scopes', pre(s.scopes.join('\n'))));
  if (s.tools && s.tools.length) main.push(section('Tools on this server', pre(s.tools.map(([t, n]) => `${t} · ${n ? plural(n, 'call') : 'not called'}`).join('\n'))));
  if (s.hook) main.push(...hookSections(env, s.hook));
  if (entry) main.push(section('Its text', fetched(entry, e => e.body ?? e.text)));
  else if (s.system_tokens_est == null && !s.hook) main.push(section('Its text', nk(s.builtin ? 'Comes from the coding agent; there is no file.' : 'No file behind this source.')));
  if (s.kind === 'agent' && s.system_tokens_est != null) {
    main.push(section(`System prompt · ${tk(s.system_tokens_est, true)} · recorded at launch`, textBlock(env.text, 'system:' + s.agent_type, systemUrl(s.agent_type))));
  }
  if (s.kind === 'agent') {
    if (s.launch_tools.length) main.push(section('Tools its launches had', pre(s.launch_tools.map(([t, n]) => `${t} · ${plural(n, 'launch', 'launches')}`).join('\n'))));
    if (s.launch_settings.length) main.push(section('Launch settings', pre(s.launch_settings.map(([label, value]) => `${label} · ${value}`).join('\n'))));
  }
  const holders = s.had_by.map(h => ix.nodes.get(h)).filter(Boolean);
  const loaded = s.kind && (ix.kinds.get(s.kind) || {}).definitions
    ? (s.launches > 0 ? `launched as ${plural(s.launches, 'subagent')}` : 'never launched')
    : unrecorded ? UNRECORDED : holders.length ? `${holders.length} of ${view.nodes.length} agents` : 'no agent';
  const why = unrecorded ? null : whyLoaded(view, s.id);
  const m = s.mcp;
  const where = m ? (m.declared_in ? `${SCOPES[m.scope] || m.scope}: ${m.declared_in}` : 'no configuration file declares it') : null;
  const side = [kv([['Path', s.path], ['Plugin', m ? m.plugin : null], ['State', m ? MCP_STATES[m.state] : null], ['Declared in', where], ['Loaded by', loaded], ['Why', why]])];
  const price = costEst(s.cost_usd_est);
  if (price && holders.length) side.push(kv([['Est. cost', `${price} across this session`], ['Method', view.price_list.source_method]]));
  if (holders.length) {
    const list = el('div', 'pk-list');
    for (const n of holders.slice(0, 8)) {
      const b = el('button', 'pk-li');
      b.type = 'button';
      b.dataset.showInGraph = n.id;
      b.append(el('span', 'lb', nodeLabel(n)), el('span', 'mono v', clock(loadTime(ix, n, s))));
      list.append(b);
    }
    if (holders.length > 8) list.append(nk(`and ${holders.length - 8} more agents`));
    side.push(section('Loaded in', list));
  }
  const tags = [unrecorded ? UNRECORDED : holders.length ? 'in context' : 'never loaded'];
  if (count) tags.push(`${plural(count, 'finding')}`);
  if (s.tokens_est != null) tags.push(`${tk(s.tokens_est, true)} each · estimated`);
  const actions = [action('Pin on graph', { pin: s.id })];
  if (count && s.path) {
    const a = el('a', 'pk-act primary', 'Open findings page');
    a.href = hashFor(env.state.path, s.path);
    actions.push(a);
  }
  const dir = s.path && s.path.includes('/') ? s.path.slice(0, s.path.lastIndexOf('/') + 1) : '';
  return { chip: k ? k.letter : null, kicker: `${k ? k.label : s.kind}${dir ? ` · ${dir}` : ''}`, title: s.label || s.name, tags, main, side, actions };
});

const VISIBLE = { hidden: 'not visible in transcript', partial: 'partly visible in transcript', shown: 'visible in transcript' };

// What a built-in item contains, and what is true of it wherever it is sent: shared by its own peek and the main
// agent's measured System prompt and Tool definitions rows.
const builtinContains = item => section('What it contains', pre(item.note || ''));
const builtinFacts = item => kv([['Sent to', 'every agent, every turn'], ['Visibility', VISIBLE[item.visible] || item.visible], ['Source', 'the coding agent itself, not your files']]);

registerPeek('builtin', (env, id) => {
  const item = (env.ix.view.builtin || []).find(b => b.key === id);
  if (!item) return null;
  const measured = !item.remainder && (item.key === 'system_prompt' || item.key === 'tool_definitions');
  const tags = [`${tk(item.tokens_est, true)} · ${item.remainder ? 'remainder' : measured ? 'measured' : 'estimated'}`, VISIBLE[item.visible] || item.visible];
  return {
    chip: '·', kicker: 'Built in', title: item.label, tags,
    main: [builtinContains(item)],
    side: [builtinFacts(item)],
    actions: [],
  };
});

// "<row key>:<node id>": a row has no colon, a node id may.
registerPeek('measured', (env, id) => {
  const at = id.indexOf(':');
  const node = at < 0 ? null : env.ix.nodes.get(id.slice(at + 1));
  const ic = node && node.detail && node.detail.in_context;
  const row = ic && (ic.rows || []).find(r => r.key === id.slice(0, at));
  if (!row || !row.measure) return null;
  const m = row.measure;
  const owner = nodeLabel(node);
  // The built-in items describe the main agent's own system prompt and tool definitions.
  const item = node.parent === null ? (env.ix.view.builtin || []).find(b => b.key === row.key) : null;
  return {
    chip: '·', kicker: `Measured · ${owner}`, title: row.label, tags: [`${k1(row.tokens_est)} · measured`],
    main: [section('How it was measured', kv([
      ['Request', ic.request_id],
      ['Characters', m.chars.toLocaleString('en-US')],
      ['Tokens per character', Number(ic.tokens_per_char).toPrecision(3)],
      ['Image tokens', m.images > 0 ? m.images.toLocaleString('en-US') : null],
      ['Already listed above', m.listed_above > 0 ? k1(m.listed_above) : null],
    ]), nk(`The share is the row’s characters times the tokens per character${m.images > 0 ? ', plus its image tokens' : ''}${m.listed_above > 0 ? ', less what is already listed above' : ''}.`)), ...(item ? [builtinContains(item)] : [])],
    side: item ? [builtinFacts(item)] : [],
    actions: [],
  };
});

registerPeek('task', (env, id) => {
  const { ix } = env;
  const node = ix.nodes.get(id);
  if (!node || node.parent === null) return null;
  const parent = ix.nodes.get(node.parent);
  const row = ((node.detail.in_context || {}).rows || []).find(r => r.key === 'task');
  const body = node.detail.brief ? fetched(env.text('brief:' + id, briefUrl(id)), e => e.text) : nk('The prompt text was not recorded.');
  const writer = parent ? nodeLabel(parent) : 'its parent';
  const b = action('Show in graph', {});
  b.dataset.showInGraph = id;
  return {
    chip: '✎', kicker: `Task prompt · written by ${writer}`, title: node.name,
    tags: row ? [`${tk(row.tokens_est, true)} · estimated`] : [],
    main: [section('The prompt', body)],
    side: [kv([['Written by', writer], ['Sent at', clock(node.start)], ['To', `${node.name} · ${typeOf(ix, node).label}`]]),
      nk('What the parent asked this subagent to do. With its definition and inherited instructions this is everything it was told.')],
    actions: [b],
  };
});

function bar(values, total) {
  const box = el('div', 'stack');
  values.forEach(([i, v]) => {
    if (v <= 0 || total <= 0) return;
    const seg = el('i');
    seg.style.width = `${v / total * 100}%`;
    seg.style.background = bandColour(i);
    box.append(seg);
  });
  return box;
}

registerPeek('peak', (env, id) => {
  const { ix } = env;
  const node = ix.nodes.get(id);
  const hit = node && peakOf(node);
  if (!hit) return null;
  const { comp, reply } = hit;
  const total = reply[1], parts = replyParts(comp, reply), measured = replyMeasured(reply);
  const adapter = ix.view.adapter;
  const base = Math.max(total, parts.reduce((a, b) => a + b, 0));
  const cats = adapter.composition.map(c => ({ c, i: comp.keys.indexOf(c.key) })).filter(x => x.i >= 0 && parts[x.i] > 0);
  const legend = el('div', 'pk-legend');
  for (const { c, i } of cats) {
    const rest = !measured && c.key === adapter.composition_remainder;
    const line = el('div', 'pk-lg');
    line.dataset.category = c.key;
    const sw = el('span', 'swatch');
    sw.style.background = bandColour(i);
    line.append(sw, el('span', 'lb', rest ? `${c.label}*` : c.label), el('span', 'v mono', `${measured ? '' : '~'}${k1(parts[i])}`), el('span', 'pct mono', `${Math.min(100, Math.round(parts[i] / base * 100))}%`));
    legend.append(line);
  }
  const cached = Math.round(reply[4] / total * 100);
  const over = replyOver(reply);
  const remLabel = (adapter.composition.find(c => c.key === adapter.composition_remainder) || {}).label || adapter.composition_remainder;
  return {
    chip: '∑', kicker: `Peak context · ${nodeLabel(node)} at ${clock(reply[0])}`, title: `${total.toLocaleString('en-US')} tokens`, tags: [],
    main: [bar(cats.map(x => [x.i, parts[x.i]]), base), legend],
    side: [kv([['Read from cache at this turn', `${cached}%`], ['New this turn', `${(reply[2] + reply[3]).toLocaleString('en-US')} tokens`]]),
      ...(over ? [nk('These estimates add up to more than the exact total, so the split is approximate and the percentages are shares of what was estimated.')] : []),
      measured
        ? nk('The total and the parts are measured: each part is its share of the request Claude Code recorded for this turn, scaled to the exact total. Instruction files, rules, memory, the skills listing and hook notes are estimated from their sizes.')
        : nk(`The total is measured. How it splits into parts is estimated, so parts show ~. *Includes whatever could not be attributed, folded into ${remLabel}, so the parts add up to the total.`)],
    actions: [],
  };
});

registerPeek('cost', (env, id) => {
  const { ix } = env;
  const node = ix.nodes.get(id);
  const cost = node && node.detail && node.detail.cost;
  if (!cost || cost.total_usd == null) return null;
  const list = ix.view.price_list;
  const pairs = [['Over', plural(cost.turns, 'turn')]];
  if (cost.peak_turn_usd != null) pairs.push(['Most expensive turn', `${usd(cost.peak_turn_usd)}${cost.peak_turn_t != null ? ` at ${clock(cost.peak_turn_t)}` : ''}`]);
  if (cost.instructions_usd_est != null) pairs.push(['Your instruction files', `~${usd(cost.instructions_usd_est)} of it`]);
  if (cost.cache_hit_rate != null) pairs.push(['Read from cache across all replies', `${Math.round(cost.cache_hit_rate * 100)}% (cheaper)`]);
  const session = sessionCost(ix.view, node);
  const main = [];
  if (session) {
    const { sc, subs, n, others } = session;
    pairs.unshift(['Session', `~${usd(sc.total_usd)}`], ['This agent', `~${usd(cost.total_usd)}`], [plural(n, 'subagent'), `~${usd(subs)}`]);
    if (sc.unpriced > 0) pairs.push(['Pricing', plural(sc.unpriced, 'reply', 'replies') + ' not priced']);
    const list = el('div', 'pk-list');
    for (const [id, usdEst] of others.slice(0, 5)) {
      const kid = ix.nodes.get(id);
      if (!kid) continue;
      const b = el('button', 'pk-li');
      b.type = 'button';
      b.dataset.showInGraph = id;
      b.append(el('span', 'lb', kid.name), el('span', 'mono v', `~${usd(usdEst)}`));
      list.append(b);
    }
    main.push(kv(pairs), section('Costliest subagents', list));
  }
  const notes = [];
  if (cost.unpriced > 0) notes.push(nk(`${plural(cost.unpriced, 'reply', 'replies')} not priced${cost.unpriced_models.length ? `: ${cost.unpriced_models.join(', ')}` : ' (no model named)'}.`));
  if (cost.split_assumed > 0) notes.push(nk(`${plural(cost.split_assumed, 'reply', 'replies')} had no 5-minute / 1-hour cache split and ${cost.split_assumed === 1 ? 'was' : 'were'} priced at the 5-minute rate.`));
  notes.push(nk(`Token counts are measured; the price is list price (${list.name}, ${list.as_of}). On a subscription you don't pay per token, so read this as API-equivalent.`));
  return {
    chip: '$', kicker: `Est. cost · ${nodeLabel(node)}`, title: usd(cost.total_usd), tags: [],
    main: main.length ? main : [kv(pairs)], side: notes, actions: [],
  };
});
