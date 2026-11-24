// The compaction's details: when it ran, what started it, the context before and after, the summary it left and the
// instruction files with no card below the stripe (the files that have one are drawn on the canvas).
import { el, nk } from '../dom.js';
import { clock, k1, tk } from '../format.js';
import { summaryUrl } from '../api.js';
import { textBlock } from './textblock.js';
import { registerPeek } from './details.js';
import { loadedKeys } from '../views.js';

// What the page says of each state of an instruction file with no card after a compaction, and why.
export const FILE_STATE_WORDS = {
  reloaded: ['loaded again after the compaction', 'the file was loaded into the context again'],
  restored: ['kept in the messages the compaction preserved', 'the file came back inside the preserved messages, not as a new load'],
  pending: ['settles at the next reply', 'whether the file came back is known after the next reply'],
  named: ['named only: the agent must read it again', 'Claude Code told the agent the file name, not its content'],
  summarized: ['only in the summary', 'nothing of the file came back; the agent knows only what the summary says'],
};

const section = (title, ...nodes) => {
  const box = el('section', 'pk-sec');
  box.append(el('h4', null, title), ...nodes);
  return box;
};

// "<node id>:<index>": a node id may hold colons, the index never does.
registerPeek('compaction', (env, id) => {
  const at = id.lastIndexOf(':');
  const nodeId = id.slice(0, at);
  const node = env.ix.nodes.get(nodeId);
  const c = ((env.ix.stations.get(nodeId) || { compactions: [] }).compactions)[Number(id.slice(at + 1))];
  if (!node || !c) return null;
  const sizes = c.before != null && c.after != null ? `${k1(c.before)} → ${k1(c.after)}` : null;
  const facts = el('div', 'pk-kv');
  for (const [k, v] of [['At', clock(c.t)], ['Started by', c.trigger], ['Context', sizes]]) {
    if (v) facts.append(el('span', 'lb', k), el('span', 'v', v));
  }
  const left = c.summary_id
    ? section(`What is left after the compaction · ${tk(c.summary_tokens, true)}`, textBlock(env.text, `summary:${c.summary_id}`, summaryUrl(c.summary_id)))
    : section('What is left after the compaction', nk('The transcript holds no summary for this compaction.'));
  const files = el('div', 'pk-list');
  const index = Number(id.slice(at + 1));
  const loaded = loadedKeys(env.ix, node);
  const gone = (c.files || []).filter(f => !loaded.has(`${index + 1}|${f.source}`));
  for (const f of gone) {
    const s = env.ix.sources.get(f.source);
    const [words, why] = FILE_STATE_WORDS[f.state] || [f.state, ''];
    const row = el('span', `fs fs-${f.state}`, `${s ? s.label : f.source} · ${words}`);
    row.title = why;
    files.append(row);
  }
  return {
    chip: '▤', kicker: `Compaction · ${node.name}`, title: `compacted at ${clock(c.t)}`, tags: [c.trigger, sizes].filter(Boolean),
    main: [section('Facts', facts), left],
    side: [gone.length ? section('Not loaded again', files) : nk(
      (c.files || []).length
        ? 'Every instruction file loaded before it came back; each is drawn below the stripe.'
        : 'No instruction file was loaded before it.')],
    actions: [],
  };
});
