// The details of a load group: the hook whose firing caused the loads, when they came and the files they loaded, one row per
// file with how many times it was loaded. Every number is the view's.
import { el, nk } from '../dom.js';
import { clock, tk } from '../format.js';
import { registerPeek } from './details.js';

const section = (title, ...nodes) => {
  const box = el('section', 'pk-sec');
  box.append(el('h4', null, title), ...nodes);
  return box;
};

// "<node id>:<index>": a node id may hold colons, the index never does.
registerPeek('loadgroup', (env, id) => {
  const at = id.lastIndexOf(':');
  const node = env.ix.nodes.get(id.slice(0, at));
  const station = env.ix.stations.get(id.slice(0, at));
  const g = station && station.groups[Number(id.slice(at + 1))];
  if (!node || !g) return null;
  const hook = env.ix.sources.get(g.hook);
  const name = hook ? hook.label : g.hook;
  const facts = el('div', 'pk-kv');
  for (const [k, v] of [['Hook', name], ['From', clock(g.first)], ['To', clock(g.last)], ['Loads', String(g.count)], ['Size', `${tk(g.tokens_est, true)} (estimated)`]]) {
    facts.append(el('span', 'lb', k), el('span', 'v', v));
  }
  const files = el('div', 'pk-list');
  for (const f of g.files) {
    const s = env.ix.sources.get(f.source);
    const row = el('span', 'lg-file', `${s ? s.label : f.source}${f.count > 1 ? ` ×${f.count}` : ''} · ${tk(f.tokens_est, true)}`);
    row.dataset.count = String(f.count);
    files.append(row);
  }
  return {
    chip: 'H', kicker: `Loads caused by a hook · ${node.name}`, title: name, tags: [`${g.count} loads`, `${g.files.length} files`, tk(g.tokens_est, true)],
    main: [section('Facts', facts), section('Instruction loads', files)],
    side: [nk('These loads are shown as one card; each is still part of the agent’s context.')],
    actions: [],
  };
});
