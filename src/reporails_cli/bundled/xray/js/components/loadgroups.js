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

// The group's id is the view's, which names the group by its first load.
registerPeek('loadgroup', (env, id) => {
  const station = env.ix.view.stations.find(st => st.groups.some(x => x.id === id));
  const g = station && station.groups.find(x => x.id === id);
  const node = station && env.ix.nodes.get(station.node);
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
