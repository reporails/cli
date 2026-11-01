// part: art (the artifacts, each with its `key`), harness. ctx: sel, groupsOpen.
import { tk } from '../format.js';
import { el, row, tpl, slot, nk } from '../dom.js';

const GROUPS = [['instructions', 'Instruction files'], ['rule', 'Rules'], ['memory', 'Memory'], ['skill', 'Skills'], ['agent', 'Agents'], ['command', 'Commands'], ['hook', 'Hooks'], ['harness', 'Harness']];
const LISTING_OF = { skill: 'skill_list', agent: 'agent_list' };

const sorted = (list, by) => [...list].sort(by);
const noneRow = text => { const n = nk(text); n.style.padding = '4px 10px'; return n; };

// The scope and link tags of an artifact (the file pane shows them too).
export function tagsOf(a) {
  const tags = [];
  if (a.scope === 'plugin') tags.push(el('span', 'tag', a.plugin || a.scope));
  else if (a.scope !== 'project' && a.scope !== 'auto') tags.push(el('span', 'tag', a.scope));
  if (a.linked === false) tags.push(el('span', 'tag warn', 'not linked'));
  return tags;
}

function fileRow(a, ctx) {
  const r = row('t-file');
  if (ctx.sel && ctx.sel.file === a.key) r.classList.add('on');
  r.dataset.file = a.key;
  r.title = a.path;
  r.querySelector('.sd').classList.add(a.loaded ? 'in' : 'not');
  slot(r, 'label').textContent = a.label;
  tagsOf(a).forEach(t => r.insertBefore(t, slot(r, 'sp')));
  if (a.findings != null) r.insertBefore(el('span', 'fc' + (a.findings ? '' : ' zero'), String(a.findings)), slot(r, 'tk'));
  slot(r, 'tk').textContent = tk(a.tokens_est, true);
  return r;
}

function groupHead(k, label, open, summary) {
  const g = row('t-group');
  g.dataset.group = k;
  g.querySelector('.cv').textContent = open ? '▾' : '▸';
  g.querySelector('.gt').textContent = label;
  g.querySelector('.gc').append(...summary);
  return g;
}

function harnessRows(harness, ctx) {
  if (!harness.length) return [noneRow('not known here')];
  return harness.map((x, i) => {
    const r = row('t-harness-row');
    if (ctx.sel && ctx.sel.harness === i) r.classList.add('on');
    r.dataset.harness = String(i);
    slot(r, 'label').textContent = x.label + (x.count != null ? ' · ' + x.count : '');
    slot(r, 'tk').textContent = tk(x.tokens_est, true);
    return r;
  });
}

function kindRows(k, part, ctx) {
  const items = part.art.filter(a => a.kind === k);
  const loaded = items.filter(a => a.loaded);
  const unlinked = k === 'memory' ? items.filter(a => a.linked === false).length : 0;
  const listing = LISTING_OF[k] ? part.harness.find(x => x.kind === LISTING_OF[k]) : null;
  const listed = listing ? listing.count : null;
  const summary = [`${items.length} · ${loaded.length} loaded`];
  if (unlinked) summary.push(' · ', el('b', 'warn', `${unlinked} not linked`));
  if (listed != null) summary.push(` · ${listed} listed`);
  const open = ctx.groupsOpen.has(k);
  const out = [groupHead(k, GROUPS.find(g => g[0] === k)[1], open, summary)];
  if (!open) return out;
  const rest = sorted(items.filter(a => !a.loaded), (a, b) => (b.linked === false) - (a.linked === false) || a.scope.localeCompare(b.scope) || a.label.localeCompare(b.label));
  out.push(...sorted(loaded, (a, b) => a.path.localeCompare(b.path)).map(a => fileRow(a, ctx)));
  if (rest.length) out.push(el('div', 'ondisk', `+${rest.length} on disk, not loaded`), ...rest.map(a => fileRow(a, ctx)));
  if (!items.length) out.push(noneRow('none found on disk'));
  return out;
}

export function render(card, part, ctx) {
  const keepScroll = card.querySelector('#alist')?.scrollTop ?? 0;
  card.replaceChildren(tpl('t-artifacts'));
  const list = card.querySelector('#alist');
  GROUPS.forEach(([k, label]) => {
    if (k !== 'harness') return list.append(...kindRows(k, part, ctx));
    const open = ctx.groupsOpen.has(k);
    list.append(groupHead(k, label, open, [`${part.harness.length} at session start`]));
    if (open) list.append(...harnessRows(part.harness, ctx));
  });
  list.scrollTop = keepScroll;
}
