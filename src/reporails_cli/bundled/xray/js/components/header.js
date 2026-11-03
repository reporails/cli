// The header: logo, breadcrumb of the agent path, the tabs with their counts, the session's date and length, and the adapter chip.
import { el, tpl, slot } from '../dom.js';
import { dur, k1, plural, startedAt } from '../format.js';
import { xrayFetch, text, sessionsUrl, firstPromptUrl } from '../api.js';
import { hashFor } from '../state.js';
import { TABS, tabCounts } from '../views.js';

const MAX_SHOWN = 3;

function crumb(node, path, last) {
  if (last) return el('b', 'crumb here', node.name);
  const a = el('a', 'crumb', node.name);
  a.href = hashFor(path);
  return a;
}

// Past three levels the middle ones collapse to "…".
export function crumbs(ix, path) {
  const nodes = path.map(id => ix.nodes.get(id));
  const last = path.length - 1;
  const parts = path.length > MAX_SHOWN ? [0, -1, last] : path.map((_, i) => i);
  const out = [];
  for (const i of parts) {
    if (out.length) out.push(el('span', 'sep', '/'));
    if (i !== -1) { out.push(crumb(nodes[i], path.slice(0, i + 1), i === last)); continue; }
    const gap = el('span', 'crumb gap', '…');
    gap.title = nodes.slice(1, -1).map(n => n.name).join(' / ');
    out.push(gap);
  }
  return out;
}

// The session switcher: its list is fetched when opened, a session's first prompt only when its toggle is clicked.
const sw = { open: false, list: null, current: null, prompts: new Set(), box: null, env: null };

const lengthOf = e => (e.length_s != null ? dur(e.length_s) : '');
const facts = e => [startedAt(e.started_at), lengthOf(e), plural(e.subagents || 0, 'subagent')].filter(Boolean).join(' · ');

async function loadSessions() {
  const res = await xrayFetch(sessionsUrl());
  if (res && res.ok && res.j && Array.isArray(res.j.sessions)) { sw.list = res.j.sessions; sw.current = res.j.session; }
  if (sw.box) render(sw.box, sw.env);
}

function renderSwitch(box, v) {
  const btn = slot(box, 'swbtn'), list = slot(box, 'swlist');
  const cur = sw.list && sw.list.find(e => e.session === sw.current);
  btn.textContent = cur ? facts(cur) : [startedAt(v.started_at), lengthOf(v)].filter(Boolean).join(' · ') || 'sessions';
  btn.setAttribute('aria-expanded', String(sw.open));
  list.hidden = !sw.open;
  if (!sw.open || !sw.list) return;
  for (const e of sw.list) {
    const row = tpl('t-session-item');
    const pick = slot(row, 'pick'), fp = slot(row, 'fp'), body = slot(row, 'fptext');
    slot(row, 'label').textContent = facts(e);
    pick.dataset.session = e.session;
    if (e.session === sw.current) pick.setAttribute('aria-current', 'true');
    fp.dataset.session = e.session;
    const shown = sw.prompts.has(e.session);
    fp.setAttribute('aria-expanded', String(shown));
    if (shown) {
      const t = text('first:' + e.session, firstPromptUrl(e.session), true);
      body.hidden = false;
      body.textContent = t.loading ? 'loading…' : t.error ? t.error : t.text;
    }
    list.append(row);
  }
}

document.addEventListener('click', e => {
  if (!sw.box) return;
  const t = e.target;
  const pick = t.closest('.swpick'), fp = t.closest('.swfp');
  if (pick) { location.search = '?session=' + encodeURIComponent(pick.dataset.session); return; }
  if (fp) { const id = fp.dataset.session; if (!sw.prompts.delete(id)) sw.prompts.add(id); render(sw.box, sw.env); return; }
  if (t.closest('.swbtn')) { sw.open = !sw.open; if (sw.open) loadSessions(); render(sw.box, sw.env); return; }
  if (sw.open && !t.closest('.swlist')) { sw.open = false; render(sw.box, sw.env); }
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && sw.open && sw.box) { sw.open = false; e.preventDefault(); render(sw.box, sw.env); }
});

const TAB_LABELS = { graph: 'Graph', calls: 'Tool calls', sources: 'Sources' };

function renderTabs(box, env) {
  const counts = tabCounts(env.ix);
  const list = slot(box, 'tabs');
  for (const key of TABS) {
    const on = env.tab === key;
    const b = el('button', 'tab', TAB_LABELS[key]);
    b.type = 'button';
    b.dataset.tab = key;
    b.id = `tab-${key}`;
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
    b.append(el('span', 'n', String(counts[key])));
    list.append(b);
  }
}

export function render(box, env) {
  const { ix, state } = env;
  const v = ix.view;
  box.replaceChildren(tpl('t-header'));
  const first = !sw.box;
  sw.box = box; sw.env = env;
  renderSwitch(box, v);
  if (first) loadSessions();
  slot(box, 'crumbs').replaceChildren(...crumbs(ix, state.path));
  renderTabs(box, env);
  slot(box, 'session').textContent = [v.project].filter(Boolean).join(' · ');
  const win = v.window && v.window.size ? `${k1(v.window.size)} window${v.window.basis === 'observed' ? '' : ' (' + v.window.basis + ')'}` : '';
  slot(box, 'model').textContent = [v.model, win].filter(Boolean).join(' · ');
  const n = v.adapter.nesting;
  slot(box, 'adapter').textContent = `adapter: ${v.adapter.tool} · nesting ${n.enabled ? 'on' : 'off'}`;
}
