// A workflow run: its card on the canvas (name, status, agents, tokens, phases) and its details with the agents under their
// phases. Every fact is the view's.
import { el, nk } from '../dom.js';
import { clock, dur, tk } from '../format.js';
import { markOpen, registerPeek } from './details.js';

const runName = w => w.name || `workflow ${w.run_id}`;
const agentsOf = w => `${w.agent_count} agent${w.agent_count === 1 ? '' : 's'}`;

export function workflowCard(env, w, p, abs) {
  const box = abs('card workflow' + (w.refusal ? ' unreadable' : ''), p.left, p.top, 'button');
  box.dataset.workflow = w.run_id;
  box.dataset.peek = `workflow:${w.run_id}`;
  markOpen(box, env.state.peek, [box.dataset.peek]);
  box.style.width = '132px';
  box.style.height = '76px';
  const phases = w.phases.map(x => x.title).join(' → ');
  const sub = w.refusal ? `${w.status_text} · ${agentsOf(w)}` : [w.status_text, agentsOf(w), w.total_tokens == null ? null : tk(w.total_tokens, true)].filter(Boolean).join(' · ');
  box.title = `${runName(w)} · ${sub}${phases ? ' · phases: ' + phases : ''}`;
  box.setAttribute('aria-label', `Workflow ${runName(w)}, ${sub}${phases ? ', phases ' + phases : ''}: open details`);
  box.append(el('span', 'wf-k mono', '⚙ workflow'), el('b', 'wf-n', runName(w)), el('span', 'wf-s mono', sub), el('span', 'wf-p mono', phases));
  return box;
}

registerPeek('workflow', (env, id) => {
  const w = (env.ix.view.workflows || []).find(x => x.run_id === id);
  if (!w) return null;
  const facts = el('div', 'pk-kv');
  const rows = [['Workflow', runName(w)], ['Status', w.status_text], ['Agents', String(w.agent_count)], ['Tokens', w.total_tokens == null ? null : `${tk(w.total_tokens, true)}`], ['Started', w.start == null ? null : clock(w.start)], ['Took', w.duration_ms == null ? null : dur(w.duration_ms / 1000)], ['Run', w.run_id]];
  for (const [k, v] of rows) if (v) facts.append(el('span', 'lb', k), el('span', 'v', v));
  const list = el('div', 'pk-list');
  const agentButton = agent => {
    const node = env.ix.nodes.get(agent);
    const b = el('button', 'wf-agent', node ? node.name : agent);
    b.type = 'button';
    b.dataset.showInGraph = agent;
    return b;
  };
  const headed = (text, phase, agents) => {
    const head = el('span', 'wf-phase', `${text} · ${agents.length} agent${agents.length === 1 ? '' : 's'}`);
    head.dataset.phase = phase;
    list.append(head, ...agents.map(agentButton));
  };
  w.phases.forEach((phase, i) => headed(`${i + 1}. ${phase.title}`, phase.title, phase.agents));
  if (w.unphased.length) headed('Not in a phase the run names', '', w.unphased);
  const sec = (title, ...nodes) => { const s = el('section', 'pk-sec'); s.append(el('h4', null, title), ...nodes); return s; };
  return {
    chip: '⚙', kicker: 'Workflow', title: runName(w), tags: [w.status_text, agentsOf(w)],
    main: [sec('Facts', facts), sec('Phases', w.phases.length || w.unphased.length ? list : nk('The run names no phase.'))],
    side: [w.refusal ? sec('Not readable', nk(`The run's record is not in the shape this version reads: ${w.refusal}`)) : nk('Each agent is also a card on the graph.')],
    actions: [],
  };
});
