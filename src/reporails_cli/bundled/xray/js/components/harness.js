// part: one harness item of the view. Reads nothing from ctx.
import { tk, clock } from '../format.js';
import { tpl, slot } from '../dom.js';

const KIND = {
  system_prompt: ['System prompt', 'Claude Code’s own instructions, sent every turn.'], deferred_tools: ['Deferred tools', 'Tool names listed; their schemas load on demand.'],
  agent_list: ['Agent listing', 'The subagent types Claude Code listed to the model.'], mcp_instructions: ['MCP instructions', 'Instructions the connected MCP servers added.'],
  skill_list: ['Skill listing', 'The skills Claude Code listed to the model: names and descriptions, not bodies.'], session_context: ['Session context', 'Account and environment facts added at session start.'],
  hook_note: ['Session-start hook notes', 'Text your SessionStart hooks added.'],
};

export function render(box, x) {
  const d = KIND[x.kind] || [x.label, ''];
  box.replaceChildren(tpl('t-harness-pane'));
  slot(box, 'name').textContent = x.label;
  const dm = slot(box, 'detail');
  dm.append(d[1], document.createElement('br'), `${x.count != null ? x.count + ' · ' : ''}${tk(x.tokens_est, true)} tokens${x.t != null ? ' · arrived at ' + clock(x.t) : ''}`);
}
