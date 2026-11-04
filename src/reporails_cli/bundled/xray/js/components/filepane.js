// The findings drill-down at #/file/<path>: a source's findings, who had it, and its text.
import { tk, plural, exclusionNote } from '../format.js';
import { el, tpl, slot, nk } from '../dom.js';
import { text, peekUrl } from '../api.js';
import { textBlock } from './textblock.js';
import { render as renderFindings, tally } from './findings.js';

function whoHad(ix, s) {
  if (s.availability === 'listed') return 'Listed to the model, never loaded this session.';
  if (s.availability === 'on_disk') return 'On disk, never loaded this session.';
  const names = s.had_by.map(id => ix.nodes.get(id).name);
  return `Loaded by ${plural(names.length, 'agent')}: ${names.join(', ')}.`;
}

function actions(s, env) {
  const out = document.createDocumentFragment();
  out.append(el('h4', null, 'reporails'));
  const act = el('div', 'act');
  for (const [kind, label] of [['check', 'Check this file'], ['heal', 'Fix this file']]) {
    const b = el('button', null, label);
    b.dataset.act = kind;
    b.dataset.path = s.path;
    b.disabled = env.busy;
    act.append(b);
  }
  out.append(act);
  const note = exclusionNote(s.excluded);
  if (note) out.append(el('div', 'nk excluded', note));
  if (env.res && env.res.path === s.path) {
    const box = el('div');
    renderFindings(box, env.res);
    out.append(box);
  }
  return out;
}

export function render(box, env) {
  const { ix, state } = env;
  const s = ix.view.sources.find(x => x.path === state.file);
  box.replaceChildren(tpl('t-file-pane'));
  const back = slot(box, 'back');
  back.dataset.back = '1';
  if (!s) {
    slot(box, 'name').textContent = state.file;
    slot(box, 'pane').append(nk('This file is not one the session lists.'));
    return;
  }
  slot(box, 'name').textContent = s.name;
  slot(box, 'path').textContent = s.path;
  slot(box, 'detail').prepend(`${whoHad(ix, s)}${s.tokens_est ? ` · ${tk(s.tokens_est, true)} tokens` : ''}`);
  const pane = slot(box, 'pane');
  if (s.findings != null) {
    const h = el('h4', null, 'reporails findings, from the last check');
    h.append(tally(s.findings));
    pane.append(h);
  }
  if (s.actionable) pane.append(actions(s, env));
  else {
    const n = nk('outside this project; run ');
    n.append(el('code', null, 'ails check'), ' on it');
    pane.append(n);
    const why = exclusionNote(s.excluded);
    if (why) pane.append(el('div', 'nk excluded', why));
  }
  pane.append(el('h4', null, 'Its text'), textBlock(text, 'p:' + s.path, peekUrl(s.path)));
}
