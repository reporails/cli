// part: artifact (one of the view's). ctx: busy, res ({path, ...a findings part}), run(kind, path), text.
import { tk, k1, plural } from '../format.js';
import { el, tpl, slot, nk } from '../dom.js';
import { tagsOf } from './artifacts.js';
import { textBlock } from './textblock.js';
import { render as renderFindings, tally } from './findings.js';

const lab = n => n === 0 ? 'start' : String(n);
const ranges = ns => {
  const out = [];
  let i = 0;
  while (i < ns.length) {
    let j = i;
    while (j + 1 < ns.length && ns[j + 1] === ns[j] + 1) j++;
    out.push(ns[i] === ns[j] ? lab(ns[i]) : `${lab(ns[i])}–${ns[j]}`);
    i = j + 1;
  }
  return out.join(', ');
};

// Where and when the file entered the context, in words, from the artifact's own fields.
function whereLoaded(a) {
  if (!a.loaded) return 'On disk, not loaded this session.';
  const ns = a.turns || [];
  const arrived = ns.length ? (ns[0] === 0 ? 'Arrived at session start' : `Arrived in turn ${ns[0]}`) : 'Arrived by a skill call';
  const cost = a.contexts ? `, in ${plural(a.contexts, 'context')}${a.session_tokens_est != null ? `, ~${k1(a.session_tokens_est)} tokens across the session` : ''}` : '';
  return `${arrived}; in context in ${ns.length ? 'turns ' + ranges(ns) : 'no turn recorded'}${cost}.`;
}

function actions(a, ctx) {
  const out = document.createDocumentFragment();
  out.append(el('h4', null, 'reporails'));
  const act = el('div', 'act');
  for (const [kind, label] of [['check', 'Check this file'], ['heal', 'Fix this file']]) {
    const b = el('button', null, label);
    b.dataset.act = kind;
    b.dataset.path = a.path;
    b.disabled = ctx.busy;
    act.append(b);
  }
  out.append(act);
  if (ctx.res && ctx.res.path === a.path) {
    const box = document.createElement('div');
    renderFindings(box, ctx.res);
    out.append(box);
  }
  return out;
}

export function render(box, part, ctx) {
  const a = part.artifact;
  box.replaceChildren(tpl('t-file-pane'));
  const name = slot(box, 'name');
  name.textContent = a.label;
  name.after(...tagsOf(a));
  const pane = slot(box, 'pane');
  const dm = slot(box, 'detail');
  dm.prepend(`${whereLoaded(a)}${a.tokens_est ? ` · ${tk(a.tokens_est, true)} tokens` : ''}`);
  slot(box, 'path').textContent = a.path;
  if (a.findings != null) {
    const h = el('h4', null, 'reporails findings, from the last check');
    h.append(tally(a.findings));
    pane.append(h);
  }
  const hook = a.kind === 'hook';
  if (a.actionable && !hook) pane.append(actions(a, ctx));
  else if (!hook) {
    const n = nk('outside this project; run ');
    n.style.margin = '2px 0 4px';
    n.append(el('code', null, 'ails check'), ' on it');
    pane.append(n);
  }
  if (hook) return pane.append(nk('a hook configuration; its text is not shown'));
  pane.append(el('h4', null, 'Its text'), textBlock(ctx, 'p:' + a.path, 'peek?path=' + encodeURIComponent(a.path)));
}
