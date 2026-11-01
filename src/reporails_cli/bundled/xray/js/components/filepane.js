// part: artifact (one of the view's), where (its arrival in words). ctx: busy, res ({path, ...a findings part}), run(kind, path), text.
import { tk } from '../format.js';
import { el, tpl, slot, nk } from '../dom.js';
import { tagsOf } from './artifacts.js';
import { textBlock } from './textblock.js';
import { render as renderFindings } from './findings.js';

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
  dm.prepend(`${part.where}${a.tokens_est ? ` · ${tk(a.tokens_est, true)} tokens` : ''}`);
  slot(box, 'path').textContent = a.path;
  if (a.findings != null) {
    const h = el('h4', null, 'reporails findings, from the last check');
    h.append(el('span', null, String(a.findings)));
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
