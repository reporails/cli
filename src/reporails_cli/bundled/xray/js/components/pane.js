// A compact/open inspector pane: a header button with a rotating chevron, the body shown only when open.
import { el } from '../dom.js';
import { state } from '../state.js';

// `head` is the header's content (nodes); `body` the content shown when open. Each key's open state lives in the page state.
export function pane(key, head, body, cls) {
  const open = !!state.panes[key];
  const box = el('section', 'pane2 ' + (cls || ''));
  box.dataset.pane = key;
  const button = el('button', 'ph');
  button.type = 'button';
  button.setAttribute('aria-expanded', String(open));
  button.append(el('span', 'chev', '›'), ...head);
  const inner = el('div', 'pb');
  inner.hidden = !open;
  inner.append(...body);
  button.addEventListener('click', () => {
    const now = !state.panes[key];
    state.panes[key] = now;
    button.setAttribute('aria-expanded', String(now));
    inner.hidden = !now;
  });
  box.append(button, inner);
  return box;
}

export const tag = (text, tone) => el('span', 'tag ' + tone, text);
