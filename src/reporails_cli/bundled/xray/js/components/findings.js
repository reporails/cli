import { el, nk, err } from '../dom.js';

// A check or fix result: part is {running}, {error} or the server's reply ({lines} of a check, {receipt} of a fix).
export function render(box, part) {
  if (part.running) return box.replaceChildren(nk('Running…'));
  if (part.error) return box.replaceChildren(err(part.error));
  if (Array.isArray(part.lines)) {
    if (!part.lines.length) return box.replaceChildren(nk('no findings'));
    return box.replaceChildren(...part.lines.map(l => {
      const d = el('div', 'fl');
      d.append(el('span', 'ln', `line ${l.line == null ? '—' : l.line}`), el('span', 'rl', l.rule), el('span', null, l.message));
      return d;
    }));
  }
  if (Array.isArray(part.receipt)) {
    if (!part.receipt.length) return box.replaceChildren(nk('nothing to fix'));
    return box.replaceChildren(...part.receipt.map(l => el('div', 'rc', l)));
  }
  box.replaceChildren(err('The reply had no result.'));
}
