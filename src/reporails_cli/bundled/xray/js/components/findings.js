import { el, nk, err, sync } from '../dom.js';

// A file's findings as a compact count; errors, when there are any, show red beside it.
export function tally(f) {
  const s = f.by_severity || {};
  const box = el('span', 'fcs');
  box.title = `${s.error || 0} errors, ${s.warning || 0} warnings, ${s.info || 0} info`;
  box.append(el('span', 'fc' + (f.count ? '' : ' zero'), String(f.count)));
  if (s.error > 0) box.append(el('span', 'fc bad', `${s.error} err`));
  return box;
}

const safeLink = url => typeof url === 'string' && url.startsWith('https://');

// A check or fix result: part is {running}, {error} or the server's reply ({lines} of a check, {receipt} of a fix).
export function render(box, part) {
  if (part.running) return sync(box, nk('Running…'));
  if (part.error) return sync(box, err(part.error));
  if (Array.isArray(part.lines)) {
    if (!part.lines.length) return sync(box, nk('no findings'));
    const out = part.lines.map(l => {
      const d = el('div', 'fl');
      d.append(el('span', 'ln', l.file_level ? 'whole file' : `line ${l.line == null ? '—' : l.line}`));
      if (l.severity) d.append(el('span', 'sv ' + l.severity, l.severity));
      d.append(el('span', 'rl', l.rule));
      if (l.title) d.append(el('span', 'ttl', l.title));
      d.append(el('span', 'msg', l.message));
      if (l.category) d.append(el('span', 'nk', l.category));
      if (safeLink(l.docs_url)) {
        const a = el('a', null, 'docs');
        a.setAttribute('href', l.docs_url);
        a.setAttribute('rel', 'noopener');
        a.setAttribute('target', '_blank');
        d.append(a);
      }
      return d;
    });
    if (part.fix_command) out.push(el('code', 'cmd', part.fix_command));
    return sync(box, ...out);
  }
  if (Array.isArray(part.receipt)) {
    if (!part.receipt.length) return sync(box, nk('nothing to fix'));
    return sync(box, ...part.receipt.map(l => el('div', 'rc', l)));
  }
  sync(box, err('The reply had no result.'));
}
