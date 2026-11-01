import { el, nk, err } from '../dom.js';

// The text behind a key, fetched once: loading, the refusal, or the text (as text, never as markup).
export function textBlock(ctx, key, url) {
  const e = ctx.text(key, url);
  const out = document.createDocumentFragment();
  if (e.loading) { out.append(nk('Loading…')); return out; }
  if (e.error) { out.append(err(e.error)); return out; }
  out.append(el('pre', 'peek', e.text));
  if (e.truncated) out.append(nk('text truncated'));
  return out;
}
