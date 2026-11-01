const SVG = 'http://www.w3.org/2000/svg';

// The cloned content of a <template> in index.html.
export const tpl = id => document.getElementById(id).content.cloneNode(true);
export const row = id => tpl(id).firstElementChild;
export const slot = (root, name) => root.querySelector(`[data-slot="${name}"]`);

export function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

export function svg(tag, attrs = {}, text) {
  const e = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  if (text != null) e.textContent = text;
  return e;
}

export const nk = text => el('div', 'nk', text);
export const err = text => el('div', 'err', text);
