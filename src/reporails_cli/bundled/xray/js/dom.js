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

// Brings `box` to hold `nodes` while touching only what differs: an element the new content repeats stays in the page
// as it is (keeping its focus, scroll position and any open state), an attribute or text that changed is set in place,
// and only an element that is no longer the same kind is replaced.
const sameKind = (a, b) => a.nodeType === b.nodeType && (a.nodeType !== 1 || (a.namespaceURI === b.namespaceURI && a.tagName === b.tagName));

function morph(old, next) {
  if (old.nodeType !== 1) { if (old.data !== next.data) old.data = next.data; return; }
  for (const { name, value } of [...next.attributes]) if (old.getAttribute(name) !== value) old.setAttribute(name, value);
  for (const { name } of [...old.attributes]) if (!next.hasAttribute(name)) old.removeAttribute(name);
  fill(old, [...next.childNodes]);
}

// How far ahead an element that is still wanted later is looked for before it is taken for changed.
const AHEAD = 8;

function fill(box, nodes) {
  nodes.forEach((n, i) => {
    const old = box.childNodes[i];
    if (!old) box.append(n);
    else if (old.isEqualNode(n)) return;
    // The element here is wanted further on: what is new goes in front of it, and it stays.
    else if (nodes.slice(i + 1, i + 1 + AHEAD).some(m => old.isEqualNode(m))) box.insertBefore(n, old);
    else if (sameKind(old, n)) morph(old, n);
    else old.replaceWith(n);
  });
  while (box.childNodes.length > nodes.length) box.lastChild.remove();
}

export function sync(box, ...nodes) {
  fill(box, nodes.flatMap(n => (n instanceof DocumentFragment ? [...n.childNodes] : [n])));
}

export const nk = text => el('div', 'nk', text);
export const err = text => el('div', 'err', text);
