// usage: node xray_shell.mjs <page-url> <mode> [width]
// Drives the bundled page's shell (tabs, hint bar, details frame, layout, type and contrast) in headless Chrome and
// prints one JSON object per mode.
import { openPage, sleep } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440)];
const page = await openPage(url, width, 1000);
const ready = await page.until(`!!document.querySelector('.tab[data-tab]') && !!document.querySelector('#sources .sr')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const centre = sel => page.ev(`(() => { const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
const mouse = async (type, p, extra = {}) => page.send('Input.dispatchMouseEvent', { type, x: p.x, y: p.y, button: 'left', clickCount: 1, ...extra });
const realClick = async sel => {
  await page.ev(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({ block: 'center' }); 0`);
  const p = await centre(sel);
  await mouse('mouseMoved', p, { button: 'none' });
  await mouse('mousePressed', p);
  await mouse('mouseReleased', p);
};
const key = async (k, code, vk) => {
  await page.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: k, code, windowsVirtualKeyCode: vk });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk });
};
const esc = () => key('Escape', 'Escape', 27);
const active = () => page.ev(`(() => { const a = document.activeElement; return { cls: a.className, source: a.dataset.source || null, closePeek: a.hasAttribute('data-close-peek'), tag: a.tagName, id: a.id }; })()`);
const rowSel = n => `#sources .sr[data-source]:nth-of-type(${n})`;

if (mode === 'tabs' && ready) {
  out.tabs = await page.ev(`[...document.querySelectorAll('[role="tablist"] [role="tab"]')].map(t => ({ tab: t.dataset.tab, selected: t.getAttribute('aria-selected') === 'true', count: Number(t.querySelector('.n').textContent) }))`);
  out.shown = await page.ev(`[...document.querySelectorAll('[data-tabbody]')].filter(b => !b.hidden).map(b => b.dataset.tabbody)`);
  out.hint = await page.ev(`document.querySelector('#hint').textContent`);
  out.toolbar = await page.ev(`!!document.querySelector('#toolbar, .toolbar, [data-type]')`);
  await click('.tab[data-tab="sources"]');
  out.afterClick = await page.ev(`({ selected: document.querySelector('.tab[aria-selected="true"]').dataset.tab, shown: [...document.querySelectorAll('[data-tabbody]')].filter(b => !b.hidden).map(b => b.dataset.tabbody) })`);
}

if (mode === 'cards' && ready) {
  await page.until(`!!document.querySelector('.card[data-node="a4"]')`);
  const hash = await page.ev(`location.hash`);
  await page.ev(`(() => { const c = document.querySelector('.card[data-node="a4"]'); c.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, detail: 2 })); return 0; })()`);
  await sleep(300);
  out.afterDouble = { hash: await page.ev(`location.hash`), start: hash, sel: await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`) };
  await click('.card[data-node="a4"]');
  out.afterClick = { hash: await page.ev(`location.hash`), sel: await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`) };
}

// The boxes of the page's landmarks, so a hover or a focus can be shown to move none of them.
const BOXES = `(() => {
  const sels = ['#header', '.hdr *', '#hint', '#sources', '#sources .sr', '#sources .ssec', '.graphcol', '#canvas', '#canvas .cv', '#canvas .fbanner', '.card', '.station', '#inspector', '#rail'];
  return Object.fromEntries(sels.map(s => [s, [...document.querySelectorAll(s)].map(e => { const r = e.getBoundingClientRect(); return [Math.round(r.left * 10) / 10, Math.round(r.top * 10) / 10, Math.round(r.width * 10) / 10, Math.round(r.height * 10) / 10]; })]));
})()`;
const moved = (a, b) => Object.keys(a).filter(k => JSON.stringify(a[k]) !== JSON.stringify(b[k]));

if (mode === 'still' && ready) {
  await page.until(`!!document.querySelector('.card.top')`);
  const before = await page.ev(BOXES);
  out.hintBefore = await page.ev(`document.querySelector('#hint').getBoundingClientRect().height`);
  await mouse('mouseMoved', await centre(rowSel(2)), { button: 'none' });
  await sleep(200);
  out.hovered = await page.ev(`(document.querySelector('#canvas .fbanner') || {}).textContent || ''`);
  out.hoverRing = await page.ev(`document.querySelectorAll('.card.ring').length`);
  out.hoverMoved = moved(before, await page.ev(BOXES));
  out.hintHover = await page.ev(`document.querySelector('#hint').getBoundingClientRect().height`);
  await mouse('mouseMoved', { x: 5, y: 5 }, { button: 'none' });
  await sleep(200);
  await page.ev(`document.querySelector(${JSON.stringify(rowSel(3))}).focus(); 0`);
  await sleep(200);
  out.focused = await active();
  out.focusMoved = moved(before, await page.ev(BOXES));
  out.hintFocus = await page.ev(`document.querySelector('#hint').getBoundingClientRect().height`);
  out.count = Object.values(before).reduce((n, v) => n + v.length, 0);
}

if (mode === 'overlay' && ready) {
  await page.until(`!!document.querySelector('.card[data-node="a4"]')`);
  await click('.card[data-node="a4"]');
  const sel0 = await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`);
  await realClick(rowSel(2));
  await page.until(`!!document.querySelector('.pk-dialog')`);
  const opener = await page.ev(`(document.querySelector('#sources .sr.on') || {dataset: {}}).dataset.source || null`);
  out.rects = await page.ev(`(() => { const r = s => { const e = document.querySelector(s); if (!e) return null; const b = e.getBoundingClientRect(); return { left: b.left, top: b.top, right: b.right, bottom: b.bottom }; };
    return { dialog: r('.pk-dialog'), back: r('.pk-back'), col: r('#graphcol'), sources: r('#sources'), inspector: r('#inspector'), vh: innerHeight }; })()`);
  out.dialog = await page.ev(`(() => { const d = document.querySelector('.pk-dialog'); return { role: d.getAttribute('role'), modal: d.getAttribute('aria-modal'), label: document.getElementById(d.getAttribute('aria-labelledby')).textContent, maxWidth: getComputedStyle(d).maxWidth, blur: getComputedStyle(document.querySelector('.pk-back')).backdropFilter, tint: getComputedStyle(document.querySelector('.pk-back')).backgroundColor, closeLabel: document.querySelector('.pk-x').getAttribute('aria-label') }; })()`);
  out.focusOnOpen = await active();
  out.opener = opener;
  out.sel = sel0;
  await page.ev(`window.scrollTo(0, 400); 0`);
  await sleep(200);
  out.scrolled = await page.ev(`(() => { const b = document.querySelector('.pk-dialog').getBoundingClientRect(); return { top: b.top, bottom: b.bottom, scrollY: window.scrollY, vh: innerHeight }; })()`);
  await page.ev(`window.scrollTo(0, 0); 0`);
  await esc();
  await sleep(300);
  out.afterEsc1 = { dialog: await page.ev(`!!document.querySelector('.pk-dialog')`), focus: await active(), sel: await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`) };
  await esc();
  await sleep(300);
  out.afterEsc2 = { sel: await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`), dialog: await page.ev(`!!document.querySelector('.pk-dialog')`) };
  await realClick(rowSel(2));
  await page.until(`!!document.querySelector('.pk-dialog')`);
  await click('.pk-back');
  await sleep(300);
  out.afterBackdrop = { dialog: await page.ev(`!!document.querySelector('.pk-dialog')`), focus: await active() };
}

if (mode === 'side' && ready) {
  await click('.tab[data-tab="calls"]');
  out.empty = await page.ev(`document.querySelector('#side-calls').textContent`);
  await realClick(rowSel(2));
  await page.until(`!!document.querySelector('#side-calls .pk-panel')`);
  out.panel = await page.ev(`({ title: document.querySelector('#side-calls .pk-title').textContent, overlay: !document.querySelector('#overlay').hidden, dialogs: document.querySelectorAll('.pk-dialog').length, sourceName: document.querySelector('#sources .sr.on .sn').textContent })`);
  out.focus = await active();
  await esc();
  await sleep(300);
  out.closed = { panel: await page.ev(`!!document.querySelector('#side-calls .pk-panel')`), focus: await active() };
}

if (mode === 'fit' && ready) {
  await page.until(`!!document.querySelector('.card.top')`);
  out.fit = await page.ev(`({ scrollWidth: document.documentElement.scrollWidth, innerWidth, wrapScroll: document.querySelector('.canvaswrap').scrollWidth, wrapClient: document.querySelector('.canvaswrap').clientWidth, colScroll: document.querySelector('#graphcol').scrollWidth, colClient: document.querySelector('#graphcol').clientWidth, zoom: getComputedStyle(document.querySelector('#canvas')).zoom, sources: document.querySelector('#sources').getBoundingClientRect().width, right: document.querySelector('#inspector').getBoundingClientRect().width, cv: document.querySelector('#canvas .cv').getBoundingClientRect().width })`);
}

if (mode === 'type' && ready) {
  await page.until(`!!document.querySelector('.card.top')`);
  await realClick(rowSel(2));
  await page.until(`!!document.querySelector('.pk-dialog')`);
  await click('.pk-x');
  await click('.card[data-node="a4"]');
  const scan = `(() => {
    const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
    const over = (top, under) => ({ r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1 });
    const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
    const backdrop = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let bg = { r: 13, g: 14, b: 16, a: 1 };
      for (const n of chain.reverse()) { const c = parse(getComputedStyle(n).backgroundColor); if (c.a > 0) bg = over(c, bg); } return bg; };
    const faded = e => { for (let n = e; n; n = n.parentElement) if (parseFloat(getComputedStyle(n).opacity) < 1) return true; return false; };
    const sizes = [], contrast = [];
    for (const e of document.querySelectorAll('body *')) {
      const own = [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
      if (!own) continue;
      const cs = getComputedStyle(e), r = e.getBoundingClientRect();
      if (cs.visibility === 'hidden' || cs.display === 'none' || !r.width || !r.height || faded(e) || e.closest('[hidden]')) continue;
      const label = e.tagName.toLowerCase() + '.' + String(e.className && e.className.baseVal !== undefined ? e.className.baseVal : e.className).trim().replace(/\\s+/g, '.') + ' "' + e.textContent.trim().slice(0, 24) + '"';
      if (parseFloat(cs.fontSize) < 10.5) sizes.push(label + ' ' + cs.fontSize);
      const fg = over(parse(cs.color), backdrop(e)), bg = backdrop(e);
      const a = lum(fg), b = lum(bg), ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      if (ratio < 4.5) contrast.push(label + ' ' + cs.color + ' on rgb(' + [bg.r, bg.g, bg.b].map(Math.round) + ') = ' + ratio.toFixed(2));
    }
    return { sizes, contrast };
  })()`;
  out.graph = await page.ev(scan);
  await realClick(rowSel(2));
  await page.until(`!!document.querySelector('.pk-dialog')`);
  out.withPeek = await page.ev(scan);
  await click('.pk-x');
  await click('.tab[data-tab="calls"]');
  await realClick(rowSel(2));
  out.calls = await page.ev(scan);
}

console.log(JSON.stringify(out));
page.close();
