// usage: node xray_a11y.mjs <page-url> <mode> [width]
// Drives the bundled page's keyboard, focus, contrast, target-size and reflow behaviour in headless Chrome and prints
// one JSON object per mode.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440)];
const page = await openPage(url, width, 1000);
const ready = await page.until(`!!document.querySelector('.tab[data-tab]') && !!document.querySelector('#sources .sr')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const focus = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.focus(); return document.activeElement === e; })()`);
const centre = sel => page.ev(`(() => { const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
const hover = async sel => {
  await page.ev(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({ block: 'center' }); 0`);
  const p = await centre(sel);
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: p.x, y: p.y, button: 'none' });
  await sleep(200);
};
const press = async (k, code, vk, text) => {
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, ...(text ? { text } : {}) });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk });
  await sleep(120);
};
const keys = {
  enter: () => press('Enter', 'Enter', 13, '\r'),
  space: () => press(' ', 'Space', 32, ' '),
  tab: () => press('Tab', 'Tab', 9),
  esc: () => press('Escape', 'Escape', 27),
  down: () => press('ArrowDown', 'ArrowDown', 40),
};
const active = () => page.ev(`(() => { const a = document.activeElement; return {
  tag: a.tagName, cls: String(a.className), source: a.dataset.source || null, eye: a.dataset.eye || null, group: a.dataset.sourceGroup || null,
  node: a.dataset.node || null, closePeek: a.hasAttribute('data-close-peek'), inCanvas: !!a.closest('.canvaswrap'), inSources: !!a.closest('#sources'),
  rowindex: a.getAttribute('aria-rowindex'), expanded: a.getAttribute('aria-expanded') }; })()`);
// Counts the click events a key press produces.
const countClicks = () => page.ev(`(() => { window.__clicks = 0; document.addEventListener('click', () => { window.__clicks++; }, true); return true; })()`);

// Tab from the first control of the canvas until a source node has focus.
async function tabToSourceNode() {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas .snode')`);
  await focus('#canvas .callslink');
  for (let i = 0; i < 60; i++) {
    await keys.tab();
    const a = await active();
    if (a.cls.split(' ').includes('snode')) return a;
  }
  return null;
}

if (mode === 'canvas-focus' && ready) {
  const a = await tabToSourceNode();
  out.tabbed = a;
  await sleep(300);
  out.afterFocus = await active();
  const other = await page.ev(`(() => { const r = [...document.querySelectorAll('#sources .sr[data-source]')].find(x => x.dataset.source !== ${JSON.stringify(a && a.source)}); return r ? r.dataset.source : null; })()`);
  await hover(`#sources .sr[data-source="${other}"]`);
  out.afterHover = await active();
  await hover('#canvas .card.top');
  out.afterLeave = await active();
}

if (mode === 'newline-focus' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas .snode')`);
  out.focused = await page.ev(`(() => { const e = [...document.querySelectorAll('#canvas .snode')].find(x => (x.dataset.source || '').includes('\\n')); if (!e) return null; e.focus(); return e.dataset.source; })()`);
  await page.ev(`fetch('/test/swap').then(() => 0)`);
  await sleep(4500);
  out.after = await page.ev(`document.activeElement.dataset.source || null`);
  out.drawn = await page.ev(`!!document.querySelector('#canvas .snode')`);
}

if (mode === 'toggles' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('.sx-eye')`);
  await focus('.sx-eye');
  const eye = await active();
  await keys.enter();
  out.eye = { before: eye, after: await active(), pressed: await page.ev(`document.querySelector('.sx-eye[data-eye="${eye.eye}"]').getAttribute('aria-pressed')`) };
  await focus('.sh[data-source-group]');
  const head = await active();
  await keys.enter();
  out.group = { before: head, after: await active() };
  await keys.space();
  out.groupSpace = await active();
}

if (mode === 'opener' && ready) {
  const a = await tabToSourceNode();
  out.opener = a;
  await countClicks();
  await keys.enter();
  await page.until(`!!document.querySelector('.pk-dialog')`);
  out.clicks = await page.ev(`window.__clicks`);
  out.open = await active();
  out.inert = await page.ev(`document.querySelector('.canvaswrap').inert === true`);
  const landed = [];
  for (let i = 0; i < 40; i++) { await keys.tab(); landed.push((await active()).inCanvas); }
  out.tabsInCanvas = landed.filter(Boolean).length;
  await focus('.pk-x');
  await keys.esc();
  await sleep(300);
  out.afterEsc = await active();
}

if (mode === 'stripe' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas button.compact')`);
  out.focused = await focus('#canvas button.compact');
  out.tag = await page.ev(`document.activeElement.tagName`);
  await countClicks();
  await keys.enter();
  await page.until(`!!document.querySelector('.pk-dialog')`);
  out.clicks = await page.ev(`window.__clicks`);
  out.title = await page.ev(`document.querySelector('.pk-dialog').getAttribute('aria-labelledby')`);
  out.open = await active();
  out.inert = await page.ev(`document.querySelector('.canvaswrap').inert === true`);
  await keys.esc();
  await sleep(300);
  out.closed = await page.ev(`!document.querySelector('.pk-dialog')`);
  out.afterEsc = await page.ev(`(() => { const a = document.activeElement; return { cls: String(a.className), tag: a.tagName, peek: a.dataset.peek || null, inCanvas: !!a.closest('.canvaswrap') }; })()`);
}

// A folded segment opens from the keyboard: Enter on its band opens it, and the open segment offers a control to fold it again.
if (mode === 'fold-key' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas .fold')`);
  out.folds = await page.ev(`document.querySelectorAll('#canvas .fold').length`);
  out.focused = await focus('#canvas .fold');
  out.tag = await page.ev(`document.activeElement.tagName`);
  await keys.enter();
  await sleep(400);
  out.foldsAfter = await page.ev(`document.querySelectorAll('#canvas .fold').length`);
  out.closers = await page.ev(`document.querySelectorAll('#canvas .gcollapse[data-group^="fold:"]').length`);
}

// Puts a time label, a stretch bar and the Tool calls link into the first compaction stripe's band and asks the page
// which element a pointer at each of them reaches, and at the stripe's own label.
if (mode === 'stripe-layers' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas button.compact')`);
  out.layers = await page.ev(`(() => {
    const band = document.querySelector('#canvas button.compact');
    const cv = band.parentElement, box = band.getBoundingClientRect(), origin = cv.getBoundingClientRect();
    const place = (cls, tag, left, text) => {
      const e = document.createElement(tag);
      e.className = cls; e.textContent = text; e.style.left = left + 'px'; e.style.top = (box.top - origin.top + 2) + 'px';
      if (cls === 'stretch') e.style.height = '10px';
      cv.append(e);
      return e;
    };
    const centre = e => { const r = e.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; };
    const topAt = e => { const [x, y] = centre(e); return document.elementFromPoint(x, y); };
    const tick = place('tick', 'div', 2, '10:00:00'), bar = place('stretch', 'div', 40, ''), link = place('callslink', 'button', 2, 'open');
    const label = band.querySelector('span');
    const labelTop = topAt(label);
    return {
      tick: topAt(tick) === tick, stretch: topAt(bar) === bar, link: topAt(link) === link,
      label: !!labelTop && band.contains(labelTop), bandBox: [box.width, box.height],
    };
  })()`);
  // A pointer on the band to the right of its label, where no card sits over it, reaches the stripe itself.
  out.awayFromLabel = await page.ev(`(() => {
    const band = document.querySelector('#canvas button.compact'), r = band.getBoundingClientRect();
    const from = band.querySelector('span').getBoundingClientRect().right + 20, y = r.top + r.height / 2;
    let hit = null;
    for (let x = from; x < r.right - 2 && !(hit === band); x += 6) hit = document.elementFromPoint(x, y);
    if (hit === band) band.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    return { reached: hit === band, opened: !!document.querySelector('.pk-dialog') };
  })()`);
}

// Scrolls the page to its end, opens a compaction's details window and fills it with more text than the screen holds,
// then reports where the window sits against the screen and the overlay.
if (mode === 'tall-window' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas button.compact')`);
  const toEnd = () => page.ev(`(window.scrollTo(0, document.documentElement.scrollHeight), document.scrollingElement.scrollTop)`);
  await toEnd();
  await page.ev(`document.querySelector('#canvas button.compact').click(); 0`);
  await page.until(`!!document.querySelector('.pk-dialog')`);
  await page.ev(`(() => { const d = document.createElement('div'); d.style.height = '3000px'; d.textContent = 'tall'; document.querySelector('.pk-main').append(d); })()`);
  await sleep(200);
  await toEnd();
  await sleep(300);
  out.fit = await page.ev(`(() => {
    const d = document.querySelector('.pk-dialog').getBoundingClientRect(), o = document.querySelector('#overlay').getBoundingClientRect();
    const x = document.querySelector('.pk-x').getBoundingClientRect(), b = document.querySelector('.pk-body');
    return { top: d.top, bottom: d.bottom, overlayBottom: o.bottom, viewport: innerHeight, closeTop: x.top, closeBottom: x.bottom, scrollY: scrollY, scrolls: b.scrollHeight > b.clientHeight };
  })()`);
}

if (mode === 'space' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas .card[data-node]:not(.top)')`);
  const node = await page.ev(`document.querySelector('#canvas .card[data-node]:not(.top)').dataset.node`);
  await focus(`#canvas .card[data-node="${node}"]`);
  await keys.space();
  out.node = node;
  out.sel = await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`);
  out.name = await page.ev(`document.querySelector('#canvas .card[data-node="${node}"]').getAttribute('aria-label')`);
  out.chips = await page.ev(`[...document.querySelectorAll('#canvas .card[data-node="${node}"] .chip[aria-label]')].map(c => c.getAttribute('aria-label'))`);
}

if (mode === 'table' && ready) {
  await click('.tab[data-tab="calls"]');
  await page.until(`!!document.querySelector('.vl .vl-row')`);
  const shape = () => page.ev(`(() => { const v = document.querySelector('#view-calls .vl'); return { role: v.getAttribute('role'), rowcount: v.getAttribute('aria-rowcount'),
    rows: [...v.querySelectorAll('.vl-row')].map(r => [r.getAttribute('role'), r.getAttribute('aria-rowindex')]),
    heads: [...document.querySelectorAll('#view-calls [role="columnheader"]')].length,
    summary: document.querySelector('.tb-summary').textContent }; })()`);
  out.all = await shape();
  await click('[data-calls-failed]');
  await sleep(200);
  out.failed = await shape();
  await click('[data-calls-failed]');
  await sleep(200);
  await focus('.vl .vl-row');
  const first = await active();
  const walked = [first.rowindex];
  for (let i = 0; i < 30; i++) { await keys.down(); walked.push((await active()).rowindex); }
  out.walked = walked;
  out.windowStart = await page.ev(`Number(document.querySelector('#view-calls .vl .vl-row').getAttribute('aria-rowindex'))`);
  await page.ev(`(() => { const s = document.querySelector('.tb-summary'); let n = 0; const o = new MutationObserver(m => { n += m.length; }); o.observe(s, { childList: true, characterData: true, subtree: true });
    window.__statusWrites = () => n; return true; })()`);
  await click('[data-calls-failed]');
  await click('[data-calls-failed]');
  await sleep(300);
  out.statusWrites = await page.ev(`window.__statusWrites()`);
}

// Contrast of every visible text, with the opacity of the element and its ancestors counted in.
const SCAN = `(() => {
  const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const over = (top, under) => ({ r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1 });
  const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const backdrop = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let bg = { r: 13, g: 14, b: 16, a: 1 };
    for (const n of chain.reverse()) { const c = parse(getComputedStyle(n).backgroundColor); if (c.a > 0) bg = over(c, bg); } return bg; };
  const fade = e => { let a = 1; for (let n = e; n; n = n.parentElement) a *= parseFloat(getComputedStyle(n).opacity); return a; };
  const bad = [];
  let seen = 0;
  for (const e of document.querySelectorAll('body *')) {
    const own = [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const cs = getComputedStyle(e), r = e.getBoundingClientRect();
    if (cs.visibility === 'hidden' || cs.display === 'none' || !r.width || !r.height || e.closest('[hidden]') || e.closest('[inert]')) continue;
    seen++;
    const bg = backdrop(e), fg = parse(cs.color);
    const eff = over({ ...fg, a: fg.a * fade(e) }, bg);
    const a = lum(eff), b = lum(bg), ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    if (ratio < 4.5) bad.push(e.tagName.toLowerCase() + '.' + String(e.className && e.className.baseVal !== undefined ? e.className.baseVal : e.className).trim().replace(/\\s+/g, '.') + ' "' + e.textContent.trim().slice(0, 24) + '" = ' + ratio.toFixed(2));
  }
  return { seen, bad };
})()`;

if (mode === 'contrast' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('.card.top')`);
  out.plain = await page.ev(SCAN);
  await click('#canvas .card[data-node]:not(.top)');
  await sleep(200);
  out.selected = await page.ev(SCAN);
  await hover('#sources .sr[data-source]');
  out.dimmed = await page.ev(SCAN);
  out.dimCount = await page.ev(`document.querySelectorAll('.card.dim, .snode.dim, .station.dim').length`);
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 3, y: 3, button: 'none' });
  await click('.tab[data-tab="calls"]');
  await sleep(200);
  out.calls = await page.ev(SCAN);
  await click('.tab[data-tab="sources"]');
  await sleep(200);
  out.sources = await page.ev(SCAN);
}

if (mode === 'borders' && ready) {
  await click('.tab[data-tab="calls"]');
  await page.until(`!!document.querySelector('.seg')`);
  out.borders = await page.ev(`(() => {
    const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
    const over = (top, under) => ({ r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1 });
    const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
    const backdrop = e => { const chain = []; for (let n = e.parentElement; n; n = n.parentElement) chain.push(n); let bg = { r: 13, g: 14, b: 16, a: 1 };
      for (const n of chain.reverse()) { const c = parse(getComputedStyle(n).backgroundColor); if (c.a > 0) bg = over(c, bg); } return bg; };
    const ratio = (a, b) => (Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05);
    const edge = (name, e) => { const cs = getComputedStyle(e), w = parseFloat(cs.borderTopWidth); const bg = backdrop(e); const b = over(parse(cs.borderTopColor), bg); return { name, width: w, ratio: w > 0 ? ratio(b, bg) : 0 }; };
    const res = [edge('seg', document.querySelector('.seg:not([aria-pressed="true"])')), edge('swbtn', document.querySelector('.swbtn'))];
    // the selected tab and segment show an indicator besides the fill
    const sel = (name, e) => { const cs = getComputedStyle(e), sh = cs.boxShadow; const m = sh.match(/rgba?\\([^)]+\\)/); const bg = over(parse(cs.backgroundColor), backdrop(e)); return { name, shadow: sh, ratio: m && sh !== 'none' ? ratio(over(parse(m[0]), bg), bg) : 0 }; };
    res.push(sel('tab', document.querySelector('.tab[aria-selected="true"]')), sel('seg-on', document.querySelector('.seg[aria-pressed="true"]')));
    return res;
  })()`);
}

if (mode === 'chip-fill' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('#canvas .card:not(.dim) .chip.lit')`);
  out.chips = await page.ev(`(() => {
    const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); const p = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
    const over = (top, under) => ({ r: top.r * top.a + under.r * (1 - top.a), g: top.g * top.a + under.g * (1 - top.a), b: top.b * top.a + under.b * (1 - top.a), a: 1 });
    const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
    const ratio = (a, b) => (Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05);
    const card = document.querySelector('#canvas .card:not(.dim):not(.sel) .chip.lit').closest('.card');
    const cardBg = over(parse(getComputedStyle(card).backgroundColor), { r: 13, g: 14, b: 16, a: 1 });
    const on = card.querySelector('.chip.lit'), off = document.querySelector('#canvas .card:not(.dim) .chip:not(.lit):not(.find):not(.hot)');
    return { onFill: ratio(over(parse(getComputedStyle(on).backgroundColor), cardBg), cardBg), offFill: off ? parse(getComputedStyle(off).backgroundColor).a : null };
  })()`);
}

if (mode === 'scale-text' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('.card.top')`);
  await sleep(300);
  out.col = await page.ev(`document.querySelector('#graphcol').clientWidth`);
  out.zoom = await page.ev(`parseFloat(getComputedStyle(document.querySelector('#canvas')).zoom) || 1`);
  out.small = await page.ev(`(() => { const z = parseFloat(getComputedStyle(document.querySelector('#canvas')).zoom) || 1; const bad = []; let seen = 0;
    for (const e of document.querySelectorAll('#canvas *')) {
      if (![...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())) continue;
      const cs = getComputedStyle(e); if (cs.display === 'none' || cs.visibility === 'hidden' || e.closest('[hidden]')) continue;
      seen++;
      const px = parseFloat(cs.fontSize) * z;
      if (px < 10.45) bad.push(e.tagName.toLowerCase() + '.' + String(e.className && e.className.baseVal !== undefined ? e.className.baseVal : e.className) + ' ' + px.toFixed(2));
    } return { seen, bad }; })()`);
}

if (mode === 'hit-areas' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('.rail-mark')`);
  out.targets = await page.ev(`[...document.querySelectorAll('.rail-mark, .station.dot')].map(e => { const r = e.getBoundingClientRect(); return { cls: String(e.className), w: r.width, h: r.height }; })`);
}

if (mode === 'reflow' && ready) {
  await toGraph(page);
  await page.until(`!!document.querySelector('.card.top')`);
  await sleep(300);
  out.layout = await page.ev(`({ scrollWidth: document.documentElement.scrollWidth, innerWidth,
    cols: getComputedStyle(document.querySelector('.cols')).gridTemplateColumns.split(' ').length,
    graphview: getComputedStyle(document.querySelector('#view-graph')).gridTemplateColumns.split(' ').length })`);
}

console.log(JSON.stringify(out));
await page.close();
