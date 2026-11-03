// usage: node xray_canvas.mjs <page-url> <mode> [width]
// Drives the Graph tab's canvas in headless Chrome (source nodes, hooks, layers, groups, jump rail, side track) and
// prints one JSON object per mode.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440)];
const page = await openPage(url, width);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.card.top')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const rects = sel => page.ev(`[...document.querySelectorAll(${JSON.stringify(sel)})].map(e => { const r = e.getBoundingClientRect(); return { id: e.dataset.node || e.dataset.source || e.dataset.group || '', left: r.left, right: r.right, top: r.top, bottom: r.bottom }; })`);

if (mode === 'layout' && ready) {
  out.spine = await page.ev(`(() => { const r = document.querySelector('line.spine').getBoundingClientRect(); return r.left + r.width / 2; })()`);
  out.cards = await rects('.card[data-node]:not(.top):not(.bottom)');
  out.groupCards = await rects('.card[data-group]');
  out.nodes = await rects('.snode');
  out.nodeIds = await page.ev(`[...document.querySelectorAll('.snode')].map(e => e.dataset.source)`);
  out.edges = await page.ev(`[...document.querySelectorAll('path.srcedge')].map(e => e.dataset.source)`);
  out.arrows = await page.ev(`document.querySelectorAll('path.srcarrow').length`);
  out.trips = await page.ev(`[...document.querySelectorAll('path.srctrip')].map(e => e.dataset.source)`);
  out.nodeText = await page.ev(`Object.fromEntries([...document.querySelectorAll('.snode')].map(e => [e.dataset.source, e.textContent]))`);
  out.stations = await page.ev(`[...document.querySelectorAll('.station')].map(e => ({ kind: e.dataset.station, source: e.dataset.source, text: e.textContent }))`);
  out.spineStations = await page.ev(`(() => { const s = document.querySelector('line.spine').getBoundingClientRect(); return [...document.querySelectorAll('.station')].filter(e => { const r = e.getBoundingClientRect(); return r.left < s.right && r.right > s.left; }).length; })()`);
  out.legend = await page.ev(`!!document.querySelector('.legend')`);
  out.link = await page.ev(`(document.querySelector('.callslink') || {}).textContent || null`);
  out.trackPaths = await page.ev(`[...document.querySelectorAll('path.tpath')].map(e => e.dataset.category)`);
  out.trackDivs = await page.ev(`document.querySelectorAll('.ctick').length`);
}

if (mode === 'eye' && ready) {
  const count = () => page.ev(`({
    cards: document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)').length,
    groups: document.querySelectorAll('.card[data-group], .gbox').length,
    arches: document.querySelectorAll('path.arch').length,
    nodes: document.querySelectorAll('.snode').length,
    top: document.querySelectorAll('.card.top').length,
    spine: document.querySelectorAll('line.spine').length,
    hooks: document.querySelectorAll('.station').length,
  })`);
  const eye = await page.ev(`(() => { const e = [...document.querySelectorAll('[data-eye]')]; return e.map(x => x.dataset.eye); })()`);
  out.eyes = eye;
  out.before = await count();
  out.kind = process.argv[5];
  await click(`[data-eye="${process.argv[5]}"]`);
  out.after = await count();
  out.height = await page.ev(`document.querySelector('.cv').offsetHeight`);
  await click(`[data-eye="${process.argv[5]}"]`);
  out.again = await count();
}

if (mode === 'collapsed' && ready) {
  // open the group, select a member, then collapse it: the group card names the selection
  await click(`.card[data-group="${process.argv[5]}"]`);
  await page.ev(`import('/static/js/state.js').then(m => { m.state.sel = ${JSON.stringify(process.argv[6])}; window.dispatchEvent(new Event('hashchange')); return 0; })`);
  await click('.gcollapse');
  out.card = await page.ev(`(() => { const c = document.querySelector('.card[data-group="${process.argv[5]}"]'); if (!c) return null; const s = getComputedStyle(c); return { text: c.textContent, border: s.borderTopStyle, colour: s.borderTopColor }; })()`);
  out.plain = await page.ev(`[...document.querySelectorAll('.card[data-group]')].filter(c => c.dataset.group !== ${JSON.stringify(process.argv[5])}).map(c => c.textContent)`);
}

if (mode === 'rail' && ready) {
  out.marks = await page.ev(`[...document.querySelectorAll('#rail .rail-mark')].map(b => ({ kind: b.className.replace('rail-mark ', ''), label: b.getAttribute('aria-label'), id: b.dataset.jump }))`);
  out.density = await page.ev(`document.querySelectorAll('#rail .rail-density rect').length`);
  out.railWidth = await page.ev(`document.querySelector('#rail').getBoundingClientRect().width`);
  out.before = await page.ev(`window.scrollY`);
  out.endMark = await page.ev(`(() => { const b = document.querySelector('#rail .rail-mark.end'); b.click(); return b.dataset.jump; })()`);
  await sleep(300);
  const here = await page.ev(`(() => { const a = document.getElementById(${JSON.stringify(out.endMark)}).getBoundingClientRect().top; return { y: a, vh: window.innerHeight, scrollY: window.scrollY }; })()`);
  out.after = here;
}

console.log(JSON.stringify(out));
await page.close();
