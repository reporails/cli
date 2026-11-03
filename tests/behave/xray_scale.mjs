// usage: node xray_scale.mjs <page-url> <mode> [width]
// Measures the x-ray page over a design-scale view in headless Chrome and prints one JSON object.
import { openPage, sleep } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440)];
const page = await openPage(url, width, 900);
const out = { mode };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);

// A smooth programmatic scroll from top to bottom in `ms`, one step per animation frame; returns the frames drawn and the longest gap.
const scrollFps = (target, ms) => page.ev(`(async () => {
  const el = ${target};
  const max = () => (el === document.scrollingElement ? el.scrollHeight - innerHeight : el.scrollHeight - el.clientHeight);
  const set = y => (el === document.scrollingElement ? scrollTo(0, y) : (el.scrollTop = y));
  set(0);
  await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
  const span = max();
  const t0 = performance.now();
  let frames = 0, last = t0, worst = 0;
  await new Promise(done => {
    const step = now => {
      frames++;
      worst = Math.max(worst, now - last);
      last = now;
      const f = Math.min(1, (now - t0) / ${ms});
      set(span * f);
      if (f < 1) requestAnimationFrame(step); else done();
    };
    requestAnimationFrame(step);
  });
  const took = performance.now() - t0;
  return { frames, ms: Math.round(took), fps: +(frames / took * 1000).toFixed(1), worstFrameMs: Math.round(worst), span };
})()`);

if (mode === 'graph') {
  // First render: milliseconds from navigation start until the top card is on the page.
  out.firstRenderMs = await page.ev(`new Promise(res => {
    const tick = () => { if (document.querySelector('.card.top')) res(Math.round(performance.now())); else setTimeout(tick, 10); };
    tick();
  })`);
  await sleep(500);
  out.agentsInView = await page.ev(`document.querySelectorAll('.card[data-node]:not(.top):not(.bottom), .card[data-group]').length`);
  // Switching away and back redraws the graph: time that redraw.
  await click('.tab[data-tab="calls"]'); await sleep(300);
  out.redrawMs = await page.ev(`(async () => { const t = performance.now(); document.querySelector('.tab[data-tab="graph"]').click(); await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); return Math.round(performance.now() - t); })()`);
  await sleep(300);
  out.canvasEls = await page.ev(`document.querySelectorAll('#canvas *').length`);
  out.railEls = await page.ev(`document.querySelectorAll('#rail *').length`);
  // The biggest run of same-kind elements anywhere in the canvas or rail, so a layer with one element per call shows.
  out.biggestLayer = await page.ev(`(() => {
    const n = {};
    for (const e of document.querySelectorAll('#canvas *, #rail *')) { const k = e.tagName + '.' + (e.getAttribute('class') || ''); n[k] = (n[k] || 0) + 1; }
    const top = Object.entries(n).sort((a, b) => b[1] - a[1])[0];
    return { key: top[0], count: top[1] };
  })()`);
  out.pageHeight = await page.ev(`document.scrollingElement.scrollHeight`);
  out.scroll = await scrollFps('document.scrollingElement', 2000);
  // Every fan-out group opened: the longest graph, one card per member.
  out.groupsOpened = 0;
  for (let i = 0; i < 12 && await click('.card[data-group]'); i++) { out.groupsOpened++; await sleep(250); }
  out.openCards = await page.ev(`document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)').length`);
  out.openCanvasEls = await page.ev(`document.querySelectorAll('#canvas *').length`);
  out.openPageHeight = await page.ev(`document.scrollingElement.scrollHeight`);
  out.openScroll = await scrollFps('document.scrollingElement', 2000);
  // A deep subagent: drill into the 12-member burst's first member, whose own children form another burst.
  await page.ev(`location.hash = '#/agent/main/b0_0'; 0`); await sleep(500);
  out.deepCards = await page.ev(`document.querySelectorAll('.card[data-node]:not(.top):not(.bottom), .card[data-group]').length`);
  out.deepScroll = await scrollFps('document.scrollingElement', 2000);
}

if (mode === 'calls') {
  await page.until(`!!document.querySelector('.tab[data-tab="calls"]')`);
  await click('.tab[data-tab="calls"]'); await sleep(500);
  // The table opens on a first page of rows; "Show all" lists every call.
  await page.ev(`(() => { const m = document.querySelector('#view-calls .tb-more'); if (m && !m.hidden && m.textContent.startsWith('Show all')) m.click(); return 0; })()`);
  await sleep(300);
  out.rows = await page.ev(`document.querySelectorAll('#view-calls .vl-row').length`);
  out.summary = await page.ev(`document.querySelector('.tb-summary').textContent`);
  out.scroll = await scrollFps(`document.querySelector('#view-calls .vl')`, 2000);
  out.rowsAfter = await page.ev(`document.querySelectorAll('#view-calls .vl-row').length`);
  out.listHeight = await page.ev(`document.querySelector('#view-calls .vl-sizer').offsetHeight`);
  await click('.tab[data-tab="sources"]'); await sleep(500);
  out.sourceRows = await page.ev(`document.querySelectorAll('#view-sources .vl-row').length`);
  out.sourceTotal = await page.ev(`Math.round(document.querySelector('#view-sources .vl-sizer').offsetHeight / document.querySelector('#view-sources .vl-row').offsetHeight)`);
  out.sourceScroll = await scrollFps(`document.querySelector('#view-sources .vl')`, 2000);
}

if (mode === 'narrow') {
  await page.until(`!!document.querySelector('.card.top')`); await sleep(500);
  // Every 12-member burst opened, long agent names on the cards.
  for (let i = 0; i < 12 && await click('.card[data-group]'); i++) await sleep(250);
  out.openCards = await page.ev(`document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)').length`);
  out.overflow = await page.ev(`(() => {
    const de = document.documentElement, w = document.querySelector('.canvaswrap');
    return { page: de.scrollWidth - de.clientWidth, graph: w.scrollWidth - w.clientWidth };
  })()`);
  // Every one-line label is checked: its text may be cut by ellipsis (and carries a full-text title elsewhere), but two cards may not overlap.
  out.overlaps = await page.ev(`(() => {
    const cards = [...document.querySelectorAll('.card[data-node], .card[data-group]')].map(e => { const r = e.getBoundingClientRect(); return { id: e.dataset.node || e.dataset.group, l: r.left, r: r.right, t: r.top, b: r.bottom }; });
    const hits = [];
    for (let i = 0; i < cards.length; i++) for (let j = i + 1; j < cards.length; j++) {
      const a = cards[i], b = cards[j];
      if (a.l < b.r - 1 && b.l < a.r - 1 && a.t < b.b - 1 && b.t < a.b - 1) hits.push([a.id, b.id]);
    }
    return hits;
  })()`);
  out.clipped = await page.ev(`[...document.querySelectorAll('.card .nm, .snode .sn, .station')].filter(e => { const c = e.closest('.card, .snode, .station').getBoundingClientRect(), r = e.getBoundingClientRect(); return r.right > c.right + 1 || r.left < c.left - 1; }).length`);
  out.stationOverlaps = await page.ev(`(() => {
    const s = [...document.querySelectorAll('.station')].map(e => { const r = e.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; });
    let n = 0;
    for (let i = 0; i < s.length; i++) for (let j = i + 1; j < s.length; j++) { const a = s[i], b = s[j]; if (a.l < b.r - 1 && b.l < a.r - 1 && a.t < b.b - 1 && b.t < a.b - 1) n++; }
    return n;
  })()`);
}

console.log(JSON.stringify(out));
await page.close();
