// usage: node xray_load_groups.mjs <page-url> [width] [hook|compaction]
// Draws the Graph tab, reads the group cards on the canvas and the rows the first one opens, and prints one JSON object.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, width, mode] = [process.argv[2], Number(process.argv[3] || 1440), process.argv[4] || 'hook'];
const page = await openPage(url, width, 900);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.cv .card.top')`, 400);
await sleep(800);
if (mode === 'compaction') {
  const groupCards = () => page.ev(`[...document.querySelectorAll('.cv .snode.lgroup')].map(e => ({ text: e.textContent, top: e.getBoundingClientRect().top }))`);
  const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (e) e.click(); })()`);
  const stripe = await page.ev(`(() => { const r = document.querySelector('.cv .compact').getBoundingClientRect(); return { top: r.top, bottom: r.bottom }; })()`);
  const seen = { ready: !!ready, stripe, cards: await groupCards() };
  await click('[data-eye="hook"]');
  await sleep(600);
  seen.hooksOff = await groupCards();
  await click('[data-eye="hook"]');
  await sleep(600);
  await click('.cv .compact');
  await sleep(600);
  seen.notBack = await page.ev(`[...document.querySelectorAll('.pk-dialog .fs')].map(e => e.textContent)`);
  await click('.cv .snode.lgroup');
  await sleep(600);
  seen.rows = await page.ev(`[...document.querySelectorAll('.pk-dialog .lg-file')].map(e => e.textContent)`);
  console.log(JSON.stringify(seen));
  await page.close();
  process.exit(0);
}
const cards = await page.ev(`[...document.querySelectorAll('.cv .snode.lgroup')].map(e => e.textContent)`);
await page.ev(`(() => { const e = document.querySelector('.cv .snode.lgroup'); if (e) e.click(); })()`);
await sleep(600);
const rows = await page.ev(`[...document.querySelectorAll('.pk-dialog .lg-file')].map(e => e.textContent)`);
console.log(JSON.stringify({ ready: !!ready, cards, rows }));
await page.close();
