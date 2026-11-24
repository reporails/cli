// usage: node xray_stripes.mjs <page-url> [width]
// Draws the Graph tab with its folds closed and prints, per compaction stripe, how far its text runs past the stripe's right edge.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, width] = [process.argv[2], Number(process.argv[3] || 1440)];
const page = await openPage(url, width, 900);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.cv .card.top')`, 400);
await sleep(800);
const stripes = await page.ev(`[...document.querySelectorAll('.cv .compact')].map(m => { const a = m.getBoundingClientRect(), s = m.querySelector('span'), b = s.getBoundingClientRect(); return { past: Math.round((b.right - a.right) * 10) / 10, text: s.textContent.length, clipped: s.scrollWidth > s.clientWidth }; })`);
console.log(JSON.stringify({ ready: !!ready, stripes }));
await page.close();
