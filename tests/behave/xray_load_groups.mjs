// usage: node xray_load_groups.mjs <page-url> [width]
// Draws the Graph tab, reads the group cards on the canvas and the rows the first one opens, and prints one JSON object.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, width] = [process.argv[2], Number(process.argv[3] || 1440)];
const page = await openPage(url, width, 900);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.cv .card.top')`, 400);
await sleep(800);
const cards = await page.ev(`[...document.querySelectorAll('.cv .snode.lgroup')].map(e => e.textContent)`);
await page.ev(`(() => { const e = document.querySelector('.cv .snode.lgroup'); if (e) e.click(); })()`);
await sleep(600);
const rows = await page.ev(`[...document.querySelectorAll('.pk-dialog .lg-file')].map(e => e.textContent)`);
console.log(JSON.stringify({ ready: !!ready, cards, rows }));
await page.close();
