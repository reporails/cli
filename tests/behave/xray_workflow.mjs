// usage: node xray_workflow.mjs <page-url> [width]
// Draws the Graph tab, reads the workflow nodes on the canvas and the details the first one opens, and prints one JSON object.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, width] = [process.argv[2], Number(process.argv[3] || 1440)];
const page = await openPage(url, width, 900);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.cv .card.top')`, 400);
await sleep(800);
const cards = await page.ev(`[...document.querySelectorAll('.cv .card.workflow')].map(e => e.textContent)`);
await page.ev(`(() => { const e = document.querySelector('.cv .card.workflow'); if (e) e.click(); })()`);
await sleep(600);
const details = await page.ev(`(document.querySelector('.pk-dialog') || {}).innerText || ''`);
const phases = await page.ev(`[...document.querySelectorAll('.pk-dialog .wf-phase, .pk-dialog .wf-agent')].map(e => e.className + '|' + e.textContent)`);
console.log(JSON.stringify({ ready: !!ready, cards, details, phases }));
await page.close();
