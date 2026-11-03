// usage: node xray_pane.mjs <page-url> <file path>
// Opens the page's drill-down for the file in headless Chrome, prints its shown text as `SHOWN <json>`, waits for a
// line on stdin, then prints the text the pane shows once the page has polled again as `AFTER <json>`.
import { createInterface } from 'node:readline';
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, path] = [process.argv[2], process.argv[3]];
const page = await openPage(url);
const peek = () => page.ev(`(document.querySelector('pre.peek')||{}).textContent||''`);

await toGraph(page);
await page.until(`!!document.querySelector('.card.top')`);
await page.ev(`location.hash = '#/file/' + ${JSON.stringify(path)}; 0`);
const shown = (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '';
console.log('SHOWN ' + JSON.stringify(shown));
await new Promise(r => createInterface({ input: process.stdin }).once('line', r));
let after = shown;
for (let i = 0; i < 40 && (after === shown || after === ''); i++) { await sleep(500); after = await peek(); }
console.log('AFTER ' + JSON.stringify(after));
page.close();
