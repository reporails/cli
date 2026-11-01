// usage: node xray_pane.mjs <page-url> <file label>
// Opens the page in headless Chrome, selects the listed file, prints its shown text as `SHOWN <json>`, waits for a
// line on stdin, then prints the text the pane shows once the page has polled again as `AFTER <json>`.
import { createInterface } from 'node:readline';
import { openPage, sleep } from './xray_cdp.mjs';

const [url, label] = [process.argv[2], process.argv[3]];
const page = await openPage(url);
const peek = () => page.ev(`(document.querySelector('pre.peek')||{}).textContent||''`);

await page.until(`!!document.querySelector('[data-file]')`);
await page.ev(`[...document.querySelectorAll('[data-file]')].find(e => e.textContent.includes(${JSON.stringify(label)})).click()`);
const shown = (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '';
console.log('SHOWN ' + JSON.stringify(shown));
await new Promise(r => createInterface({ input: process.stdin }).once('line', r));
let after = shown;
for (let i = 0; i < 40 && (after === shown || after === ''); i++) { await sleep(500); after = await peek(); }
console.log('AFTER ' + JSON.stringify(after));
page.close();
