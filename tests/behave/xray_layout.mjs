// usage: node xray_layout.mjs <page-url> <memory|prompt|markup|check|compactions>
// Drives the real `ails xray` page in headless Chrome and prints one JSON object describing what it drew.
import { openPage } from './xray_cdp.mjs';

const [url, mode] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440);
const ready = await page.until(`!!document.querySelector('.card.top')`);
let out = { ready: !!ready };
const peekText = () => page.until(`(document.querySelector('pre.peek')||{}).textContent`).then(t => t || '');
const openRow = needle => page.ev(`(() => {
  const row = [...document.querySelectorAll('#sources .sr')].find(r => r.querySelector('.sn').textContent.includes(${JSON.stringify(needle)}));
  if (!row) return null;
  const label = row.querySelector('.sn').textContent; row.querySelector('a.sopen').click(); return label;
})()`);

if (mode === 'memory' && ready) {
  out.row = await openRow('orphan');
  out.text = out.row ? await peekText() : '';
}

if (mode === 'check' && ready) {
  await page.ev(`location.hash = '#/file/CLAUDE.md'; 0`);
  await page.until(`!!document.querySelector('.fl')`, 240);
  out.rows = await page.ev(`[...document.querySelectorAll('.fl')].map(r => r.textContent)`);
}

if (mode === 'prompt' && ready) {
  await page.until(`!!document.querySelector('[data-open^="prompt:"]')`);
  const count = `document.querySelectorAll('pre.peek').length + ' ' + performance.getEntriesByType('resource').filter(e => e.name.includes('prompt?id=')).length`;
  out.before = await page.ev(count);
  out.id = await page.ev(`document.querySelector('[data-open^="prompt:"]').dataset.open.slice('prompt:'.length)`);
  await page.ev(`document.querySelector('[data-open^="prompt:"]').click(); 0`);
  out.text = await peekText();
}

if (mode === 'markup' && ready) {
  out.row = await openRow('onerror');
  out.text = out.row ? await peekText() : '';
  await page.ev(`location.hash = '#/agent/main'; 0`);
  await page.until(`!!document.querySelector('[data-open^="prompt:"]')`);
  await page.ev(`document.querySelector('[data-open^="prompt:"]').click(); 0`);
  out.promptText = await peekText();
  out.dom = await page.ev(`({
    pwned: window.__pwned === undefined ? null : window.__pwned,
    imgs: document.querySelectorAll('img').length,
    inPeek: document.querySelectorAll('pre.peek *').length,
    rowChildren: [...document.querySelectorAll('#sources .sn *')].length,
  })`);
}

if (mode === 'compactions' && ready) {
  out.markers = await page.ev(`[...document.querySelectorAll('.compact')].map(e => e.textContent)`);
}

console.log(JSON.stringify(out));
page.close();
