// usage: node xray_layout.mjs <page-url> <memory|prompt|markup|check|compactions|summaries|summarylink|recorded|excluded|agent> [source id]
// Drives the real `ails xray` page in headless Chrome and prints one JSON object describing what it drew.
import { openPage, toGraph } from './xray_cdp.mjs';

const [url, mode] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.card.top')`);
let out = { ready: !!ready };
const peekText = () => page.until(`(document.querySelector('pre.peek')||{}).textContent`).then(t => t || '');
const openRow = needle => page.ev(`(() => {
  const all = document.querySelector('[data-groups="open"]'); if (all) all.click();
  const row = [...document.querySelectorAll('#sources .sr')].find(r => r.querySelector('.sn').textContent.includes(${JSON.stringify(needle)}));
  if (!row) return null;
  const label = row.querySelector('.sn').textContent; row.click(); return label;
})()`);

if (mode === 'recorded' && ready) {
  await page.ev(`(() => { const all = document.querySelector('[data-groups="open"]'); if (all) all.click(); })()`);
  out.opened = await page.ev(`(() => { const row = document.querySelector('#sources .sr[data-source=' + JSON.stringify(${JSON.stringify(process.argv[4])}) + ']'); if (!row) return false; row.click(); return true; })()`);
  out.text = out.opened ? await peekText() : '';
  out.dialog = await page.ev(`(document.querySelector('.pk-dialog') || {}).textContent || ''`);
  out.controls = await page.ev(`[...document.querySelectorAll('.pk-dialog button')].map(b => b.textContent)`);
}

if (mode === 'excluded' && ready) {
  const source = process.argv[4];
  await page.ev(`(() => { const all = document.querySelector('[data-groups="open"]'); if (all) all.click(); })()`);
  out.opened = await page.ev(`(() => { const row = document.querySelector('#sources .sr[data-source=' + JSON.stringify(${JSON.stringify(source)}) + ']'); if (!row) return false; row.click(); return true; })()`);
  out.text = out.opened ? await peekText() : '';
  out.dialogControls = await page.ev(`[...document.querySelectorAll('.pk-dialog button')].map(b => b.textContent)`);
  out.dialogNote = await page.ev(`[...document.querySelectorAll('.pk-dialog .excluded')].map(n => n.textContent).join(' ')`);
  await page.ev(`location.hash = '#/file/' + ${JSON.stringify(source)}; 0`);
  await page.until(`!!document.querySelector('#view-file .act')`, 240);
  out.paneControls = await page.ev(`[...document.querySelectorAll('#view-file .act button')].map(b => b.textContent)`);
  out.paneNote = await page.ev(`[...document.querySelectorAll('#view-file .excluded')].map(n => n.textContent).join(' ')`);
}

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
  await page.ev(`document.querySelector('.pk-x').click(); location.hash = '#/agent/main'; 0`);
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

if (mode === 'agent' && ready) {
  await page.ev(`document.querySelector('[data-groups="open"]').click(); 0`);
  await page.until(`!!document.querySelector('#sources .ssec[data-kind="agent"] .sr')`);
  out.row = await openRow('general');
  out.text = out.row ? await peekText() : '';
  out.tools = out.row ? await page.ev(`(document.querySelector('.pk-pre') || {}).textContent || ''`) : '';
  out.pres = out.row ? await page.ev(`[...document.querySelectorAll('.pk-pre')].map(e => e.textContent)`) : [];
  out.dialog = await page.ev(`(document.querySelector('.pk-dialog') || {}).textContent || ''`);
}

if (mode === 'compactions' && ready) {
  out.markers = await page.ev(`[...document.querySelectorAll('.compact')].map(e => e.textContent)`);
}

if (mode === 'summaries' && ready) {
  await page.ev(`location.hash = '#/agent/main'; 0`);
  await page.until(`!!document.querySelector('[data-open^="summary:"]')`);
  for (let i = 0; i < 2; i++) {
    await page.ev(`document.querySelectorAll('[data-open^="summary:"]')[${i}].click(); 0`);
    await page.until(`document.querySelectorAll('pre.peek').length === ${i + 1}`);
  }
  out.rows = await page.ev(`[...document.querySelectorAll('[data-open^="summary:"]')].map(b => b.textContent)`);
  out.texts = await page.ev(`[...document.querySelectorAll('pre.peek')].map(e => e.textContent)`);
}

if (mode === 'summarylink' && ready) {
  await page.until(`!!document.querySelector('.compact-summary')`);
  await page.ev(`document.querySelector('.compact-summary').click(); 0`);
  await page.until(`document.querySelectorAll('pre.peek').length === 1`);
  out.texts = await page.ev(`[...document.querySelectorAll('pre.peek')].map(e => e.textContent)`);
}

console.log(JSON.stringify(out));
await page.close();
