// usage: node xray_panels.mjs <page-url> <mode>
// Drives the Sources panel, the right column and the details contents of the bundled page and prints one JSON object.
import { openPage, toGraph, sleep } from './xray_cdp.mjs';

const [url, mode] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440, 1000);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('#sources .ssec') && !!document.querySelector('#inspector .ix-head')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const groups = () => page.ev(`[...document.querySelectorAll('#sources .ssec')].map(s => ({
  kind: s.dataset.kind, used: (s.querySelector('.ct .used') || {}).textContent || '', total: (s.querySelector('.ct .tot') || {}).textContent || '',
  title: (s.querySelector('.ct') || {}).title || '', finds: (s.querySelector('.sx-sub.gf') || {}).textContent || null,
  off: (s.querySelector('.sx-sub.off') || {}).textContent || null, eye: s.querySelector('.sx-eye') ? s.querySelector('.sx-eye').getAttribute('aria-label') : null,
  rows: s.querySelectorAll('.sr').length, more: (s.querySelector('.smore') || {}).textContent || null, dots: s.querySelectorAll('.sh .sdot').length }))`);

if (mode === 'eye' && ready) {
  await click('[data-groups="open"]');
  await click('#sources .smore');
  await sleep(100);
  out.before = await groups();
  out.cardsBefore = await page.ev(`document.querySelectorAll('.card[data-node]').length`);
  await click('.sx-eye[data-eye="agent"]');
  await sleep(150);
  out.after = await groups();
  out.cardsAfter = await page.ev(`document.querySelectorAll('.card[data-node]').length`);
}

if (mode === 'rows' && ready) {
  await click('[data-groups="open"]');
  await sleep(100);
  out.groups = await groups();
  out.rows = await page.ev(`[...document.querySelectorAll('#sources .sr')].map(r => ({ id: r.dataset.source || r.dataset.peek, name: r.querySelector('.sn').textContent, line2: r.querySelector('.sw').textContent, scoped: !!r.querySelector('.scoped'), never: r.classList.contains('never') }))`);
}

if (mode === 'column' && ready) {
  const read = () => page.ev(`({ kicker: document.querySelector('#inspector .ix-kicker').textContent, back: (document.querySelector('#inspector .ix-back') || {}).textContent || null,
    name: document.querySelector('#inspector .nm').textContent, output: (document.querySelector('#inspector .ix-out') || {}).textContent || null,
    chips: document.querySelectorAll('#inspector .ix-chips .chip[aria-label]').length, tiles: [...document.querySelectorAll('#inspector .ix-tile')].map(t => t.textContent),
    total: document.querySelector('#inspector .ix-total').textContent,
    rows: [...document.querySelectorAll('#inspector .ic')].map(r => ({ size: r.querySelector('.ic-k').textContent, label: r.querySelector('.ic-n').textContent, source: r.dataset.source || null, peek: r.dataset.peek || null })),
    tools: [...document.querySelectorAll('#inspector .ix-tool')].map(r => ({ tool: r.dataset.tool, n: Number(r.querySelector('.n').textContent) })),
    withheld: [...document.querySelectorAll('#inspector .ix-quiet')].map(q => q.textContent), drill: !!document.querySelector('#inspector [data-drill]') })`);
  out.main = await read();
  await click('.card[data-node="a4"]');
  await sleep(150);
  out.sub = await read();
  await click('#inspector .ix-back');
  await sleep(150);
  out.again = await read();
}

if (mode === 'details' && ready) {
  await click('#sources .sr[data-source="CLAUDE.md"]');
  await page.until(`!!document.querySelector('.pk-dialog pre.peek')`);
  out.source = await page.ev(`({ title: document.querySelector('.pk-title').textContent, text: document.querySelector('.pk-dialog pre.peek').textContent, body: document.querySelector('.pk-dialog').textContent })`);
  await click('[data-close-peek].pk-x');
  await sleep(100);
  await click('#inspector [data-peek="peak:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-lg')`);
  out.peak = await page.ev(`({ title: document.querySelector('.pk-title').textContent, pcts: [...document.querySelectorAll('.pk-dialog .pk-lg .pct')].map(e => e.textContent), sizes: [...document.querySelectorAll('.pk-dialog .pk-lg .v')].map(e => e.textContent) })`);
  await click('[data-close-peek].pk-x');
  await sleep(100);
  await click('#inspector [data-peek="cost:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
  out.cost = await page.ev(`document.querySelector('.pk-dialog').textContent`);
}

page.close();
console.log(JSON.stringify(out));
