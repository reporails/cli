// usage: node xray_guard_health.mjs <page-url>
// Drives the real `ails xray` page: opens the Hooks group, reads its header and rows, opens the details of the hook that cannot fire,
// reads the Sources table's "In context" cell and prints one JSON object. It also records every request the page made.
import { openPage, sleep } from './xray_cdp.mjs';

const [url] = process.argv.slice(2);
const page = await openPage(url, 1440, 1000);
const ready = await page.until(`!!document.querySelector('#sources .ssec[data-kind="hook"]')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
if (ready) {
  out.requests = await page.ev(`performance.getEntriesByType('resource').map(r => r.name)`);
  out.autoOpen = await page.ev(`document.querySelector('#sources .ssec[data-kind="hook"] .sbody').hidden === false`);
  out.tabs = await page.ev(`[...document.querySelectorAll('.tab')].map(t => t.dataset.tab)`);
  out.header = await page.ev(`(() => { const s = document.querySelector('#sources .ssec[data-kind="hook"]'); return { used: s.querySelector('.ct .used').textContent, total: s.querySelector('.ct .tot').textContent, subs: [...s.querySelectorAll('.sx-sub')].map(e => e.textContent) }; })()`);
  await click('#sources .ssec[data-kind="hook"] .sh');
  await sleep(150);
  // The other sessions are read in the background; the rows settle on the poll after the read is done.
  await page.until(`![...document.querySelectorAll('#sources .ssec[data-kind="hook"] .sr .sw')].some(e => e.textContent.includes('checking'))`);
  out.rows = await page.ev(`[...document.querySelectorAll('#sources .ssec[data-kind="hook"] .sr')].map(r => ({ id: r.dataset.source, name: r.querySelector('.sn').textContent, facts: r.querySelector('.sw').textContent }))`);
  const broken = out.rows.find(r => r.facts.includes('cannot') || r.facts.includes('not executable'));
  if (broken) {
    await click(`#sources .sr[data-source=${JSON.stringify(broken.id)}]`);
    await page.until(`!!document.querySelector('.pk-dialog .pk-sec')`);
    out.details = await page.ev(`(() => { const secs = [...document.querySelectorAll('.pk-dialog .pk-sec')]; return { titles: secs.map(s => s.querySelector('h4').textContent), health: secs[0].textContent }; })()`);
    await click('[data-close-peek].pk-x');
  }
  await click('.tab[data-tab="sources"]');
  await page.until(`!!document.querySelector('.tb-src-grid.vl-row')`);
  out.table = await page.ev(`[...document.querySelectorAll('.vl-row.tb-src-grid')].map(r => [...r.children].map(c => c.textContent))`);
  out.resourcesAfter = await page.ev(`performance.getEntriesByType('resource').map(r => r.name)`);
}
await page.close();
console.log(JSON.stringify(out));
