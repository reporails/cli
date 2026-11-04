// usage: node xray_flicker.mjs <page-url> <source path>
// Opens the source's details on the Graph tab, the Sources tab and the Tool calls tab in turn; for each tab prints `READY <tab>`, waits for a line on stdin (the session has then been written to), waits until the page took a new view and
// drew it, and prints `SEEN <json>`: the elements removed and added again with identical content, the times a text block showed its loading state and the times a text block was empty.
import { createInterface } from 'node:readline';
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

const [url, path] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440, 1000);
const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const line = async () => (await lines.next()).value;

const WATCH = `(() => {
  const m = window.__flicker = { views: 0, replaced: {}, loading: 0, emptied: 0 };
  const of = window.fetch;
  window.fetch = async (...a) => { const r = await of(...a); if (String(a[0]).startsWith('view') && r.status === 200) m.views++; return r; };
  const where = n => { const p = n.parentElement && n.parentElement.closest('[id]'); return (p ? '#' + p.id : 'body') + ' ' + n.tagName.toLowerCase() + '.' + String(n.className).split(' ')[0]; };
  const loading = n => (n.nodeType === 3 ? n.textContent : [...n.querySelectorAll('.nk'), ...(n.matches('.nk') ? [n] : [])].map(x => x.textContent).join('|')).includes('Loading…');
  new MutationObserver(list => {
    const gone = new Map(), made = new Map();
    for (const r of list) {
      for (const n of r.removedNodes) if (n.nodeType === 1) gone.set(n.outerHTML, (gone.get(n.outerHTML) || 0) + 1);
      for (const n of r.addedNodes) {
        if (n.nodeType === 1) { const k = n.outerHTML; made.set(k, { n: (made.get(k) ? made.get(k).n : 0) + 1, at: where(n) }); }
        if (loading(n)) m.loading++;
      }
      if (r.type === 'characterData' && r.target.textContent.includes('Loading…')) m.loading++;
    }
    for (const [k, v] of made) if (gone.has(k)) m.replaced[v.at] = (m.replaced[v.at] || 0) + Math.min(v.n, gone.get(k));
    if ([...document.querySelectorAll('pre.peek')].some(p => !p.textContent)) m.emptied++;
  }).observe(document.body, { subtree: true, childList: true, characterData: true });
})()`;

await toGraph(page);
await page.until(`!!document.querySelector('#sources .sr[data-source=${JSON.stringify(path)}]')`);
await page.ev(WATCH);
await page.ev(`document.querySelector('#sources .sr[data-source=${JSON.stringify(path)}]').click(); 0`);
await page.until(`!!document.querySelector('.pk-dialog pre.peek')`);

for (const tab of ['graph', 'sources', 'calls']) {
  await page.ev(`document.querySelector('.tab[data-tab="${tab}"]').click(); 0`);
  await sleep(600);
  await page.ev(`Object.assign(window.__flicker, { views: 0, replaced: {}, loading: 0, emptied: 0 }); 0`);
  console.log('READY ' + tab);
  await line();
  await page.until(`window.__flicker.views > 0`, 80);
  await sleep(1200);
  const seen = await page.ev(`({ ...window.__flicker, text: !!document.querySelector('pre.peek') })`);
  console.log('SEEN ' + JSON.stringify({ tab, ...seen }));
}
await page.close();
