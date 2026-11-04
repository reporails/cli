// usage: node xray_fix.mjs <page-url> <mode> <json args>
// Drives the fixes to the Tool calls, Sources, panels and canvas of the bundled page and prints one JSON object per mode.
import { openPage, sleep } from './xray_cdp.mjs';

const [url, mode, argText] = [process.argv[2], process.argv[3], process.argv[4]];
const args = JSON.parse(argText || '{}');
const page = await openPage(url, 1440, 1000);
const ready = await page.until(`!!document.querySelector('.tab[data-tab]') && !!document.querySelector('#sources .ssec')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const tab = async name => { await click(`.tab[data-tab="${name}"]`); await sleep(200); };
const text = sel => page.ev(`(document.querySelector(${JSON.stringify(sel)}) || {}).textContent || null`);
const texts = sel => page.ev(`[...document.querySelectorAll(${JSON.stringify(sel)})].map(e => e.textContent)`);
// A virtualised table's rows, collected by scrolling it from top to bottom.
const walk = (sel, pick) => page.ev(`(async () => {
  const vl = document.querySelector(${JSON.stringify(sel + ' .vl')});
  const seen = new Map();
  vl.scrollTop = 0;
  for (let i = 0; i < 200; i++) {
    await new Promise(r => setTimeout(r, 40));
    for (const r of vl.querySelectorAll('.vl-row')) seen.set(r.style.top, (${pick})(r));
    if (vl.scrollTop + vl.clientHeight >= vl.scrollHeight - 1) break;
    vl.scrollTop += vl.clientHeight - 40;
  }
  return [...seen.values()];
})()`);
// A member of a collapsed fan-out group has no card until its group is open.
const select = async id => {
  while (await page.ev(`!document.querySelector('.card[data-node="${id}"]') && !!document.querySelector('.card[data-group][aria-expanded="false"]')`)) await click('.card[data-group][aria-expanded="false"]');
  await click(`.card[data-node="${id}"]`);
  await page.until(`!!document.querySelector('#inspector .ix-out')`);
};
const selectedTab = () => page.ev(`(document.querySelector('.tab[aria-selected="true"]') || {}).dataset.tab || null`);

if (mode === 'sources_table' && ready) {
  await tab('sources');
  out.rows = await walk('#view-sources', `r => ({ id: r.dataset.source || r.dataset.peek, name: r.children[1].textContent, who: r.children[3].textContent, kind: r.children[2].textContent, finds: r.children[5].textContent, findsClass: r.children[5].className })`);
  out.all = out.rows.map(r => r.name + r.who + r.finds).join(' ');
}

if (mode === 'calls_instr' && ready) {
  await tab('calls');
  await page.ev(`document.querySelector('#view-calls .vl').scrollTop = ${args.index * 34}; 0`);
  await sleep(250);
  await click(`#view-calls [data-peek="call:${args.id}"]`);
  await page.until(`/Instructions in context/.test(document.querySelector('#side-calls').textContent)`);
  out.sources = await page.ev(`[...document.querySelectorAll('#side-calls .tb-src')].map(b => b.dataset.source)`);
  out.finds = await texts('#side-calls .tb-find');
}

if (mode === 'solo' && ready) {
  out.tab = await selectedTab();
  await tab('calls');
  out.hintHidden = await page.ev(`document.querySelector('#hint').hidden`);
  out.scopeButtons = await page.ev(`document.querySelectorAll('#view-calls [data-calls-scope]').length`);
  out.tiles = await texts('#side-calls .ix-tile');
  out.context = await text('#side-calls .ix-ctx .ix-total');
  await tab('sources');
  out.hintSources = await page.ev(`document.querySelector('#hint').hidden`);
  out.tilesSources = await texts('#side-sources .ix-tile');
  await tab('graph');
  out.hintGraph = await page.ev(`document.querySelector('#hint').hidden`);
}

if (mode === 'scope_name' && ready) {
  await page.ev(`location.hash = '#/agent/' + ${JSON.stringify(args.chain)}.join('/'); 0`);
  await sleep(200);
  await tab('calls');
  out.button = await page.ev(`(() => { const b = document.querySelector('#view-calls [data-calls-scope="one"]'); const n = b.querySelector('.segname'); return { title: b.title, text: b.textContent, truncated: n.scrollWidth > n.clientWidth, width: b.getBoundingClientRect().width }; })()`);
}

if (mode === 'show_all' && ready) {
  await tab('calls');
  const more = () => page.ev(`(() => { const m = document.querySelector('#view-calls .tb-more'); return m.hidden ? null : m.textContent; })()`);
  out.start = await more();
  await click('[data-calls-all]'); await sleep(150);
  out.opened = await more();
  const tools = await page.ev(`[...document.querySelectorAll('#view-calls [data-calls-tool]')].map(b => b.dataset.callsTool).filter(t => t !== 'all')`);
  for (const t of tools) {
    await click(`#view-calls [data-calls-tool="${t}"]`); await sleep(120);
    const m = await more();
    if (m !== null) { out.afterFilter = m; out.filter = t; break; }
  }
}

if (mode === 'late_result' && ready) {
  await tab('calls');
  await click('#view-calls .vl-row');
  await page.until(`/No result recorded/.test((document.querySelector('#side-calls') || {}).textContent || '')`);
  out.before = await text('#side-calls');
  await page.ev(`fetch('/test/swap?result=1').then(() => 0)`);
  out.after = (await page.until(`/result of toolu_/.test(document.querySelector('#side-calls').textContent) && document.querySelector('#side-calls').textContent`, 24)) || await text('#side-calls');
}

if (mode === 'default_tab' && ready) {
  out.first = await selectedTab();
  await click('.swbtn');
  await page.until(`document.querySelectorAll('.swrow').length === 3`);
  // The new document has no marker: the old page's marker is gone once the reload has happened.
  await page.ev(`window.__oldPage = true; 0`);
  await click('.swrow:nth-child(2) .swpick');
  out.picked = await page.until(`location.search === '?session=sess-bbb' && location.search`);
  await page.until(`window.__oldPage !== true && !!document.querySelector('.tab[aria-selected="true"]')`);
  out.later = await selectedTab();
}

if (mode === 'cost' && ready) {
  out.tile = await page.ev(`(document.querySelector('#inspector .ix-tile.cost') || {}).textContent || null`);
  await click('#inspector [data-peek="cost:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
  out.panel = await text('.pk-dialog');
  out.list = await page.ev(`[...document.querySelectorAll('.pk-dialog .pk-li[data-show-in-graph]')].map(b => ({ id: b.dataset.showInGraph, text: b.textContent }))`);
}

if (mode === 'wording' && ready) {
  out.total = await text('#inspector .ix-total');
  await click('#inspector [data-peek="peak:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-lg')`);
  out.peak = await text('.pk-dialog');
  await click('.pk-x');
  await click('#inspector [data-peek="cost:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
  out.cost = await text('.pk-dialog');
  await click('.pk-x');
  await click('[data-groups="open"]');
  await sleep(100);
  out.roles = await texts('#sources .ssec[data-kind="memory"] .sx-role');
  await click('#sources .sr[data-source="CLAUDE.md"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-li')`);
  out.loadedIn = await page.ev(`[...document.querySelectorAll('.pk-dialog .pk-li')].map(b => ({ id: b.dataset.showInGraph, text: b.textContent }))`);
  await click('.pk-x');
  await select('a1');
  out.output = await text('#inspector .ix-out');
  await tab('calls');
  out.head = await text('#view-calls .tb-head');
  await click('#view-calls .vl-row');
  await page.until(`!!document.querySelector('#side-calls .tb-kv')`);
  out.kv = await text('#side-calls .tb-kv');
  out.k1 = await page.ev(`import('/static/js/format.js').then(m => [m.k1(10000000), m.k1(999999), m.k1(1500000), m.k1(9999), m.k1(1234567)])`);
}

if (mode === 'unrecorded' && ready) {
  await click('[data-groups="open"]');
  await sleep(100);
  out.header = await page.ev(`(() => { const s = document.querySelector('#sources .ssec[data-kind="memory"]'); return { used: s.querySelector('.ct .used').textContent, total: s.querySelector('.ct .tot').textContent, title: s.querySelector('.ct').title }; })()`);
  out.rows = await texts('#sources .ssec[data-kind="memory"] .sr .sw');
  await select('a1');
  out.output = await text('#inspector .ix-out');
  await tab('sources');
  out.table = (await walk('#view-sources', `r => ({ kind: r.children[2].textContent, who: r.children[3].textContent })`)).filter(r => r.kind === 'Memory').map(r => r.who);
  await click('#sources .ssec[data-kind="memory"] .sr');
  await page.until(`!!document.querySelector('#side-sources .pk-panel')`);
  out.peek = await text('#side-sources .pk-panel');
}

if (mode === 'over' && ready) {
  await click('#inspector [data-peek="peak:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-lg')`);
  out.peak = await text('.pk-dialog');
  out.pcts = await texts('.pk-dialog .pk-lg .pct');
}

if (mode === 'canvas' && ready) {
  out.stations = await page.ev(`[...document.querySelectorAll('.station')].map(e => e.dataset.source).filter(Boolean)`);
  out.link = await page.ev(`(() => { const b = document.querySelector('.callslink'); return { tab: b.dataset.tab, scope: b.dataset.callsScope || null }; })()`);
  await click('.callslink');
  await sleep(250);
  out.tab = await selectedTab();
  out.scopeOne = await page.ev(`(document.querySelector('#view-calls [data-calls-scope="one"]') || {getAttribute: () => null}).getAttribute('aria-pressed')`);
  out.summary = await text('.tb-summary');
}

console.log(JSON.stringify(out));
await page.close();
