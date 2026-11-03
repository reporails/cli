// usage: node xray_tables.mjs <page-url> <mode>
// Drives the Tool calls and Sources tables in headless Chrome and prints one JSON object per mode.
import { openPage, sleep } from './xray_cdp.mjs';

const [url, mode] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440, 1000);
const ready = await page.until(`!!document.querySelector('.tab[data-tab]') && !!document.querySelector('#sources .sr')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const tab = async name => { await click(`.tab[data-tab="${name}"]`); await sleep(150); };
const summary = () => page.ev(`document.querySelector('.tb-summary').textContent`);
const rowCount = () => page.ev(`document.querySelectorAll('#view-calls .vl-row').length`);
// The table's scroll area is walked to its end so every row is seen once.
const allRows = () => page.ev(`(async () => {
  const seen = new Set();
  if (!document.querySelector('#view-calls .vl') || document.querySelector('#view-calls .vl').hidden) return [];
  const more = document.querySelector('#view-calls .tb-more');
  if (more && !more.hidden && more.textContent.startsWith('Show all')) { more.click(); await new Promise(r => setTimeout(r, 120)); }
  const vl2 = document.querySelector('#view-calls .vl');
  vl2.scrollTop = 0;
  for (let i = 0; i < 400; i++) {
    await new Promise(r => setTimeout(r, 40));
    for (const r of vl2.querySelectorAll('.vl-row')) seen.add(r.dataset.peek + '|' + r.style.top);
    if (vl2.scrollTop + vl2.clientHeight >= vl2.scrollHeight - 1) break;
    vl2.scrollTop += vl2.clientHeight - 40;
  }
  return [...seen];
})()`);
const setScope = async s => { await click(`[data-calls-scope="${s}"]`); await sleep(100); };
const setTool = async t => { await page.ev(`(() => { const b = [...document.querySelectorAll('[data-calls-tool]')].find(x => x.dataset.callsTool === ${JSON.stringify(t)}); b.click(); return 0; })()`); await sleep(100); };

// Each agent is opened by its path in the hash, so the Tool calls tab's agent is that agent.
const chains = JSON.parse(process.argv[4] || '{}');
const goTo = async id => { await page.ev(`location.hash = '#/agent/' + ${JSON.stringify(chains[id])}.join('/'); 0`); await sleep(150); };

if (mode === 'counts' && ready) {
  await tab('calls');
  out.summary = await summary();
  out.strip = await page.ev(`({ canvases: document.querySelectorAll('#view-calls canvas').length, tickEls: document.querySelectorAll('#view-calls .tb-strip *').length })`);
  await click('[data-calls-failed]'); await sleep(100);
  out.failedOnly = await summary();
  out.failedPressed = await page.ev(`document.querySelector('[data-calls-failed]').getAttribute('aria-pressed')`);
  out.failedRows = (await allRows()).length;
  await click('[data-calls-failed]'); await sleep(100);
  out.scopes = {};
  for (const id of Object.keys(chains)) {
    await goTo(id);
    const have = await page.ev(`[...document.querySelectorAll('[data-calls-scope]')].map(b => b.dataset.callsScope)`);
    const r = { have };
    for (const sc of have) { await setScope(sc); r[sc] = await summary(); r[sc + 'Rows'] = (await allRows()).length; }
    out.scopes[id] = r;
    await setScope('all');
  }
}

if (mode === 'tools' && ready) {
  await tab('calls');
  out.rows = {};
  for (const id of Object.keys(chains)) {
    await goTo(id);
    await setScope('one');
    const tools = await page.ev(`[...document.querySelectorAll('[data-calls-tool]')].map(b => b.dataset.callsTool).filter(t => t !== 'all')`);
    out.rows[id] = {};
    for (const t of tools) {
      await setTool(t);
      const s = await summary();
      await click('[data-calls-failed]'); await sleep(80);
      out.rows[id][t] = { s, failed: await summary() };
      await click('[data-calls-failed]'); await sleep(80);
    }
    await setTool('all');
    await setScope('all');
  }
}

if (mode === 'peek' && ready) {
  await tab('calls');
  await click('#view-calls .vl-row');
  await page.until(`!!document.querySelector('#side-calls .pk-panel')`);
  await page.until(`/result of/.test(document.querySelector('#side-calls').textContent)`);
  out.panel = await page.ev(`document.querySelector('#side-calls').textContent`);
  out.overlay = await page.ev(`!document.querySelector('#overlay').hidden`);
  out.showInGraph = await page.ev(`!!document.querySelector('#side-calls [data-show-in-graph]')`);
  out.instr = await page.ev(`document.querySelectorAll('#side-calls [data-source]').length`);
  out.opened = await page.ev(`(document.querySelector('#view-calls .vl-row.on') || {dataset: {}}).dataset.peek || null`);
}

if (mode === 'virtual' && ready) {
  await tab('calls');
  out.summary = await summary();
  out.rowsFirst = await rowCount();
  await click('[data-calls-all]'); await sleep(200);
  out.rowsAll = await rowCount();
  out.height = await page.ev(`document.querySelector('#view-calls .vl-sizer').offsetHeight`);
  await page.ev(`(() => { const vl = document.querySelector('#view-calls .vl'); vl.scrollTop = vl.scrollHeight; return 0; })()`);
  await sleep(300);
  out.rowsEnd = await rowCount();
  out.lastPeek = await page.ev(`(() => { const rows = [...document.querySelectorAll('#view-calls .vl-row')]; return rows[rows.length - 1].dataset.peek; })()`);
}

if (mode === 'summary' && ready) {
  await tab('calls');
  await sleep(600);
  out.drawn = await rowCount();
  await click('[data-calls-failed]');
  await page.until(`/npm test/.test(document.querySelector('#view-calls .vl').textContent)`, 20);
  out.failedRows = await page.ev(`[...document.querySelectorAll('#view-calls .vl-row')].map(r => ({ peek: r.dataset.peek, summary: r.children[3].textContent }))`);
}

if (mode === 'summary_draw' && ready) {
  await tab('calls');
  await sleep(800);
  out.drawn = await rowCount();
}

if (mode === 'running_call' && ready) {
  await tab('calls');
  await sleep(800);
  const swap = async q => { await page.ev(`fetch('/test/swap${q}').then(() => 0)`); await sleep(4500); };
  await swap('');
  await swap('');
  await swap('?result=1');
}

if (mode === 'sources' && ready) {
  await tab('sources');
  out.rows = await page.ev(`[...document.querySelectorAll('#view-sources .vl-row')].map(r => ({ source: r.dataset.source || null, peek: r.dataset.peek || null, text: r.textContent }))`);
  out.height = await page.ev(`document.querySelector('#view-sources .vl-sizer').offsetHeight`);
  await click('#view-sources .vl-row[data-peek]');
  await page.until(`!!document.querySelector('#side-sources .pk-panel')`);
  out.builtinPanel = await page.ev(`document.querySelector('#side-sources .pk-title') ? document.querySelector('#side-sources .pk-title').textContent : ''`);
}

console.log(JSON.stringify(out));
page.close();
