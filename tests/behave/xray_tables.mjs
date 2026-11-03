// usage: node xray_tables.mjs <page-url> <mode>
// Drives the Tool calls and Sources tables in headless Chrome and prints one JSON object per mode.
import { openPage, sleep } from './xray_cdp.mjs';

const [url, mode] = [process.argv[2], process.argv[3]];
const page = await openPage(url, 1440, 1000);
const ready = await page.until(`!!document.querySelector('.tab[data-tab]') && !!document.querySelector('#sources .sr')`);
const out = { ready: !!ready };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const tab = async name => {
  await click(`.tab[data-tab="${name}"]`);
  await page.until(`document.querySelector('.tab[data-tab="${name}"]').getAttribute('aria-selected') === 'true' && !!document.querySelector('#view-${name} ${name === 'calls' ? '.tb-summary' : '.vl-sizer'}')`);
};
const pressed = (sel, on) => page.until(`(() => { const b = document.querySelector(${JSON.stringify(sel)}); return !!b && b.getAttribute('aria-pressed') === '${on}'; })()`);
// Flips the Failed-only button and waits until it shows the new state.
const failed = async on => { await click('[data-calls-failed]'); await pressed('[data-calls-failed]', on); };
const frame = () => page.frame();
const summary = () => page.ev(`document.querySelector('.tb-summary').textContent`);
const rowCount = () => page.ev(`document.querySelectorAll('#view-calls .vl-row').length`);
// The table's scroll area is walked to its end so every row is seen once.
const allRows = () => page.ev(`(async () => {
  const seen = new Set();
  if (!document.querySelector('#view-calls .vl') || document.querySelector('#view-calls .vl').hidden) return [];
  const more = document.querySelector('#view-calls .tb-more');
  if (more && !more.hidden && more.textContent.startsWith('Show all')) { more.click(); await new Promise(r => requestAnimationFrame(() => r(1))); }
  const vl2 = document.querySelector('#view-calls .vl');
  vl2.scrollTop = 0;
  for (let i = 0; i < 400; i++) {
    await new Promise(r => requestAnimationFrame(() => r(1)));
    for (const r of vl2.querySelectorAll('.vl-row')) seen.add(r.dataset.peek + '|' + r.style.top);
    if (vl2.scrollTop + vl2.clientHeight >= vl2.scrollHeight - 1) break;
    vl2.scrollTop += vl2.clientHeight - 40;
  }
  return [...seen];
})()`);
// The click keeps the page's first match (a button, or an inspector link that sets the same scope); the wait reads the table's own button. A one-agent view draws none: nothing to wait for.
const setScope = async s => { if (!await click(`[data-calls-scope="${s}"]`)) return; await frame(); if (!await page.ev(`!!document.querySelector('.seg[data-calls-scope]')`)) return; await pressed(`.seg[data-calls-scope="${s}"]`, true); };
const setTool = async t => { await page.ev(`(() => { const b = [...document.querySelectorAll('[data-calls-tool]')].find(x => x.dataset.callsTool === ${JSON.stringify(t)}); b.click(); return 0; })()`); await pressed(`.seg[data-calls-tool=${JSON.stringify(t)}]`, true); };

// Each agent is opened by its path in the hash, so the Tool calls tab's agent is that agent.
const chains = JSON.parse(process.argv[4] || '{}');
// The page's own hashchange listener has drawn the agent by the time this listener resolves.
const goTo = async id => { await page.ev(`new Promise(r => { const h = '#/agent/' + ${JSON.stringify(chains[id])}.join('/'); if (location.hash === h) return r(1); addEventListener('hashchange', () => r(1), { once: true }); location.hash = h; })`); await frame(); };

if (mode === 'counts' && ready) {
  await tab('calls');
  out.summary = await summary();
  out.strip = await page.ev(`({ canvases: document.querySelectorAll('#view-calls canvas').length, tickEls: document.querySelectorAll('#view-calls .tb-strip *').length })`);
  await failed('true');
  out.failedOnly = await summary();
  out.failedPressed = await page.ev(`document.querySelector('[data-calls-failed]').getAttribute('aria-pressed')`);
  out.failedRows = (await allRows()).length;
  await failed('false');
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
      await failed('true');
      out.rows[id][t] = { s, failed: await summary() };
      await failed('false');
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
  await click('[data-calls-all]'); await frame(); await frame();
  out.rowsAll = await rowCount();
  out.height = await page.ev(`document.querySelector('#view-calls .vl-sizer').offsetHeight`);
  await page.ev(`(() => { const vl = document.querySelector('#view-calls .vl'); vl.scrollTop = vl.scrollHeight; return 0; })()`);
  await frame();
  out.rowsEnd = await rowCount();
  out.lastPeek = await page.ev(`(() => { const rows = [...document.querySelectorAll('#view-calls .vl-row')]; return rows[rows.length - 1].dataset.peek; })()`);
}

if (mode === 'summary' && ready) {
  await tab('calls');
  await page.until(`document.querySelectorAll('#view-calls .vl-row').length > 0`);
  out.drawn = await rowCount();
  await click('[data-calls-failed]');
  await page.until(`/npm test/.test(document.querySelector('#view-calls .vl').textContent)`, 20);
  out.failedRows = await page.ev(`[...document.querySelectorAll('#view-calls .vl-row')].map(r => ({ peek: r.dataset.peek, summary: r.children[3].textContent, title: r.title }))`);
  out.requested = await page.ev(`fetch('/test/requests', { headers: { 'X-Xray-Token': document.querySelector('meta[name=xray-token]').content } }).then(r => r.json())`);
}

if (mode === 'summary_draw' && ready) {
  await tab('calls');
  await page.until(`document.querySelectorAll('#view-calls .vl-row').length > 0`);
  out.drawn = await rowCount();
}

if (mode === 'running_call' && ready) {
  await tab('calls');
  await page.until(`document.querySelectorAll('#view-calls .vl-row').length > 0`);
  // The page polls the view every 2 s: after a swap, wait for the poll that adopts the new view, its command requests, and a frame.
  await page.ev(`(() => { window.__views = 0; window.__pending = 0; const real = window.fetch; window.fetch = (u, ...a) => { window.__pending++; const p = real(u, ...a); p.then(r => { if (/view/.test(String(u)) && r.status === 200) window.__views++; }).catch(() => {}).finally(() => { window.__pending--; }); return p; }; return 0; })()`);
  const swap = async q => {
    const before = await page.ev(`window.__views`);
    await page.ev(`fetch('/test/swap${q}').then(() => 0)`);
    await page.until(`window.__views > ${before}`, 40);
    await page.frame(); await page.frame();
    await page.until(`window.__pending === 0`, 40);
    await page.frame();
  };
  await swap('');
  await swap('');
  await swap('?result=1');
}

// Every /call answer is held until all are asked for, then released at once: each arrival asks the page to draw again.
if (mode === 'text_burst' && ready) {
  await page.ev(`(() => {
    window.__held = [];
    const real = window.fetch;
    window.fetch = (u, ...a) => /^\\/?call\\?/.test(String(u)) ? new Promise(res => window.__held.push(() => res(real(u, ...a)))) : real(u, ...a);
    window.__draws = 0;
    new MutationObserver(rs => { if (rs.some(r => r.addedNodes.length)) window.__draws++; }).observe(document.body, { childList: true, subtree: true });
    return 0;
  })()`);
  await tab('calls');
  await page.until(`window.__held.length > 0`); await frame();
  out.held = await page.ev(`window.__held.length`);
  await page.ev(`(() => { window.__draws = 0; window.__held.forEach(f => f()); return 0; })()`);
  await sleep(1000);
  out.draws = await page.ev(`window.__draws`);
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
await page.close();
