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

if (mode === 'unpriced' && ready) {
  await click('#inspector [data-peek="cost:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
  out.cost = await page.ev(`document.querySelector('.pk-dialog').textContent`);
}

if (mode === 'eye_hover' && ready) {
  await click('[data-groups="open"]');
  await sleep(100);
  await click('.sx-eye[data-eye="agent"]');
  await sleep(150);
  const sel = '#sources .ssec[data-kind="agent"] .sr';
  await page.ev(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({ block: 'center' }); 0`);
  const p = await page.ev(`(() => { const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: p.x, y: p.y, button: 'none' });
  await sleep(300);
  out.eyePressed = await page.ev(`document.querySelector('.sx-eye[data-eye="agent"]').getAttribute('aria-pressed')`);
  out.hovered = await page.ev(`document.querySelector(${JSON.stringify(sel)}).classList.contains('on')`);
}

const swap = view => page.ev(`fetch('/test/swap?view=${view}').then(() => 0)`);
const centre = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.scrollIntoView({ block: 'center', inline: 'center' }); const r = e.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
const hoverOn = async sel => { const p = await centre(sel); await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: p.x, y: p.y, button: 'none' }); await sleep(250); };

if (mode === 'hover_calm' && ready) {
  const column = () => page.ev(`document.querySelector('#inspector').innerText`);
  const open = () => page.ev(`[...document.querySelectorAll('#sources .sh[data-source-group]')].map(b => b.dataset.sourceGroup + ':' + b.getAttribute('aria-expanded')).join(' ')`);
  out.columnBefore = await column();
  out.openBefore = await open();
  const spine = await page.ev(`[...document.querySelectorAll('#canvas [data-source]')].filter(e => e.tagName !== 'path').map(e => e.tagName.toLowerCase() + '[data-source="' + e.dataset.source + '"]')`);
  out.hovered = 0;
  for (const sel of spine.slice(0, 8)) { await hoverOn(sel); out.hovered++; }
  await hoverOn('#sources .sh[data-source-group]:last-of-type');
  await hoverOn('#sources .ssec:last-child .sh');
  out.columnAfter = await column();
  out.openAfter = await open();
  const station = await page.ev(`(() => { const e = document.querySelector('#canvas .station[data-source]'); return e ? e.dataset.source : null; })()`);
  out.station = station;
  await click('#canvas .station[data-source]');
  out.dialog = !!(await page.until(`!!document.querySelector('.pk-dialog .pk-title')`));
  out.title = await page.ev(`(document.querySelector('.pk-title') || {}).textContent || ''`);
}

if (mode === 'pin' && ready) {
  const name = () => page.ev(`(document.querySelector('#canvas .fbanner b') || {}).textContent || ''`);
  const rows = await page.ev(`[...document.querySelectorAll('#sources .sr[data-source]')].map(r => r.dataset.source)`);
  await click(`#sources .sr[data-source="${rows[0]}"]`);
  await page.until(`!!document.querySelector('.pk-dialog .pk-act')`);
  out.pinnedByClick = await page.ev(`!!document.querySelector('#canvas [data-clear]')`);
  await page.ev(`[...document.querySelectorAll('.pk-dialog .pk-act')].find(b => b.textContent.trim() === 'Pin on graph').click(); 0`);
  await sleep(200);
  out.pinned = await name();
  out.clearAtOnce = await page.ev(`!!document.querySelector('#canvas [data-clear]')`);
  await hoverOn(`#sources .sr[data-source="${rows[1]}"]`);
  out.whileHovering = await name();
  await swap('view_sample');
  await sleep(3000);
  out.afterUpdate = await name();
  out.clearAfterUpdate = await page.ev(`!!document.querySelector('#canvas [data-clear]')`);
  await click('#canvas [data-clear]');
  await sleep(200);
  out.clearAfterClear = await page.ev(`!!document.querySelector('#canvas [data-clear]')`);
}

if (mode === 'eye_line' && ready) {
  out.rows = await page.ev(`[...document.querySelectorAll('#sources .ssec')].filter(s => s.querySelector('.sx-eye')).map(s => {
    const t = s.querySelector('.sx-title').getBoundingClientRect(), e = s.querySelector('.sx-eye').getBoundingClientRect(), sub = s.querySelector('.sx-sub');
    return { kind: s.dataset.kind, titleTop: t.top, titleBottom: t.bottom, eyeTop: e.top, eyeBottom: e.bottom, subTop: sub ? sub.getBoundingClientRect().top : null };
  })`);
  await click('.sx-eye[data-eye="agent"]');
  await sleep(150);
  out.hiddenRow = await page.ev(`(() => { const s = document.querySelector('#sources .ssec[data-kind="agent"]'); const t = s.querySelector('.sx-title').getBoundingClientRect(), e = s.querySelector('.sx-eye').getBoundingClientRect(), sub = s.querySelector('.sx-sub.off'); return { titleTop: t.top, titleBottom: t.bottom, eyeTop: e.top, eyeBottom: e.bottom, subTop: sub ? sub.getBoundingClientRect().top : null }; })()`);
}

if (mode === 'sub_cost' && ready) {
  const tiles = () => page.ev(`[...document.querySelectorAll('#inspector .ix-tile.cost')].map(t => t.innerText)`);
  out.mainTile = await tiles();
  await click('.card[data-node="a1"]');
  await sleep(200);
  out.subTile = await tiles();
}

await page.close();
console.log(JSON.stringify(out));
