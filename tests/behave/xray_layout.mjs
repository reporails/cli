// usage: node xray_layout.mjs <page-url> <memory|prompt|markup|check|compactions|summaries|stripe|restart|recorded|excluded|agent|moments> [source id | call ids]
// Drives the real `ails xray` page in headless Chrome and prints one JSON object describing what it drew.
import { openPage, sleep, toGraph } from './xray_cdp.mjs';

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
  out.tools = out.row ? await page.ev(`(document.querySelector('.pk-pre') || {}).textContent || ''`) : '';
  out.pres = out.row ? await page.ev(`[...document.querySelectorAll('.pk-pre')].map(e => e.textContent)`) : [];
  out.dialog = await page.ev(`(document.querySelector('.pk-dialog') || {}).textContent || ''`);
  out.action = await page.ev(`(([...document.querySelectorAll('.pk-dialog .pk-act')].find(b => b.dataset.peek) || {}).textContent) || null`);
  if (out.action) {
    await page.ev(`[...document.querySelectorAll('.pk-dialog .pk-act')].find(b => b.dataset.peek).click(); 0`);
    out.text = await peekText();
    out.opened = await page.ev(`document.querySelector('.pk-title').textContent`);
  }
}

if (mode === 'compactions' && ready) {
  out.markers = await page.ev(`[...document.querySelectorAll('.compact')].map(e => e.textContent)`);
}

if (mode === 'summaries' && ready) {
  await page.ev(`location.hash = '#/agent/main'; 0`);
  await page.until(`!!document.querySelector('.ix-kid[data-peek^="compaction:"]')`);
  out.rows = await page.ev(`[...document.querySelectorAll('.ix-kid[data-peek^="compaction:"]')].map(b => b.textContent)`);
  out.texts = [];
  for (let i = 0; i < out.rows.length; i++) {
    await page.ev(`document.querySelectorAll('.ix-kid[data-peek^="compaction:"]')[${i}].click(); 0`);
    await page.until(`!!document.querySelector('.pk-dialog pre.peek')`);
    out.texts.push(await page.ev(`document.querySelector('.pk-dialog pre.peek').textContent`));
    await page.ev(`document.querySelector('.pk-x').click(); 0`);
    await page.until(`!document.querySelector('.pk-dialog')`);
  }
}

// The inspector's compaction rows, and the details window each opens.
if (mode === 'compaction-rows' && ready) {
  await page.ev(`location.hash = '#/agent/main'; 0`);
  await page.until(`!!document.querySelector('#inspector .ix-sub')`);
  const rows = `[...document.querySelectorAll('#inspector .ix-kid[data-peek^="compaction:"]')]`;
  out.rows = await page.ev(`${rows}.map(b => b.textContent)`);
  out.dialogs = [];
  for (let i = 0; i < out.rows.length; i++) {
    await page.ev(`${rows}[${i}].click(); 0`);
    await page.until(`!!document.querySelector('.pk-dialog')`);
    out.dialogs.push(await page.ev(`document.querySelector('.pk-dialog').textContent`));
    await page.ev(`document.querySelector('.pk-x').click(); 0`);
    await page.until(`!document.querySelector('.pk-dialog')`);
  }
}

// Clicks the compaction stripe at index argv[4] and reports the one details dialog it opens.
if (mode === 'stripe' && ready) {
  await page.until(`!!document.querySelector('button.compact')`);
  const i = Number(process.argv[4] || 0);
  out.stripes = await page.ev(`[...document.querySelectorAll('button.compact')].map(b => ({ peek: b.dataset.peek, name: b.getAttribute('aria-label') }))`);
  await page.ev(`document.querySelectorAll('button.compact')[${i}].click(); 0`);
  await page.until(`!!document.querySelector('.pk-dialog')`);
  await page.until(`!document.querySelector('.pk-dialog .nk') || !!document.querySelector('.pk-dialog pre.peek')`);
  out.dialogs = await page.ev(`document.querySelectorAll('.pk-dialog, .pk-panel, [role="dialog"]').length`);
  out.dialog = await page.ev(`document.querySelector('.pk-dialog').textContent`);
  out.summary = await page.ev(`(document.querySelector('.pk-dialog pre.peek') || {}).textContent || null`);
  out.files = await page.ev(`[...document.querySelectorAll('.pk-dialog .fs')].map(e => e.textContent)`);
  out.over = await page.ev(`!!document.querySelector('.pk-dialog').closest('#overlay')`);
}

// Reports every source card with its source and rect beside the compaction stripes' rects, and what overlaps a stripe.
if (mode === 'restart' && ready) {
  await page.until(`!!document.querySelector('button.compact')`);
  const r = await page.ev(`(() => {
    const box = e => { const b = e.getBoundingClientRect(); return { top: b.top, bottom: b.bottom }; };
    const stripes = [...document.querySelectorAll('button.compact')].map(box);
    const cards = [...document.querySelectorAll('.snode')].map(e => ({ source: e.dataset.source, ...box(e) }));
    const overlaps = [];
    for (const e of document.querySelectorAll('.card, .station')) for (const s of stripes) { const b = box(e); if (b.top < s.bottom && b.bottom > s.top) overlaps.push({ cls: e.className, text: e.textContent.slice(0, 40), top: b.top, bottom: b.bottom }); }
    const stations = [...document.querySelectorAll('.station')].map(box);
    return { stripes, cards, overlaps, stations };
  })()`);
  Object.assign(out, r);
  out.sources = [...new Set(r.cards.map(c => c.source))];
  // Hiding the memory layer leaves the stripe and the canvas height where they were.
  const stripeTop = () => page.ev(`(() => {
    const top = document.querySelector('button.compact').getBoundingClientRect().top + scrollY;
    return top + ' ' + document.querySelector('.cv').offsetHeight;
  })()`);
  out.stripeBefore = await stripeTop();
  await page.ev(`document.querySelector('[data-eye="memory"]').click(); 0`);
  out.stripeHidden = await stripeTop();
  await page.ev(`document.querySelector('[data-eye="memory"]').click(); 0`);
  // Closing the details of the card below the stripe puts focus back on that card.
  const below = await page.ev(`(() => {
    const s = document.querySelector('button.compact').getBoundingClientRect();
    const e = [...document.querySelectorAll('.snode')].find(x => x.getBoundingClientRect().top >= s.bottom);
    if (!e) return null;
    e.click();
    return e.dataset.card || null;
  })()`);
  await page.until(`!!document.querySelector('.pk-dialog')`);
  await page.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await page.until(`!document.querySelector('.pk-dialog')`);
  out.belowCard = below;
  out.focusedCard = await page.ev(`document.activeElement.dataset.card || null`);
}

// The inspector's In context list as the page draws it with nothing picked, then with each call (argv[4..]) picked in turn.
if (mode === 'moments' && ready) {
  const list = () => page.ev(`(() => { const s = document.querySelector('#inspector .ix-ctx'); return s ? { heading: (s.querySelector('.ix-total') || {}).textContent || null, sources: [...s.querySelectorAll('[data-source]')].map(b => b.dataset.source), text: s.textContent } : null; })()`);
  out.base = await list();
  out.picked = [];
  out.opened = [];
  for (const id of process.argv.slice(4)) {
    await page.ev(`(() => { const x = document.createElement('button'); x.dataset.peek = 'call:' + ${JSON.stringify(id)}; document.body.append(x); x.click(); x.remove(); return 0; })()`);
    await page.until(`(() => { const s = document.querySelector('#inspector .ix-ctx'); return !!s && !!s.querySelector('.ix-total') && !/Loading/.test(s.textContent); })()`, 120);
    await sleep(300);
    out.picked.push(await list());
    // A row of the picked list that is not a source opens the details of that list's reply, and the list stays.
    await page.ev(`(document.querySelector('#inspector .ix-ctx [data-peek^="reply:"]') || { click() {} }).click(); 0`);
    await page.until(`!!document.querySelector('.pk-dialog .pk-lg')`, 120);
    out.opened.push({ kicker: await page.ev(`(document.querySelector('.pk-dialog .pk-k') || {}).textContent || null`), title: await page.ev(`(document.querySelector('.pk-title') || {}).textContent || null`), list: await list() });
    await page.ev(`(document.querySelector('[data-close-peek].pk-x') || { click() {} }).click(); 0`);
    await sleep(300);
  }
}

console.log(JSON.stringify(out));
await page.close();
