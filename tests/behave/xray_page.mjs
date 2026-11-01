// usage: node xray_page.mjs <page-url> <mode> [width]
// Drives the bundled page, served over a fixture view, in headless Chrome and prints one JSON object per mode.
import { openPage } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440)];
const page = await openPage(url, width);
const ready = await page.until(`!!document.querySelector('.card.top')`);
const out = { ready: !!ready };
const go = async hash => { await page.ev(`location.hash = ${JSON.stringify(hash)}; 0`); await page.until(`location.hash === ${JSON.stringify(hash)}`); };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const cardsState = () => page.ev(`[...document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)')].map(c => ({ id: c.dataset.node, ring: c.classList.contains('ring'), dim: c.classList.contains('dim') }))`);

if (mode === 'overlap' && ready) {
  Object.assign(out, await page.ev(`(() => {
    const cards = [...document.querySelectorAll('.card[data-node], .card.bottom')];
    const r = cards.map(c => c.getBoundingClientRect());
    let overlaps = 0;
    for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) {
      const a = r[i], b = r[j];
      if (a.left < b.right - 0.5 && a.right > b.left + 0.5 && a.top < b.bottom - 0.5 && a.bottom > b.top + 0.5) overlaps++;
    }
    return { cards: cards.length, overlaps, running: [...document.querySelectorAll('.running')].map(e => e.textContent) };
  })()`));
}

if (mode === 'drill' && ready) {
  await go('#/agent/main/a5/a5b/a5c');
  await page.until(`document.querySelector('.crumb.here') && document.querySelector('.crumb.here').textContent === 'Fetch the spec'`);
  Object.assign(out, await page.ev(`({
    crumbs: [...document.querySelectorAll('.crumbs > *')].map(e => e.textContent),
    strip: !document.querySelector('#parentstrip').hidden,
    parent: document.querySelector('#parentstrip [data-slot="parent"]').textContent,
    bars: [...document.querySelectorAll('#parentstrip .pbar')].map(e => e.dataset.node),
    current: [...document.querySelectorAll('#parentstrip .pbar.cur')].map(e => e.dataset.node),
  })`));
  await go('#/agent/main');
  out.rootStrip = await page.ev(`document.querySelector('#parentstrip').hidden`);
}

if (mode === 'focus' && ready) {
  await click('#sources .sr[data-source="mcp:docs-server"]');
  out.mcp = await cardsState();
  out.mcpTop = await page.ev(`document.querySelector('.card.top').classList.contains('ring')`);
  out.mcpBanner = await page.ev(`document.querySelector('.fbanner').textContent`);
  await click('[data-clear]');
  await click('#sources .sr[data-source="packages/cli/CLAUDE.md"]');
  out.never = await cardsState();
  out.neverBanner = await page.ev(`document.querySelector('.fbanner').textContent`);
  out.neverRow = await page.ev(`document.querySelector('#sources .sr[data-source="packages/cli/CLAUDE.md"]').classList.contains('never')`);
}

if (mode === 'layer' && ready) {
  const count = () => page.ev(`({
    chips: document.querySelectorAll('.card .chip[data-kind="skill"]').length,
    sections: document.querySelectorAll('#sources .ssec[data-kind="skill"]').length,
    stations: document.querySelectorAll('.station[data-source^=".claude/skills"]').length,
    other: document.querySelectorAll('.card .chip[data-kind="rule"]').length,
  })`);
  out.before = await count();
  await click('[data-layer="skill"]');
  out.after = await count();
  await click('[data-layer="skill"]');
  out.again = await count();
}

if (mode === 'omitted' && ready) {
  Object.assign(out, await page.ev(`({
    toggles: [...document.querySelectorAll('[data-layer]')].map(e => e.dataset.layer),
    sections: [...document.querySelectorAll('#sources .ssec')].map(e => e.dataset.kind),
    chips: [...new Set([...document.querySelectorAll('.card .chip[data-kind]')].map(e => e.dataset.kind))],
    stations: [...document.querySelectorAll('.station')].map(e => e.dataset.source),
    empty: [...document.querySelectorAll('.chip')].filter(e => e.textContent === '' ).length,
    adapter: document.querySelector('.achip').textContent,
  })`));
}

if (mode === 'markers' && ready) {
  out.compact = await page.ev(`[...document.querySelectorAll('.compact')].map(e => e.textContent)`);
  out.never = await page.ev(`[...document.querySelectorAll('#sources .sr.never')].map(e => e.querySelector('.sn').textContent + ' | ' + e.querySelector('.sw').textContent)`);
  await click('.card[data-node="a6"]');
  out.stopped = await page.ev(`({
    up: document.querySelectorAll('.pill-arch.up').length,
    down: document.querySelectorAll('.pill-arch.down').length,
    dashed: document.querySelector('path.arch.back[data-node="a6"]').classList.contains('dashed'),
    stroke: document.querySelector('path.arch.back[data-node="a6"]').getAttribute('stroke'),
    inspector: document.querySelector('#inspector').textContent,
    animated: document.querySelectorAll('path.arch.flow').length,
  })`);
  await click('.card[data-node="a1"]');
  out.returned = await page.ev(`({ up: document.querySelectorAll('.pill-arch.up').length, down: document.querySelectorAll('.pill-arch.down').length, animated: document.querySelectorAll('path.arch.flow').length })`);
  await page.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  out.reduced = await page.ev(`getComputedStyle(document.querySelector('path.arch.flow')).animationName`);
  out.bracket = await page.until(`(document.querySelector('.blabel')||{}).textContent && document.querySelector('.blabel').textContent.includes('npm test')`) ? await page.ev(`document.querySelector('.blabel').textContent`) : '';
}

if (mode === 'file' && ready) {
  out.pill = await page.ev(`(() => { const a = document.querySelector('#sources .sr[data-source="CLAUDE.md"] a.pill'); const h = a.getAttribute('href'); a.click(); return h; })()`);
  await page.until(`location.hash.startsWith('#/file/')`);
  out.hash = await page.ev(`location.hash`);
  out.name = await page.until(`(document.querySelector('#view-file .fn')||{}).textContent`);
  out.peek = await page.until(`(document.querySelector('pre.peek')||{}).textContent`);
  await click('[data-back]');
  await page.until(`location.hash.startsWith('#/agent/')`);
  out.backHash = await page.ev(`location.hash`);
  out.row = await page.ev(`document.querySelector('#sources .sr[data-source=".claude/rules/rules-engine.md"] a.sopen').getAttribute('href')`);
}

if (mode === 'stub' && ready) {
  await go('#/agent/main/a1');
  await page.until(`!!document.querySelector('.card[data-node="stub1"]')`);
  out.before = await page.ev(`document.querySelector('.card[data-node="stub1"]').textContent`);
  await page.ev(`import('/test/stub_node.js').then(() => 0)`);
  out.after = (await page.until(`(document.querySelector('.card[data-node="stub1"] .stubcard')||{}).textContent`)) || '';
  await click('.card[data-node="stub1"]');
  out.inspector = await page.until(`(document.querySelector('#inspector .stubinspector')||{}).textContent`);
  out.agentCard = await page.ev(`document.querySelectorAll('.card[data-node="a1"] .nc, .card.top .nc').length`);
}

console.log(JSON.stringify(out));
page.close();
