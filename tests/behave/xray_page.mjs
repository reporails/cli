// usage: node xray_page.mjs <page-url> <mode> [width] [session]
// Drives the bundled page, served over a fixture view, in headless Chrome and prints one JSON object per mode.
import { openPage, sleep as sleepMs, toGraph } from './xray_cdp.mjs';

const [url, mode, width, picked] = [process.argv[2], process.argv[3], Number(process.argv[4] || 1440), process.argv[5]];
const page = await openPage(url, width);
await toGraph(page);
const ready = await page.until(`!!document.querySelector('.card.top')`);
const out = { ready: !!ready };
const go = async hash => { await page.ev(`location.hash = ${JSON.stringify(hash)}; 0`); await page.until(`location.hash === ${JSON.stringify(hash)}`); };
const click = sel => page.ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; e.click(); return true; })()`);
const expandAll = () => click('[data-groups="open"]');
const cardsState = () => page.ev(`[...document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)')].map(c => ({ id: c.dataset.node, ring: c.classList.contains('ring'), dim: c.classList.contains('dim') }))`);

// The graph column scales by CSS zoom, so a measured length divides by it to compare with the view's own pixels.
const ZOOM = `(parseFloat(getComputedStyle(document.querySelector('#canvas')).zoom) || 1)`;

const overlapsOf = () => page.ev(`(() => {
  const cards = [...document.querySelectorAll('.card[data-node], .card[data-group], .card.bottom')];
  const r = cards.map(c => c.getBoundingClientRect());
  const hit = (a, b) => a.left < b.right - 0.5 && a.right > b.left + 0.5 && a.top < b.bottom - 0.5 && a.bottom > b.top + 0.5;
  let overlaps = 0;
  for (let i = 0; i < r.length; i++) for (let j = i + 1; j < r.length; j++) if (hit(r[i], r[j])) overlaps++;
  // a station pill that touches any card, and a fan-out box that cuts a card it does not hold whole
  const stations = [...document.querySelectorAll('.station')].map(e => e.getBoundingClientRect());
  const stationHits = stations.filter(s => r.some(c => hit(s, c))).length;
  const boxes = [...document.querySelectorAll('.gbox')].map(e => e.getBoundingClientRect());
  const boxHits = boxes.reduce((n, b) => n + r.filter(c => hit(b, c) && !(c.left >= b.left - 0.5 && c.right <= b.right + 0.5 && c.top >= b.top - 0.5 && c.bottom <= b.bottom + 0.5)).length, 0);
  return { cards: cards.length, overlaps, stations: stations.length, stationHits, boxes: boxes.length, boxHits };
})()`);
const runningText = () => page.ev(`[...document.querySelectorAll('.cv *')].filter(e => e.classList.contains('running') || /\\+\\d+ running/.test(e.textContent)).length`);
// Each card's top and the y its out-edge leaves the spine at, both measured from the drawn page.
const launchOf = () => page.ev(`(() => {
  const cv = document.querySelector('.cv').getBoundingClientRect();
  return [...document.querySelectorAll('.card[data-node]:not(.top):not(.bottom), .card[data-group]')].map(c => {
    const attr = c.dataset.node ? 'data-node' : 'data-group';
    const key = c.dataset.node || c.dataset.group;
    const edge = document.querySelector('path.arch.out[' + attr + '="' + key + '"]');
    const out = Number(edge.getAttribute('d').match(/^M[\\d.]+,([\\d.]+)/)[1]);
    return { key, top: (c.getBoundingClientRect().top - cv.top) / ${ZOOM}, out, launchY: Number(c.dataset.launchY || NaN) };
  });
})()`);

if (mode === 'overlap' && ready) {
  Object.assign(out, await overlapsOf());
  out.running = await runningText();
}

if (mode === 'fxtop' && ready) {
  Object.assign(out, await overlapsOf());
  out.opened = await click('.card[data-group="main:a1"]');
  await page.until(`!!document.querySelector('.gbox')`);
  out.expanded = await overlapsOf();
  const cv = await page.ev(`document.querySelector('.cv').getBoundingClientRect().top`);
  out.early = await page.ev(`(() => { const c = document.querySelector('.card[data-node="a0"]'); return { top: (c.getBoundingClientRect().top - ${cv}) / ${ZOOM}, launchY: Number(c.dataset.launchY) }; })()`);
  out.topBottom = await page.ev(`(document.querySelector('.card.top').getBoundingClientRect().bottom - ${cv}) / ${ZOOM}`);
  out.boxTop = await page.ev(`(document.querySelector('.gbox').getBoundingClientRect().top - ${cv}) / ${ZOOM}`);
}

if (mode === 'fxgroup' && ready) {
  out.groups = await page.ev(`[...document.querySelectorAll('.card.group')].map(g => {
    const b = g.getBoundingClientRect();
    return { key: g.dataset.group, expand: g.textContent.includes('expand'), over: [...g.querySelectorAll('*')].filter(x => { const q = x.getBoundingClientRect(); return q.right > b.right - 0.5 || q.left < b.left + 0.5; }).length };
  })`);
}

if (mode === 'fxup' && ready) {
  const open = () => page.ev(`!!document.querySelector('.gbox')`);
  out.before = await open();
  await go('#/agent/main/a1');
  await page.until(`document.querySelector('.crumb.here') && !document.querySelector('.card.top').dataset.node.startsWith('main')`);
  await go('#/agent/main');
  await page.until(`document.querySelector('.card.top').dataset.node === 'main'`);
  out.afterUp = await open();
  out.sel = await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`);
}

if (mode === 'fxbare' && ready) {
  await expandAll();
  const rows = () => page.ev(`[...document.querySelectorAll('#sources .sr')].filter(r => /\\btok\\b/.test(r.querySelector('.sw').textContent))`);
  out.rows = await page.ev(`[...document.querySelectorAll('#sources .sr .sw')].map(e => e.textContent).filter(t => /\\btok\\b/.test(t))`);
  await page.ev(`(() => { const r = [...document.querySelectorAll('#sources .sr')].find(r => r.dataset.source && /\\btok\\b/.test(r.querySelector('.sw').textContent)); r.dispatchEvent(new MouseEvent('mouseover', { bubbles: true })); return 0; })()`);
  out.focus = await page.ev(`(document.querySelector('.fbanner') || {}).textContent || ''`);
  out.titles = await page.ev(`[...document.querySelectorAll('.snode')].map(e => e.title).filter(t => /\\d[kM]? loaded/.test(t))`);
}

if (mode === 'fxcost' && ready) {
  const note = async () => {
    await click('#inspector [data-peek^="cost:"]');
    await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
    const lines = await page.ev(`[...document.querySelectorAll('.pk-dialog .nk')].map(e => e.textContent).filter(t => t.includes('not priced')).map(t => t.replace(/\\.$/, ''))`);
    await click('.pk-x');
    return lines;
  };
  out.main = await note();
  await click('.card[data-group="main:a1"]');
  await click('.card[data-node="a1"]');
  out.member = await note();
}

if (mode === 'p1layout' && ready) {
  Object.assign(out, await overlapsOf());
  out.launches = await launchOf();
  out.running = await runningText();
}

if (mode === 'p1groups' && ready) {
  const rows = () => page.ev(`[...document.querySelectorAll('.card[data-node]:not(.top):not(.bottom)')].filter(c => /^b/.test(c.dataset.node)).map(c => ({ id: c.dataset.node, left: Math.round(c.getBoundingClientRect().left), top: Math.round(c.getBoundingClientRect().top) }))`);
  out.groupsBefore = await page.ev(`[...document.querySelectorAll('.card[data-group]')].map(c => ({ key: c.dataset.group, text: c.textContent, expanded: c.getAttribute('aria-expanded'), tiles: c.querySelectorAll('.tile').length, dashed: getComputedStyle(c).borderTopStyle }))`);
  out.membersBefore = await rows();
  await click('.card[data-group="main:b1"]');
  out.membersOpen = await rows();
  out.head = await page.ev(`(document.querySelector('.ghead') || {}).textContent || ''`);
  out.box = await page.ev(`!!document.querySelector('.gbox')`);
  out.groupCardsOpen = await page.ev(`[...document.querySelectorAll('.card[data-group]')].map(c => c.dataset.group)`);
  out.arches = await page.ev(`[...document.querySelectorAll('path.arch.out[data-node]')].filter(p => /^b/.test(p.dataset.node)).length`);
  await click('.gcollapse');
  out.membersAfter = await rows();
  out.groupCardsAfter = await page.ev(`document.querySelectorAll('.card[data-group]').length`);
}

if (mode === 'p1select' && ready) {
  const open = () => page.ev(`[...document.querySelectorAll('.card[data-node]')].filter(c => /^c/.test(c.dataset.node)).length`);
  out.before = await open();
  await page.ev(`import('/static/js/state.js').then(m => { m.state.sel = 'c2'; window.dispatchEvent(new Event('hashchange')); return 0; })`);
  out.after = await open();
  out.selected = await page.ev(`(document.querySelector('.card.sel') || {dataset: {}}).dataset.node || null`);
  await click('.gcollapse');
  out.collapsed = await open();
  out.groupCard = await page.ev(`document.querySelectorAll('.card[data-group="main:c1"]').length`);
}

if (mode === 'p1stretch' && ready) {
  out.bars = await page.ev(`[...document.querySelectorAll('.stretch')].map(e => ({ title: e.title, width: Math.round(e.getBoundingClientRect().width / ${ZOOM} * 100) / 100, colour: getComputedStyle(e).backgroundColor }))`);
  out.note = await page.ev(`(document.querySelector('.scalenote') || {}).textContent || null`);
  out.ticks = await page.ev(`[...document.querySelectorAll('.tick')].map(e => e.getBoundingClientRect().top / ${ZOOM}).sort((a, b) => a - b)`);
  out.dense = await page.ev(`import('/static/js/geometry.js').then(g => g.tickMarks({ start: 0, end: 7200 }, t => t * 0.01).map(m => m.y))`);
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
  await expandAll();
  await click('#sources .sr[data-source="mcp:docs-server"]');
  out.mcp = await cardsState();
  out.mcpGroup = await page.ev(`[...document.querySelectorAll('.card[data-group]')].map(c => ({ key: c.dataset.group, ring: c.classList.contains('ring'), dim: c.classList.contains('dim') }))`);
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
    nodes: document.querySelectorAll('.snode[data-source*=".claude/skills"]').length,
    other: document.querySelectorAll('.card .chip[data-kind="rule"]').length,
  })`);
  out.before = await count();
  await click('[data-eye="skill"]');
  out.after = await count();
  await click('[data-eye="skill"]');
  out.again = await count();
}

if (mode === 'omitted' && ready) {
  Object.assign(out, await page.ev(`({
    toggles: [...document.querySelectorAll('[data-eye]')].map(e => e.dataset.eye),
    sections: [...document.querySelectorAll('#sources .ssec')].map(e => e.dataset.kind),
    chips: [...new Set([...document.querySelectorAll('.card .chip[data-kind]')].map(e => e.dataset.kind))],
    stations: [...document.querySelectorAll('.station')].map(e => e.dataset.source),
    empty: [...document.querySelectorAll('.chip')].filter(e => e.textContent === '' ).length,
    adapter: document.querySelector('.achip').textContent,
  })`));
}

if (mode === 'markers' && ready) {
  await expandAll();
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
  await click('.card[data-group="main:a1"]');
  await click('.card[data-node="a1"]');
  out.returned = await page.ev(`({ up: document.querySelectorAll('.pill-arch.up').length, down: document.querySelectorAll('.pill-arch.down').length, animated: document.querySelectorAll('path.arch.flow').length })`);
  await page.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  out.reduced = await page.ev(`getComputedStyle(document.querySelector('path.arch.flow')).animationName`);
  out.bracket = await page.until(`(document.querySelector('.blabel')||{}).textContent && document.querySelector('.blabel').textContent.includes('npm test')`) ? await page.ev(`document.querySelector('.blabel').textContent`) : '';
}

if (mode === 'file' && ready) {
  await expandAll();
  await click('#sources .sr[data-source="CLAUDE.md"]');
  await page.until(`!!document.querySelector('.pk-dialog a.pk-act')`);
  out.pill = await page.ev(`document.querySelector('.pk-dialog a.pk-act').getAttribute('href')`);
  await click('.pk-dialog a.pk-act');
  await page.until(`location.hash.startsWith('#/file/')`);
  out.hash = await page.ev(`location.hash`);
  out.name = await page.until(`(document.querySelector('#view-file .fn')||{}).textContent`);
  out.peek = await page.until(`(document.querySelector('pre.peek')||{}).textContent`);
  await click('[data-back]');
  await page.until(`location.hash.startsWith('#/agent/')`);
  out.backHash = await page.ev(`location.hash`);
  await click('#sources .sr[data-source=".claude/rules/rules-engine.md"]');
  await page.until(`!!document.querySelector('.pk-dialog a.pk-act')`);
  out.row = await page.ev(`document.querySelector('.pk-dialog a.pk-act').getAttribute('href')`);
}

if (mode === 'stub' && ready) {
  await go('#/agent/main/a1');
  await page.until(`!!document.querySelector('.card[data-node="stub1"]')`);
  out.before = await page.ev(`document.querySelector('.card[data-node="stub1"]').textContent`);
  await page.ev(`import('/test/stub_node.js').then(() => 0)`);
  out.after = (await page.until(`(document.querySelector('.card[data-node="stub1"] .stubcard')||{}).textContent`)) || '';
  await click('.card[data-node="stub1"]');
  out.inspector = await page.until(`(document.querySelector('#inspector .ix-kicker')||{}).textContent`);
  out.agentCard = await page.ev(`document.querySelectorAll('.card[data-node="a1"] .nc, .card.top .nc').length`);
}

if (mode === 'panes' && ready) {
  const selectNode = async id => {
    const before = await page.ev(`document.querySelector('#inspector .nm').textContent`);
    // A member of a collapsed fan-out group has no card until its group is expanded: expand the groups first.
    while (await page.ev(`!document.querySelector('.card[data-node="${id}"]') && !!document.querySelector('.card[data-group][aria-expanded="false"]')`)) {
      await click('.card[data-group][aria-expanded="false"]');
    }
    await click(`.card[data-node="${id}"]`);
    await page.until(`document.querySelector('#inspector .nm').textContent !== ${JSON.stringify(before)}`);
  };
  const tiles = () => page.ev(`[...document.querySelectorAll('#inspector .ix-tile')].map(t => ({ label: t.querySelector('.lb').textContent, value: t.querySelector('.big').textContent, line: t.querySelector('.ix-line').textContent, peek: (t.querySelector('[data-peek]') || {dataset: {}}).dataset.peek || null }))`);
  out.mainTiles = await tiles();
  out.mainText = await page.ev(`document.querySelector('#inspector').textContent`);
  await click('#inspector [data-peek="peak:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-lg')`);
  out.peakOpen = await page.ev(`({ cats: [...document.querySelectorAll('.pk-dialog .pk-lg')].map(r => ({ key: r.dataset.category, label: r.querySelector('.lb').textContent, value: r.querySelector('.v').textContent })), text: document.querySelector('.pk-dialog').textContent, title: document.querySelector('.pk-title').textContent })`);
  await click('.pk-x');
  await click('#inspector [data-peek="cost:main"]');
  await page.until(`!!document.querySelector('.pk-dialog .pk-kv')`);
  out.costText = await page.ev(`document.querySelector('.pk-dialog').textContent`);
  await click('.pk-x');
  await selectNode('a1');
  out.a1Tiles = await tiles();
  out.a1Text = await page.ev(`document.querySelector('#inspector').textContent`);
  out.withheld = await page.ev(`[...document.querySelectorAll('#inspector .ix-quiet')].map(e => e.textContent)`);
}

if (mode === 'words' && ready) {
  await expandAll();
  out.header = await page.ev(`document.querySelector('.hmeta').textContent`);
  out.unknown = await page.ev(`document.querySelector('#unknown').textContent`);
  out.titles = await page.ev(`[...document.querySelectorAll('[title]')].map(e => e.title)`);
  out.claudeRow = await page.ev(`document.querySelector('#sources .sr[data-source="CLAUDE.md"] .sw').textContent`);
  await click('#sources .sr[data-source="CLAUDE.md"]');
  await page.until(`!!document.querySelector('.pk-dialog')`);
  out.claudeDetails = await page.ev(`document.querySelector('.pk-dialog').textContent`);
  await click('.pk-x');
  await click('.card[data-group="main:a1"]');
  await click('.card[data-node="a1"]');
  out.returned = await page.ev(`document.querySelector('#inspector').textContent`);
  await click('.card[data-node="a6"]');
  out.stopped = await page.ev(`document.querySelector('#inspector').textContent`);
  await click('#sources .sr[data-source="mcp:docs-server"]');
  out.banner = await page.ev(`document.querySelector('.fbanner').textContent`);
}

if (mode === 'absent' && ready) {
  await expandAll();
  out.absent = await page.ev(`[...document.querySelectorAll('#sources .nk')].map(e => e.textContent)`);
  out.typeButtons = await page.ev(`[...document.querySelectorAll('[data-type]')].map(e => e.dataset.type)`);
  out.untypedCard = await page.ev(`!!document.querySelector('.card[data-node="a9"]')`);
}

if (mode === 'autocheck' && ready) {
  await go('#/file/CLAUDE.md');
  await page.until(`document.querySelector('#view-file').textContent.includes('Running')`);
  await go('#/file/.claude/rules/rules-engine.md');
  out.second = await page.until(`document.querySelector('#view-file').textContent.includes('fixture finding') && document.querySelector('#view-file').textContent`, 40);
}

if (mode === 'calls' && ready) {
  out.bracket = await page.until(`(document.querySelector('.blabel')||{}).textContent && document.querySelector('.blabel').textContent.includes('npm test')`) ? await page.ev(`document.querySelector('.blabel').textContent`) : '';
  await new Promise(r => setTimeout(r, 7000));
}

if (mode === 'groups' && ready) {
  const snap = () => page.ev(`[...document.querySelectorAll('#sources .ssec')].map(s => ({
    kind: s.dataset.kind, open: s.querySelector('.sh').getAttribute('aria-expanded') === 'true',
    rows: [...s.querySelectorAll('.sr')].map(r => r.dataset.source),
    head: s.querySelector('.sh').textContent,
    more: (s.querySelector('.smore') || {}).textContent || null,
    note: (s.querySelector('.snote') || {}).textContent || null,
  }))`);
  out.initial = await snap();
  await click('[data-groups="open"]');
  out.expanded = await snap();
  await click('[data-groups="closed"]');
  out.collapsed = await snap();
  await click('.sh[data-source-group="agent"]');
  out.agentOpen = await snap();
  await click('.smore');
  out.agentAll = await snap();
  await click('.smore');
  out.agentFewer = await snap();
  await click('.sh[data-source-group="agent"]');
  out.closedAgain = await snap();
  // focus a source past the first four of a group the user collapsed
  await page.ev(`document.querySelector('.snode[data-source=\".claude/agents/auditor.md\"]').dispatchEvent(new MouseEvent('mouseover', { bubbles: true })); 0`);
  out.focused = await page.until(`!!document.querySelector('#sources .sr[data-source=".claude/agents/auditor.md"]')`) ? await snap() : null;
}

if (mode === 'agents' && ready) {
  await click('.sh[data-source-group="agent"]');
  await click('.smore');
  const rows = await page.ev(`Object.fromEntries([...document.querySelectorAll('#sources .ssec[data-kind="agent"] .sr')].map(r => [r.dataset.source, { name: r.querySelector('.sn').textContent, who: r.querySelector('.sw').textContent, }]))`);
  out.rows = rows;
  out.lit = {};
  for (const id of ['.claude/agents/reviewer.md', '.claude/agents/idle.md']) {
    await click('[data-clear]');
    await click(`#sources .sr[data-source="${id}"]`);
    out.lit[id] = (await cardsState()).filter(c => c.ring).map(c => c.id);
    out.lit[id + ' top'] = await page.ev(`document.querySelector('.card.top').classList.contains('ring')`);
  }
  await click('[data-clear]');
  // Fan-out groups start collapsed; open them so every card shows its chips.
  while (await page.ev(`!!document.querySelector('.card[data-group][aria-expanded="false"]')`)) await click('.card[data-group][aria-expanded="false"]');
  out.chips = await page.ev(`Object.fromEntries([...document.querySelectorAll('.card[data-node]:not(.top)')].map(c => { const a = c.querySelector('.chip[data-kind="agent"]'); return [c.dataset.node, a ? a.className : null]; }))`);
  out.toggles = await page.ev(`[...document.querySelectorAll('[data-eye]')].map(e => e.dataset.eye)`);
}

if (mode === 'cost' && ready) {
  out.claude = await page.ev(`document.querySelector('#sources .sr[data-source="CLAUDE.md"] .sw').textContent`);
  out.other = await page.ev(`document.querySelector('#sources .sr[data-source="~/.claude/CLAUDE.md"] .sw').textContent`);
  await expandAll();
  out.rule = await page.ev(`document.querySelector('#sources .sr[data-source=".claude/rules/rules-engine.md"] .sw').textContent`);
}

if (mode === 'p4spine' && ready) {
  Object.assign(out, await page.ev(`({
    outline: document.querySelector('polygon.band').getAttribute('points'),
    bands: [...document.querySelectorAll('polygon.cband')].map(e => ({ key: e.dataset.category, points: e.getAttribute('points'), opacity: e.getAttribute('fill-opacity') })),
    legend: (document.querySelector('.legend .lg-text') || {}).textContent || null,
  })`));
}

if (mode === 'p4stations' && ready) {
  out.stations = await page.ev(`[...document.querySelectorAll('.station')].map(e => ({ kind: e.dataset.station, source: e.dataset.source, sources: e.dataset.sources, text: e.textContent, title: e.title, label: e.getAttribute('aria-label'), tag: e.tagName }))`);
  await click('.station.merged');
  out.pinned = await page.ev(`(document.querySelector('.fbanner b') || {}).textContent || null`);
}

if (mode === 'p4pills' && ready) {
  const pills = () => page.ev(`[...document.querySelectorAll('.pill-arch')].map(e => e.textContent)`);
  out.none = await pills();
  await click('.card[data-group="main:a1"]');
  await click('.card[data-node="a1"]');
  out.selected = await pills();
  await click('.card[data-node="a2"]');
  out.member = await pills();
  await click('.card.top');
  out.cleared = await pills();
}

if (mode === 'p4cards' && ready) {
  await click('.card[data-group="main:a1"]');
  out.cards = await page.ev(`[...document.querySelectorAll('.card[data-node]:not(.top)')].map(c => {
    const nm = c.querySelector('.nm');
    return { id: c.dataset.node, title: c.title, name: nm.textContent, lines: Math.round(nm.getBoundingClientRect().height / parseFloat(getComputedStyle(nm).lineHeight)), sub: c.querySelector('.sub').textContent, fits: c.scrollHeight <= c.clientHeight + 1 };
  })`);
}

if (mode === 'notice' && ready) {
  out.hidden = await page.ev(`document.querySelector('#picked').hidden`);
  out.text = await page.ev(`document.querySelector('#picked').textContent`);
}

if (mode === 'switcher' && ready) {
  const requests = async () => (await fetch(new URL('test/requests', url), { headers: { 'X-Xray-Token': 'fixture-token' } })).json();
  await page.until(`document.querySelector('.swbtn').textContent.includes('subagent')`);
  out.button = await page.ev(`document.querySelector('.swbtn').textContent`);
  await click('.swbtn');
  await page.until(`document.querySelectorAll('.swrow').length === 3`);
  out.rows = await page.ev(`[...document.querySelectorAll('.swrow .swpick')].map(b => b.textContent)`);
  out.current = await page.ev(`[...document.querySelectorAll('.swpick[aria-current="true"]')].map(b => b.textContent)`);
  out.promptsBefore = (await requests()).filter(r => r.startsWith('/first-prompt'));
  await click('.swrow:nth-child(2) .swfp');
  await page.until(`!document.querySelector('.swrow:nth-child(2) .swtext').hidden && document.querySelector('.swrow:nth-child(2) .swtext').textContent.startsWith('first prompt')`);
  out.promptsAfter = (await requests()).filter(r => r.startsWith('/first-prompt'));
  out.promptText = await page.ev(`document.querySelector('.swrow:nth-child(2) .swtext').textContent`);
  out.promptAsText = await page.ev(`document.querySelector('.swrow:nth-child(2) .swtext').children.length === 0`);
  await page.ev(`document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); 0`);
  out.escapeClosed = await page.ev(`document.querySelector('.swlist').hidden`);
  await click('.swbtn');
  await page.until(`document.querySelectorAll('.swrow').length === 3`);
  const mark = (await requests()).length;
  await click('.swrow:nth-child(2) .swpick');
  await page.until(`location.search === '?session=sess-bbb'`);
  await page.until(`!!document.querySelector('.card.top') && document.querySelector('.swbtn').textContent.includes('subagent')`);
  await go('#/file/CLAUDE.md');
  await page.until(`!document.querySelector('#view-file').hidden`);
  await sleepMs(1500);
  out.search = await page.ev(`location.search`);
  out.footer = await page.ev(`document.querySelector('#src').textContent`);
  out.after = (await requests()).slice(mark);
}

// Against the real server: open the switcher, pick the session named in argv, and read what the page then shows.
if (mode === 'pickother' && ready) {
  out.firstSrc = await page.ev(`document.querySelector('#src').textContent`);
  await click('.swbtn');
  await page.until(`document.querySelectorAll('.swpick').length >= 2`);
  out.listed = await page.ev(`[...document.querySelectorAll('.swpick')].map(b => b.dataset.session)`);
  out.noIdTyped = await page.ev(`!document.querySelector('input, textarea')`);
  await click(`.swpick[data-session="${picked}"]`);
  await page.until(`location.search === '?session=${picked}'`);
  await page.until(`!!document.querySelector('.card.top') && document.querySelector('#src').textContent.includes('Session ${picked}.')`);
  out.search = await page.ev(`location.search`);
  out.src = await page.ev(`document.querySelector('#src').textContent`);
}

console.log(JSON.stringify(out));
page.close();
