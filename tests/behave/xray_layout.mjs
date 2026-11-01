// usage: node xray_layout.mjs <page-url> <layout|memory|prompt|markup|facts> [width]
// Drives the page in headless Chrome and prints one JSON object describing what it drew.
import { openPage } from './xray_cdp.mjs';

const [url, mode, width] = [process.argv[2], process.argv[3], Number(process.argv[4] || 925)];
const page = await openPage(url, width);
const ready = await page.until(`!!document.querySelector('#chart') && !!document.querySelector('#alist')`);
let out = { ready: !!ready };

if (mode === 'layout' && ready) {
  out = { ...out, ...await page.ev(`(() => {
    const box = s => { const e = document.querySelector(s); return e ? e.getBoundingClientRect() : null; };
    const chart = box('#chartcard'), art = box('#art'), info = box('#info');
    const texts = [...document.querySelectorAll('#chart text')], rects = texts.map(t => t.getBoundingClientRect());
    let overlaps = 0;
    for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) {
      const a = rects[i], b = rects[j];
      if (a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top) overlaps++;
    }
    return { chartBottom: chart && chart.bottom, chartWidth: chart && chart.width, artRight: art && art.right, infoLeft: info && info.left, artTop: art && art.top, infoTop: info && info.top, labels: texts.length, overlaps };
  })()`) };
}

if (mode === 'memory' && ready) {
  await page.ev(`document.querySelector('[data-group="memory"]').click(); 0`);
  const picked = await page.ev(`(() => {
    const row = [...document.querySelectorAll('#alist .fr[data-file^="memory:"]')].find(r => r.querySelector('.sd.not') && r.querySelector('.tag.warn'));
    if (!row) return null;
    const label = row.querySelector('.p').textContent; row.click(); return label;
  })()`);
  out.row = picked;
  out.text = picked ? (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '' : '';
}

if (mode === 'prompt' && ready) {
  await page.ev(`document.querySelector('[data-turnh]').click(); 0`);
  await page.until(`!!document.querySelector('[data-prompt]')`);
  const count = `document.querySelectorAll('pre.peek').length + ' ' + performance.getEntriesByType('resource').filter(e => e.name.includes('prompt?id=')).length`;
  out.before = await page.ev(count);
  out.id = await page.ev(`document.querySelector('[data-prompt]').dataset.prompt`);
  await page.ev(`document.querySelector('[data-prompt]').click(); 0`);
  out.text = (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '';
}

if (mode === 'markup' && ready) {
  await page.ev(`document.querySelector('[data-group="memory"]').click(); 0`);
  out.row = await page.ev(`(() => {
    const row = [...document.querySelectorAll('#alist .fr[data-file^="memory:"]')].find(r => r.dataset.file.includes('onerror'));
    if (!row) return null;
    const label = row.querySelector('.p').textContent; row.click(); return label;
  })()`);
  out.text = out.row ? (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '' : '';
  await page.ev(`document.querySelector('[data-back]').click(); 0`);
  await page.ev(`document.querySelector('[data-turnh]').click(); 0`);
  await page.until(`!!document.querySelector('[data-prompt]')`);
  await page.ev(`document.querySelector('[data-prompt]').click(); 0`);
  out.promptText = (await page.until(`(document.querySelector('pre.peek')||{}).textContent`)) || '';
  out.dom = await page.ev(`({
    pwned: window.__pwned === undefined ? null : window.__pwned,
    imgs: document.querySelectorAll('img').length,
    inPeek: document.querySelectorAll('pre.peek *').length,
    rowChildren: [...document.querySelectorAll('#alist .fr *')].filter(e => e.tagName !== 'SPAN').length,
  })`);
}

if (mode === 'facts' && ready) {
  out = { ...out, ...await page.ev(`(() => {
    const num = e => ({ x: +e.getAttribute('x'), w: +e.getAttribute('width') });
    return {
      bands: [...document.querySelectorAll('#chart rect.band')].map(num),
      lines: [...document.querySelectorAll('#chart line.cmpl')].map(e => +e.getAttribute('x1')),
      header: document.querySelector('#sess').textContent,
      tags: [...document.querySelectorAll('[data-turnh]')].map(h => ({ n: +h.dataset.turnh, label: h.querySelector('.lbl').textContent, rt: h.querySelector('.rt').textContent, start: h.querySelector('.tm0').textContent })),
    };
  })()`) };
}

console.log(JSON.stringify(out));
page.close();
