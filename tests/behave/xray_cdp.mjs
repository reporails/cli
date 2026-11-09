// Opens a page in headless Chrome at a given viewport and returns what the xray scenarios need to drive it.
// With XRAY_CDP_URL set (behave starts one browser per run) each page gets its own tab in that browser; without it the script spawns a Chrome of its own, so every script still runs standalone.
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { appendFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const sleep = ms => new Promise(r => setTimeout(r, ms));

const freePort = () => new Promise((res, rej) => {
  const s = createServer();
  s.once('error', rej);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

const connect = async wsUrl => {
  const ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  let id = 0; const wait = new Map();
  ws.addEventListener('message', m => { const d = JSON.parse(m.data); if (wait.has(d.id)) { wait.get(d.id)(d); wait.delete(d.id); } });
  const send = (method, params = {}) => new Promise(r => { const i = ++id; wait.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  return { ws, send };
};

const version = async base => { for (let i = 0; i < 300; i++) { try { return await (await fetch(`${base}/json/version`)).json(); } catch { await sleep(100); } } throw new Error(`no Chrome answering at ${base}`); };

// `view` stands in for the server's /view answer: 'hold' keeps the request unanswered until page.release(), '409' answers 409,
// 'none' fails the connection. It is armed before the page loads, so the first poll meets it.
export async function openPage(url, width = 925, height = 1000, view = null) {
  let base = process.env.XRAY_CDP_URL, chrome = null, profile = null;
  if (!base) {
    const port = await freePort();
    profile = mkdtempSync(join(tmpdir(), 'xray-cdp-chrome-'));
    chrome = spawn(process.env.CHROME_BIN || 'google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`,
      `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
    base = `http://127.0.0.1:${port}`;
  }
  await version(base);
  // The page keeps nothing in storage and each scenario serves it from its own origin, so a tab in the shared profile starts clean;
  // media emulation is per tab. (A separate browser context changes the page's focus behaviour, so tabs share the default one.)
  const { id: targetId } = await (await fetch(`${base}/json/new?about:blank`, { method: 'PUT' })).json();
  const { ws, send } = await connect(`${base.replace('http', 'ws')}/devtools/page/${targetId}`);
  const ev = async expr => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.result.value;
  // A tab made by Target.createTarget is not the focused window; the page's focus and visibility logic reads it as one.
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  const held = [];
  let releasing = false;
  if (view) {
    const isView = p => new URL(p.request.url).pathname === '/view';
    const answer = {
      '409': p => send('Fetch.fulfillRequest', { requestId: p.requestId, responseCode: 409, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify({ error: 'ails changed since this page started; run `ails xray` again to open a current page.' })).toString('base64') }),
      none: p => send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'ConnectionRefused' }),
      hold: p => { if (releasing) return send('Fetch.continueRequest', { requestId: p.requestId }); held.push(p.requestId); },
    }[view];
    ws.addEventListener('message', m => {
      const d = JSON.parse(m.data);
      if (d.method !== 'Fetch.requestPaused') return;
      if (isView(d.params)) answer(d.params); else send('Fetch.continueRequest', { requestId: d.params.requestId });
    });
    await send('Fetch.enable', { patterns: [{ urlPattern: '*/view*', requestStage: 'Request' }] });
  }
  await send('Page.navigate', { url });
  // Polls every 25 ms up to the ceiling the old 250 ms x tries loop gave.
  const until = async (expr, tries = 60) => { const end = Date.now() + tries * 250; for (;;) { const v = await ev(expr); if (v) return v; if (Date.now() >= end) { if (process.env.XRAY_DEBUG) appendFileSync(process.env.XRAY_DEBUG, `until timed out: ${expr.slice(0, 200)}\n`); return null; } await sleep(25); } };
  const frame = () => ev('new Promise(r => requestAnimationFrame(() => r(1)))');
  const close = async () => {
    ws.close();
    await fetch(`${base}/json/close/${targetId}`);
    if (chrome) { chrome.kill(); await sleep(100); rmSync(profile, { recursive: true, force: true }); }
  };
  // Lets every held /view request through, and the ones after it.
  const release = async () => { releasing = true; await Promise.all(held.splice(0).map(requestId => send('Fetch.continueRequest', { requestId }))); };
  const heldCount = () => held.length;
  return { ev, until, frame, send, close, release, heldCount };
}

// The page opens on the Graph tab; this waits for the tab and clicks it, so a scenario starts on the Graph whatever came first.
export async function toGraph(page) {
  await page.until(`!!document.querySelector('.tab[data-tab="graph"]')`);
  await page.ev(`document.querySelector('.tab[data-tab="graph"]').click(); 0`);
}
