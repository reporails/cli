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

export async function openPage(url, width = 925, height = 1000) {
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
  await send('Page.navigate', { url });
  // Polls every 25 ms up to the ceiling the old 250 ms x tries loop gave.
  const until = async (expr, tries = 60) => { const end = Date.now() + tries * 250; for (;;) { const v = await ev(expr); if (v) return v; if (Date.now() >= end) { if (process.env.XRAY_DEBUG) appendFileSync(process.env.XRAY_DEBUG, `until timed out: ${expr.slice(0, 200)}\n`); return null; } await sleep(25); } };
  const frame = () => ev('new Promise(r => requestAnimationFrame(() => r(1)))');
  const close = async () => {
    ws.close();
    await fetch(`${base}/json/close/${targetId}`);
    if (chrome) { chrome.kill(); await sleep(100); rmSync(profile, { recursive: true, force: true }); }
  };
  return { ev, until, frame, send, close };
}

// The page opens on the Graph tab; this waits for the tab and clicks it, so a scenario starts on the Graph whatever came first.
export async function toGraph(page) {
  await page.until(`!!document.querySelector('.tab[data-tab="graph"]')`);
  await page.ev(`document.querySelector('.tab[data-tab="graph"]').click(); 0`);
}
