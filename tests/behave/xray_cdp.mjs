// Opens a page in headless Chrome at a given viewport and returns what the xray scenarios need to drive it.
import { spawn } from 'node:child_process';

export const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function openPage(url, width = 925, height = 1000) {
  const port = 9800 + Math.floor(Math.random() * 500);
  const chrome = spawn(process.env.CHROME_BIN || 'google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`,
    `--user-data-dir=/tmp/xray-cdp-chrome-${port}`, 'about:blank'], { stdio: 'ignore' });
  let target;
  for (let i = 0; i < 50 && !target; i++) { try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === 'page'); } catch { await sleep(200); } }
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise(r => ws.addEventListener('open', r));
  let id = 0; const wait = new Map();
  ws.addEventListener('message', m => { const d = JSON.parse(m.data); if (wait.has(d.id)) { wait.get(d.id)(d); wait.delete(d.id); } });
  const send = (method, params = {}) => new Promise(r => { const i = ++id; wait.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async expr => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.result.value;
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url });
  const until = async (expr, tries = 60) => { for (let i = 0; i < tries; i++) { const v = await ev(expr); if (v) return v; await sleep(250); } return null; };
  return { ev, until, send, close: () => { ws.close(); chrome.kill(); } };
}
