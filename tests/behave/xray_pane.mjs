// usage: node xray_pane.mjs <page-url> <file label>
// Opens the page in headless Chrome, selects the listed file, prints its shown text as `SHOWN <json>`, waits for a
// line on stdin, then prints the text the pane shows once the page has polled again as `AFTER <json>`.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const [url, label] = [process.argv[2], process.argv[3]];
const port = 9800 + Math.floor(Math.random() * 500);
const dir = `/tmp/xray-pane-chrome-${port}`;
const chrome = spawn(process.env.CHROME_BIN || 'google-chrome', ['--headless=new', '--no-sandbox', '--disable-gpu', `--remote-debugging-port=${port}`,
  `--user-data-dir=${dir}`, 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) { try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === 'page'); } catch { await sleep(200); } }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let id = 0; const wait = new Map();
ws.addEventListener('message', m => { const d = JSON.parse(m.data); if (wait.has(d.id)) { wait.get(d.id)(d); wait.delete(d.id); } });
const send = (method, params = {}) => new Promise(r => { const i = ++id; wait.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async expr => (await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.result.value;
const peek = () => ev(`(document.querySelector('pre.peek')||{}).textContent||''`);

await send('Page.navigate', { url });
for (let i = 0; i < 60 && !(await ev(`!!document.querySelector('[data-art]')`)); i++) await sleep(250);
await ev(`[...document.querySelectorAll('[data-art]')].find(e => e.textContent.includes(${JSON.stringify(label)})).click()`);
let shown = '';
for (let i = 0; i < 40 && !shown; i++) { shown = await peek(); if (!shown) await sleep(250); }
console.log('SHOWN ' + JSON.stringify(shown));
await new Promise(r => createInterface({ input: process.stdin }).once('line', r));
let after = shown;
for (let i = 0; i < 40 && after === shown; i++) { await sleep(500); after = await peek(); }
console.log('AFTER ' + JSON.stringify(after));
ws.close(); chrome.kill();
