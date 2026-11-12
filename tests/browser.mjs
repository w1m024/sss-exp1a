// Uses the already-installed Windows Edge and Node's built-in CDP transport.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const base = process.env.WIRELENS_URL || 'http://127.0.0.1:8080';
const output = path.resolve('.cache/browser');
await mkdir(output, { recursive: true });
const edge = process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const browser = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=19223', `--user-data-dir=${path.join(output, 'profile')}`, 'about:blank'],
  { stdio: 'ignore', windowsHide: true });
let ws;
const errors = [];
let commandId = 0;
const pending = new Map();
function cdp(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++commandId;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timeout });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text + ': ' + JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function waitFor(expression, label, timeout = 8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (await evaluate(expression)) return; await delay(100); }
  throw new Error(`UI condition timed out: ${label}`);
}
async function traffic() {
  const root = path.resolve('.').replaceAll('\\', '/').replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`);
  await promisify(execFile)('wsl.exe', ['-d', process.env.WIRELENS_DISTRO || 'SSS-Exp1A', '-u', 'exp1a',
    '--', 'python3', `${root}/tests/traffic.py`], { timeout: 15000, windowsHide: true });
}
try {
  let target;
  for (let i = 0; i < 50; i++) {
    try { target = await (await fetch('http://127.0.0.1:19223/json/new?about:blank', { method: 'PUT' })).json(); break; }
    catch { await delay(100); }
  }
  assert(target?.webSocketDebuggerUrl, 'Edge debugging target');
  ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.addEventListener('open', resolve, { once: true }); ws.addEventListener('error', reject, { once: true }); });
  ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const request = pending.get(message.id); pending.delete(message.id); clearTimeout(request.timeout);
      message.error ? request.reject(new Error(message.error.message)) : request.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error' &&
        !/status of (404|422)/.test(message.params.entry.text)) errors.push(message.params.entry.text);
  });
  await cdp('Runtime.enable'); await cdp('Page.enable'); await cdp('Log.enable');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false });
  await cdp('Page.navigate', { url: base });
  await waitFor("document.getElementById('start') && !document.getElementById('start').disabled", 'ready');
  await evaluate("document.getElementById('interface').value='any'; document.getElementById('bpf').value='tcp and host 127.0.0.1'; document.getElementById('start').click()");
  await waitFor("document.getElementById('state').dataset.state==='running'", 'capture running');
  await traffic();
  await waitFor("document.querySelectorAll('#packet-body tr').length>0", 'live packet rows');
  await evaluate("[...document.querySelectorAll('#protocols button')].find(b=>b.textContent==='HTTP').click()");
  await waitFor("document.querySelectorAll('#packet-body tr').length>1", 'HTTP filter');
  await evaluate("document.querySelector('#packet-body tr').click()");
  await waitFor("document.querySelectorAll('#fields button').length>0 && document.querySelectorAll('#hex [data-offset]').length>0", 'fields and bytes');
  await evaluate("document.querySelector('#fields button').click()");
  assert(await evaluate("document.querySelectorAll('#hex .highlight').length>0"), 'field highlights bytes');
  assert(await evaluate("document.querySelectorAll('img').length===0"), 'packet content remains text');
  await evaluate("document.getElementById('stop').click()");
  await waitFor("document.getElementById('state').dataset.state==='stopped'", 'stopped');
  await cdp('Page.captureScreenshot', { format: 'png' }).then(r => writeFile(path.join(output, 'desktop.png'), Buffer.from(r.data, 'base64')));
  await evaluate("document.getElementById('follow').click()");
  await waitFor("!document.getElementById('flow-filter').hidden && document.querySelectorAll('#packet-body tr').length>0", 'follow TCP conversation');
  await evaluate("document.getElementById('clear-flow').click(); document.getElementById('flows-button').click()");
  await waitFor("document.querySelectorAll('#flows .flow-row').length>0", 'flow dialog');
  await evaluate("document.getElementById('close-flows').click(); document.getElementById('bpf').value='tcp and ('; document.getElementById('start').click()");
  await waitFor("!document.getElementById('error').hidden", 'bad BPF error');
  assert(await evaluate("document.getElementById('state').dataset.state==='stopped'"), 'invalid filter preserves stopped capture');
  await cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await delay(200);
  assert(await evaluate('document.documentElement.scrollWidth <= innerWidth + 2'), 'narrow layout does not overflow the page');
  await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }).then(r => writeFile(path.join(output, 'mobile.png'), Buffer.from(r.data, 'base64')));
  assert.equal(errors.length, 0, JSON.stringify(errors));
  console.log('PASS: real Edge live capture, HTTP filter, fields, hex highlight, TCP flow, error state and desktop/mobile layouts');
} finally {
  try {
    const session = await (await fetch(`${base}/api/session`)).json();
    await fetch(`${base}/api/stop`, { method: 'POST', headers: { 'X-Capture-Token': session.token } });
  } catch {}
  if (ws?.readyState === WebSocket.OPEN) { try { await cdp('Browser.close'); } catch {} ws.close(); }
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(new Error('Browser closed')); }
  browser.kill();
}
