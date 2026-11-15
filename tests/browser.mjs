// Uses the already-installed Windows Edge and Node's built-in CDP transport.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const base = process.env.WIRELENS_URL || 'http://127.0.0.1:8080';
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const output = path.join(projectRoot, '.cache/browser');
await mkdir(output, { recursive: true });
const edge = process.env.EDGE_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const browser = spawn(edge, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=19223', `--user-data-dir=${path.join(tmpdir(), `wirelens-edge-${process.pid}`)}`, 'about:blank'],
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
  const root = process.env.WIRELENS_LINUX_ROOT || projectRoot.replaceAll('\\', '/').replace(/^([A-Za-z]):/, (_, drive) => `/mnt/${drive.toLowerCase()}`);
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
  await evaluate("document.getElementById('interface').value='any'; document.getElementById('bpf').value='tcp and host 127.0.0.1 and not port 8080 and not port 8081'; document.getElementById('start').click()");
  await waitFor("document.getElementById('state').dataset.state==='running'", 'capture running');
  await traffic();
  await waitFor("document.querySelectorAll('#packet-body tr').length>0", 'live packet rows');
  await evaluate("[...document.querySelectorAll('#protocols button')].find(b=>b.textContent==='HTTP').click()");
  await waitFor("document.querySelectorAll('#packet-body tr').length>1", 'HTTP filter');
  await waitFor("document.getElementById('time-range').textContent.includes('全部保留数据')", 'retained overview');
  await evaluate("document.getElementById('metric-bytes').click()");
  assert(await evaluate("echarts.getInstanceByDom(document.getElementById('traffic-overview')).getOption().yAxis[0].name==='B / 桶'"), 'byte metric uses wire bytes');
  await evaluate("document.getElementById('metric-packets').click(); window.__timelineQueries=[];window.__timelineFetch=window.fetch;window.fetch=(...args)=>{if(String(args[0]).includes('/api/packets?'))window.__timelineQueries.push(String(args[0]));return window.__timelineFetch(...args)};echarts.getInstanceByDom(document.getElementById('traffic-overview')).dispatchAction({type:'dataZoom',start:20,end:60})");
  await waitFor("window.__timelineQueries.some(q=>q.includes('from_us=')&&q.includes('to_us=')) && document.querySelectorAll('#packet-body tr').length>0", 'time bounds reach packet API');
  const selectedRange = await evaluate("window.__timelineQueries.filter(q=>q.includes('from_us=')).at(-1).split('&').filter(s=>s.startsWith('from_us=')||s.startsWith('to_us=')).join('&')");
  await traffic(); await delay(800);
  assert.equal(await evaluate("window.__timelineQueries.filter(q=>q.includes('from_us=')).at(-1).split('&').filter(s=>s.startsWith('from_us=')||s.startsWith('to_us=')).join('&')"), selectedRange, 'live traffic preserves absolute time bounds');
  await evaluate("document.getElementById('reset-time').click()");
  await waitFor("document.getElementById('reset-time').disabled && document.querySelectorAll('#packet-body tr').length>1", 'reset time selection');
  await evaluate("document.getElementById('brush-time').click()");
  const chartBox = await evaluate("(()=>{const r=document.getElementById('traffic-overview').getBoundingClientRect();return {x:r.x,y:r.y,width:r.width}})()");
  await cdp('Input.dispatchMouseEvent', { type: 'mousePressed', x: chartBox.x + chartBox.width * .15, y: chartBox.y + 55, button: 'left', clickCount: 1 });
  await cdp('Input.dispatchMouseEvent', { type: 'mouseMoved', x: chartBox.x + chartBox.width * .8, y: chartBox.y + 60, buttons: 1 });
  await cdp('Input.dispatchMouseEvent', { type: 'mouseReleased', x: chartBox.x + chartBox.width * .8, y: chartBox.y + 60, button: 'left', clickCount: 1 });
  await waitFor("!document.getElementById('reset-time').disabled", 'pointer brush selects time');
  await evaluate("document.getElementById('reset-time').click();document.getElementById('brush-time').click();window.fetch=window.__timelineFetch");
  await waitFor("document.querySelectorAll('#packet-body tr').length>1", 'rows after brush reset');
  await evaluate("document.querySelector('.packet-table th button').focus()");
  await cdp('Input.dispatchKeyEvent', {type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
  await cdp('Input.dispatchKeyEvent', {type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  assert(await evaluate("Number(document.querySelector('#packet-body tr').dataset.id)>Number(document.querySelector('#packet-body tr:last-child').dataset.id)"), 'column descending sort');
  await evaluate("document.querySelector('.packet-table th button').click()");
  await evaluate("document.querySelector('#packet-body tr').click()");
  await waitFor("document.querySelectorAll('#fields button').length>0 && document.querySelectorAll('#hex [data-offset]').length>0", 'fields and bytes');
  await evaluate("document.querySelector('.packet-table th button').click(); document.querySelector('#packet-body tr').click()");
  const focusedRow = await evaluate("document.activeElement.closest('tr').dataset.id");
  const previousRows = await evaluate("document.querySelectorAll('#packet-body tr').length");
  await traffic();
  await waitFor(`document.querySelectorAll('#packet-body tr').length>${previousRows}`, 'additional packets during descending sort');
  assert(await evaluate(`document.activeElement.closest('tr')?.dataset.id===${JSON.stringify(focusedRow)}`), 'sorted insertion preserves selected row keyboard focus');
  await evaluate("document.querySelector('.packet-table th button').click(); document.querySelector('#packet-body tr').click()");
  await waitFor("document.querySelectorAll('#fields button').length>0", 'detail after sorted insertion');
  const dragClose = await evaluate("(()=>{const g=document.querySelector('.gutter').getBoundingClientRect();return {x:g.x+2,y:g.y+g.height/2}})()");
  await cdp('Input.dispatchMouseEvent', {type:'mousePressed',x:dragClose.x,y:dragClose.y,button:'left',buttons:1,clickCount:1});
  await cdp('Input.dispatchMouseEvent', {type:'mouseMoved',x:dragClose.x+15,y:dragClose.y,button:'left',buttons:1});
  await cdp('Input.dispatchKeyEvent', {type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await cdp('Input.dispatchKeyEvent', {type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await cdp('Input.dispatchMouseEvent', {type:'mouseMoved',x:dragClose.x+100,y:dragClose.y,button:'left',buttons:1});
  await cdp('Input.dispatchMouseEvent', {type:'mouseReleased',x:dragClose.x+100,y:dragClose.y,button:'left',buttons:0,clickCount:1});
  assert(await evaluate("document.getElementById('inspector').hidden && document.getElementById('packet-pane').clientWidth>=document.getElementById('workspace').clientWidth-2"), 'closing during drag fully releases Split.js listeners');
  await evaluate("document.querySelector('#packet-body tr').click()");
  await waitFor("!document.getElementById('inspector').hidden && document.querySelectorAll('#fields button').length>0", 'inspector reopens');
  const split = await evaluate("(()=>{const g=document.querySelector('.gutter').getBoundingClientRect();return {x:g.x+g.width/2,y:g.y+g.height/2,width:document.getElementById('packet-pane').getBoundingClientRect().width}})()");
  await cdp('Input.dispatchMouseEvent', {type:'mouseMoved',x:split.x,y:split.y});
  await cdp('Input.dispatchMouseEvent', {type:'mousePressed',x:split.x,y:split.y,button:'left',buttons:1,clickCount:1});
  await cdp('Input.dispatchMouseEvent', {type:'mouseMoved',x:split.x+50,y:split.y,button:'left',buttons:1});
  await cdp('Input.dispatchMouseEvent', {type:'mouseReleased',x:split.x+50,y:split.y,button:'left',buttons:0,clickCount:1});
  assert(await evaluate(`document.getElementById('packet-pane').getBoundingClientRect().width>${split.width+20}`), 'Split.js real pointer resize');
  const resizedWidth = await evaluate("document.getElementById('packet-pane').getBoundingClientRect().width");
  await evaluate("document.querySelector('.gutter').focus(); document.querySelector('.gutter').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowLeft',bubbles:true}))");
  assert(await evaluate(`document.getElementById('packet-pane').getBoundingClientRect().width<${resizedWidth-5}`), 'separator keyboard resize');
  const beforeKey = await evaluate("document.getElementById('detail-id').textContent");
  await evaluate("document.getElementById('packet-scroll').focus(); document.getElementById('packet-scroll').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true}))");
  await waitFor(`document.getElementById('detail-id').textContent!==${JSON.stringify(beforeKey)} && document.querySelectorAll('#fields button').length>0`, 'keyboard row selection');
  await evaluate("document.querySelector('#fields button').click()");
  assert(await evaluate("document.querySelectorAll('#hex .highlight').length>0"), 'field highlights bytes');
  assert(await evaluate("!document.getElementById('bytes-panel').hidden && document.getElementById('bytes-tab').getAttribute('aria-selected')==='true'"), 'field selection opens bytes tab');
  assert(await evaluate("document.querySelectorAll('img').length===0"), 'packet content remains text');
  await evaluate("document.getElementById('stop').click()");
  await waitFor("document.getElementById('state').dataset.state==='stopped'", 'stopped');
  await evaluate("document.getElementById('search').value='x'.repeat(300); document.getElementById('search').dispatchEvent(new Event('input',{bubbles:true}))");
  await delay(1100);
  assert(await evaluate("document.getElementById('search').getAttribute('aria-invalid')==='true' && !document.getElementById('start').disabled"), 'oversized search does not disconnect capture UI');
  await evaluate("document.getElementById('search').value=''; document.getElementById('search').dispatchEvent(new Event('input',{bubbles:true}))");
  await delay(350);
  await waitFor("document.querySelectorAll('#packet-body tr').length>1", 'search recovers without reload');
  await evaluate("document.querySelector('#packet-body tr').click()");
  await waitFor("document.querySelectorAll('#fields button').length>0", 'detail after filter recovery');
  await evaluate("document.querySelector('#fields button').click()");
  await cdp('Page.captureScreenshot', { format: 'png' }).then(r => writeFile(path.join(output, 'desktop-bytes.png'), Buffer.from(r.data, 'base64')));
  await evaluate("document.getElementById('fields-tab').focus(); document.getElementById('fields-tab').click()");
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
  await evaluate("document.querySelector('#packet-body tr').click()");
  await waitFor("!document.getElementById('inspector').hidden && document.querySelectorAll('#fields button').length>0", 'mobile inspector');
  assert(await evaluate('document.documentElement.scrollWidth <= innerWidth + 2'), 'narrow layout does not overflow the page');
  await cdp('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }).then(r => writeFile(path.join(output, 'mobile.png'), Buffer.from(r.data, 'base64')));
  await evaluate("window.__originalFetch=window.fetch; window.fetch=async(...args)=>{const response=await window.__originalFetch(...args);if(String(args[0]).endsWith('/api/status')){const data=await response.json();data.latest_id=0;return new Response(JSON.stringify(data),{status:200,headers:{'Content-Type':'application/json'}})}return response}");
  await delay(700);
  await evaluate("document.getElementById('clear-view').click()");
  await waitFor("document.querySelectorAll('#packet-body tr').length===0 && document.getElementById('inspector').hidden", 'clear view closes inspector');
  await delay(700);
  assert(await evaluate("document.querySelectorAll('#packet-body tr').length===0"), 'clear boundary also covers packet cursor newer than status');
  await evaluate("window.fetch=window.__originalFetch");
  assert(await evaluate("Number(document.getElementById('retained').textContent.replaceAll(',',''))>0"), 'clear view preserves exportable server packets');
  assert.equal(errors.length, 0, JSON.stringify(errors));
  console.log('PASS: real Edge capture, sorting, Split.js pointer resize, detail tabs, byte highlight, TCP flow, clear view and responsive layouts');
} finally {
  try {
    const session = await (await fetch(`${base}/api/session`)).json();
    await fetch(`${base}/api/stop`, { method: 'POST', headers: { 'X-Capture-Token': session.token } });
  } catch {}
  if (ws?.readyState === WebSocket.OPEN) { try { await cdp('Browser.close'); } catch {} ws.close(); }
  for (const request of pending.values()) { clearTimeout(request.timeout); request.reject(new Error('Browser closed')); }
  browser.kill();
}
