'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const LIMIT = 1000;
  const model = { token: '', ready: false, state: 'idle', session: undefined, cursor: 0,
    epoch: 0, packets: new Map(), selected: null, detail: null, detailSeq: 0,
    protocol: 'ALL', search: '', flow: '', busy: false, polling: false, failures: 0, timer: null, connectionError: false };
  const number = value => Number(value || 0).toLocaleString('zh-CN');
  const bytes = value => { const n = Number(value || 0); return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`; };
  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text ?? '');
    if (className) node.className = className;
    return node;
  }
  function message(text) { $('error').textContent = text; $('error').hidden = !text; }
  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(`/api${path}`, { ...options, cache: 'no-store', signal: controller.signal,
        headers: { ...(model.token ? { 'X-Capture-Token': model.token } : {}), ...options.headers } });
      if (!response.ok) {
        let reason = `请求失败（${response.status}）`;
        try { const body = await response.json(); if (body.error) reason = String(body.error); } catch { /* Preserve HTTP status. */ }
        throw new Error(reason);
      }
      return options.blob ? await response.blob() : response.status === 204 ? null : await response.json();
    } finally { clearTimeout(timeout); }
  }
  function controls() {
    const running = model.state === 'running';
    $('start').disabled = !model.ready || model.busy || running || !$('interface').value;
    $('stop').disabled = !model.ready || model.busy || !running;
    $('interface').disabled = model.busy || running;
    $('bpf').disabled = model.busy || running;
    $('export').disabled = !model.ready || model.busy;
  }
  function clearDetail() {
    model.detailSeq++; model.selected = null; model.detail = null;
    $('fields').replaceChildren(el('p', '选择数据包，查看协议字段。', 'placeholder'));
    $('hex').replaceChildren(el('p', '等待选择数据包。', 'placeholder'));
    $('detail-id').textContent = '—'; $('detail-warning').hidden = true;
    $('byte-range').textContent = '选择字段可定位对应字节'; $('follow').disabled = true;
  }
  function resetPackets() {
    model.epoch++; model.cursor = 0; model.packets.clear();
    $('packet-body').replaceChildren(); $('gap').hidden = true;
    clearDetail(); updateCount();
  }
  function updateCount() {
    $('visible-count').textContent = `${number(model.packets.size)} 条`;
    $('empty').hidden = model.packets.size > 0;
    if (!model.packets.size) {
      const filtered = model.protocol !== 'ALL' || model.search || model.flow;
      $('empty').firstElementChild.textContent = filtered ? '没有匹配的数据包' : model.state === 'running' ? '正在监听网络' : '准备观察网络';
      $('empty').querySelector('p').textContent = filtered ? '调整协议、搜索词或会话筛选。' : model.state === 'running' ? '捕获已开始，等待数据包到达。' : '选择网络接口，开始捕获数据包。';
    }
  }
  function status(data) {
    if (model.session !== undefined && model.session !== data.session) {
      model.flow = ''; $('flow-filter').hidden = true;
      resetPackets();
      $('flows-dialog').close();
    }
    model.session = data.session; model.state = data.state;
    const names = { idle: '就绪', running: '捕获中', stopped: '已停止', error: '捕获错误' };
    $('state').textContent = names[data.state] || '未知状态'; $('state').dataset.state = data.state;
    for (const key of ['retained', 'received', 'evicted']) $(key).textContent = number(data[key]);
    $('bytes').textContent = bytes(data.bytes);
    $('dropped').textContent = data.stats?.supported ? `${number(data.stats.dropped)} / 接口 ${data.stats.interface_dropped == null ? '未提供' : number(data.stats.interface_dropped)}` : '未提供';
    $('status-note').textContent = data.interface ? `${data.interface} · ${data.effective_filter || data.filter || '未设置捕获过滤器'}` : '本地捕获服务';
    if (data.error) message(String(data.error));
    if (data.interface && [...$('interface').options].some(o => o.value === data.interface)) $('interface').value = data.interface;
    if (data.state === 'running') $('bpf').value = data.filter || '';
    prune(data.oldest_id); controls(); updateCount();
  }
  function prune(oldest) {
    let removed = false;
    for (const [id, entry] of model.packets) {
      if (Number(id) < Number(oldest)) { entry.row.remove(); model.packets.delete(id); removed = true; }
    }
    if (removed) updateCount();
  }
  function time(us) {
    const date = new Date(Number(us) / 1000);
    if (!Number.isFinite(date.getTime())) return '—';
    return `${date.toLocaleTimeString('zh-CN', { hour12: false })}.${String(Math.abs(Number(us)) % 1000000).padStart(6, '0')}`;
  }
  function endpoint(address, port) {
    const host = address || '—';
    return port == null ? host : `${host.includes(':') ? `[${host}]` : host}:${port}`;
  }
  function packetRow(packet) {
    const row = el('tr'); row.dataset.id = String(packet.id); row.tabIndex = -1;
    row.setAttribute('aria-selected', 'false');
    row.setAttribute('aria-label', `数据包 ${packet.id}，${packet.protocol}，${packet.source} 到 ${packet.destination}，${packet.summary}`);
    const id = el('td'); id.append(el('span', `#${packet.id}`), el('span', time(packet.timestamp_us), 'secondary'));
    const endpoints = el('td'); endpoints.append(el('span', endpoint(packet.source, packet.ports_known ? packet.source_port : null)), el('span', `→ ${endpoint(packet.destination, packet.ports_known ? packet.destination_port : null)}`, 'secondary'));
    const protocol = el('td'); protocol.append(el('span', packet.protocol, 'proto'), el('span', number(packet.length), 'secondary'));
    const summary = el('td', `${packet.truncated ? '[截断] ' : ''}${packet.malformed ? '[异常] ' : ''}${packet.fragmented ? '[分片] ' : ''}${packet.summary || ''}`);
    summary.title = summary.textContent; row.append(id, endpoints, protocol, summary); return row;
  }
  function appendPackets(data) {
    prune(data.oldest_id);
    const fresh = (data.packets || []).filter(p => Number(p.id) > Number(model.cursor) && !model.packets.has(String(p.id))).slice(-LIMIT);
    if (fresh.length) {
      const scroll = $('packet-scroll'); const atBottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 40;
      const fragment = document.createDocumentFragment();
      const excess = Math.max(0, model.packets.size + fresh.length - LIMIT);
      for (const id of [...model.packets.keys()].slice(0, excess)) { model.packets.get(id).row.remove(); model.packets.delete(id); }
      for (const packet of fresh) {
        const row = packetRow(packet); model.packets.set(String(packet.id), { packet, row }); fragment.append(row);
      }
      $('packet-body').append(fragment);
      if (atBottom && model.selected === null) scroll.scrollTop = scroll.scrollHeight;
      updateCount();
    }
    if (data.gap) { $('gap').hidden = false; $('gap').textContent = '部分旧包已被淘汰；当前列表已从服务端仍保留的数据继续更新。'; }
    model.cursor = data.cursor ?? model.cursor;
  }
  async function poll() {
    if (!model.ready || model.polling || document.hidden) return;
    model.polling = true;
    try {
      const current = await api('/status'); status(current);
      const epoch = model.epoch;
      const query = new URLSearchParams({ after: String(model.cursor), protocol: model.protocol, search: model.search, flow: model.flow });
      const data = await api(`/packets?${query}`);
      if (epoch === model.epoch) appendPackets(data);
      model.failures = 0;
      if (model.connectionError && !current.error) message('');
      model.connectionError = false;
    } catch (error) {
      model.failures++; model.connectionError = true; message(`连接异常：${error.message}${model.failures >= 2 ? '。连续两次失败，已暂停自动刷新；重新加载页面可重连。' : '。将在下一轮重试一次。'}`);
      if (model.failures >= 2) { clearInterval(model.timer); model.ready = false; $('state').textContent = '连接中断'; $('state').dataset.state = 'error'; controls(); }
    } finally { model.polling = false; }
  }
  function filterChanged() { resetPackets(); void poll(); }
  const protocolFragment = document.createDocumentFragment();
  for (const protocol of ['ALL', 'HTTP', 'TCP', 'UDP', 'IPv4', 'IPv6', 'ICMP', 'ICMPv6']) {
    const button = el('button', protocol); button.type = 'button'; button.setAttribute('aria-pressed', String(protocol === 'ALL'));
    button.setAttribute('aria-label', protocol === 'ALL' ? '显示所有协议' : `筛选 ${protocol} 协议`);
    button.addEventListener('click', () => {
      if (model.protocol === protocol) return;
      model.protocol = protocol;
      for (const sibling of $('protocols').children) sibling.setAttribute('aria-pressed', String(sibling === button));
      filterChanged();
    }); protocolFragment.append(button);
  }
  $('protocols').append(protocolFragment);
  let searchTimer;
  $('search').addEventListener('input', () => {
    // Invalidate an outstanding query immediately, before the debounce expires.
    model.epoch++; clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { model.search = $('search').value.trim(); filterChanged(); }, 250);
  });
  function highlight(offset, length, button) {
    for (const field of $('fields').querySelectorAll('button')) field.setAttribute('aria-pressed', String(field === button));
    for (const node of $('hex').querySelectorAll('[data-offset]')) {
      const index = Number(node.dataset.offset);
      node.classList.toggle('highlight', index >= offset && index < offset + length);
      node.classList.toggle('highlight-start', index === offset && length > 0);
    }
    $('byte-range').textContent = length > 0 ? `字节 ${offset}–${offset + length - 1} · ${length} B` : '此字段没有可定位的字节';
    $('hex').querySelector('.highlight')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }
  function renderDetail(packet) {
    $('detail-id').textContent = `#${packet.id}`;
    const warnings = [];
    if (packet.truncated) warnings.push(`数据包已截断：捕获 ${packet.caplen} / 原始 ${packet.length} 字节`);
    if (packet.malformed) warnings.push('协议解析异常');
    if (packet.fragmented) warnings.push('IP 分片，内容可能不完整');
    $('detail-warning').textContent = warnings.join('；'); $('detail-warning').hidden = !warnings.length;
    const groups = new Map(); const fragment = document.createDocumentFragment();
    const hexString = String(packet.hex || '');
    const octets = /^[0-9a-f]*$/i.test(hexString) && hexString.length % 2 === 0 ? hexString.match(/../g) || [] : [];
    for (const field of packet.fields || []) {
      const section = String(field.section || '其他字段');
      if (!groups.has(section)) { const group = el('details'); group.open = true; group.append(el('summary', section)); groups.set(section, group); fragment.append(group); }
      const button = el('button', field.name, 'field'); button.type = 'button'; button.append(el('span', field.value)); button.setAttribute('aria-pressed', 'false');
      const offset = Math.max(0, Math.min(octets.length, Number(field.offset) || 0));
      const length = Math.max(0, Math.min(octets.length - offset, Number(field.length) || 0));
      button.addEventListener('click', () => highlight(offset, length, button)); groups.get(section).append(button);
    }
    if (packet.http_line) fragment.append(el('p', packet.http_line, 'placeholder mono'));
    if (!fragment.childNodes.length) fragment.append(el('p', '没有可解析的协议字段。', 'placeholder'));
    $('fields').replaceChildren(fragment);
    const hexFragment = document.createDocumentFragment();
    for (let offset = 0; offset < octets.length; offset += 16) {
      const row = el('div', undefined, 'hex-row'); const hex = el('span', undefined, 'hex-bytes'); const ascii = el('span', undefined, 'hex-ascii');
      row.append(el('span', offset.toString(16).padStart(4, '0'), 'hex-offset'));
      for (let j = 0; j < 16; j++) {
        const value = octets[offset + j]; const h = el('span', value || '  '); const code = parseInt(value, 16);
        const a = el('span', value ? code >= 32 && code <= 126 ? String.fromCharCode(code) : '·' : ' ');
        if (value) { h.dataset.offset = a.dataset.offset = String(offset + j); }
        hex.append(h); ascii.append(a);
      }
      row.append(hex, ascii); hexFragment.append(row);
    }
    if (!octets.length) hexFragment.append(el('p', '无可用字节数据。', 'placeholder'));
    $('hex').replaceChildren(hexFragment); $('byte-range').textContent = `${number(octets.length)} 字节 · 选择字段可定位`;
    $('follow').disabled = !packet.flow_id || !(packet.transport === 'TCP' || packet.protocol === 'TCP' || packet.protocol === 'HTTP');
  }
  async function selectPacket(id, focus = false) {
    id = String(id); const entry = model.packets.get(id); if (!entry) return;
    model.selected = id; model.detail = null; const sequence = ++model.detailSeq;
    for (const [key, value] of model.packets) { value.row.setAttribute('aria-selected', String(key === id)); value.row.tabIndex = key === id ? 0 : -1; }
    if (focus) { entry.row.focus({ preventScroll: true }); entry.row.scrollIntoView({ block: 'nearest' }); }
    $('detail-id').textContent = `#${id}`; $('follow').disabled = true; $('detail-warning').hidden = true;
    $('fields').replaceChildren(el('p', '正在读取协议详情…', 'placeholder'));
    $('hex').replaceChildren(); $('byte-range').textContent = '正在读取字节…';
    try {
      const packet = await api(`/packets/${encodeURIComponent(id)}`);
      if (sequence !== model.detailSeq) return;
      model.detail = packet; renderDetail(packet);
    } catch (error) {
      if (sequence === model.detailSeq) $('fields').replaceChildren(el('p', `无法读取数据包：${error.message}。该包可能已被淘汰，请选择其他数据包。`, 'placeholder'));
    }
  }
  $('packet-body').addEventListener('click', event => { const row = event.target.closest('tr'); if (row) void selectPacket(row.dataset.id, true); });
  $('packet-scroll').addEventListener('keydown', event => {
    if (!['ArrowUp', 'ArrowDown', 'Home', 'End', 'Enter'].includes(event.key)) return;
    const ids = [...model.packets.keys()]; if (!ids.length) return; event.preventDefault();
    let index = ids.indexOf(model.selected);
    if (event.key === 'Home') index = 0;
    else if (event.key === 'End') index = ids.length - 1;
    else if (event.key === 'ArrowDown') index = Math.min(ids.length - 1, index + 1);
    else if (event.key === 'ArrowUp') index = index < 0 ? ids.length - 1 : Math.max(0, index - 1);
    else index = Math.max(0, index);
    void selectPacket(ids[index], true);
  });
  async function action(work) {
    if (model.busy || !model.ready) return;
    model.busy = true; controls(); message('');
    try { await work(); } catch (error) { message(error.message); }
    finally { model.busy = false; controls(); }
  }
  $('interface').addEventListener('change', controls);
  $('capture-form').addEventListener('submit', event => {
    event.preventDefault(); if ($('start').disabled) return;
    void action(async () => {
      await api('/start', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ interface: $('interface').value, filter: $('bpf').value.trim() }) });
      model.state = 'running'; await poll();
    });
  });
  $('stop').addEventListener('click', () => { if (!$('stop').disabled) void action(async () => { await api('/stop', { method: 'POST' }); model.state = 'stopped'; await poll(); }); });
  $('export').addEventListener('click', () => void action(async () => {
    const blob = await api('/export', { blob: true }); const url = URL.createObjectURL(blob);
    const link = el('a'); link.href = url; link.download = `wirelens-${new Date().toISOString().replace(/[:.]/g, '-')}.pcap`;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
  function setFlow(id, label) { model.flow = String(id || ''); $('flow-filter').hidden = !model.flow; $('flow-label').textContent = label || `TCP 会话 ${model.flow}`; filterChanged(); }
  $('follow').addEventListener('click', () => { if (model.detail?.flow_id) setFlow(model.detail.flow_id); });
  $('clear-flow').addEventListener('click', () => setFlow(''));
  $('close-flows').addEventListener('click', () => $('flows-dialog').close());
  let flowsBusy = false;
  $('flows-button').addEventListener('click', async () => {
    if (flowsBusy || !model.ready) return; flowsBusy = true; $('flows-button').disabled = true;
    $('flows-dialog').showModal(); $('flows').replaceChildren(el('p', '正在读取会话…', 'placeholder'));
    const epoch = model.epoch;
    try {
      const data = await api('/flows'); const fragment = document.createDocumentFragment();
      if (epoch !== model.epoch) { $('flows').replaceChildren(el('p', '捕获上下文已改变，请关闭后重新打开会话列表。', 'placeholder')); return; }
      for (const flow of (data.flows || []).slice(-500).reverse()) {
        const button = el('button', `${flow.endpoint_a} ↔ ${flow.endpoint_b}`, 'flow-row'); button.type = 'button';
        button.append(el('small', `${number(flow.packets)} 包 · ${bytes(flow.bytes)} · ${flow.state || '—'} · ${time(flow.started_us)} → ${time(flow.last_us)}`));
        button.addEventListener('click', () => { $('flows-dialog').close(); setFlow(flow.id, `${flow.endpoint_a} ↔ ${flow.endpoint_b}`); }); fragment.append(button);
      }
      if (!fragment.childNodes.length) fragment.append(el('p', '尚无 TCP 会话。', 'placeholder'));
      $('flows').replaceChildren(fragment);
    } catch (error) { $('flows').replaceChildren(el('p', `无法读取会话：${error.message}`, 'placeholder')); }
    finally { flowsBusy = false; $('flows-button').disabled = false; }
  });
  async function initialize() {
    try {
      const session = await api('/session');
      if (!session.token) throw new Error('服务未返回捕获令牌');
      model.token = session.token; $('version').textContent = session.version ? `v${session.version}` : '';
      const data = await api('/interfaces'); const fragment = document.createDocumentFragment();
      for (const item of data.interfaces || []) {
        const option = el('option', `${item.description || item.name}${item.loopback ? ' · 回环' : ''} · ${(item.addresses || []).join(', ') || '无地址'}`);
        option.value = item.name; option.title = `${item.name} · ${option.textContent}`; fragment.append(option);
      }
      if (!fragment.childNodes.length) fragment.append(el('option', '没有可用的捕获接口'));
      $('interface').replaceChildren(fragment);
      if (!data.interfaces?.length) $('interface').firstElementChild.value = '';
      model.ready = true; controls(); await poll();
      if (model.ready) model.timer = setInterval(() => void poll(), 500);
    } catch (error) { message(`初始化失败：${error.message}。请检查捕获服务后重新加载页面。`); $('state').textContent = '连接失败'; $('state').dataset.state = 'error'; }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  window.addEventListener('pagehide', () => clearInterval(model.timer));
  void initialize();
})();
