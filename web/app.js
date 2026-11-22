import { createTimeline } from './timeline.js';
import Split from './vendor/split.js';

'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const interfaces = new Map();
  function updateInterfaceDetails() {
    const item = interfaces.get($('interface').value);
    $('interface-details-button').disabled = !item;
    const panel = $('interface-details');
    panel.replaceChildren();
    if (!item) return;
    panel.append(el('strong', item.name));
    if (item.description && item.description !== item.name) panel.append(el('p', item.description));
    if (!item.addresses?.length) {
      panel.append(el('p', item.name === 'any' ? 'Captures across interfaces visible to libpcap.' : 'No IP addresses listed.'));
      return;
    }
    const addresses = el('ul');
    for (const address of item.addresses) addresses.append(el('li', address));
    panel.append(addresses);
  }
  const LIMIT = 1000;
  const model = { token: '', ready: false, state: 'idle', session: undefined, cursor: 0,
    epoch: 0, packets: new Map(), selected: null, detail: null, detailSeq: 0,
    protocol: 'ALL', search: '', flow: '', busy: false, polling: false, failures: 0, timer: null, connectionError: false,
    timeRange: null, timelineKey: '', clearAfter: 0, latestId: 0, sortKey: 'id', sortDirection: 1, filterInvalid: false };
  let panelSplit = null;
  let inspectorOpen = false;
  let savedSizes = [56, 44];
  try {
    const stored = JSON.parse(localStorage.getItem('wirelens:panel-widths'));
    if (Array.isArray(stored) && stored.length === 2 && stored.every(n => Number.isFinite(n) && n >= 20 && n <= 80) && Math.abs(stored[0] + stored[1] - 100) < 0.1) savedSizes = stored;
  } catch { /* 布局偏好读取失败不能影响抓包。 */ }
  const desktop = matchMedia('(min-width: 901px)');
  function saveSizes() {
    if (!panelSplit) return;
    savedSizes = panelSplit.getSizes();
    const gutter = $('workspace').querySelector('.gutter');
    gutter?.setAttribute('aria-valuenow', String(Math.round(savedSizes[0])));
    try { localStorage.setItem('wirelens:panel-widths', JSON.stringify(savedSizes)); } catch {}
  }
  function destroySplit() {
    if (!panelSplit) return;
    // Split.js 的 destroy() 不会结束正在进行的拖动，销毁前先停止拖动。
    window.dispatchEvent(new MouseEvent('mouseup', { button: 0 }));
    window.dispatchEvent(new Event('touchcancel'));
    saveSizes(); panelSplit.destroy(); panelSplit = null;
  }
  function configureSplit() {
    destroySplit();
    if (!inspectorOpen || !desktop.matches) return;
    panelSplit = Split(['#packet-pane', '#inspector'], {
      sizes: savedSizes, minSize: [380, 320], gutterSize: 4, snapOffset: 0,
      gutter: () => {
        const node = document.createElement('div'); node.className = 'gutter gutter-horizontal';
        node.tabIndex = 0; node.setAttribute('role', 'separator');
        node.setAttribute('aria-label', 'Resize packet list and details'); node.setAttribute('aria-orientation', 'vertical');
        node.setAttribute('aria-valuemin', '30'); node.setAttribute('aria-valuemax', '75');
        node.setAttribute('aria-valuenow', String(Math.round(savedSizes[0])));
        node.addEventListener('keydown', event => {
          if (!['ArrowLeft', 'ArrowRight', 'Home'].includes(event.key)) return;
          event.preventDefault();
          const size = event.key === 'Home' ? 56 : Math.max(30, Math.min(75, panelSplit.getSizes()[0] + (event.key === 'ArrowRight' ? 2 : -2)));
          panelSplit.setSizes([size, 100 - size]); saveSizes();
        });
        return node;
      }, onDragEnd: saveSizes,
    });
  }
  function openInspector() {
    if (inspectorOpen) return;
    inspectorOpen = true; $('inspector').hidden = false; $('workspace').classList.add('is-inspecting'); configureSplit();
  }
  function closeInspector() {
    destroySplit();
    inspectorOpen = false; $('inspector').hidden = true; $('workspace').classList.remove('is-inspecting');
  }
  function detailTab(name, focus = false) {
    const fields = name === 'fields';
    $('fields-panel').hidden = !fields; $('bytes-panel').hidden = fields;
    for (const [id, active] of [['fields-tab', fields], ['bytes-tab', !fields]]) {
      $(id).setAttribute('aria-selected', String(active)); $(id).tabIndex = active ? 0 : -1;
    }
    if (focus) $(fields ? 'fields-tab' : 'bytes-tab').focus();
  }
  for (const name of ['fields', 'bytes']) {
    $(`${name}-tab`).addEventListener('click', () => detailTab(name));
    $(`${name}-tab`).addEventListener('keydown', event => {
      if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
        event.preventDefault(); detailTab(event.key === 'Home' ? 'fields' : event.key === 'End' ? 'bytes' : name === 'fields' ? 'bytes' : 'fields', true);
      }
    });
  }
  $('close-detail').addEventListener('click', () => { closeInspector(); model.packets.get(model.selected)?.row.focus(); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape' && !$('flows-dialog').open && inspectorOpen) { closeInspector(); model.packets.get(model.selected)?.row.focus(); } });
  desktop.addEventListener('change', configureSplit);
  const timeline = createTimeline(range => { model.timeRange = range; filterChanged(); });
  const number = value => Number(value || 0).toLocaleString('en-US');
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
        let reason = `Request failed (${response.status})`;
        try { const body = await response.json(); if (body.error) reason = String(body.error); } catch { /* 保留 HTTP 状态码。 */ }
        const error = new Error(reason); error.status = response.status; throw error;
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
    closeInspector(); detailTab('fields');
    model.detailSeq++; model.selected = null; model.detail = null;
    $('fields').replaceChildren(el('p', 'Select a packet to view its details.', 'placeholder'));
    $('hex').replaceChildren(el('p', 'Select a packet to view its bytes.', 'placeholder'));
    $('detail-id').textContent = '—'; $('detail-warning').hidden = true;
    $('byte-range').textContent = 'Select a field to highlight its bytes'; $('follow').disabled = true;
  }
  function resetPackets() {
    model.epoch++; model.cursor = model.clearAfter; model.packets.clear();
    $('packet-body').replaceChildren(); $('gap').hidden = true;
    clearDetail(); updateCount();
  }
  function updateCount() {

    $('empty').hidden = model.packets.size > 0;
    if (!model.packets.size) {
      const filtered = model.protocol !== 'ALL' || model.search || model.flow || model.timeRange;
      $('empty').firstElementChild.textContent = filtered ? 'No matching packets' : model.state === 'running' ? 'Recording network activity…' : 'No packets recorded';
      $('empty').querySelector('p').textContent = filtered ? 'Adjust the protocol, text, stream, or time filters.' : model.state === 'running' ? 'Recording started. Waiting for packets.' : 'Select an interface and start recording.';
    }
  }
  function status(data) {
    const firstStatus = model.session === undefined;
    if (model.session !== undefined && model.session !== data.session) {
      model.clearAfter = 0; model.filterInvalid = false; model.timeRange = null; model.timelineKey = ''; timeline.reset();
      model.flow = ''; $('flow-filter').hidden = true;
      resetPackets();
      $('flows-dialog').close();
    }
    model.session = data.session; model.state = data.state; model.latestId = Number(data.latest_id) || 0;
    const names = { idle: 'Ready', running: 'Recording', stopped: 'Stopped', error: 'Capture error' };
    $('state').textContent = names[data.state] || 'Unknown state'; $('state').dataset.state = data.state;
    for (const key of ['retained', 'received', 'evicted']) $(key).textContent = number(data[key]);
    $('bytes').textContent = bytes(data.bytes);
    $('dropped').textContent = data.stats?.supported ? number(data.stats.dropped) : 'N/A';
    $('status-note').textContent = data.interface ? `${data.interface} · ${data.effective_filter || data.filter || 'No capture filter'}` : 'Local capture service';
    if (data.error) message(String(data.error));
    if ((data.state === 'running' || firstStatus) && interfaces.has(data.interface) && $('interface').value !== data.interface) {
      $('interface').value = data.interface;
      updateInterfaceDetails();
    }
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
    return `${date.toLocaleTimeString('en-GB', { hour12: false })}.${String(Math.abs(Number(us)) % 1000000).padStart(6, '0')}`;
  }
  function endpoint(address, port) {
    const host = address || '—';
    return port == null ? host : `${host.includes(':') ? `[${host}]` : host}:${port}`;
  }
  function packetRow(packet) {
    const row = el('tr'); row.dataset.id = String(packet.id); row.tabIndex = -1;
    row.dataset.protocol = packet.protocol;
    row.classList.toggle('packet-error', Boolean(packet.malformed));
    row.classList.toggle('packet-warning', Boolean(packet.truncated || packet.fragmented));
    row.setAttribute('aria-selected', 'false');
    row.setAttribute('aria-label', `Packet ${packet.id}, ${packet.protocol}, ${packet.source} to ${packet.destination}, ${packet.summary}`);
    const id = el('td', packet.id, 'numeric');
    const stamp = el('td', time(packet.timestamp_us));
    const source = el('td', endpoint(packet.source, packet.ports_known ? packet.source_port : null)); source.title = source.textContent;
    const destination = el('td', endpoint(packet.destination, packet.ports_known ? packet.destination_port : null)); destination.title = destination.textContent;
    const protocol = el('td', packet.protocol, 'proto');
    const length = el('td', number(packet.length), 'numeric');
    let summaryText = String(packet.summary || '').replace(` ${packet.source} -> ${packet.destination}`, '');
    if (summaryText === packet.protocol && packet.tcp_flags) summaryText = packet.tcp_flags;
    const summary = el('td', `${packet.truncated ? '[Truncated] ' : ''}${packet.malformed ? '[Malformed] ' : ''}${packet.fragmented ? '[Fragmented] ' : ''}${summaryText}`);
    summary.title = summary.textContent; row.append(id, stamp, source, destination, protocol, length, summary); return row;
  }
  const sortKeys = ['id', 'timestamp_us', 'source', 'destination', 'protocol', 'length', 'summary'];
  function sortRows() {
    const entries = [...model.packets.values()].sort((a, b) => {
      const aValue = a.packet[model.sortKey], bValue = b.packet[model.sortKey];
      const result = typeof aValue === 'number' ? aValue - bValue : String(aValue || '').localeCompare(String(bValue || ''));
      return result * model.sortDirection || Number(a.packet.id) - Number(b.packet.id);
    });
    const current = [...$('packet-body').children];
    if (entries.some((entry, i) => current[i] !== entry.row)) {
      const focused = document.activeElement;
      const retainFocus = $('packet-body').contains(focused);
      $('packet-body').append(...entries.map(entry => entry.row));
      if (retainFocus && focused.isConnected) focused.focus({ preventScroll: true });
    }
    document.querySelectorAll('.packet-table th').forEach((th, index) => th.setAttribute('aria-sort', sortKeys[index] === model.sortKey ? model.sortDirection === 1 ? 'ascending' : 'descending' : 'none'));
  }
  document.querySelectorAll('.packet-table th').forEach((th, index) => {
    const button = el('button', th.textContent); button.type = 'button'; button.title = `Sort by ${th.textContent}`;
    th.replaceChildren(button); th.setAttribute('aria-sort', index === 0 ? 'ascending' : 'none');
    button.addEventListener('click', () => { model.sortDirection = model.sortKey === sortKeys[index] ? -model.sortDirection : 1; model.sortKey = sortKeys[index]; sortRows(); });
  });
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
      sortRows();
      if (atBottom && model.selected === null) scroll.scrollTop = scroll.scrollHeight;
      updateCount();
    }
    if (data.gap) { $('gap').hidden = false; $('gap').textContent = 'Older packets were evicted. The list now continues from the earliest retained packet.'; }
    model.cursor = data.cursor ?? model.cursor;
  }
  // 定期读取捕获状态和新数据包，再更新列表与时间图。
  async function poll() {
    if (!model.ready || model.polling || document.hidden) return;
    model.polling = true;
    try {
      const current = await api('/status'); status(current);
      if (model.filterInvalid) return;
      const epoch = model.epoch;
      const query = new URLSearchParams({ after: String(model.cursor), protocol: model.protocol, search: model.search, flow: model.flow });
      if (model.timeRange) {
        query.set('from_us', String(model.timeRange.from_us));
        query.set('to_us', String(model.timeRange.to_us));
      }
      const overviewQuery = new URLSearchParams({ after: String(model.clearAfter), protocol: model.protocol, search: model.search, flow: model.flow });
      const key = `${current.session}:${current.oldest_id}:${current.latest_id}:${overviewQuery}`;
      const [data, overview] = await Promise.all([api(`/packets?${query}`), key === model.timelineKey ? null : api(`/timeline?${overviewQuery}`)]);
      if (epoch === model.epoch && overview && overview.session === model.session) { timeline.setData(overview); model.timelineKey = key; }
      if (epoch === model.epoch) appendPackets(data);
      model.failures = 0;
      if (model.connectionError && !current.error) message('');
      model.connectionError = false;
    } catch (error) {
      if (error.status === 400 || error.status === 422) {
        model.filterInvalid = true; message(`Invalid display filter: ${error.message}. Edit the filter to resume updates.`); return;
      }
      model.failures++; model.connectionError = true; message(`Connection error: ${error.message}${model.failures >= 2 ? '. Updates paused after two failures. Reload to reconnect.' : '. Retrying once on the next update.'}`);
      if (model.failures >= 2) { clearInterval(model.timer); model.ready = false; $('state').textContent = 'Disconnected'; $('state').dataset.state = 'error'; controls(); }
    } finally { model.polling = false; }
  }
  function filterChanged() {
    if (model.filterInvalid) message('');
    model.filterInvalid = false; resetPackets(); void poll();
  }
  const protocolFragment = document.createDocumentFragment();
  for (const protocol of ['ALL', 'HTTP', 'DNS', 'TCP', 'UDP', 'IPv4', 'IPv6', 'ICMP', 'ICMPv6']) {
    const button = el('button', protocol === 'ALL' ? 'All' : protocol); button.type = 'button'; button.setAttribute('aria-pressed', String(protocol === 'ALL'));
    button.setAttribute('aria-label', protocol === 'ALL' ? 'Show all protocols' : `Filter ${protocol} packets`);
    button.addEventListener('click', () => {
      if (model.protocol === protocol) return;
      model.protocol = protocol;
      for (const sibling of $('protocols').children) sibling.setAttribute('aria-pressed', String(sibling === button));
      filterChanged();
    }); protocolFragment.append(button);
  }
  $('protocols').append(protocolFragment);
  let searchTimer, searchInvalid = false;
  $('search').addEventListener('input', () => {
    const value = $('search').value.trim();
    clearTimeout(searchTimer);
    if (new TextEncoder().encode(value).length > 256) {
      searchInvalid = true; $('search').setAttribute('aria-invalid', 'true');
      message('Filter text is limited to 256 UTF-8 bytes. Showing results for the last valid filter.'); return;
    }
    if (searchInvalid) { searchInvalid = false; message(''); }
    $('search').removeAttribute('aria-invalid');
    // 防抖等待期间立即使之前的查询失效。
    model.epoch++; clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { model.search = value; filterChanged(); }, 250);
  });
  function highlight(offset, length, button) {
    detailTab('bytes', true);
    for (const field of $('fields').querySelectorAll('button')) field.setAttribute('aria-pressed', String(field === button));
    for (const node of $('hex').querySelectorAll('[data-offset]')) {
      const index = Number(node.dataset.offset);
      node.classList.toggle('highlight', index >= offset && index < offset + length);
      node.classList.toggle('highlight-start', index === offset && length > 0);
    }
    $('byte-range').textContent = length > 0 ? `Bytes ${offset}–${offset + length - 1} · ${length} B` : 'No byte range is available for this field';
    $('hex').querySelector('.highlight')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }
  function renderDetail(packet) {
    $('detail-id').textContent = `#${packet.id}`;
    const warnings = [];
    if (packet.truncated) warnings.push(`Packet truncated: captured ${packet.caplen} / original ${packet.length} bytes`);
    if (packet.malformed) warnings.push('Malformed packet');
    if (packet.fragmented) warnings.push('IP fragment; contents may be incomplete');
    $('detail-warning').textContent = warnings.join('; '); $('detail-warning').hidden = !warnings.length;
    const groups = new Map(); const fragment = document.createDocumentFragment();
    const hexString = String(packet.hex || '');
    const octets = /^[0-9a-f]*$/i.test(hexString) && hexString.length % 2 === 0 ? hexString.match(/../g) || [] : [];
    for (const field of packet.fields || []) {
      const section = String(field.section || 'Other fields');
      if (!groups.has(section)) { const group = el('details'); group.open = true; group.append(el('summary', section)); groups.set(section, group); fragment.append(group); }
      const button = el('button', field.name, 'field'); button.type = 'button'; button.append(el('span', field.value)); button.setAttribute('aria-pressed', 'false');
      const offset = Math.max(0, Math.min(octets.length, Number(field.offset) || 0));
      const length = Math.max(0, Math.min(octets.length - offset, Number(field.length) || 0));
      button.addEventListener('click', () => highlight(offset, length, button)); groups.get(section).append(button);
    }
    if (packet.http_line) fragment.append(el('p', packet.http_line, 'placeholder mono'));
    if (!fragment.childNodes.length) fragment.append(el('p', 'No decoded fields available.', 'placeholder'));
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
    if (!octets.length) hexFragment.append(el('p', 'No bytes available.', 'placeholder'));
    $('hex').replaceChildren(hexFragment); $('byte-range').textContent = `${number(octets.length)} bytes · Select a field to highlight its bytes`;
    $('follow').disabled = !packet.flow_id || !(packet.transport === 'TCP' || packet.protocol === 'TCP' || packet.protocol === 'HTTP');
  }
  async function selectPacket(id, focus = false) {
    id = String(id); const entry = model.packets.get(id);
    model.selected = id; model.detail = null; const sequence = ++model.detailSeq;
    openInspector();
    for (const [key, value] of model.packets) { value.row.setAttribute('aria-selected', String(key === id)); value.row.tabIndex = key === id ? 0 : -1; }
    if (focus && entry) { entry.row.focus({ preventScroll: true }); entry.row.scrollIntoView({ block: 'nearest' }); }
    $('detail-id').textContent = `#${id}`; $('follow').disabled = true; $('detail-warning').hidden = true;
    $('fields').replaceChildren(el('p', 'Loading packet details…', 'placeholder'));
    $('hex').replaceChildren(); $('byte-range').textContent = 'Loading bytes…';
    try {
      const packet = await api(`/packets/${encodeURIComponent(id)}`);
      if (sequence !== model.detailSeq) return;
      model.detail = packet; renderDetail(packet);
    } catch (error) {
      if (sequence === model.detailSeq) $('fields').replaceChildren(el('p', `Could not load packet: ${error.message}. The packet may have been evicted. Select another packet.`, 'placeholder'));
    }
  }
  $('packet-body').addEventListener('click', event => { const row = event.target.closest('tr'); if (row) void selectPacket(row.dataset.id, true); });
  $('packet-scroll').addEventListener('keydown', event => {
    if (event.target.closest('button,input,select,textarea,a')) return;
    if (!['ArrowUp', 'ArrowDown', 'Home', 'End', 'Enter'].includes(event.key)) return;
    const ids = [...$('packet-body').rows].map(row => row.dataset.id); if (!ids.length) return; event.preventDefault();
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
  $('interface').addEventListener('change', () => { controls(); updateInterfaceDetails(); });
  $('clear-view').addEventListener('click', () => {
    model.clearAfter = Math.max(model.clearAfter, model.latestId, model.cursor, ...[...model.packets.keys()].map(Number));
    model.timeRange = null; model.timelineKey = ''; timeline.reset();
    resetPackets(); void poll();
  });
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
    const link = el('a'); link.href = url; link.download = `capture-${new Date().toISOString().replace(/[:.]/g, '-')}.pcap`;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
  function setFlow(id, label) { model.flow = String(id || ''); $('flow-filter').hidden = !model.flow; $('flow-label').textContent = label || `TCP stream ${model.flow}`; filterChanged(); }
  $('follow').addEventListener('click', () => { if (model.detail?.flow_id) setFlow(model.detail.flow_id); });
  $('clear-flow').addEventListener('click', () => setFlow(''));
  $('close-flows').addEventListener('click', () => $('flows-dialog').close());
  // 展示请求、响应和抓包时间；点击包号可查看原始数据。
  function renderHttpAnalysis(output, data) {
    const states = {
      complete: data.partial_capture
        ? 'Complete HTTP exchanges found in the retained data.'
        : 'All retained HTTP messages in this stream were paired.',
      no_messages: 'No captured application data.',
      missing_handshake: 'The TCP handshake is unavailable and no complete HTTP exchange was identified at the start of the retained stream.',
      uncertain_direction: 'Could not determine the client direction.',
      missing_segments: 'TCP sequence gap. Analysis stopped before the missing bytes.',
      conflicting_overlap: 'Overlapping TCP segments contain different bytes.',
      truncated_capture: 'One or more packets were truncated during capture.',
      analysis_limit: 'Analysis limit reached.',
      invalid_framing: 'Invalid or unrecognized HTTP message framing.',
      awaiting_close: 'Cannot confirm the end of the HTTP response without a valid server FIN.',
      unsupported_framing: 'Unsupported framing, tunnel, or protocol upgrade.',
      incomplete_message: 'The next request or response is incomplete.',
    };
    output.replaceChildren(el('p', states[data.state] || 'Analysis unavailable.', 'placeholder'));
    if (data.partial_capture && data.exchanges.length) {
      output.prepend(el('p', 'Partial capture: the TCP handshake is unavailable or incomplete. HTTP pairs are inferred from retained data.', 'placeholder'));
    }
    const exchanges = data.exchanges;
    if (!exchanges.length) return;
    const validTiming = exchange => exchange.response_us >= exchange.request_us &&
      exchange.response_complete_us >= exchange.response_us;
    const timed = exchanges.filter(validTiming);
    const origin = Math.min(...timed.map(exchange => exchange.request_us));
    const end = Math.max(...timed.map(exchange => exchange.response_complete_us));
    const duration = Math.max(1, end - origin);
    const list = el('div', undefined, 'http-exchanges');
    list.setAttribute('role', 'group');
    list.setAttribute('aria-label', 'HTTP exchanges');
    const details = el('div', undefined, 'http-exchange-details');
    const buttons = [];
    const ms = us => `${(us / 1000).toFixed(3)} ms`;
    function show(exchange, selected) {
      for (const button of buttons) button.setAttribute('aria-pressed', String(button === selected));
      details.replaceChildren();
      for (const [label, line, id, meta] of [
        ['Request', exchange.request, exchange.request_packet, exchange.request_details],
        ['Response', exchange.response, exchange.response_packet, exchange.response_details],
      ]) {
        const section = el('details');
        section.open = true;
        section.append(el('summary', `${label} · ${meta.body_bytes} body bytes · ${meta.framing}`));
        const jump = el('button', `#${id} ${line}`, 'http-packet-link');
        jump.type = 'button';
        jump.addEventListener('click', () => { $('flows-dialog').close(); void selectPacket(id, true); });
        section.append(jump, el('pre', meta.headers || 'No headers'));
        details.append(section);
      }
      if (exchange.response_last_packet !== exchange.response_packet) {
        const id = exchange.response_last_packet;
        const jump = el('button', `Last response byte · #${id}`, 'http-packet-link');
        jump.type = 'button';
        jump.addEventListener('click', () => { $('flows-dialog').close(); void selectPacket(id, true); });
        details.append(jump);
      }
      if (exchange.response_fin_packet) {
        const id = exchange.response_fin_packet;
        const jump = el('button', `Server FIN · #${id}`, 'http-packet-link');
        jump.type = 'button';
        jump.addEventListener('click', () => { $('flows-dialog').close(); void selectPacket(id, true); });
        details.append(jump);
      }
      if (validTiming(exchange)) {
        details.append(el('p', `First response byte: ${ms(exchange.response_us - exchange.request_us)} · Response completion: ${ms(exchange.response_complete_us - exchange.response_us)}`));
      } else details.append(el('p', 'Timing unavailable: capture timestamps are out of order.'));
    }
    for (const exchange of exchanges) {
      const row = el('button', undefined, 'http-exchange-row');
      row.type = 'button';
      const label = el('span', `${exchange.method} ${exchange.target}`);
      label.title = label.textContent;
      row.append(label, el('span', exchange.status));
      const track = el('span', undefined, 'http-waterfall');
      if (validTiming(exchange)) {
        for (const [start, finish, style] of [
          [exchange.request_us, exchange.response_us, 'http-wait'],
          [exchange.response_us, exchange.response_complete_us, 'http-receive'],
        ]) {
          const bar = el('span', undefined, style);
          bar.style.left = `${100 * (start - origin) / duration}%`;
          bar.style.width = `${100 * (finish - start) / duration}%`;
          track.append(bar);
        }
        track.title = `${ms(exchange.response_complete_us - exchange.request_us)} from request to response completion`;
      } else track.textContent = '—';
      row.append(track);
      row.addEventListener('click', () => show(exchange, row));
      buttons.push(row);
      list.append(row);
    }
    const legend = timed.length
      ? `Capture timeline · 0–${ms(end - origin)} · Blue: request to response · Green: response completion`
      : 'Capture timing unavailable';
    output.append(el('p', legend, 'placeholder'), list, details);
    show(exchanges[0], buttons[0]);
  }

  let flowsBusy = false;
  $('flows-button').addEventListener('click', async () => {
    if (flowsBusy || !model.ready) return; flowsBusy = true; $('flows-button').disabled = true;
    $('flows-dialog').showModal(); $('flows').replaceChildren(el('p', 'Loading streams…', 'placeholder'));
    const epoch = model.epoch;
    try {
      const data = await api('/flows'); const fragment = document.createDocumentFragment();
      if (epoch !== model.epoch) { $('flows').replaceChildren(el('p', 'The capture has changed. Close and reopen the stream list.', 'placeholder')); return; }
      for (const flow of (data.flows || []).slice(-500).reverse()) {
        const button = el('button', `${flow.endpoint_a} ↔ ${flow.endpoint_b}`, 'flow-row'); button.type = 'button';
        button.append(el('small', `${number(flow.packets)} packets · ${bytes(flow.bytes)} · ${flow.state || '—'} · ${time(flow.started_us)} → ${time(flow.last_us)}`));
        button.addEventListener('click', () => { $('flows-dialog').close(); setFlow(flow.id, `${flow.endpoint_a} ↔ ${flow.endpoint_b}`); });
        const entry = el('div'); entry.append(button);
        const analysis = el('button', 'Analyze HTTP'); analysis.type = 'button';
        const output = el('div'); output.setAttribute('aria-live', 'polite');
        entry.append(analysis, output);
        analysis.addEventListener('click', async () => {
          const session = model.session;
          analysis.disabled = true;
          output.textContent = 'Reassembling retained TCP packets…';
          try {
            const data = await api(`/flows/http?flow=${encodeURIComponent(flow.id)}`);
            if (session !== model.session) { output.textContent = 'Capture changed. Reopen TCP streams.'; return; }
            renderHttpAnalysis(output, data);
          } catch (error) { output.textContent = `Could not analyze HTTP: ${error.message}`; }
          finally { analysis.disabled = false; }
        });
        if (!flow.processes?.length) entry.append(el('small', '进程未知', 'placeholder'));
        for (const owner of flow.processes || []) {
          const process = el('button', `${owner.name} · PID ${owner.pid} · Show all TCP streams for this process`);
          process.type = 'button'; process.style.margin = '3px 8px';
          process.className = 'process-owner'; process.dataset.process = owner.key;
          process.addEventListener('click', () => {
            $('flows-dialog').close(); model.flow = ''; $('flow-filter').hidden = true;
            model.search = `process:${owner.key}`; $('search').value = model.search; filterChanged();
          }); entry.append(process);
        }
        fragment.append(entry);
      }
      if (!fragment.childNodes.length) fragment.append(el('p', 'No TCP streams recorded.', 'placeholder'));
      $('flows').replaceChildren(fragment);
    } catch (error) { $('flows').replaceChildren(el('p', `Could not load streams: ${error.message}`, 'placeholder')); }
    finally { flowsBusy = false; $('flows-button').disabled = false; }
  });
  // 初始化会话令牌、接口列表和定时刷新。
  async function initialize() {
    try {
      const session = await api('/session');
      if (!session.token) throw new Error('The server did not return a capture token');
      model.token = session.token;
      const data = await api('/interfaces'); const fragment = document.createDocumentFragment();
      const advanced = el('optgroup'); advanced.label = 'Advanced interfaces';
      const items = data.interfaces || [];
      function addInterface(item) {
        interfaces.set(item.name, item);
        const ipv4 = item.addresses?.find(address => !address.includes(':'));
        const loopback = item.loopback || /^loopback\d*$/.test(item.name);
        const description = item.name === 'any' ? 'All interfaces' : loopback ? 'Loopback' : ipv4;
        const option = el('option', description ? `${item.name} · ${description}` : item.name);
        option.value = item.name;
        (/^(?:bluetooth|nflog|nfqueue|dbus|usbmon)/.test(item.name) ? advanced : fragment).append(option);
      }
      items.filter(item => item.name === 'any').forEach(addInterface);
      items.filter(item => item.name !== 'any').forEach(addInterface);
      if (advanced.children.length) fragment.append(advanced);
      if (!fragment.childNodes.length) fragment.append(el('option', 'No capture interfaces available'));
      $('interface').replaceChildren(fragment);
      if ((data.interfaces || []).some(item => item.name === 'any')) $('interface').value = 'any';
      if (!data.interfaces?.length) $('interface').firstElementChild.value = '';
      updateInterfaceDetails();
      model.ready = true; controls(); await poll();
      if (model.ready) model.timer = setInterval(() => void poll(), 500);
    } catch (error) { message(`Initialization failed: ${error.message}. Check the capture service and reload.`); $('state').textContent = 'Connection failed'; $('state').dataset.state = 'error'; }
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) void poll(); });
  window.addEventListener('pagehide', () => clearInterval(model.timer));
  void initialize();
})();
