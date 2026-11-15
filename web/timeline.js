export function createTimeline(onRangeChange) {
  const $ = id => document.getElementById(id);
  const chart = globalThis.echarts.init($('traffic-overview'));
  let data = null, range = null, metric = 'packets', origin = 0;
  function choose(from, to) {
    range = { from_us: Math.max(1, Math.floor(origin + from * 1000)), to_us: Math.max(1, Math.ceil(origin + to * 1000)) };
    render(); onRangeChange(range);
  }
  function render() {
    const bins = data?.bins || [];
    origin = data?.start_us || 0;
    const end = Math.max(data?.end_us || origin + 1000, range?.to_us || 0);
    if (range) origin = Math.min(origin || range.from_us, range.from_us);
    const span = Math.max(1, (end - origin) / 1000);
    $('time-range').textContent = bins.length ? `${data.matched.toLocaleString()} 包 · ${data.bytes.toLocaleString()} B${range ? ' · 已筛选时间范围' : ' · 全部保留数据'}` : '暂无匹配数据';
    $('reset-time').disabled = !range;
    chart.setOption({ animation: false, toolbox: { show: false }, grid: { left: 58, right: 20, top: 16, bottom: 48 },
      tooltip: { trigger: 'axis', renderMode: 'richText', formatter: params => {
        const b = bins[params[0]?.dataIndex];
        return b ? `${new Date(b.start_us / 1000).toLocaleTimeString('zh-CN', { hour12: false })}\n${b.packets} 包 · ${b.bytes} B\n桶宽 ${((b.end_us - b.start_us) / 1000).toFixed(3)} ms` : '';
      } },
      xAxis: { type: 'value', min: 0, max: span, axisLabel: { formatter: '{value} ms' }, splitLine: { lineStyle: { color: '#e8edf1' } } },
      yAxis: { type: 'value', minInterval: 1, name: metric === 'packets' ? '包 / 桶' : 'B / 桶', nameGap: 2, nameTextStyle: { align: 'left' }, splitLine: { show: false } },
      dataZoom: [{ type: 'slider', bottom: 3, height: 16, startValue: range ? (range.from_us - origin) / 1000 : 0, endValue: range ? (range.to_us - origin) / 1000 : span, showDetail: false }, { type: 'inside', zoomOnMouseWheel: true }],
      brush: { xAxisIndex: 0, brushType: 'lineX', brushMode: 'single', throttleType: 'debounce', throttleDelay: 200 },
      series: [{ type: 'bar', itemStyle: { color: '#8ab4f8' }, barMaxWidth: 24, data: bins.map(b => [((b.start_us + b.end_us) / 2 - origin) / 1000, b[metric]]) }],
    }, { notMerge: true, silent: true });
    chart.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: $('brush-time').getAttribute('aria-pressed') === 'true' ? 'lineX' : false } });
  }
  chart.on('datazoom', () => {
    const axis = chart.getOption().dataZoom[0];
    const span = Math.max(1, ((data?.end_us || origin + 1000) - origin) / 1000);
    choose(axis.startValue ?? span * axis.start / 100, axis.endValue ?? span * axis.end / 100);
  });
  chart.on('brushEnd', event => {
    const selected = event.areas?.[0]?.coordRange;
    if (selected) choose(selected[0], selected[1]);
  });
  $('brush-time').addEventListener('click', () => {
    const enabled = $('brush-time').getAttribute('aria-pressed') !== 'true';
    $('brush-time').setAttribute('aria-pressed', String(enabled));
    chart.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: enabled ? 'lineX' : false } });
  });
  $('reset-time').addEventListener('click', () => { range = null; render(); onRangeChange(null); });
  for (const key of ['packets', 'bytes']) $(`metric-${key}`).addEventListener('click', () => {
    metric = key;
    for (const k of ['packets', 'bytes']) $(`metric-${k}`).setAttribute('aria-pressed', String(k === key));
    render();
  });
  const observer = new ResizeObserver(() => chart.resize()); observer.observe($('traffic-overview'));
  render();
  return { setData(value) { data = value; render(); }, reset() { range = null; data = null; $('brush-time').setAttribute('aria-pressed', 'false'); render(); } };
}
