/* Only host measurements returned by Aegis are plotted. */
const Telemetry = {
  percent(value) { return Number.isFinite(value) ? `${value.toFixed(1)}%` : 'Unavailable'; },
  bytes(value) {
    if (!Number.isFinite(value)) return 'Unavailable';
    return value >= 1024 ** 3 ? `${(value / 1024 ** 3).toFixed(1)} GB` : `${(value / 1024 ** 2).toFixed(0)} MB`;
  },
  time(value) { return Number.isFinite(value) ? new Date(value * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '—'; },
  points(samples, field) {
    const rows = samples.filter(row => Number.isFinite(row.timestamp) && Number.isFinite(row[field]));
    if (!rows.length) return '';
    const first = samples[0].timestamp, last = samples.at(-1).timestamp;
    return rows.map(row => `${last > first ? ((row.timestamp - first) / (last - first) * 720).toFixed(1) : 720},${(179 - Math.max(0, Math.min(100, row[field])) * 1.78).toFixed(1)}`).join(' ');
  },
  render(latest, history) {
    const put = (id, value) => { document.getElementById(id).textContent = value; };
    put('cpu-value', this.percent(latest.cpu_percent));
    put('cpu-note', `${latest.cpu_cores ?? 'Unknown'} logical CPU cores`);
    put('memory-value', this.percent(latest.memory_percent));
    put('memory-note', `${this.bytes(latest.memory_used_bytes)} of ${this.bytes(latest.memory_total_bytes)}`);
    put('disk-value', this.percent(latest.disk_percent));
    put('disk-note', `${this.bytes(latest.disk_used_bytes)} of ${this.bytes(latest.disk_total_bytes)}`);
    put('process-value', this.bytes(latest.process_rss_bytes));
    put('gpu-note', `GPU: ${latest.gpu_percent === null ? 'unavailable' : this.percent(latest.gpu_percent)}. ${latest.gpu_note || ''}`);
    put('uptime', `Process uptime: ${Math.floor((latest.uptime_seconds || 0) / 60)} min`);
    put('telemetry-updated', `Measured ${this.time(latest.timestamp)}`);
    document.getElementById('telemetry-updated').title = new Date(latest.timestamp * 1000).toLocaleString();
    const rows = history.filter(row => row.source === 'HOST_MEASURED' && Number.isFinite(row.timestamp)).sort((a,b) => a.timestamp - b.timestamp);
    document.getElementById('cpu-line').setAttribute('points', this.points(rows, 'cpu_percent'));
    document.getElementById('memory-line').setAttribute('points', this.points(rows, 'memory_percent'));
    document.getElementById('history-chart').setAttribute('aria-label', `Measured CPU and memory history, ${rows.length} samples. Latest CPU ${this.percent(latest.cpu_percent)}, memory ${this.percent(latest.memory_percent)}.`);
    put('history-start', this.time(rows[0]?.timestamp));
    put('history-end', this.time(rows.at(-1)?.timestamp));
    put('history-note', rows.length > 1 ? `${rows.length} host measurements · ${Math.round((rows.at(-1).timestamp - rows[0].timestamp) / 60)} minutes · utilization in percent` : 'Collecting measured history. The chart fills as samples arrive.');
  }
};
if (typeof module !== 'undefined') module.exports = Telemetry;
