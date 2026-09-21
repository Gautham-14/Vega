// Browser-only fixtures. Never used for hardware eligibility or task decisions.
const Telemetry = {
  intervalMs: 3000,
  historySize: 41,
  scenario: 'review',
  tick: 0,
  paused: false,
  samples: [],
  profiles: {
    idle: {name: 'Idle workspace', cpu: 12, ram: 5.4, gpu: 3, vram: 0.4, disk: 8},
    review: {name: 'Inspection review', cpu: 44, ram: 11.8, gpu: 38, vram: 3.2, disk: 95},
    busy: {name: 'Busy queue', cpu: 78, ram: 24.2, gpu: 81, vram: 6.7, disk: 310}
  },
  sample(tick) {
    const profile = this.profiles[this.scenario];
    const wave = Math.sin(tick * 0.47) * 0.65 + Math.cos(tick * 0.19) * 0.35;
    const bound = (value, max) => Math.min(max, Math.max(0, value));
    return {
      cpu: bound(profile.cpu + wave * 8, 100),
      ram: bound(profile.ram + wave * 0.8, 32),
      gpu: bound(profile.gpu + Math.sin(tick * 0.31) * 7, 100),
      vram: bound(profile.vram + wave * 0.3, 8),
      disk: bound(profile.disk * (1 + wave * 0.3), 500)
    };
  },
  reset() {
    this.tick = 0;
    this.samples = Array.from({length: this.historySize}, (_, i) => this.sample(i - this.historySize + 1));
    this.updatedAt = new Date();
    this.render();
  },
  advance() {
    if (this.paused || document.hidden) return;
    this.samples.push(this.sample(++this.tick));
    this.samples.shift();
    this.updatedAt = new Date();
    this.render();
  },
  text(id, value) { document.getElementById(id).textContent = value; },
  meter(id, value) { document.getElementById(id).style.width = `${value}%`; },
  render() {
    const current = this.samples.at(-1);
    const ramPercent = current.ram / 32 * 100;
    this.text('cpu-info', `8 cores · ${current.cpu.toFixed(0)}% in use`);
    this.text('ram-info', `${(32 - current.ram).toFixed(1)} / 32 GB free`);
    this.text('gpu-info', `${current.gpu.toFixed(0)}% · ${current.vram.toFixed(1)} / 8 GB`);
    this.meter('cpu-meter', current.cpu);
    this.meter('ram-meter', ramPercent);
    this.meter('gpu-meter', current.gpu);
    this.text('telemetry-overview-status', `${this.profiles[this.scenario].name} · ${this.paused ? 'Paused' : 'Updates every 3 seconds'}`);
    this.text('telemetry-cpu', `${current.cpu.toFixed(0)}%`);
    this.text('telemetry-ram', `${current.ram.toFixed(1)} GB`);
    this.text('telemetry-gpu', `${current.gpu.toFixed(0)}%`);
    this.text('telemetry-vram', `${current.vram.toFixed(1)} of 8 GB VRAM`);
    this.text('telemetry-disk', `${current.disk.toFixed(0)} MB/s`);
    this.text('system-free-ram', `${(32 - current.ram).toFixed(1)} GB`);
    this.text('telemetry-updated', this.updatedAt.toLocaleTimeString());
    this.text('telemetry-status', this.paused ? 'Simulation paused' : 'Simulation running · 3-second samples');
    this.text('telemetry-pause', this.paused ? 'Resume simulation' : 'Pause simulation');
    document.getElementById('telemetry-pause').setAttribute('aria-pressed', String(this.paused));
    for (const metric of ['cpu', 'ram', 'gpu']) {
      const points = this.samples.map((sample, i) => {
        const percent = metric === 'ram' ? sample.ram / 32 * 100 : sample[metric];
        return `${(i / (this.historySize - 1) * 720).toFixed(1)},${(180 - percent * 1.8).toFixed(1)}`;
      }).join(' ');
      document.getElementById(`telemetry-line-${metric}`).setAttribute('points', points);
    }
    document.getElementById('overview-cpu-line').setAttribute('points', this.samples.map((sample, i) =>
      `${(i / (this.historySize - 1) * 720).toFixed(1)},${(90 - sample.cpu * 0.9).toFixed(1)}`).join(' '));
    document.getElementById('telemetry-chart').setAttribute('aria-label',
      `Simulated resource history. Current CPU ${current.cpu.toFixed(0)} percent, memory ${ramPercent.toFixed(0)} percent, GPU ${current.gpu.toFixed(0)} percent.`);
  },
  init() {
    this.paused = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    document.getElementById('telemetry-scenario').addEventListener('change', event => {
      this.scenario = event.target.value;
      this.reset();
    });
    document.getElementById('telemetry-pause').addEventListener('click', () => {
      this.paused = !this.paused;
      this.render();
    });
    document.getElementById('telemetry-reset').addEventListener('click', () => this.reset());
    this.reset();
    setInterval(() => this.advance(), this.intervalMs);
  }
};
