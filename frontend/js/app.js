/* The dashboard may mutate only its own authentication session. */
const App = {
  identity: null,
  demo: false,
  actor: 'operator',
  epoch: 0,
  timer: null,
  loading: false,
  lastSample: null,
  text(id, value) { document.getElementById(id).textContent = value; },
  show(id, visible) { document.getElementById(id).hidden = !visible; },
  escape(value) { return String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); },
  pretty(value) { return String(value ?? 'Unavailable').replaceAll('_', ' ').toLowerCase(); },
  async request(path, options = {}) {
    const headers = {...options.headers};
    if (this.demo) headers['X-Aegis-Actor'] = this.actor;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    let response;
    try { response = await fetch(path, {...options, headers, credentials:'same-origin', cache:'no-store', signal:controller.signal}); }
    catch (error) { throw error.name === 'AbortError' ? new Error('The runtime did not respond within ten seconds.') : error; }
    finally { clearTimeout(timeout); }
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try { const body = await response.json(); if (typeof body.detail === 'string') message = body.detail; } catch (_) { /* Preserve status. */ }
      const error = new Error(message); error.status = response.status; throw error;
    }
    return response.json();
  },
  status(message, kind = '') {
    const element = document.getElementById('connection-status');
    element.textContent = message; element.className = `connection ${kind}`;
  },
  message(value = '', error = false) {
    this.text('page-message', value); this.show('page-message', Boolean(value));
    document.getElementById('page-message').className = `notice${error ? ' error' : ''}`;
  },
  reset() {
    this.epoch += 1; this.identity = null; this.lastSample = null;
    clearTimeout(this.timer); this.timer = null; this.loading = false;
    for (const id of ['dashboard','signin','demo-mode','session-identity','logout','refresh','events-panel','hosted-preview']) this.show(id, false);
    for (const id of ['tasks-body','approvals-body','receipts-body','events-body']) document.getElementById(id).replaceChildren();
    for (const id of ['task-count','approval-count','receipt-count','chain-status','cpu-value','memory-value','disk-value','process-value','history-start','history-end']) this.text(id, '—');
    for (const id of ['cpu-line','memory-line']) document.getElementById(id).setAttribute('points', '');
    for (const id of ['cpu-note','memory-note','disk-note','telemetry-updated','history-note']) this.text(id, 'Waiting for host measurement');
    this.text('gpu-note', 'GPU: unavailable. No measurement adapter configured.'); this.text('uptime', 'Process uptime: —');
    this.message();
  },
  async boot() {
    this.reset(); this.demo = false; const epoch = this.epoch;
    this.status('Connecting');
    try {
      const health = await this.request('/health');
      if (epoch !== this.epoch) return;
      if (health.deployment_mode === 'HOSTED_PREVIEW') {
        this.show('hosted-preview', true); this.status('Hosted preview'); return;
      }
      const setup = await this.request('/api/auth/status');
      if (epoch !== this.epoch) return;
      this.demo = setup.demo === true;
      this.show('account-setup', !setup.configured && !this.demo);
      try { await this.connect(epoch); }
      catch (error) {
        if (epoch !== this.epoch) return;
        if (error.status !== 401) throw error;
        this.show('signin', true); this.show('refresh', true); this.status('Sign in required');
      }
    } catch (error) {
      if (epoch !== this.epoch) return;
      this.status('Runtime offline', 'offline'); this.message(`Unable to reach Aegis. ${error.message}`, true); this.show('refresh', true);
    }
  },
  async connect(epoch = this.epoch) {
    const identity = await this.request('/api/auth/me');
    if (epoch !== this.epoch) return;
    this.identity = identity;
    this.text('session-identity', `${identity.id} · ${identity.role}`);
    this.show('session-identity', true); this.show('signin', false); this.show('dashboard', true);
    this.show('demo-mode', this.demo); this.show('logout', !this.demo); this.show('refresh', true);
    this.show('login-error', false); this.message();
    await this.refresh();
  },
  async login(event) {
    event.preventDefault(); const button = document.getElementById('login-button');
    button.disabled = true; this.show('login-error', false);
    try {
      // The browser keeps the HttpOnly cookie. Never persist returned bearer tokens.
      await this.request('/api/auth/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value.trim(),password:document.getElementById('password').value})});
      document.getElementById('password').value = ''; this.demo = false;
      await this.connect();
    } catch (error) { this.text('login-error', error.message); this.show('login-error', true); }
    finally { button.disabled = false; }
  },
  async logout() {
    const button = document.getElementById('logout'); button.disabled = true;
    try { await this.request('/api/auth/logout', {method:'POST'}); await this.boot(); }
    catch (error) {
      if (error.status === 401) await this.boot();
      else this.message(`Sign-out was not confirmed. ${error.message}`, true);
    } finally { button.disabled = false; }
  },
  date(value) { return Number.isFinite(value) ? new Date(value * 1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—'; },
  id(value) { return `<span class="record-id" title="${this.escape(value)}">${this.escape(value)}</span>`; },
  badge(value) {
    const kind = /BLOCK|REJECT|FAIL|TAMPER/i.test(value) ? ' blocked' : /PENDING|AWAIT|EXPIRE/i.test(value) ? ' warning' : '';
    return `<span class="badge${kind}">${this.escape(this.pretty(value))}</span>`;
  },
  table(id, rows, columns, empty) {
    document.getElementById(id).innerHTML = rows.length ? rows.map(cells => `<tr>${cells.map(cell => `<td>${cell}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${columns}" class="empty">${this.escape(empty)}</td></tr>`;
  },
  workspace(data) {
    this.text('task-count', data.counts.tasks); this.text('approval-count', data.counts.approvals_pending); this.text('receipt-count', data.counts.receipts);
    this.text('chain-status', data.chain.is_valid ? 'Verified' : 'Failed'); this.text('chain-note', data.chain.scope);
    this.text('workspace-scope', data.system_events_allowed ? 'Your tasks · system audit summaries' : 'Your account’s records');
    this.table('tasks-body', data.tasks.map(task => [this.id(task.id), this.badge(task.status), `${this.escape(task.mode || '—')}<small>${this.escape(task.provider || '—')}</small>`, `${Number(task.decisions.ALLOW) || 0} allowed · ${Number(task.decisions.DENY) || 0} denied`, this.escape(this.date(task.created_at))]), 5, 'No coding tasks for this account. Start a governed task from aegis-cli.');
    this.table('approvals-body', data.approvals.map(approval => [this.id(approval.id),this.escape(this.pretty(approval.action)),this.badge(approval.status === 'PENDING' && approval.expires_at * 1000 < Date.now() ? 'EXPIRED' : approval.status),`${Number(approval.decisions_received) || 0} / ${Number(approval.decisions_required) || 0}`,this.escape(this.date(approval.expires_at))]), 5, 'No approval requests visible to this account.');
    this.table('receipts-body', data.receipts.map(receipt => [this.id(receipt.id),this.escape(this.pretty(receipt.action)),this.escape(this.date(receipt.timestamp))]), 3, 'No receipts visible to this account.');
    this.show('events-panel', data.system_events_allowed);
  },
  async refresh() {
    if (!this.identity) return this.boot();
    if (this.loading) return;
    clearTimeout(this.timer); this.loading = true;
    const epoch = this.epoch;
    const audit = ['Auditor','Security Officer'].includes(this.identity.role);
    const paths = ['/api/telemetry/latest','/api/telemetry/history?limit=120','/api/telemetry/workspace'];
    if (audit) paths.push('/api/telemetry/events?limit=50');
    try {
      const results = await Promise.allSettled(paths.map(path => this.request(path)));
      if (epoch !== this.epoch) return;
      if (results.some(result => result.status === 'rejected' && result.reason.status === 401)) {
        await this.boot(); return;
      }
      const [latest, history, workspace, events] = results;
      if (latest.status === 'fulfilled' && history.status === 'fulfilled') {
        if (latest.value.source !== 'HOST_MEASURED') throw new Error('The backend did not return a host measurement.');
        this.lastSample = latest.value.timestamp; Telemetry.render(latest.value, history.value);
      }
      if (workspace.status === 'fulfilled') this.workspace(workspace.value);
      if (events?.status === 'fulfilled') this.table('events-body', events.value.map(value => [this.escape(this.date(value.timestamp)),this.escape(value.method),this.escape(value.route),this.escape(value.status),`${Number(value.duration_ms).toFixed(1)} ms`]), 5, 'No system requests recorded.');
      const failures = results.filter(result => result.status === 'rejected');
      if (failures.length) {
        this.status('Connection interrupted', 'offline'); this.message(`Some readings could not be refreshed. Displayed values may be outdated. ${failures[0].reason.message}`, true);
      } else if (!this.lastSample || Date.now() / 1000 - this.lastSample > 15) {
        this.status('Measurements stale', 'offline'); this.message('The backend is reachable, but the latest measurement is more than 15 seconds old.', true);
      } else {
        this.status('Runtime connected', 'live'); this.message();
      }
    } catch (error) {
      if (epoch === this.epoch) { this.status('Runtime offline', 'offline'); this.message(`Readings are unavailable or outdated. ${error.message}`, true); }
    } finally {
      if (epoch === this.epoch) { this.loading = false; this.timer = setTimeout(() => this.refresh(), 5000); }
    }
  },
  init() {
    document.getElementById('login-form').addEventListener('submit', event => this.login(event));
    document.getElementById('logout').addEventListener('click', () => this.logout());
    document.getElementById('refresh').addEventListener('click', () => this.refresh());
    document.getElementById('demo-actor').addEventListener('change', event => { this.actor = event.target.value; this.boot(); });
    document.addEventListener('visibilitychange', () => { if (!document.hidden && this.identity) this.refresh(); });
    this.boot();
  }
};
if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', () => App.init());
if (typeof module !== 'undefined') module.exports = App;
