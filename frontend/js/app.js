const App = {
  page: 'overview',
  hostedPreview: false,
  receipt: null,
  labels: {overview:'Overview',models:'Model registry',knowledge:'Knowledge base',security:'Security center',receipts:'Receipts',system:'Telemetry'},
  icon(name) { return `<svg class="icon" aria-hidden="true"><use href="/static/icons.svg#${name}"/></svg>`; },
  empty(icon, title, copy, action = '') { return `<div class="empty-state"><span class="empty-icon">${this.icon(icon)}</span><h3>${title}</h3><p>${copy}</p>${action}</div>`; },
  escape(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); },
  pretty(value) { return String(value ?? '').toLowerCase().replaceAll('_',' ').replace(/^./, c => c.toUpperCase()); },
  async request(path, options) {
    const response = await fetch(path, options);
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try { detail = (await response.json()).detail || detail; } catch (_) { /* Keep status. */ }
      throw new Error(Array.isArray(detail) ? detail.map(item => `${item.loc?.at(-1) || 'Field'}: ${item.msg}`).join('; ') : typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    return response.json();
  },
  notify(message, error = false) {
    const region = document.getElementById('notifications');
    const item = document.createElement('div');
    item.className = `toast${error ? ' error' : ''}`;
    item.textContent = message;
    region.replaceChildren(item);
    setTimeout(() => { if (item.isConnected) item.remove(); }, 8000);
  },
  showError(bodyId, columns, error) {
    document.getElementById(bodyId).innerHTML = `<tr><td colspan="${columns}" class="empty">Could not load records. ${this.escape(error.message)}</td></tr>`;
  },
  filter(input) {
    const body = document.getElementById(input.dataset.search);
    const query = input.value.trim().toLocaleLowerCase();
    body.querySelector('.filter-empty')?.remove();
    const rows = [...body.rows];
    for (const row of rows) row.hidden = !(`${row.textContent} ${row.dataset.search || ''}`).toLocaleLowerCase().includes(query);
    if (rows.length && rows.every(row => row.hidden)) {
      const row = body.insertRow(); row.className = 'filter-empty';
      const cell = row.insertCell(); cell.className = 'empty'; cell.colSpan = body.closest('table').querySelectorAll('th').length;
      cell.textContent = 'No matches. Try a different search.';
    }
  },
  reapply(bodyId) { const input = document.querySelector(`[data-search="${bodyId}"]`); if (input) this.filter(input); },
  navigate(name) {
    const page = this.labels[name] ? name : 'overview';
    this.page = page;
    for (const section of document.querySelectorAll('.page')) section.hidden = section.id !== `page-${page}`;
    for (const link of document.querySelectorAll('[data-page]')) {
      const active = link.dataset.page === page;
      link.classList.toggle('active', active);
      if (active) link.setAttribute('aria-current','page'); else link.removeAttribute('aria-current');
    }
    document.getElementById('breadcrumb').textContent = this.labels[page];
    document.title = `${this.labels[page]} Â· Aegis`;
    this.closeNav();
    window.scrollTo(0,0);
    document.querySelector(`#page-${page} h1`)?.focus({preventScroll:true});
    ({overview:()=>this.loadOverview(),models:()=>this.loadModels(),knowledge:()=>this.loadDocuments(),security:()=>this.loadEvents(),receipts:()=>this.loadReceipts(),system:()=>this.loadOverview(),control:()=>Control.load()})[page]();
  },
  openNav() { document.body.classList.add('nav-open'); document.getElementById('workspace').inert = true; document.getElementById('nav-scrim').hidden = false; document.getElementById('nav-toggle').setAttribute('aria-expanded','true'); document.querySelector('[data-page].active')?.focus(); },
  closeNav() { document.body.classList.remove('nav-open'); document.getElementById('workspace').inert = false; document.getElementById('nav-scrim').hidden = true; document.getElementById('nav-toggle').setAttribute('aria-expanded','false'); },
  openDialog(id) { const dialog = document.getElementById(id); const error = dialog.querySelector('.form-error'); if (error) error.hidden = true; dialog.showModal(); dialog.querySelector('input')?.focus(); },
  closeDialog() { for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close(); },
  async loadOverview() {
    try {
      const data = await this.request('/api/dashboard/status');
      document.getElementById('connection-status').textContent = this.hostedPreview ? 'Hosted preview' : 'Runtime connected';
      document.getElementById('connection-dot').classList.remove('offline');
      document.getElementById('model-count').textContent = data.registered_models;
      document.getElementById('model-note').textContent = `${data.qualified_models} qualified Â· ${data.quarantined_models} in quarantine`;
      document.getElementById('document-count').textContent = data.registered_documents;
      document.getElementById('receipt-count').textContent = data.recent_receipts_count;
      document.getElementById('security-status').textContent = data.recent_security_events_count;
      document.getElementById('recent-events').innerHTML = data.recent_security_events.length ? data.recent_security_events.map(e => `<div class="event"><strong>${this.escape(this.pretty(e.event_type))}</strong><small>${this.escape(e.source_document)}</small></div>`).join('') : this.empty('shield', 'A fresh activity log', 'Scanner events will appear here after you inspect text in the security center.');
    } catch (error) {
      document.getElementById('connection-status').textContent = 'Runtime unavailable';
      document.getElementById('connection-dot').classList.add('offline');
      this.notify(error.message, true);
    }
  },
  async loadModels() {
    try {
      const rows = await this.request('/api/models');
      document.getElementById('models-body').innerHTML = rows.length ? rows.map(m => {
        const summary = m.benchmark_summary || {};
        const issue = summary.integrity_check === 'FAIL_HASH_MISMATCH' ? 'Checksum mismatch' : summary.license_compliant === false ? 'License review required' : '';
        return `<tr><td><strong>${this.escape(m.name)}</strong><small>${this.escape(m.id)} Â· ${this.escape(m.version)}</small></td><td>${this.escape((m.capabilities || []).join(', '))}</td><td>${this.escape(m.memory_req_mb)} MB Â· ${this.escape(m.cpu_cores_req)} cores</td><td><span class="badge">${this.escape(this.pretty(m.status))}</span>${issue ? `<small>${issue}</small>` : ''}</td></tr>`;
      }).join('') : `<tr><td colspan="4" class="empty">${this.empty('layers', 'Your model registry starts here', 'Keep model identity, capabilities and resource requirements together. Registration saves metadata only.', this.hostedPreview ? '' : '<button class="button secondary" data-open="model-dialog">Add your first manifest</button>')}</td></tr>`;
      this.reapply('models-body');
    } catch (error) { this.showError('models-body',4,error); }
  },
  async loadDocuments() {
    try {
      const rows = await this.request('/api/knowledge');
      document.getElementById('documents-body').innerHTML = rows.length ? rows.map(d => `<tr><td><strong>${this.escape(d.title)}</strong><small>${this.escape(d.filename)}</small></td><td>${this.escape(d.revision)}</td><td><span class="badge">${this.escape(this.pretty(d.status))}</span></td><td>${this.escape(d.department)}</td><td>${this.escape(this.pretty(d.classification))}</td></tr>`).join('') : `<tr><td colspan="5" class="empty">${this.empty('folder', 'A home for your source documents', 'Add text with its revision, department and access classification.', this.hostedPreview ? '' : '<button class="button secondary" data-open="document-dialog">Add your first document</button>')}</td></tr>`;
      this.reapply('documents-body');
    } catch (error) { this.showError('documents-body',5,error); }
  },
  async loadEvents() {
    try {
      const rows = await this.request('/api/security/events');
      document.getElementById('events-body').innerHTML = rows.length ? rows.map(e => `<tr><td>${this.escape(this.pretty(e.event_type))}</td><td><span class="badge">${this.escape(this.pretty(e.severity))}</span></td><td>${this.escape(e.source_document)}</td><td>${this.escape(this.pretty(e.action_taken))}</td><td>${this.escape((e.created_at || '').slice(0,19))}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">No security events recorded.</td></tr>';
    } catch (error) { this.showError('events-body',5,error); }
  },
  async loadReceipts() {
    try {
      const rows = await this.request('/api/receipts');
      document.getElementById('receipts-body').innerHTML = rows.length ? rows.map(r => `<tr data-search="${this.escape(`${r.id} ${r.task_id}`)}"><td><strong>${this.escape(r.id)}</strong></td><td>${this.escape(r.task_id)}</td><td>${this.escape((r.created_at || '').slice(0,19))}</td><td><button class="button secondary small" data-receipt="${this.escape(r.task_id)}">Open</button></td></tr>`).join('') : `<tr><td colspan="4" class="empty">${this.empty('receipt', 'No legacy task receipts yet', 'Looking for governed task records? They live in the control plane under Audit & records.', '<button class="button secondary" data-audit>View governance records</button>')}</td></tr>`;
      this.reapply('receipts-body');
    } catch (error) { this.showError('receipts-body',4,error); }
  },
  async openReceipt(taskId) {
    try {
      const record = await this.request(`/api/receipts/${encodeURIComponent(taskId)}`);
      this.receipt = record;
      const detail = document.getElementById('receipt-detail');
      detail.hidden = false;
      detail.innerHTML = `<div class="card-head"><div><h2>Receipt ${this.escape(record.id)}</h2><p>Task ${this.escape(record.task_id)}</p></div></div><div class="actions"><button class="button secondary" id="verify-receipt">Verify integrity</button><button class="button secondary" id="export-json">Export JSON</button><button class="button secondary" id="export-md">Export Markdown</button></div><div id="verification-result" class="result" role="status" hidden></div><pre>${this.escape(record.markdown_content || JSON.stringify(record,null,2))}</pre>`;
      detail.scrollIntoView({block:'start',behavior:'smooth'});
    } catch (error) { this.notify(error.message,true); }
  },
  async verifyReceipt() {
    try {
      const result = await this.request(`/api/receipts/${encodeURIComponent(this.receipt.task_id)}/verify`,{method:'POST'});
      const panel = document.getElementById('verification-result'); panel.hidden = false;
      panel.className = `result ${result.is_valid ? 'good' : 'bad'}`;
      panel.textContent = result.is_valid ? 'Stored hashes match. This is not a digital signature.' : `Verification failed: ${result.status}`;
    } catch (error) { this.notify(error.message,true); }
  },
  downloadReceipt(format) {
    if (!this.receipt) return;
    const content = format === 'json' ? JSON.stringify(this.receipt.json_content, null, 2) : this.receipt.markdown_content;
    const blob = new Blob([content], {type: format === 'json' ? 'application/json' : 'text/markdown'});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `receipt_${this.receipt.task_id}.${format === 'json' ? 'json' : 'md'}`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
  async scan() {
    const text = document.getElementById('scan-text').value.trim();
    if (!text) { this.notify('Enter text to inspect.',true); return; }
    const button = document.getElementById('scan-button'); button.disabled = true; button.textContent = 'Scanningâ€¦';
    try {
      const result = await this.request('/api/security/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
      const panel = document.getElementById('scan-result'); panel.hidden = false;
      panel.className = `result ${result.is_safe ? 'good' : 'bad'}`;
      panel.textContent = result.is_safe ? 'No suspicious patterns detected by the current rules.' : `Suspicious context detected. ${result.matched_rules.map(r => r.rule_name).join(', ')}`;
      this.loadEvents(); this.loadOverview();
    } catch (error) { this.notify(error.message,true); }
    finally { button.disabled = false; button.textContent = 'Scan text'; }
  },
  manifest(form) {
    const fields = Object.fromEntries(new FormData(form).entries());
    return {id:fields.id.trim(),name:fields.name.trim(),version:fields.version.trim(),architecture:fields.architecture.trim(),parameters:fields.parameters.trim(),quantization:fields.quantization.trim(),capabilities:fields.capabilities.split(',').map(s=>s.trim()),license:fields.license.trim(),memory_req_mb:Number(fields.memory_req_mb),cpu_cores_req:Number(fields.cpu_cores_req),gpu_vram_req_mb:Number(fields.gpu_vram_req_mb),sha256:fields.sha256.trim()};
  },
  async hashManifest() {
    const form = document.getElementById('model-form');
    const data = this.manifest(form); delete data.sha256;
    const sorted = Object.fromEntries(Object.entries(data).sort(([a],[b])=>a.localeCompare(b)));
    const bytes = new TextEncoder().encode(JSON.stringify(sorted));
    const digest = await crypto.subtle.digest('SHA-256',bytes);
    form.elements.sha256.value = [...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('');
  },
  formError(form,message) { const box = form.querySelector('.form-error'); box.textContent = message; box.hidden = false; box.focus(); },
  async submitForm(form) {
    const isModel = form.getAttribute('id') === 'model-form';
    const endpoint = isModel ? '/api/models/import' : '/api/knowledge/upload';
    const payload = isModel ? this.manifest(form) : Object.fromEntries(new FormData(form).entries());
    const submit = form.querySelector('[type="submit"]'); submit.disabled = true;
    form.querySelector('.form-error').hidden = true;
    try {
      const result = await this.request(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      form.closest('dialog').close(); form.reset();
      this.notify(isModel ? (result.integrity_verified ? 'Manifest saved to quarantine.' : 'Manifest quarantined: checksum mismatch.') : 'Document saved locally.',isModel && !result.integrity_verified);
      if (isModel) this.loadModels(); else this.loadDocuments();
      this.loadOverview();
    } catch (error) {
      const message = error.message.includes('UNIQUE constraint failed') ? 'This ID is already registered. Use a new ID.' : error.message;
      this.formError(form,message);
    } finally { submit.disabled = false; }
  },
  async init() {
    Telemetry.init();
    try {
      const health = await this.request('/health');
      if (health.deployment_mode === 'HOSTED_PREVIEW') {
        this.hostedPreview = true;
        document.getElementById('hosted-preview-notice').hidden = false;
        document.getElementById('connection-status').textContent = 'Hosted preview';
        document.querySelector('.brand small').textContent = 'HOSTED PREVIEW';
        document.querySelector('.sidebar-foot').innerHTML = 'Read-only preview<br><small>Private workspace runs locally</small>';
        for (const button of document.querySelectorAll('[data-open],#scan-button')) {
          button.disabled = true;
          button.title = 'Available in the local workspace';
        }
        document.querySelector('#page-overview .page-heading p').textContent = 'Explore the interface. Private data stays in your local workspace.';
        document.querySelector('#page-overview .hero p').textContent = 'Explore the interface and simulated telemetry. Run Aegis locally to add sources and follow the governed task demonstration.';
      }
    } catch (_) { /* The regular connection indicator reports API failures. */ }
    document.getElementById('document-form').elements.effective_date.value = new Date().toISOString().slice(0,10);
    document.getElementById('nav-toggle').addEventListener('click',()=>document.body.classList.contains('nav-open') ? this.closeNav() : this.openNav());
    document.getElementById('nav-scrim').addEventListener('click',()=>this.closeNav());
    document.getElementById('scan-button').addEventListener('click',()=>this.scan());
    document.getElementById('hash-button').addEventListener('click',()=>this.hashManifest().catch(e=>this.notify(e.message,true)));
    for (const form of document.querySelectorAll('dialog form')) form.addEventListener('submit',event=>{event.preventDefault();this.submitForm(form);});
    document.addEventListener('click',event=>{
      const target = event.target.closest('[data-open],[data-close],[data-goto],[data-receipt],[data-guide],[data-guide-goto],[data-audit],#verify-receipt,#export-json,#export-md');
      if (!target) return;
      if (target.disabled) return;
      if (target.hasAttribute('data-guide')) this.openDialog('guide-dialog');
      if (target.dataset.guideGoto) { this.closeDialog(); location.hash = target.dataset.guideGoto; }
      if (target.hasAttribute('data-audit')) { Control.selectTab('audit'); location.hash = 'control'; }
      if (target.dataset.open) this.openDialog(target.dataset.open);
      if (target.hasAttribute('data-close')) this.closeDialog();
      if (target.dataset.goto) location.hash = target.dataset.goto;
      if (target.dataset.receipt) this.openReceipt(target.dataset.receipt);
      if (target.id === 'verify-receipt') this.verifyReceipt();
      if (target.id === 'export-json') this.downloadReceipt('json');
      if (target.id === 'export-md') this.downloadReceipt('markdown');
    });
    document.addEventListener('input',event=>{if(event.target.matches('[data-search]')) this.filter(event.target);});
    document.addEventListener('keydown',event=>{
      if (!document.body.classList.contains('nav-open')) return;
      if (event.key==='Escape') { this.closeNav(); document.getElementById('nav-toggle').focus(); }
      if (event.key==='Tab') {
        const links = [...document.querySelectorAll('#sidebar a,#sidebar button')];
        const current = links.indexOf(document.activeElement);
        event.preventDefault();
        links[(current + (event.shiftKey ? -1 : 1) + links.length) % links.length].focus();
      }
    });
    window.addEventListener('resize',()=>{if(window.innerWidth>750) this.closeNav();});
    window.addEventListener('hashchange',()=>this.navigate(location.hash.slice(1)));
    this.navigate(location.hash.slice(1));
    setInterval(()=>{if(this.page==='overview'||this.page==='system') this.loadOverview(); if(this.page==='control'&&Control.state&&!Control.busy) Control.renderGuide();},30000);
  }
};
document.addEventListener('DOMContentLoaded',()=>App.init());
