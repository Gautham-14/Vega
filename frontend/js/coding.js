/* Server-enforced coding authority; this UI never executes generated source. */
App.labels.coding = 'Coding workbench';
const Coding = {
  state: null, busy: false, task: null, loadId: 0, nextExpiry: Infinity, reviewExpires: 0,
  el(id) { return document.getElementById(`coding-${id}`); },
  actor() { return this.el('persona').value; },
  request(path, body, control = false) {
    return App.request(`/api/${control ? 'control' : 'coding'}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: {'Content-Type':'application/json','X-Aegis-Actor':this.actor()},
      ...(body === undefined ? {} : {body:JSON.stringify(body)})
    });
  },
  options(id, rows, label) {
    const el = this.el(id), selected = el.value;
    el.innerHTML = rows.length ? rows.map(r=>`<option value="${App.escape(r.id)}">${App.escape(label(r))}</option>`).join('') : '<option value="">None available</option>';
    if (rows.some(r=>r.id===selected)) el.value = selected;
  },
  async load() {
    const generation = ++this.loadId;
    try {
      const status = await App.request('/api/coding/status');
      if (generation !== this.loadId) return;
      const enabled = status.enabled && !App.hostedPreview;
      this.el('disabled').hidden = enabled; this.el('workspace').hidden = !enabled;
      if (!enabled) return;
      const state = await this.request('/state');
      if (generation !== this.loadId) return;
      this.state = state; this.render();
    } catch (error) { App.notify(error.message, true); }
  },
  render() {
    const e = App.escape, s = this.state, now = Date.now()/1000;
    this.nextExpiry = Math.min(...[...s.leases,...s.approvals,this.task].filter(Boolean).map(v=>v.expires_at).filter(t=>t>now));
    const expanded = new Set([...this.el('workspace').querySelectorAll('details[open] > summary')].map(el=>el.textContent));
    const persona = this.actor(), role = s.actors[persona].role;
    this.options('repository',s.repositories,r=>`${r.name} · ${r.file_count} files · ${r.label.compartments.join(', ')}`);
    this.options('capsule',s.capsules.filter(c=>c.status==='APPROVED'),c=>`${c.components.model.provider} · ${c.id.slice(-10)}`);
    this.options('active-lease',s.leases.filter(l=>l.user===persona && !l.revoked && l.expires_at>now),l=>`${l.mode} · ${l.purpose} · expires ${new Date(l.expires_at*1000).toLocaleTimeString()}`);
    const approved = s.capsules.some(c=>c.status==='APPROVED');
    this.el('next').textContent = !approved ? 'Approve the stack before accessing code.' : !s.repositories.length ? 'Import a repository snapshot as Data Owner.' : !this.el('active-lease').value ? 'Issue a lease, then switch to its recipient.' : 'Ready to run under the selected purpose lease.';
    this.el('next-copy').textContent = `Active role: ${role}. Every action is checked again by the server.`;
    this.el('stacks').innerHTML = s.capsules.map(c=>`<details class="coding-record"><summary>${e(c.components.model.provider)} · ${e(c.status)} · ${e(c.id.slice(-10))}</summary><pre class="coding-code">${e(JSON.stringify(c.components,null,2))}</pre></details>`).join('');
    this.el('approvals').innerHTML = s.approvals.map(a=>{
      const active = a.expires_at>now, eligible = active && a.status==='PENDING' && a.required_roles.includes(role) && a.requester!==persona && !a.decisions.some(d=>d.actor===persona);
      const canActivate = a.capsule_id && active && a.status==='APPROVED' && role==='Model Custodian' && s.capsules.find(c=>c.id===a.capsule_id)?.status!=='APPROVED';
      return `<div class="coding-record"><strong>${a.capsule_id ? 'Capsule approval' : 'Patch export approval'}</strong><p>${e(a.status)} · ${active ? 'Active' : 'Expired'} · ${e(a.id.slice(-10))}</p><small>${e(a.decisions.map(d=>`${d.role}: ${d.decision}`).join(' · ') || 'Awaiting two reviewers')}</small><div class="actions">${a.task_id && ['Data Owner','Security Officer'].includes(role) ? `<button class="button subtle" data-coding-review="${e(a.id)}">Inspect export diff</button>` : ''}<button class="button secondary" data-coding-decide="${e(a.id)}" data-decision="APPROVE" ${eligible ? '' : 'disabled'}>Approve</button><button class="button subtle" data-coding-decide="${e(a.id)}" data-decision="REJECT" ${eligible ? '' : 'disabled'}>Reject</button>${canActivate ? `<button class="button primary" data-coding-activate="${e(a.capsule_id)}" data-approval="${e(a.id)}">Activate Capsule</button>` : ''}</div></div>`;
    }).join('') || '<p class="body-copy">No coding approvals yet.</p>';
    this.el('leases').innerHTML = s.leases.map(l=>`<div class="coding-record"><strong>${e(l.mode)} · ${e(l.user)}</strong><p>${e(l.purpose)} · ${l.revoked ? 'Revoked' : l.expires_at<=now ? 'Expired' : `Expires ${e(new Date(l.expires_at*1000).toLocaleTimeString())}`}</p>${role==='Data Owner' && !l.revoked ? `<button class="button subtle" data-coding-revoke="${e(l.id)}">Revoke lease and remove its task content</button>` : ''}</div>`).join('');
    this.el('history').innerHTML = s.tasks.length ? `<details class="coding-record"><summary>Task history (${s.tasks.length})</summary>${s.tasks.map(t=>`<button class="button subtle" data-coding-task="${e(t.id)}">${e(t.status)} · ${e(t.id.slice(-10))}</button>`).join('')}</details>` : '';
    this.el('register').disabled = this.busy || role!=='Operator';
    for (const control of this.el('import').querySelectorAll('button,input,select')) control.disabled = this.busy || role!=='Data Owner';
    for (const control of this.el('lease').querySelectorAll('button,input,select')) control.disabled = this.busy || role!=='Data Owner';
    this.el('run').querySelector('button').disabled = this.busy || !this.el('active-lease').value;
    if (this.task) this.renderTask(this.task);
    for (const summary of this.el('workspace').querySelectorAll('details > summary')) {
      if (expanded.has(summary.textContent)) summary.parentElement.open = true;
    }
  },
  tick(now = Date.now()/1000) {
    // Leave forms, focus, disclosure panels and code selection alone between expiries.
    if (this.reviewExpires && now>=this.reviewExpires) {
      this.el('review').textContent=''; this.el('review').hidden=true; this.reviewExpires=0;
    }
    if (this.task?.expires_at<=now && (this.task.diff || this.task.messages)) this.renderTask(this.task);
    if (!this.busy && this.state && now>=this.nextExpiry) this.render();
  },
  renderTask(task) {
    this.task = task;
    const e = App.escape, s = this.state;
    const expired = task.expires_at && task.expires_at<=Date.now()/1000;
    const lease = s.leases.find(l=>l.id===task.lease_id);
    const live = !expired && !lease?.revoked && !['CLOSED','EXPIRED','REVOKED','BLOCKED','FAILED'].includes(task.status);
    if (!live) { delete task.messages; delete task.diff; }
    const approvals = s.approvals.filter(a=>a.task_id===task.id && a.status==='APPROVED' && a.expires_at>Date.now()/1000);
    this.el('result').innerHTML = `<div class="coding-result-head"><h3>${e(expired ? 'EXPIRED' : lease?.revoked ? 'REVOKED' : task.status)}</h3><span class="badge">${e(task.provider || 'Policy gate')}</span></div>${task.reason ? `<p role="alert">${e(task.reason)}</p>` : ''}${(task.messages||[]).map(m=>`<p class="coding-message">${e(m)}</p>`).join('')}${task.quarantined_files ? `<p class="notice">${e(task.quarantined_files)} file(s) withheld by the context firewall.</p>` : ''}${live && task.diff ? `<h3>Review proposed diff</h3><pre class="coding-code" tabindex="0">${e(task.diff)}</pre>` : ''}<p class="form-help">Tests: ${e(task.tests)}. Original checkout modified: ${e(task.host_checkout_modified)}.</p><div class="actions">${live && task.status==='AWAITING_REVIEW' ? '<button class="button primary" id="coding-apply">Apply reviewed diff to task snapshot</button>' : ''}${live && task.status==='APPLIED' && lease?.allow_export ? '<button class="button secondary" id="coding-request-export">Request patch download approval</button>' : ''}${live && task.status==='APPLIED' && approvals.length ? `<button class="button secondary" id="coding-download" data-approval="${e(approvals.at(-1).id)}">Download approved patch</button>` : ''}${live ? '<button class="button subtle" id="coding-close">Close task and remove retained content</button>' : ''}</div><details class="coding-record"><summary>Tool decisions and receipt evidence</summary><pre class="coding-code">${e(JSON.stringify({task_id:task.id,trace:task.trace,hygiene:task.hygiene,chain:s.chain,local_model_calls:task.local_model_calls},null,2))}</pre></details>`;
  },
  async perform(action) {
    if (this.busy) return;
    this.busy = true;
    for (const el of this.el('workspace').querySelectorAll('button,input,textarea,select')) el.disabled = true;
    this.el('refresh').disabled = true;
    this.el('next-copy').textContent = 'Working. Local inference can take a minute per turn.';
    try { await action(); }
    catch (error) { App.notify(error.message,true); }
    finally {
      this.busy = false;
      for (const el of this.el('workspace').querySelectorAll('button,input,textarea,select')) el.disabled = false;
      this.el('refresh').disabled = false;
      await this.load();
    }
  },
  async importFiles() {
    const selected = [...this.el('files').files], files = Object.create(null);
    if (!selected.length || selected.length>64 || selected.reduce((n,f)=>n+f.size,0)>512000) throw new Error('Select 1-64 text files totaling at most 512 KB.');
    for (const file of selected) {
      if (file.size>128000) throw new Error('Each file must be at most 128 KB.');
      if (Object.hasOwn(files,file.name)) throw new Error('Duplicate filenames: import a snapshot with unique root filenames.');
      files[file.name] = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());
    }
    await this.request('/repositories',{name:this.el('repo-name').value,files,compartment:this.el('compartment').value,classification:'INTERNAL'});
    this.el('files').value = ''; App.notify('Encrypted snapshot imported.');
  },
  async validate() {
    this.el('validation').textContent = 'Running isolated adversarial checks…';
    try {
      const result = await this.request('/validation',{});
      this.el('validation').innerHTML = `<h3>${result.tests_passed}/${result.tests_total} checks passed</h3><div class="coding-test-grid">${result.tests.map(t=>`<div class="coding-record"><strong>${App.escape(t.status)}</strong> ${App.escape(t.name)}<small>${App.escape(t.security_event)}</small></div>`).join('')}</div><p class="body-copy">Not verified: ${App.escape(result.not_verified.join(', '))}.</p>`;
    } catch(error) { this.el('validation').textContent = 'Validation did not complete.'; throw error; }
  },
  init() {
    this.el('persona').addEventListener('change',()=>{this.task=null; this.el('result').replaceChildren(); this.el('review').hidden=true; this.el('review').textContent=''; this.reviewExpires=0; this.load();});
    this.el('refresh').addEventListener('click',()=>this.load());
    this.el('import').addEventListener('submit',event=>{event.preventDefault();this.perform(()=>this.importFiles());});
    this.el('lease').addEventListener('submit',event=>{event.preventDefault();this.perform(()=>this.request('/leases',{repository_id:this.el('repository').value,capsule_id:this.el('capsule').value,user:this.el('user').value,mode:this.el('mode').value,minutes:15,allow_export:this.el('export-permission').checked}));});
    this.el('run').addEventListener('submit',event=>{event.preventDefault();const lease=this.state.leases.find(l=>l.id===this.el('active-lease').value);if(lease)this.perform(async()=>{this.task=await this.request('/tasks',{lease_id:lease.id,purpose:lease.purpose,prompt:this.el('prompt').value});});});
    this.el('workspace').addEventListener('click',event=>{
      const b=event.target.closest('button'); if(!b || b.disabled)return;
      if(b.id==='coding-register')this.perform(()=>this.request('/capsules',{provider:this.el('provider').value}));
      if(b.id==='coding-sample')this.perform(()=>this.request('/demo/repository',{}));
      if(b.id==='coding-validate')this.perform(()=>this.validate());
      if(b.dataset.codingDecide)this.perform(()=>this.request(`/approvals/${b.dataset.codingDecide}/decide`,{decision:b.dataset.decision},true));
      if(b.dataset.codingActivate)this.perform(()=>this.request(`/capsules/${b.dataset.codingActivate}/approve`,{approval_id:b.dataset.approval},true));
      if(b.dataset.codingRevoke)this.perform(()=>this.request(`/leases/${b.dataset.codingRevoke}/revoke`,{}));
      if(b.dataset.codingReview)this.perform(async()=>{const r=await this.request(`/approvals/${b.dataset.codingReview}/review`);this.el('review').textContent=r.diff;this.el('review').hidden=false;this.reviewExpires=r.expires_at;});
      if(b.dataset.codingTask)this.perform(async()=>{this.task=await this.request(`/tasks/${b.dataset.codingTask}`);});
      if(b.id==='coding-apply')this.perform(async()=>{this.task=await this.request(`/tasks/${this.task.id}/apply`,{diff_hash:this.task.diff_hash});});
      if(b.id==='coding-close')this.perform(async()=>{this.task=await this.request(`/tasks/${this.task.id}/close`,{});});
      if(b.id==='coding-request-export')this.perform(()=>this.request(`/tasks/${this.task.id}/export-request`,{}));
      if(b.id==='coding-download')this.perform(async()=>{const r=await this.request(`/tasks/${this.task.id}/export`,{approval_id:b.dataset.approval});const url=URL.createObjectURL(new Blob([r.patch],{type:'text/x-diff;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download=r.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
    });
    setInterval(()=>this.tick(),1000);
  }
};
document.addEventListener('DOMContentLoaded',()=>Coding.init());
