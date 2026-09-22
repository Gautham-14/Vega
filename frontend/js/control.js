/* Opt-in local prototype controls. Every decision is made by the server. */
App.labels.control = 'Control plane';
const Control = {
  state: null,
  busy: false,
  loadId: 0,
  next: null,
  selectTab(name, focus = false) {
    for (const tab of document.querySelectorAll('[data-control-tab]')) {
      const selected = tab.dataset.controlTab === name;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      document.getElementById(tab.getAttribute('aria-controls')).hidden = !selected;
      if (selected && focus) tab.focus();
    }
  },
  guide(state, now = Date.now() / 1000) {
    const {demo, packages, capsules, approvals, leases} = state;
    if (!demo) return {title:'Prepare a sample workflow', copy:'Start as Operator to create the synthetic source and request approvals.', role:'operator', target:'#control-prepare', tab:'setup'};
    const packageRecord = packages.find(item=>item.id===demo.package_id);
    const capsule = capsules.find(item=>item.id===demo.capsule_id);
    const requests = demo.approval_ids.map(id=>approvals.find(item=>item.id===id)).filter(item=>
      !item || (item.action==='package' ? packageRecord?.status : capsule?.status)!=='APPROVED');
    const active = packageRecord?.status==='APPROVED' && capsule?.status==='APPROVED';
    if (!active) {
      if (requests.some(item=>!item || item.status==='REJECTED' || item.expires_at<=now)) {
        return {title:'Renew the approval requests', copy:'Return to Operator and prepare the demo again to renew expired or rejected requests.', role:'operator', target:'#control-prepare', tab:'setup'};
      }
      for (const [role, label] of [['model-custodian','Model Custodian'],['security-officer','Security Officer']]) {
        if (requests.some(item=>item.status!=='APPROVED' && !item.decisions.some(decision=>decision.actor===role && decision.decision==='APPROVE'))) {
          return {title:`Review approvals as ${label}`, copy:'Review the package and Capsule requests below. Approve each to continue the demonstration.', role, target:'#control-approvals button:not(:disabled)', tab:'setup'};
        }
      }
      return {title:'Activate your approved stack', copy:'Both roles have approved. The Model Custodian can now activate the package and Capsule.', role:'model-custodian', target:'#control-activate', tab:'setup'};
    }
    const lease = leases.find(item=>item.id===demo.lease_id);
    if (!lease || lease.expires_at<=now) return {title:lease ? 'Renew the purpose lease' : 'Issue a purpose lease', copy:'Switch to Data Owner to grant 15 minutes of access for the inspection review.', role:'data-owner', target:'#control-lease', tab:'setup'};
    if (state.tasks?.some(task=>task.lease_id===demo.lease_id && task.capsule_id===demo.capsule_id && task.status==='COMPLETED')) {
      return {title:'Task complete. Review the audit trail.', copy:'Verify the receipt chain or expand governance records to inspect the completed task.', role:'operator', target:'#control-verify', tab:'audit'};
    }
    return {title:'You are ready to run', copy:'Switch to Operator and run the protected task. Your output will include source evidence and disclosure decisions.', role:'operator', target:'[data-scenario="success"]', tab:'run'};
  },
  renderGuide() {
    this.next = this.guide(this.state);
    if (this.next.target==='#control-lease') {
      for (const scenario of ['success','wrong-purpose','tripwire']) document.querySelector(`[data-scenario="${scenario}"]`).disabled = true;
    }
    document.getElementById('control-next-title').textContent = this.next.title;
    document.getElementById('control-next-copy').textContent = this.next.copy;
    const button = document.getElementById('control-next');
    button.disabled = this.busy;
    button.textContent = this.actor()===this.next.role ? ({run:'Go to task',audit:'Go to audit',setup:'Show action'}[this.next.tab]) : `Switch to ${this.state.actors[this.next.role].role}`;
  },
  async followGuide() {
    const next = this.next;
    if (!next || this.busy) return;
    document.getElementById('control-persona').value = next.role;
    this.selectTab(next.tab);
    await this.load();
    const target = document.querySelector(next.target);
    target?.scrollIntoView({block:'center',behavior:'smooth'});
    target?.focus({preventScroll:true});
  },
  actor() { return document.getElementById('control-persona').value; },
  request(path, body) {
    return App.request(`/api/control${path}`, {method: body === undefined ? 'GET' : 'POST',
      headers: {'Content-Type':'application/json', 'X-Aegis-Actor': this.actor()},
      ...(body === undefined ? {} : {body: JSON.stringify(body)})});
  },
  async perform(button, action) {
    if (this.busy) return;
    this.busy = true;
    const content = button.innerHTML;
    for (const control of document.querySelectorAll('#page-control button:not([data-control-tab]),#control-persona')) control.disabled = true;
    button.textContent = 'Workingâ€¦';
    try { await action(); }
    catch (error) { App.notify(error.message, true); }
    finally {
      button.innerHTML = content;
      this.busy = false;
      for (const id of ['control-persona','control-refresh','control-verify','control-self-test']) document.getElementById(id).disabled = false;
      for (const guide of document.querySelectorAll('#page-control [data-guide]')) guide.disabled = false;
      await this.load();
    }
  },
  async load() {
    const loadId = ++this.loadId;
    for (const button of document.querySelectorAll('#control-prepare,#control-activate,#control-lease,#control-next,[data-scenario],#control-approvals button')) button.disabled = true;
    try {
      const status = await App.request('/api/control/status');
      if (loadId!==this.loadId) return;
      const enabled = status.enabled && !App.hostedPreview;
      document.getElementById('control-disabled').hidden = enabled;
      document.getElementById('control-enabled').hidden = !enabled;
      if (!enabled) {
        document.getElementById('control-disabled-copy').textContent = App.hostedPreview ? 'This hosted preview is read-only. Run Aegis locally with demo mode to use approvals and protected tasks.' : 'Run Aegis with demo mode enabled to prepare and approve a synthetic task.';
        return;
      }
      const state = await this.request('/state');
      if (loadId!==this.loadId) return;
      this.state = state;
      document.getElementById('connection-status').textContent = 'Runtime connected';
      document.getElementById('connection-dot').classList.remove('offline');
      const {demo, packages, capsules, leases, approvals, chain} = this.state;
      const packageRecord = packages.find(p => p.id === demo?.package_id);
      const capsule = capsules.find(c => c.id === demo?.capsule_id);
      const lease = leases.find(l => l.id === demo?.lease_id);
      const leaseStatus = lease ? (lease.expires_at * 1000 > Date.now() ? `Active until ${new Date(lease.expires_at * 1000).toLocaleTimeString()}` : 'Expired â€” renew as Data Owner') : 'Not issued';
      document.getElementById('control-prepare').disabled = this.actor() !== 'operator';
      document.getElementById('control-activate').disabled = this.actor() !== 'model-custodian' || !demo || !demo.approval_ids.every(id => approvals.some(a=>a.id === id && a.status === 'APPROVED'));
      document.getElementById('control-lease').disabled = this.actor() !== 'data-owner' || capsule?.status !== 'APPROVED';
      for (const button of document.querySelectorAll('[data-scenario]')) button.disabled = this.actor() !== 'operator' || !demo || ((!lease || lease.expires_at * 1000 <= Date.now() || capsule?.status !== 'APPROVED' || packageRecord?.status !== 'APPROVED') && ['success','wrong-purpose','tripwire'].includes(button.dataset.scenario));
      document.getElementById('control-readiness').textContent = demo ? `Package: ${packageRecord?.status} Â· Capsule: ${capsule?.status} Â· Lease: ${leaseStatus}` : 'No synthetic fixture prepared. Select Operator, then Prepare demo.';
      const escape = App.escape;
      document.getElementById('control-approvals').innerHTML = approvals.length ? approvals.map(a => {
        const role = this.state.actors[this.actor()]?.role;
        const eligible = a.status === 'PENDING' && a.expires_at * 1000 > Date.now() && a.requester !== this.actor() && a.required_roles.includes(role) && !a.decisions.some(d => d.actor === this.actor());
        return `<tr><td data-label="Action"><strong>${escape(App.pretty(a.action))}</strong><small>${escape(a.id.slice(0,16))}</small></td><td data-label="Status"><span class="badge ${a.status==='REJECTED' ? 'bad' : a.status==='PENDING' ? 'simulated-badge' : ''}">${escape(a.status)}</span></td><td data-label="Approvals">${escape(a.decisions.map(d=>`${d.role}: ${d.decision}`).join(' Â· ') || 'Awaiting two distinct roles')}</td><td data-label="Decision"><button class="button secondary small" data-approval="${escape(a.id)}" data-decision="APPROVE" ${eligible ? '' : 'disabled'}>Approve</button> <button class="button secondary small" data-approval="${escape(a.id)}" data-decision="REJECT" ${eligible ? '' : 'disabled'}>Reject</button></td></tr>`;
      }).join('') : '<tr><td colspan="4" class="empty">No approvals requested.</td></tr>';
      this.renderChain(chain);
      document.getElementById('control-records').innerHTML = ['capsules','packages','sources','leases','tasks','artifacts','receipts'].map(kind => `<details><summary>${escape(App.pretty(kind))} Â· ${this.state[kind].length}</summary><pre>${escape(JSON.stringify(this.state[kind],null,2))}</pre></details>`).join('');
      this.renderGuide();
      if (this.busy) for (const button of document.querySelectorAll('#page-control button:not([data-control-tab])')) button.disabled = true;
    } catch (error) { App.notify(error.message, true); }
  },
  renderChain(value) {
    const panel = document.getElementById('control-chain');
    panel.className = `result ${value.is_valid ? 'good' : 'bad'}`;
    panel.textContent = `${value.status} Â· ${value.count} chained receipts. Local software trust anchor.`;
  },
  showResult(value) {
    const escape = App.escape;
    const exported = value.export;
    const title = value.status || exported?.decision || 'Result';
    const summary = [value.reason, value.changed_components ? `Changed: ${value.changed_components.join(', ')}` : exported?.decision].filter(Boolean).join(' Â· ');
    document.getElementById('control-result').innerHTML = `<div class="result ${value.status === 'COMPLETED' ? 'good' : ''}"><strong>${escape(title)}</strong> ${escape(summary)}</div>${value.steps ? `<ol class="control-steps">${value.steps.map(s=>`<li><strong>${escape(App.pretty(s.step))}</strong><small>${escape(s.status || s.workspace || s.mode || s.route || '')}</small></li>`).join('')}</ol>` : ''}${exported?.text ? `<h3>Approved deliverable</h3><pre>${escape(exported.text)}</pre>` : '<p class="body-copy">No protected deliverable was released.</p>'}<details><summary>Inspect decision and receipt</summary><pre>${escape(JSON.stringify(value,null,2))}</pre></details>`;
  },
  init() {
    document.querySelector('.workflow-tabs').addEventListener('keydown',event=>{
      if (!['ArrowRight','ArrowLeft','Home','End'].includes(event.key)) return;
      const tabs = [...document.querySelectorAll('[data-control-tab]')];
      const index = tabs.indexOf(event.target);
      if (index<0) return;
      event.preventDefault();
      const next = event.key==='Home' ? 0 : event.key==='End' ? tabs.length-1 : (index + (event.key==='ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      this.selectTab(tabs[next].dataset.controlTab, true);
    });
    document.getElementById('control-persona').addEventListener('change',()=>this.load());
    document.getElementById('page-control').addEventListener('click',event=>{
      const button = event.target.closest('button');
      if (!button || button.disabled) return;
      if (button.dataset.controlTab) { this.selectTab(button.dataset.controlTab); return; }
      if (button.id==='control-next') { this.followGuide(); return; }
      const paths = {'control-prepare':'/demo/prepare','control-activate':'/demo/activate','control-lease':'/demo/lease'};
      if (paths[button.id]) this.perform(button,async()=>{await this.request(paths[button.id],{}); App.notify('Governance state updated.');});
      else if (button.dataset.approval) this.perform(button,()=>this.request(`/approvals/${encodeURIComponent(button.dataset.approval)}/decide`,{decision:button.dataset.decision}));
      else if (button.dataset.scenario) this.perform(button,async()=>this.showResult(await this.request('/demo/run',{scenario:button.dataset.scenario})));
      else if (button.id === 'control-refresh') this.load();
      else if (button.id === 'control-verify') this.perform(button,async()=>this.renderChain(await this.request('/receipts/verify')));
      else if (button.id === 'control-self-test') this.perform(button,async()=>{
        const result = await this.request('/self-test',{});
        document.getElementById('control-tests').innerHTML = `<h3>${result.tests_passed} / ${result.tests_total} passed</h3><ul>${result.tests.map(t=>`<li><strong>${App.escape(t.status)}</strong> ${App.escape(t.name)}</li>`).join('')}</ul>`;
      });
    });
  }
};
document.addEventListener('DOMContentLoaded',()=>Control.init());
