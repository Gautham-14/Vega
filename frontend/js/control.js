/* Opt-in local prototype controls. Every decision is made by the server. */
App.labels.control = 'Sovereign control plane';
const Control = {
  state: null,
  actor() { return document.getElementById('control-persona').value; },
  request(path, body) {
    return App.request(`/api/control${path}`, {method: body === undefined ? 'GET' : 'POST',
      headers: {'Content-Type':'application/json', 'X-Vega-Actor': this.actor()},
      ...(body === undefined ? {} : {body: JSON.stringify(body)})});
  },
  async perform(button, action) {
    const text = button.textContent; button.disabled = true; button.textContent = 'Working…';
    try { await action(); }
    catch (error) { App.notify(error.message, true); }
    finally { button.disabled = false; button.textContent = text; await this.load(); }
  },
  async load() {
    try {
      const status = await App.request('/api/control/status');
      const enabled = status.enabled && !App.hostedPreview;
      document.getElementById('control-disabled').hidden = enabled;
      document.getElementById('control-enabled').hidden = !enabled;
      if (!enabled) return;
      this.state = await this.request('/state');
      document.getElementById('connection-status').textContent = 'Runtime connected';
      document.getElementById('connection-dot').classList.remove('offline');
      const {demo, packages, capsules, leases, approvals, chain} = this.state;
      const packageRecord = packages.find(p => p.id === demo?.package_id);
      const capsule = capsules.find(c => c.id === demo?.capsule_id);
      const lease = leases.find(l => l.id === demo?.lease_id);
      const leaseStatus = lease ? (lease.expires_at * 1000 > Date.now() ? `Active until ${new Date(lease.expires_at * 1000).toLocaleTimeString()}` : 'Expired — renew as Data Owner') : 'Not issued';
      document.getElementById('control-prepare').disabled = this.actor() !== 'operator';
      document.getElementById('control-activate').disabled = this.actor() !== 'model-custodian' || !demo || !demo.approval_ids.every(id => approvals.some(a=>a.id === id && a.status === 'APPROVED'));
      document.getElementById('control-lease').disabled = this.actor() !== 'data-owner' || capsule?.status !== 'APPROVED';
      for (const button of document.querySelectorAll('[data-scenario]')) button.disabled = this.actor() !== 'operator' || !demo || (!lease && ['success','wrong-purpose','tripwire'].includes(button.dataset.scenario));
      document.getElementById('control-readiness').textContent = demo ? `Package: ${packageRecord?.status} · Capsule: ${capsule?.status} · Lease: ${leaseStatus}` : 'No synthetic fixture prepared. Select Operator, then Prepare demo.';
      const escape = App.escape;
      document.getElementById('control-approvals').innerHTML = approvals.length ? approvals.map(a => {
        const role = this.state.actors[this.actor()]?.role;
        const eligible = a.status === 'PENDING' && a.expires_at * 1000 > Date.now() && a.requester !== this.actor() && a.required_roles.includes(role) && !a.decisions.some(d => d.actor === this.actor());
        return `<tr><td>${escape(App.pretty(a.action))}<small>${escape(a.id.slice(0,16))}</small></td><td>${escape(a.status)}</td><td>${escape(a.decisions.map(d=>`${d.role}: ${d.decision}`).join(' · ') || 'Awaiting two distinct roles')}</td><td><button class="button secondary small" data-approval="${escape(a.id)}" data-decision="APPROVE" ${eligible ? '' : 'disabled'}>Approve</button> <button class="button secondary small" data-approval="${escape(a.id)}" data-decision="REJECT" ${eligible ? '' : 'disabled'}>Reject</button></td></tr>`;
      }).join('') : '<tr><td colspan="4" class="empty">No approvals requested.</td></tr>';
      this.renderChain(chain);
      document.getElementById('control-records').innerHTML = ['capsules','packages','sources','leases','tasks','artifacts','receipts'].map(kind => `<details><summary>${escape(App.pretty(kind))} · ${this.state[kind].length}</summary><pre>${escape(JSON.stringify(this.state[kind],null,2))}</pre></details>`).join('');
    } catch (error) { App.notify(error.message, true); }
  },
  renderChain(value) {
    const panel = document.getElementById('control-chain');
    panel.className = `result ${value.is_valid ? 'good' : 'bad'}`;
    panel.textContent = `${value.status} · ${value.count} chained receipts. Local software trust anchor.`;
  },
  showResult(value) {
    const escape = App.escape;
    const exported = value.export;
    const title = value.status || exported?.decision || 'Result';
    const summary = [value.reason, value.changed_components ? `Changed: ${value.changed_components.join(', ')}` : exported?.decision].filter(Boolean).join(' · ');
    document.getElementById('control-result').innerHTML = `<div class="result ${value.status === 'COMPLETED' ? 'good' : ''}"><strong>${escape(title)}</strong> ${escape(summary)}</div>${value.steps ? `<ol class="control-steps">${value.steps.map(s=>`<li><strong>${escape(App.pretty(s.step))}</strong><small>${escape(s.status || s.workspace || s.mode || s.route || '')}</small></li>`).join('')}</ol>` : ''}${exported?.text ? `<h3>Approved deliverable</h3><pre>${escape(exported.text)}</pre>` : '<p class="body-copy">No protected deliverable was released.</p>'}<details><summary>Inspect decision and receipt</summary><pre>${escape(JSON.stringify(value,null,2))}</pre></details>`;
  },
  init() {
    document.getElementById('control-persona').addEventListener('change',()=>this.load());
    document.getElementById('page-control').addEventListener('click',event=>{
      const button = event.target.closest('button');
      if (!button || button.disabled) return;
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
