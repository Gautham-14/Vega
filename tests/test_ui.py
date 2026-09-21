"""Check time-sensitive next-step guidance without a browser dependency."""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_guide_tracks_approvals_activation_and_lease_expiry():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is optional for frontend checks")
    script = r'''
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const context = vm.createContext({App:{labels:{}},document:{addEventListener(){}}});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8') + '\n globalThis.control = Control;', context);
const guide = state => context.control.guide(state, 1000);
const state = {demo:null,packages:[],capsules:[],leases:[],approvals:[]};
assert.equal(guide(state).target, '#control-prepare');
state.demo = {package_id:'P',capsule_id:'C',approval_ids:['AP','AC']};
state.packages = [{id:'P',status:'QUALIFIED'}];
state.capsules = [{id:'C',status:'UNAPPROVED'}];
state.approvals = ['package','capsule'].map((action,i)=>({id:i?'AC':'AP',action,status:'PENDING',expires_at:1200,decisions:[]}));
assert.equal(guide(state).role, 'model-custodian');
state.approvals[0].decisions.push({actor:'model-custodian',decision:'APPROVE'});
assert.equal(guide(state).role, 'model-custodian');
state.approvals[1].decisions.push({actor:'model-custodian',decision:'APPROVE'});
assert.equal(guide(state).role, 'security-officer');
state.approvals.forEach(a=>a.status='APPROVED');
assert.equal(guide(state).target, '#control-activate');
state.approvals[0].expires_at = 999;
assert.equal(guide(state).target, '#control-prepare');
// A previously activated package does not need its old approval renewed.
state.packages[0].status = 'APPROVED';
assert.equal(guide(state).target, '#control-activate');
state.capsules[0].status = 'APPROVED';
assert.equal(guide(state).target, '#control-lease');
state.demo.lease_id = 'L';
state.leases = [{id:'L',expires_at:1001}];
assert.equal(guide(state).tab, 'run');
state.tasks = [{lease_id:'old',capsule_id:'C',status:'COMPLETED'}];
assert.equal(guide(state).tab, 'run');
state.tasks.push({lease_id:'L',capsule_id:'C',status:'COMPLETED'});
assert.equal(guide(state).tab, 'audit');
state.leases[0].expires_at = 1000;
assert.equal(guide(state).role, 'data-owner');
assert.equal(guide(state).tab, 'setup');
'''
    source = Path(__file__).resolve().parents[1] / "frontend/js/control.js"
    subprocess.run([node, "-e", script, str(source)], check=True, capture_output=True, text=True, timeout=15)
