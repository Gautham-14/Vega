"""Telemetry must contain measurements and scoped metadata, never task content."""
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis import telemetry
from aegis.api.routes import auth as auth_routes
from aegis.api.routes.telemetry import router
from aegis.coding import service
from aegis.control import store
from aegis.security import auth
from aegis.storage.database import init_db


@pytest.fixture
def client():
    init_db()
    store.init_control()
    auth.init_auth()
    telemetry.init_telemetry()
    app = FastAPI()
    app.include_router(router)
    app.include_router(auth_routes.router)
    with TestClient(app) as connection:
        yield connection


def test_measured_samples_history_and_limits(client):
    latest = client.get('/api/telemetry/latest').json()
    assert latest['source'] == 'HOST_MEASURED'
    assert latest['gpu_percent'] is None
    assert latest['memory_total_bytes'] > 0
    assert latest['process_rss_bytes'] > 0
    assert 0 <= latest['cpu_percent'] <= 100
    assert latest['stale'] is False
    history = client.get('/api/telemetry/history?limit=1').json()
    assert len(history) == 1 and history[0]['timestamp'] == latest['timestamp']
    for limit in (0, 1201, 'invalid'):
        assert client.get(f'/api/telemetry/history?limit={limit}').status_code == 422


def test_latest_marks_old_sample_stale(client, monkeypatch):
    old = telemetry.sample()
    old['timestamp'] = time.time() - 100
    monkeypatch.setattr(telemetry, 'history', lambda limit: [old])
    assert client.get('/api/telemetry/latest').json()['stale'] is True


def test_telemetry_requires_auth_and_cookie_login_logout(client, monkeypatch):
    monkeypatch.setenv('AEGIS_ENABLE_DEMO_ENDPOINTS', '0')
    for path in ('latest', 'history', 'events', 'workspace'):
        assert client.get('/api/telemetry/' + path).status_code == 401
    auth.provision('operator', 'correct-secret-password')
    assert client.post('/api/auth/login', json={'username':'operator','password':'wrong'}).status_code == 401
    login = client.post('/api/auth/login', json={'username':'operator','password':'correct-secret-password'})
    assert login.status_code == 200
    assert 'HttpOnly' in login.headers['set-cookie']
    assert client.get('/api/auth/me').json()['id'] == 'operator'
    assert client.get('/api/telemetry/latest').status_code == 200
    assert client.post('/api/auth/logout').status_code == 200
    assert client.get('/api/telemetry/latest').status_code == 401


def test_only_audit_roles_can_read_system_events(client):
    telemetry.event('GET', '/api/coding/tasks/{task_id}', 200, 8.25)
    assert client.get('/api/telemetry/events').status_code == 403
    response = client.get('/api/telemetry/events', headers={'X-Aegis-Actor':'auditor'})
    assert response.status_code == 200
    event = response.json()[0]
    assert event['route'] == '/api/coding/tasks/{task_id}'
    assert set(event) == {'id', 'timestamp', 'method', 'route', 'status', 'duration_ms'}
    assert client.get('/api/telemetry/events?limit=501', headers={'X-Aegis-Actor':'auditor'}).status_code == 422


def test_workspace_redaction_and_scope(client, monkeypatch):
    tasks = [
        {'id':'OWN', 'user':'operator', 'status':'COMPLETED', 'mode':'PLAN', 'created_at':1,
         'label':{'compartments':['Engineering'], 'classification':'INTERNAL'},
         'prompt':'PRIVATE_PROMPT', 'diff':'PRIVATE_SOURCE', 'trace':[{'decision':'ALLOW','arguments':'PRIVATE_ARGUMENT'}]},
        {'id':'FOREIGN', 'user':'finance-operator', 'status':'BLOCKED', 'created_at':2},
        {'id':'OTHER_COMPARTMENT', 'user':'operator', 'status':'COMPLETED', 'created_at':3,
         'label':{'compartments':['Finance'], 'classification':'INTERNAL'}},
    ]
    monkeypatch.setattr(service, 'state', lambda identity: {'tasks':tasks})
    store.put('approval', 'MINE', {'id':'MINE','requester':'operator','action':'export','status':'PENDING',
                                  'created_at':1,'expires_at':time.time()+60,'binding':'PRIVATE_BINDING','decisions':[], 'required_roles':['Data Owner']})
    store.put('approval', 'THEIRS', {'id':'THEIRS','requester':'finance-operator','action':'export','status':'PENDING','created_at':2,'expires_at':time.time()+60})
    store.receipt('OWN_ACTION', 'operator', prompt='PRIVATE_PROMPT')
    store.receipt('FOREIGN_ACTION', 'finance-operator', output='PRIVATE_OUTPUT')
    result = client.get('/api/telemetry/workspace').json()
    assert [task['id'] for task in result['tasks']] == ['OWN']
    assert result['tasks'][0]['decisions'] == {'ALLOW':1, 'DENY':0}
    assert [approval['id'] for approval in result['approvals']] == ['MINE']
    assert [receipt['action'] for receipt in result['receipts']] == ['OWN_ACTION']
    serialized = json.dumps(result)
    assert 'PRIVATE_' not in serialized and 'FOREIGN' not in serialized
    assert 'count' not in result['chain']
    assert result['counts'] == {'tasks':1, 'approvals_pending':1, 'receipts':1}
    audit = client.get('/api/telemetry/workspace', headers={'X-Aegis-Actor':'auditor'}).json()
    assert audit['tasks'] == []
    assert audit['system_events_allowed'] is True
    assert len(audit['receipts']) == 2
    assert 'PRIVATE_' not in json.dumps(audit)
