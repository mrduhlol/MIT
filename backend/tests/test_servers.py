"""Server enrollment and ingest trust boundaries, including cross-server isolation."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from backend.app.main import create_app


@pytest.fixture
def clients(tmp_path):
    app = create_app(tmp_path / 'servers.sqlite')
    with TestClient(app, base_url='https://localhost', client=('127.0.0.1', 50000)) as admin:
        admin.headers['X-SOC-Token'] = admin.get('/api/session').json()['token']
        agent = TestClient(app, base_url='https://localhost', client=('192.0.2.25', 50001))
        yield app, admin, agent
        agent.close()


def register(admin, name='Test Linux', hostname='demo-linux', mode='simulated'):
    result = admin.post('/api/servers', json={'name': name, 'hostname': hostname, 'mode': mode, 'website_url': 'https://example.test'})
    assert result.status_code in (200, 201), result.text
    return result.json()


def enroll(agent, registered, hostname='demo-linux', mode='simulated'):
    result = agent.post('/api/agent/enroll', json={'enrollment_token': registered['enrollment_token'], 'hostname': hostname, 'mode': mode})
    assert result.status_code == 200, result.text
    return result.json()


def payload(event_id='sample-1', suspicious=True):
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        'batch_id': uuid.uuid4().hex,
        'collected_at': timestamp,
        'metrics': {'cpu_percent': 21.5, 'memory_percent': 25.0, 'memory_used_bytes': 1024, 'memory_total_bytes': 4096, 'load_1m': .2, 'uptime_seconds': 120.0},
        'events': [{'id': event_id, 'timestamp': timestamp, 'source': 'email', 'identity': 'demo-user', 'ip': '192.0.2.44',
                    'details': {'body': 'Please verify your account now.' if suspicious else 'Weekly meeting notes.',
                                'sender_domain': 'attacker.invalid' if suspicious else 'company.example', 'claimed_domain': 'company.example'}}],
    }


def send(agent, credential, body=None):
    return agent.post('/api/agent/ingest', headers={'Authorization': 'Bearer ' + credential['agent_token']}, json=body or payload())


def test_registration_requires_admin_and_does_not_accept_agent_token(clients):
    _, admin, agent = clients
    assert agent.post('/api/servers', json={'name': 'x', 'hostname': 'x', 'mode': 'simulated'}).status_code in (401, 403)
    registered = register(admin)
    credential = enroll(agent, registered)
    assert agent.get('/api/servers', headers={'Authorization': 'Bearer ' + credential['agent_token']}).status_code in (401, 403)
    assert agent.get('/api/dashboard').status_code in (401, 403)
    assert agent.get('/api/session').status_code in (401, 403)
    assert agent.get('/api/session', headers={'X-Forwarded-For': '127.0.0.1'}).status_code in (401, 403)


def test_enrollment_one_use_hash_only_and_no_secret_listings(clients):
    app, admin, agent = clients
    registered = register(admin)
    assert len(registered['enrollment_token']) >= 32
    credential = enroll(agent, registered)
    assert credential['server_id'] == registered['server']['id']
    again = agent.post('/api/agent/enroll', json={'enrollment_token': registered['enrollment_token'], 'hostname': 'demo-linux', 'mode': 'simulated'})
    assert again.status_code in (401, 403, 409)
    listing = admin.get('/api/servers').text
    audit = admin.get('/api/dashboard').text
    dump = '\n'.join(app.state.store.conn.iterdump())
    for secret in (registered['enrollment_token'], credential['agent_token']):
        assert secret not in listing and secret not in audit and secret not in dump


def test_concurrent_enrollment_has_one_winner(clients):
    _, admin, agent = clients
    registered = register(admin)
    body = {'enrollment_token': registered['enrollment_token'], 'hostname': 'demo-linux', 'mode': 'simulated'}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: agent.post('/api/agent/enroll', json=body).status_code, range(2)))
    assert results.count(200) == 1
    assert all(status in (200, 401, 403, 409) for status in results)


def test_http_agent_transport_rejected_before_credentials_consumed(clients):
    app, admin, agent = clients
    registered = register(admin)
    with TestClient(app, base_url='http://localhost', client=('192.0.2.25', 50001)) as insecure:
        result = insecure.post('/api/agent/enroll', json={'enrollment_token': registered['enrollment_token'], 'hostname': 'demo-linux', 'mode': 'simulated'})
        assert result.status_code in (400, 403, 426)
        credential = enroll(agent, registered)
        result = insecure.post('/api/agent/ingest', headers={'Authorization': 'Bearer ' + credential['agent_token']}, json=payload())
        assert result.status_code in (400, 403, 426)


def test_enrollment_rejects_mismatched_identity_and_provenance(clients):
    _, admin, agent = clients
    registered = register(admin)
    for hostname, mode in [('wrong-host', 'simulated'), ('demo-linux', 'real')]:
        result = agent.post('/api/agent/enroll', json={'enrollment_token': registered['enrollment_token'], 'hostname': hostname, 'mode': mode})
        assert result.status_code in (400, 401, 403, 409, 422)
    enroll(agent, registered)


def test_ingestion_metrics_events_incidents_and_idempotency(clients):
    _, admin, agent = clients
    registered = register(admin)
    credential = enroll(agent, registered)
    body = payload()
    assert send(agent, credential, body).status_code == 200
    again = send(agent, credential, body)
    assert again.status_code == 200 and again.json()['duplicate'] is True
    body['batch_id'] = uuid.uuid4().hex
    assert send(agent, credential, body).status_code == 200
    result = admin.get('/api/servers/' + credential['server_id']).json()
    assert result['server']['status'] == 'online'
    assert result['server']['metrics']['cpu_percent'] == 21.5
    assert len(result['events']) == 1
    assert result['server']['event_count'] == 1
    assert result['server']['threat_count'] == 1
    assert result['metric_history']
    assert result['incidents']
    assert all(event['server_id'] == credential['server_id'] and event['telemetry_mode'] == 'simulated' for event in result['events'])
    assert result['events'][0]['id'] != body['events'][0]['id']


def test_scoped_ids_prevent_cross_server_or_fixture_overwrite_and_correlation(clients):
    _, admin, agent = clients
    a, b = register(admin), register(admin, name='Other Linux')
    ca, cb = enroll(agent, a), enroll(agent, b)
    body = payload('evt-0002')
    assert send(agent, ca, body).status_code == 200
    assert send(agent, cb, body).status_code == 200
    data = admin.get('/api/dashboard').json()
    assert len([e for e in data['events'] if e['id'] == 'evt-0002']) == 1
    for credential in (ca, cb):
        detail = admin.get('/api/servers/' + credential['server_id']).json()
        assert len(detail['events']) == 1 and len(detail['incidents']) == 1
        assert detail['incidents'][0]['server_id'] == credential['server_id']
    incidents = [i for i in data['incidents'] if i.get('server_id')]
    assert len(incidents) == 2
    assert incidents[0]['id'] != incidents[1]['id']


def test_ingest_does_not_accept_server_id_host_spoof_or_bad_metrics(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin))
    for extra in ['server_id', 'host']:
        body = payload()
        body[extra] = 'forged-target'
        assert send(agent, credential, body).status_code == 422
    body = payload()
    body['metrics']['cpu_percent'] = 101
    assert send(agent, credential, body).status_code == 422
    body = payload()
    body['events'][0]['timestamp'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert send(agent, credential, body).status_code in (400, 422)
    body = payload()
    body['events'][0]['host'] = 'different-server'
    assert send(agent, credential, body).status_code == 422
    assert agent.post('/api/agent/ingest', json=payload()).status_code in (401, 403)


def test_rotation_and_revocation_stop_old_agents(clients):
    _, admin, agent = clients
    registered = register(admin)
    old = enroll(agent, registered)
    rotated = admin.post('/api/servers/' + old['server_id'] + '/enrollment', json={})
    assert rotated.status_code == 200, rotated.text
    assert send(agent, old).status_code in (401, 403)
    new = enroll(agent, rotated.json())
    assert send(agent, new).status_code == 200
    assert admin.post('/api/servers/' + old['server_id'] + '/revoke', json={}).status_code == 200
    assert send(agent, new).status_code in (401, 403)
    assert admin.get('/api/servers/' + old['server_id']).json()['server']['status'] == 'revoked'


def test_ingested_threat_requires_individual_human_approval(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin))
    assert send(agent, credential).status_code == 200
    detail = admin.get('/api/servers/' + credential['server_id']).json()
    incident_id = detail['incidents'][0]['id']
    response = admin.post('/api/incidents/' + incident_id + '/investigate', json={})
    assert response.status_code == 200
    action = response.json()['recommendations'][0]
    assert action['status'] == 'pending'
    decision = {'decision': 'approve', 'confirmed': False, 'actor': 'analyst', 'reason': 'Reviewed server evidence'}
    assert admin.post('/api/actions/' + action['id'] + '/decision', json=decision).status_code in (400, 403, 422)
    decision['confirmed'] = True
    assert agent.post('/api/actions/' + action['id'] + '/decision', headers={'Authorization': 'Bearer ' + credential['agent_token']}, json=decision).status_code in (401, 403)
    decision['decision'] = 'reject'
    assert admin.post('/api/actions/' + action['id'] + '/decision', json=decision).json()['status'] == 'rejected'
    decision['decision'] = 'approve'
    assert admin.post('/api/actions/' + action['id'] + '/decision', json=decision).status_code == 409
    state = admin.get('/api/dashboard').json()['sandbox']
    assert state == {'isolated_hosts': [], 'revoked_identities': []}


def test_simulation_reset_preserves_connected_server_evidence(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin))
    assert send(agent, credential).status_code == 200
    detail = admin.get('/api/servers/' + credential['server_id']).json()
    incident_id = detail['incidents'][0]['id']
    proposal = admin.post('/api/incidents/' + incident_id + '/investigate', json={}).json()['recommendations'][0]
    assert admin.post('/api/reset', json={}).status_code == 200
    assert len(admin.get('/api/servers/' + credential['server_id']).json()['events']) == 1
    assert any(a['id'] == proposal['id'] for a in admin.get('/api/dashboard').json()['actions'])


def test_invalid_payload_never_reflects_tokens(clients):
    _, admin, agent = clients
    registered = register(admin)
    token = registered['enrollment_token']
    result = agent.post('/api/agent/enroll', json={'enrollment_token': token, 'hostname': [], 'mode': 'simulated'})
    assert result.status_code == 422
    assert token not in result.text


def test_expired_token_and_offline_heartbeat(clients):
    app, admin, agent = clients
    registered = register(admin)
    with app.state.store.transaction() as db:
        db.execute('UPDATE servers SET enrollment_expires_at=? WHERE id=?', ((datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat(), registered['server']['id']))
    result = agent.post('/api/agent/enroll', json={'enrollment_token': registered['enrollment_token'], 'hostname': 'demo-linux', 'mode': 'simulated'})
    assert result.status_code == 401
    rotated = admin.post('/api/servers/' + registered['server']['id'] + '/enrollment', json={}).json()
    credential = enroll(agent, rotated)
    assert send(agent, credential).status_code == 200
    with app.state.store.transaction() as db:
        db.execute('UPDATE servers SET last_seen_at=? WHERE id=?', ((datetime.now(timezone.utc)-timedelta(seconds=121)).isoformat(), credential['server_id']))
    assert admin.get('/api/servers/' + credential['server_id']).json()['server']['status'] == 'offline'


def test_batch_id_payload_binding_body_limit_and_no_public_reads(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin))
    body = payload()
    assert send(agent, credential, body).status_code == 200
    body['metrics']['cpu_percent'] = 99
    assert send(agent, credential, body).status_code == 409
    oversized = agent.post('/api/agent/ingest', headers={'Authorization': 'Bearer ' + credential['agent_token'], 'Content-Type':'application/json'}, content=b'x' * (1024*1024+1))
    assert oversized.status_code == 413
    for route in ('/api/servers', '/api/dashboard', '/api/agent', '/api/analytics'):
        assert agent.get(route).status_code == 403


def test_ssh_failures_detected_without_false_mfa_claim(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin, mode='real'), mode='real')
    body = payload()
    body['events'][0].update(source='auth', details={'result':'failed','failed_attempts':6,'timestamp_basis':'log'})
    assert send(agent, credential, body).status_code == 200
    detail = admin.get('/api/servers/' + credential['server_id']).json()
    event = detail['events'][0]
    assert event['telemetry_mode'] == 'real' and event['suspicious']
    assert any('failed authentication' in e['explanation'] for e in event['evidence'])
    assert all('MFA' not in e['explanation'] for e in event['evidence'])


def test_approval_targets_only_its_registered_server(clients):
    _, admin, agent = clients
    first = enroll(agent, register(admin, name='Host A'))
    second = enroll(agent, register(admin, name='Host B'))
    for credential in (first, second):
        assert send(agent, credential).status_code == 200
    a = admin.get('/api/servers/' + first['server_id']).json()
    response = admin.post('/api/incidents/' + a['incidents'][0]['id'] + '/investigate', json={}).json()
    action = response['recommendations'][0]
    assert action['target'].startswith(first['server_id'] + '::')
    approved = admin.post('/api/actions/' + action['id'] + '/decision', json={'decision':'approve','confirmed':True,'actor':'Reviewer','reason':'Verified scoped target'})
    assert approved.status_code == 200
    state = admin.get('/api/dashboard').json()['sandbox']
    assert state['isolated_hosts'] == [first['server_id'] + '::demo-linux']
    assert not any(target.startswith(second['server_id']) for target in state['isolated_hosts'])
    # Even approved containment remains a simulation; collectors receive no commands.
    assert send(agent, first, payload(event_id='after-approved-simulation')).status_code == 200
    assert send(agent, second, payload(event_id='after-other-server-approval')).status_code == 200


def test_real_health_without_logs_is_not_labeled_as_unconnected_demo(clients):
    _, admin, agent = clients
    credential = enroll(agent, register(admin, mode='real'), mode='real')
    body = payload()
    body['events'] = []
    assert send(agent, credential, body).status_code == 200
    overview = admin.get('/api/agent').json()
    assert overview['mode'] == 'mixed'  # Existing fixture plus real health report.
    assert overview['site']['collector_status'] == 'connected'
    assert overview['site']['name'] == 'Registered servers'
