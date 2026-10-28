"""End-to-end approval safety, replay, persistence and evidence contracts."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app

@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path/'soc.sqlite')) as c:
        c.headers['X-SOC-Token'] = c.get('/api/session').json()['token']
        yield c

def proposal(client):
    incident = client.get('/api/dashboard').json()['incidents'][0]
    response = client.post(f"/api/incidents/{incident['id']}/investigate")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['summary'] and body['evidence'] and body['limitations']
    assert all(item['event_id'] in incident['event_ids'] for item in body['evidence'])
    return body['recommendations'][0], incident

def decide(client, action, decision='approve', confirmed=True):
    return client.post(f"/api/actions/{action['id']}/decision", json={
        'decision':decision, 'confirmed':confirmed, 'actor':'test.analyst',
        'reason':'Reviewed the correlated synthetic evidence.'})

def test_dashboard_has_traceable_multisource_campaign(client):
    data = client.get('/api/dashboard').json()
    assert data['events'] and data['incidents']
    events = {e['id']:e for e in data['events']}
    assert all(set(i['event_ids']) <= events.keys() for i in data['incidents'])
    assert any(len({events[e]['source'] for e in i['event_ids']}) >= 3 for i in data['incidents'])
    assert data['sandbox']['isolated_hosts'] == []
    assert data['sandbox']['revoked_identities'] == []

def test_proposals_do_not_execute_and_are_idempotent(client):
    action, incident = proposal(client)
    data = client.get('/api/dashboard').json()
    assert action['status'] == 'pending'
    assert not data['sandbox']['isolated_hosts'] and not data['sandbox']['revoked_identities']
    before = {a['id'] for a in data['actions']}
    assert client.post(f"/api/incidents/{incident['id']}/investigate").status_code == 200
    assert {a['id'] for a in client.get('/api/dashboard').json()['actions']} == before

def test_missing_token_cannot_mutate(client):
    client.headers.pop('X-SOC-Token')
    assert client.post('/api/reset').status_code in (401,403)
    assert client.post('/api/replay',json={'mode':'all'}).status_code in (401,403)

def test_approval_requires_explicit_confirmation(client):
    action, _ = proposal(client)
    assert decide(client, action, confirmed=False).status_code in (400,403,422)
    data = client.get('/api/dashboard').json()
    assert not data['sandbox']['isolated_hosts'] and not data['sandbox']['revoked_identities']
    assert next(a for a in data['actions'] if a['id']==action['id'])['status'] == 'pending'

def test_approved_action_executes_verifies_and_cannot_repeat(client):
    action, _ = proposal(client)
    result = decide(client, action)
    assert result.status_code == 200, result.text
    assert result.json()['status'] == 'approved'
    assert result.json()['verification']
    data = client.get('/api/dashboard').json()
    field = 'isolated_hosts' if action['kind']=='isolate_host' else 'revoked_identities'
    assert action['target'] in data['sandbox'][field]
    assert any(a['actor']=='test.analyst' for a in data['audit'])
    assert decide(client, action).status_code == 409

def test_rejected_action_never_executes(client):
    action, _ = proposal(client)
    response = decide(client, action, decision='reject',confirmed=False)
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'rejected'
    assert decide(client, action).status_code == 409
    data = client.get('/api/dashboard').json()
    assert not data['sandbox']['isolated_hosts'] and not data['sandbox']['revoked_identities']

def test_concurrent_decisions_have_one_winner(client):
    action, _ = proposal(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: decide(client,action).status_code, range(2)))
    assert sorted(results) == [200,409]

def test_reset_then_guided_replay(client):
    assert client.post('/api/reset').status_code == 200
    data = client.get('/api/dashboard').json()
    assert data['events'] == [] and data['actions'] == [] and data['replay']['cursor'] == 0
    assert client.post('/api/replay',json={'mode':'step'}).status_code == 200
    assert len(client.get('/api/dashboard').json()['events']) == 1
    assert client.post('/api/replay',json={'mode':'all'}).status_code == 200
    data = client.get('/api/dashboard').json()
    assert len(data['events']) == data['replay']['total'] == data['replay']['cursor']
    assert client.post('/api/replay',json={'mode':'all'}).status_code == 200
    assert len(client.get('/api/dashboard').json()['events']) == len(data['events'])

def test_evaluate_reports_actual_holdout_metrics(client):
    response = client.post('/api/evaluate')
    assert response.status_code == 200
    metrics = response.json()
    assert metrics['samples'] == metrics['tp']+metrics['fp']+metrics['tn']+metrics['fn']
    assert metrics['fp'] > 0 and metrics['fn'] > 0

def test_state_persists_across_application_restart(tmp_path):
    db = tmp_path/'persist.sqlite'
    with TestClient(create_app(db)) as client:
        client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
        action, _ = proposal(client)
        assert decide(client,action).status_code == 200
    with TestClient(create_app(db)) as client:
        data = client.get('/api/dashboard').json()
        assert next(a for a in data['actions'] if a['id']==action['id'])['status']=='approved'
        field = 'isolated_hosts' if action['kind']=='isolate_host' else 'revoked_identities'
        assert action['target'] in data['sandbox'][field]

def test_wrong_origin_cannot_mutate_even_with_session_token(client):
    assert client.post('/api/reset',headers={'Origin':'https://untrusted.example'}).status_code == 403

def test_string_confirmation_and_blank_analyst_are_rejected(client):
    action, _ = proposal(client)
    payload = {'decision':'approve','confirmed':'true','actor':'test.analyst','reason':'Reviewed.'}
    assert client.post(f"/api/actions/{action['id']}/decision",json=payload).status_code == 422
    payload.update(confirmed=True,actor='   ')
    assert client.post(f"/api/actions/{action['id']}/decision",json=payload).status_code == 422
