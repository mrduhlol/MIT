"""Scheduling and autonomous investigation must never bypass human response approval."""
from datetime import datetime, timedelta, timezone
import threading

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.patrol import PatrolScheduler
from backend.app.store import Store


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path / 'patrol.sqlite')) as client:
        client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
        yield client


def set_due(store, *, enabled=True):
    with store.transaction() as db:
        store.set_meta(db, 'agent_settings', {
            'enabled': enabled, 'interval_seconds': 300,
            'next_run_at': (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        })


def test_agent_starts_paused_with_real_source_coverage(client):
    agent = client.get('/api/agent').json()
    events = client.get('/api/dashboard').json()['events']
    assert agent['status'] == 'paused' and agent['enabled'] is False
    assert agent['next_run_at'] is None and agent['runs'] == []
    assert sum(source['events'] for source in agent['coverage']) == len(events)
    assert {source['source'] for source in agent['coverage']} == {'email', 'auth', 'network'}
    assert all(source['status'] == 'simulated' for source in agent['coverage'])


def test_patrol_investigates_and_proposes_without_executing(client):
    before = client.get('/api/dashboard').json()
    result = client.post('/api/agent/patrol', json={})
    assert result.status_code == 200
    run = result.json()
    assert run['status'] == 'completed' and run['trigger'] == 'manual'
    assert run['events_analyzed'] == len(before['events'])
    assert run['incidents_found'] == run['investigated_incidents'] == len(before['incidents'])
    assert run['suspicious_events'] == sum(e['suspicious'] for e in before['events'])
    assert run['duration_ms'] > 0 and run['completed_at'] >= run['started_at']
    after = client.get('/api/dashboard').json()
    assert after['sandbox'] == before['sandbox']
    assert after['events'] == before['events']
    assert after['actions'] and all(a['status'] == 'pending' for a in after['actions'])
    assert run['pending_recommendations'] == len(after['actions'])
    assert any(a['action'] == 'patrol_completed' for a in after['audit'])
    assert client.get('/api/agent').json()['runs'][0]['id'] == run['id']


def test_patrol_preserves_approved_and_rejected_decisions(client):
    client.post('/api/agent/patrol', json={})
    actions = client.get('/api/dashboard').json()['actions']
    for action, decision in zip(actions[:2], ['approve', 'reject']):
        response = client.post(f"/api/actions/{action['id']}/decision", json={
            'decision': decision, 'confirmed': decision == 'approve',
            'actor': 'test.analyst', 'reason': 'Reviewed synthetic incident evidence.',
        })
        assert response.status_code == 200
    before = client.get('/api/dashboard').json()
    assert client.post('/api/agent/patrol', json={}).status_code == 200
    after = client.get('/api/dashboard').json()
    assert after['actions'] == before['actions']
    assert after['sandbox'] == before['sandbox']


@pytest.mark.parametrize('payload', [
    {'enabled': True, 'interval_seconds': 29},
    {'enabled': True, 'interval_seconds': 86401},
    {'enabled': 'true', 'interval_seconds': 60},
    {'enabled': True, 'interval_seconds': 60.5},
    {'enabled': True, 'interval_seconds': True},
])
def test_schedule_validates_strict_input(client, payload):
    assert client.post('/api/agent/settings', json=payload).status_code == 422
    assert client.get('/api/agent').json()['enabled'] is False


def test_patrol_and_schedule_require_authorization(client):
    client.headers.pop('X-SOC-Token')
    assert client.post('/api/agent/patrol', json={}).status_code == 403
    assert client.post('/api/agent/settings', json={'enabled': True, 'interval_seconds': 60}).status_code == 403


def test_schedule_persists_and_pausing_clears_due_time(tmp_path):
    path = tmp_path / 'persist.sqlite'
    with TestClient(create_app(path)) as client:
        client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
        result = client.post('/api/agent/settings', json={'enabled': True, 'interval_seconds': 600})
        assert result.status_code == 200
        assert result.json()['status'] == 'scheduled'
        due = result.json()['next_run_at']
        assert due
    with TestClient(create_app(path)) as client:
        client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
        agent = client.get('/api/agent').json()
        assert agent['enabled'] and agent['interval_seconds'] == 600 and agent['next_run_at'] == due
        paused = client.post('/api/agent/settings', json={'enabled': False, 'interval_seconds': 600}).json()
        assert paused['status'] == 'paused' and paused['next_run_at'] is None


def test_due_guard_skips_paused_and_future_runs(tmp_path):
    store = Store(tmp_path / 'due.sqlite')
    set_due(store, enabled=False)
    assert store.patrol('scheduled') is None
    store.configure_agent(True, 300)
    assert store.patrol('scheduled') is None
    assert store.agent()['runs'] == []
    set_due(store)
    run = store.patrol('scheduled')
    assert run['status'] == 'completed'
    assert datetime.fromisoformat(store.agent()['next_run_at']) > datetime.now(timezone.utc)
    assert store.patrol('scheduled') is None
    assert len(store.agent()['runs']) == 1


def test_scheduler_runs_due_work_without_browser_and_stops(tmp_path, monkeypatch):
    store = Store(tmp_path / 'thread.sqlite')
    set_due(store)
    completed = threading.Event()
    original = store.patrol

    def record(trigger):
        try:
            return original(trigger)
        finally:
            completed.set()

    monkeypatch.setattr(store, 'patrol', record)
    scheduler = PatrolScheduler(store)
    try:
        scheduler.start()
        thread = scheduler.thread
        scheduler.start()
        assert scheduler.thread is thread, 'Starting twice must not create duplicate workers'
        assert completed.wait(3), 'Due patrol did not run independently of browser requests'
    finally:
        scheduler.stop()
    assert not scheduler.thread.is_alive()
    runs = store.agent()['runs']
    assert len(runs) == 1 and runs[0]['trigger'] == 'scheduled'
    assert store.dashboard()['sandbox'] == {'isolated_hosts': [], 'revoked_identities': []}


def test_busy_patrol_refuses_overlap_and_failed_scan_is_recorded(tmp_path, monkeypatch):
    store = Store(tmp_path / 'failure.sqlite')
    store.patrol_lock.acquire()
    try:
        with pytest.raises(RuntimeError, match='already running'):
            store.patrol()
    finally:
        store.patrol_lock.release()

    def fail(_event):
        raise ValueError('simulated detector failure')

    monkeypatch.setattr(store.detector, 'predict', fail)
    run = store.patrol()
    assert run['status'] == 'failed' and run['error'] == 'simulated detector failure'
    assert store.agent()['runs'][0]['id'] == run['id']
    assert not store.patrol_lock.locked()
    assert store.dashboard()['actions'] == []
    assert any(a['action'] == 'patrol_failed' for a in store.dashboard()['audit'])


def test_patrol_persists_fresh_predictions_for_dashboard_and_investigation(tmp_path, monkeypatch):
    store = Store(tmp_path / 'fresh.sqlite')
    original = store.detector.predict

    def refreshed(event):
        return {**original(event), 'confidence': 0.777}

    monkeypatch.setattr(store.detector, 'predict', refreshed)
    assert store.patrol()['status'] == 'completed'
    assert all(e['confidence'] == 0.777 for e in store.dashboard()['events'])
    assert all(i['confidence'] == 0.777 for i in store.dashboard()['incidents'])
