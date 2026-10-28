"""Synthetic analytics must reconcile with source events and actual time windows."""
from collections import Counter
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / 'analytics.sqlite')


@pytest.mark.parametrize('window', [15, 60, 1440])
def test_series_sources_categories_and_hosts_reconcile(store, window):
    events = store.dashboard()['events']
    result = store.analytics(window)
    expected = {
        'events': len(events),
        'suspicious': sum(e['suspicious'] for e in events),
        'bytes_out': sum(e['details'].get('bytes_out', 0) for e in events if e['source'] == 'network'),
        'auth_failures': sum(e['details'].get('mfa_denials', 0) + int(e['details'].get('result') in ('failure', 'failed', 'denied')) for e in events if e['source'] == 'auth'),
    }
    assert result['totals'] == expected
    for measure, total in expected.items():
        assert sum(bucket[measure] for bucket in result['series']) == total
    assert sum(source['total'] for source in result['sources']) == len(events)
    assert sum(source['suspicious'] for source in result['sources']) == expected['suspicious']
    assert sum(host['events'] for host in result['hosts']) == len(events)
    counts = Counter(category for e in events if e['suspicious'] for category in {item['category'] for item in e['evidence']})
    assert {c['category']: c['count'] for c in result['categories']} == dict(counts)
    assert result['anchor_at'] == max(e['timestamp'] for e in events)
    assert len(result['series']) == (24 if window == 1440 else 12)


def test_window_includes_boundary_but_excludes_older_events(store):
    anchor = datetime.fromisoformat(max(e['timestamp'] for e in store.dashboard()['events']))
    template = store.fixtures[0]
    with store.transaction() as db:
        store.ingest(db, [
            {**template, 'id': 'boundary', 'timestamp': (anchor-timedelta(minutes=15)).isoformat()},
            {**template, 'id': 'outside', 'timestamp': (anchor-timedelta(minutes=15, seconds=1)).isoformat()},
        ])
    assert store.analytics(15)['totals']['events'] == len(store.fixtures) + 1
    assert store.analytics(60)['totals']['events'] == len(store.fixtures) + 2
    assert store.analytics(15)['series'][0]['events'] == 1


def test_empty_reset_has_no_invented_metrics_or_time_axis(store):
    store.reset()
    result = store.analytics(60)
    assert result['totals'] == {'events': 0, 'suspicious': 0, 'bytes_out': 0, 'auth_failures': 0}
    assert result['anchor_at'] is None and result['start_at'] is None
    assert result['series'] == result['hosts'] == result['categories'] == []
    assert all(source['total'] == 0 for source in result['sources'])


def test_host_status_reflects_approved_simulation_only(store):
    incident = store.dashboard()['incidents'][0]
    action = next(a for a in store.investigate(incident['id'])['recommendations'] if a['kind'] == 'isolate_host')
    assert next(h for h in store.analytics(60)['hosts'] if h['host'] == action['target'])['status'] == 'attention'
    store.decide(action['id'], 'approve', True, 'test.analyst', 'Reviewed evidence.')
    assert next(h for h in store.analytics(60)['hosts'] if h['host'] == action['target'])['status'] == 'isolated'


def test_analytics_endpoint_rejects_unsupported_windows(tmp_path):
    with TestClient(create_app(tmp_path / 'api.sqlite')) as client:
        client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
        assert client.get('/api/analytics?window_minutes=15').status_code == 200
        assert client.get('/api/analytics?window_minutes=30').status_code == 422
        assert client.get('/api/analytics?window_minutes=invalid').status_code == 422
