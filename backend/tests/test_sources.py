"""Authorized website API ingestion over actual loopback TLS, not mocked connectivity."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import threading

import pytest
from fastapi.testclient import TestClient
from backend.app.main import create_app

CATEGORIES = ['authentication', 'suspicious_sessions', 'account_changes', 'application_security']
KEY = 'fixture-api-key-only-not-a-real-credential'


def upstream_event(category='authentication', event_id='evt-0002'):
    return {'id': event_id, 'timestamp': datetime.now(timezone.utc).isoformat(), 'category': category,
            'identity': 'alice', 'ip': '192.0.2.51', 'details': {'result': 'failed', 'failed_attempts': 8}}


@pytest.fixture(scope='module')
def certificate(tmp_path_factory):
    root = tmp_path_factory.mktemp('website-ca')
    key, cert = root / 'key.pem', root / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext',
                    'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return key, cert


@pytest.fixture
def website(certificate):
    state = {'key': KEY, 'status': 200, 'requests': [], 'body': {
        'schema_version': 1, 'telemetry_mode': 'real',
        'permissions': {'available': CATEGORIES.copy(), 'granted': CATEGORIES.copy()},
        'events': [upstream_event()]}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            state['requests'].append({'path': self.path, 'authorization': self.headers.get('Authorization')})
            status = state['status'] if self.headers.get('Authorization') == 'Bearer ' + state['key'] else 401
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            if status in (301, 302, 307, 308):
                self.send_header('Location', 'https://127.0.0.1:9/stolen')
            self.end_headers()
            self.wfile.write(json.dumps(state['body'] if status == 200 else {'detail': 'DO NOT LEAK ' + KEY}).encode())

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate[1], certificate[0])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state['origin'] = f'https://localhost:{server.server_port}'
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def clients(tmp_path, monkeypatch, website, certificate):
    monkeypatch.setenv('SOC_CONNECTOR_ALLOWED_ORIGINS', website['origin'])
    monkeypatch.setenv('SOC_CONNECTOR_CA_FILE', str(certificate[1]))
    app = create_app(tmp_path / 'sources.sqlite')
    with TestClient(app, base_url='https://localhost', client=('127.0.0.1', 50000)) as admin:
        admin.headers['X-SOC-Token'] = admin.get('/api/session').json()['token']
        with TestClient(app, base_url='https://localhost', client=('192.0.2.20', 50001)) as remote:
            yield app, admin, remote


def config(website, **changes):
    return {'name': 'Authorized website', 'base_url': website['origin'],
            'events_url': website['origin'] + '/security-events', 'api_key': KEY,
            'categories': ['authentication'], **changes}


def connect(admin, website, **changes):
    result = admin.post('/api/sources/website', json=config(website, **changes))
    assert result.status_code in (200, 201), result.text
    return result.json()['source']


def test_connection_is_authenticated_tls_and_does_not_save_on_probe(clients, website):
    _, admin, _ = clients
    before = admin.get('/api/sources').json()['sources']
    result = admin.post('/api/sources/website/test', json=config(website))
    assert result.status_code == 200, result.text
    assert result.json()['valid'] is True
    assert result.json()['enabled_categories'] == ['authentication']
    assert 'authentication' in result.json()['granted_permissions']
    assert website['requests'][-1]['authorization'] == 'Bearer ' + KEY
    assert admin.get('/api/sources').json()['sources'] == before
    source = connect(admin, website)
    assert source['status'] == 'connected'
    assert KEY not in json.dumps(source)


def test_failed_auth_and_provider_errors_never_save_or_leak_credentials(clients, website):
    _, admin, _ = clients
    for status in (401, 403, 500, 302):
        website['status'] = status
        result = admin.post('/api/sources/website', json=config(website))
        assert result.status_code >= 400
        assert KEY not in result.text and 'DO NOT LEAK' not in result.text
    website['status'] = 200
    result = admin.post('/api/sources/website/test', json=config(website, api_key='invalid-fixture-key'))
    assert result.status_code >= 400
    assert not admin.get('/api/sources').json()['sources']


def test_credentials_are_encrypted_and_admin_only(clients, website, tmp_path):
    app, admin, remote = clients
    source = connect(admin, website)
    for path in ('/api/sources', '/api/sources/' + source['id']):
        assert remote.get(path).status_code == 403
    assert remote.post('/api/sources/website', json=config(website)).status_code == 403
    assert remote.post('/api/sources/' + source['id'] + '/poll', json={}).status_code == 403
    dump = '\n'.join(app.state.store.conn.iterdump())
    for output in (dump, admin.get('/api/sources').text, admin.get('/api/dashboard').text,
                   admin.get('/api/sources/' + source['id']).text):
        assert KEY not in output
    key_file = tmp_path / '.agent-state' / 'connector.key'
    assert key_file.exists() and key_file.stat().st_mode & 0o777 == 0o600


def test_permissions_are_verified_and_enforced_on_ingestion(clients, website):
    _, admin, _ = clients
    website['body']['permissions']['granted'] = ['authentication']
    denied = admin.post('/api/sources/website', json=config(website, categories=['account_changes']))
    assert denied.status_code >= 400
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    denied = admin.post(path + '/permissions', json={'categories': ['account_changes']})
    assert denied.status_code >= 400
    website['body']['events'] = [upstream_event('account_changes', 'forbidden')]
    denied = admin.post(path + '/poll', json={})
    assert denied.status_code >= 400
    assert not any(e.get('external_id') == 'forbidden' or e['id'].endswith(':forbidden')
                   for e in admin.get(path).json()['events'])


def test_multiple_sources_are_isolated_deduplicated_and_keep_timestamps(clients, website):
    _, admin, _ = clients
    a, b = connect(admin, website, name='Website A'), connect(admin, website, name='Website B')
    for source in (a, b):
        path = '/api/sources/' + source['id']
        assert admin.post(path + '/poll', json={}).status_code == 200
        assert admin.post(path + '/poll', json={}).status_code == 200
        detail = admin.get(path).json()
        assert len(detail['events']) == 1 and detail['incidents']
        event = detail['events'][0]
        assert event['server_id'] == source['id'] and event['telemetry_mode'] == 'real'
        assert datetime.fromisoformat(event['timestamp']) == datetime.fromisoformat(website['body']['events'][0]['timestamp'])
        assert datetime.fromisoformat(event['received_at']) >= datetime.fromisoformat(event['timestamp'])
        assert detail['source']['last_event_received_at'] == event['received_at']
        assert all(i['server_id'] == source['id'] for i in detail['incidents'])
    assert a['id'] != b['id']
    fixture = [e for e in admin.get('/api/dashboard').json()['events'] if e['id'] == 'evt-0002']
    assert len(fixture) == 1 and fixture[0].get('telemetry_mode', 'simulated') == 'simulated'


def test_disabled_event_categories_are_not_ingested(clients, website):
    _, admin, _ = clients
    website['body']['events'].append(upstream_event('account_changes', 'not-selected'))
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    assert admin.post(path + '/poll', json={}).status_code == 200
    assert len(admin.get(path).json()['events']) == 1
    assert admin.post(path + '/permissions', json={'categories': ['authentication', 'account_changes']}).status_code == 200
    assert admin.post(path + '/poll', json={}).status_code == 200
    assert len(admin.get(path).json()['events']) == 2


def test_revoked_upstream_key_marks_error_and_disconnect_stops_collection(clients, website):
    _, admin, _ = clients
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    website['key'] = 'upstream-rotated-key'
    assert admin.post(path + '/test', json={}).status_code >= 400
    assert admin.get(path).json()['source']['status'] == 'error'
    website['key'] = KEY
    assert admin.post(path + '/test', json={}).status_code == 200
    assert admin.post(path + '/disconnect', json={}).status_code == 200
    before = len(website['requests'])
    assert admin.post(path + '/poll', json={}).status_code >= 400
    assert len(website['requests']) == before


def test_revoke_removes_stored_credential_and_prevents_reuse(clients, website):
    _, admin, _ = clients
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    assert admin.post(path + '/revoke', json={}).status_code == 200
    before = len(website['requests'])
    assert admin.post(path + '/test', json={}).status_code >= 400
    assert admin.post(path + '/poll', json={}).status_code >= 400
    assert len(website['requests']) == before


@pytest.mark.parametrize('url', ['http://localhost/events', 'https://127.0.0.1/events',
    'https://169.254.169.254/latest/meta-data', 'https://[::1]/events',
    'https://user:password@example.com/events', 'https://example.com/events?api_key=secret',
    'https://example.com/events#secret'])
def test_unsafe_endpoints_are_refused_before_auth_disclosure(clients, website, url):
    _, admin, _ = clients
    before = len(website['requests'])
    result = admin.post('/api/sources/website/test', json=config(website, base_url=url, events_url=url))
    assert result.status_code >= 400
    assert KEY not in result.text
    assert len(website['requests']) == before


def test_untrusted_tls_certificate_rejected(clients, website, monkeypatch):
    _, admin, _ = clients
    monkeypatch.delenv('SOC_CONNECTOR_CA_FILE')
    result = admin.post('/api/sources/website/test', json=config(website))
    assert result.status_code >= 400
    assert KEY not in result.text


def test_synthetic_upstream_stays_explicitly_simulated(clients, website):
    _, admin, _ = clients
    website['body']['telemetry_mode'] = 'simulated'
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    assert admin.post(path + '/poll', json={}).status_code == 200
    assert admin.get(path).json()['source']['mode'] == 'simulated'
    assert all(e['telemetry_mode'] == 'simulated' for e in admin.get(path).json()['events'])


def test_website_actions_remain_individually_approval_gated_simulations(clients, website):
    _, admin, remote = clients
    source = connect(admin, website)
    assert admin.post('/api/sources/' + source['id'] + '/poll', json={}).status_code == 200
    incident = admin.get('/api/sources/' + source['id']).json()['incidents'][0]
    investigation = admin.post('/api/incidents/' + incident['id'] + '/investigate', json={}).json()
    action = investigation['recommendations'][0]
    assert action['status'] == 'pending'
    path = '/api/actions/' + action['id'] + '/decision'
    decision = {'decision': 'approve', 'confirmed': False, 'actor': 'Test reviewer', 'reason': 'Reviewed evidence'}
    assert admin.post(path, json=decision).status_code == 403
    decision['confirmed'] = True
    assert remote.post(path, json=decision).status_code == 403
    decision['decision'] = 'reject'
    assert admin.post(path, json=decision).json()['status'] == 'rejected'
    decision['decision'] = 'approve'
    assert admin.post(path, json=decision).status_code == 409
    assert admin.get('/api/dashboard').json()['sandbox'] == {'isolated_hosts': [], 'revoked_identities': []}


def test_offline_age_and_explicit_resume_preserve_history(clients, website):
    app, admin, _ = clients
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    assert admin.post(path + '/poll', json={}).status_code == 200
    with app.state.store.transaction() as db:
        db.execute('UPDATE data_sources SET last_success_at=? WHERE id=?',
                   ((datetime.now(timezone.utc) - timedelta(seconds=301)).isoformat(), source['id']))
    assert admin.get(path).json()['source']['status'] == 'offline'
    assert admin.post(path + '/disconnect', json={}).status_code == 200
    assert admin.post(path + '/test', json={}).json()['source']['status'] == 'disconnected'
    assert admin.post(path + '/resume', json={}).json()['source']['status'] == 'connected'
    assert len(admin.get(path).json()['events']) == 1
    assert admin.post('/api/reset', json={}).status_code == 200
    assert len(admin.get(path).json()['events']) == 1


def test_provenance_change_cannot_mix_real_and_synthetic_evidence(clients, website):
    _, admin, _ = clients
    source = connect(admin, website)
    path = '/api/sources/' + source['id']
    website['body']['telemetry_mode'] = 'simulated'
    assert admin.post(path + '/poll', json={}).status_code == 502
    assert admin.get(path).json()['source']['mode'] == 'real'
    assert not admin.get(path).json()['events']


def test_http_cannot_send_source_credentials(clients, website):
    app, _, _ = clients
    with TestClient(app, base_url='http://localhost', client=('127.0.0.1', 51000)) as insecure:
        insecure.headers['X-SOC-Token'] = app.state.token
        assert insecure.post('/api/sources/website/test', json=config(website)).status_code == 403
        assert insecure.post('/api/sources/website', json=config(website)).status_code == 403
    assert website['requests'] == []


def test_connection_checks_are_rate_limited_without_secret_response(clients, website):
    _, admin, _ = clients
    responses = [admin.post('/api/sources/website/test', json=config(website, api_key='invalid-fixture-key')) for _ in range(61)]
    assert any(response.status_code == 429 for response in responses)
    assert all(KEY not in response.text for response in responses)
