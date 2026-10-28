"""Connector trust-boundary regression tests; transport fixtures elsewhere exercise real TLS."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import socket
import threading

import pytest
from fastapi.testclient import TestClient
from backend.app import connectors
from backend.app.connectors import ConnectorError, PinnedHTTPSConnection, WebsiteConnector, WebsiteResponse
from backend.app.main import create_app

KEY = 'test-provider-secret-not-production'
CONFIG = {'name': 'Read-only API', 'base_url': 'https://website.example', 'events_url': 'https://website.example/security-events',
          'api_key': KEY, 'categories': ['authentication']}


def response():
    return WebsiteResponse.model_validate({'schema_version': 1, 'telemetry_mode': 'real',
        'permissions': {'available': connectors.CATEGORIES, 'granted': connectors.CATEGORIES},
        'events': [{'id': 'event-1', 'timestamp': datetime.now(timezone.utc).isoformat(), 'category': 'authentication',
                    'identity': 'alice', 'ip': '192.0.2.9', 'details': {'failed_attempts': 8}}]})


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '224.0.0.1', 'ff02::1'])
def test_private_and_multicast_dns_never_receive_authorization(monkeypatch, address):
    monkeypatch.delenv('SOC_CONNECTOR_ALLOWED_ORIGINS', raising=False)
    monkeypatch.setattr(connectors, 'resolve', lambda *_: [address])
    def forbidden(*_args, **_kwargs):
        pytest.fail('A connection was attempted before the destination passed SSRF checks.')
    monkeypatch.setattr(connectors, 'PinnedHTTPSConnection', forbidden)
    with pytest.raises(ConnectorError, match='origin allowlist'):
        WebsiteConnector().fetch(CONFIG, KEY)


def test_mixed_public_private_dns_is_rejected(monkeypatch):
    monkeypatch.delenv('SOC_CONNECTOR_ALLOWED_ORIGINS', raising=False)
    monkeypatch.setattr(connectors, 'resolve', lambda *_: ['93.184.216.34', '127.0.0.1'])
    with pytest.raises(ConnectorError):
        WebsiteConnector().fetch(CONFIG, KEY)


def test_transport_connects_to_pinned_address_with_original_tls_hostname(monkeypatch):
    calls = []
    sock = object()
    class Context:
        def wrap_socket(self, raw, server_hostname):
            calls.append(('tls', raw, server_hostname))
            return raw
    conn = object.__new__(PinnedHTTPSConnection)
    conn.address, conn.port, conn.timeout, conn.host = '93.184.216.34', 443, 5, 'website.example'
    conn._context = Context()
    def create_connection(address, timeout):
        calls.append(('socket', address, timeout))
        return sock
    monkeypatch.setattr(socket, 'create_connection', create_connection)
    conn.connect()
    assert calls == [('socket', ('93.184.216.34', 443), 5), ('tls', sock, 'website.example')]


def test_dns_is_resolved_once_and_selected_address_is_passed_to_transport(monkeypatch):
    monkeypatch.delenv('SOC_CONNECTOR_ALLOWED_ORIGINS', raising=False)
    calls = []
    def lookup(*args, **kwargs):
        calls.append('dns')
        # A subsequent resolver call would return loopback (rebinding).
        address = '93.184.216.34' if calls.count('dns') == 1 else '127.0.0.1'
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]
    monkeypatch.setattr(socket, 'getaddrinfo', lookup)
    raw = response().model_dump_json().encode()
    class Transport:
        def __init__(self, host, port, address, context):
            calls.append(('transport', host, port, address))
            self.remaining = raw
        def request(self, method, path, headers):
            assert headers['Authorization'] == 'Bearer ' + KEY
        def getresponse(self):
            return self
        status = 200
        def getheader(self, name, default=None):
            return 'application/json' if name == 'Content-Type' else str(len(raw))
        def read1(self, size):
            chunk, self.remaining = self.remaining[:size], self.remaining[size:]
            return chunk
        def close(self):
            pass
    monkeypatch.setattr(connectors, 'PinnedHTTPSConnection', Transport)
    assert WebsiteConnector().fetch(CONFIG, KEY).telemetry_mode == 'real'
    assert calls == ['dns', ('transport', 'website.example', 443, '93.184.216.34')]


class StubConnector:
    def fetch(self, config, key):
        assert key == KEY
        return response()


def admin_for(app):
    client = TestClient(app, base_url='https://localhost', client=('127.0.0.1', 50000))
    client.headers['X-SOC-Token'] = client.get('/api/session').json()['token']
    return client


def test_encrypted_credential_survives_restart_without_leaking(tmp_path, monkeypatch):
    monkeypatch.delenv('SOC_CREDENTIAL_KEY', raising=False)
    database = tmp_path / 'sources.sqlite'
    app = create_app(database)
    app.state.website_connector = StubConnector()
    with admin_for(app) as admin:
        created = admin.post('/api/sources/website', json=CONFIG)
        assert created.status_code == 200, created.text
        source_id = created.json()['source']['id']
        dump = '\n'.join(app.state.store.conn.iterdump())
        assert KEY not in dump
    app.state.store.conn.close()
    restarted = create_app(database)
    restarted.state.website_connector = StubConnector()
    with admin_for(restarted) as admin:
        polled = admin.post(f'/api/sources/{source_id}/poll')
        assert polled.status_code == 200, polled.text
        assert polled.json()['accepted_events'] == 1
        assert KEY not in admin.get('/api/sources').text
    key_file = tmp_path / '.agent-state' / 'connector.key'
    assert key_file.stat().st_mode & 0o777 == 0o600
    restarted.state.store.conn.close()


@pytest.mark.parametrize('operation', ['revoke', 'disconnect', 'permissions'])
def test_inflight_poll_cannot_override_revocation_pause_or_permissions(tmp_path, operation):
    app = create_app(tmp_path / 'sources.sqlite')
    app.state.website_connector = StubConnector()
    with admin_for(app) as admin:
        source_id = admin.post('/api/sources/website', json=CONFIG).json()['source']['id']
        entered, release = threading.Event(), threading.Event()
        class BlockingConnector:
            calls = 0
            def fetch(self, config, key):
                self.calls += 1
                if self.calls == 1:
                    entered.set()
                    assert release.wait(10), 'Concurrent operation never released the poll.'
                return response()
        app.state.website_connector = BlockingConnector()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(admin.post, f'/api/sources/{source_id}/poll')
            assert entered.wait(5)
            try:
                changed = admin.post(f'/api/sources/{source_id}/{operation}', json={'categories': ['account_changes']} if operation == 'permissions' else None)
                assert changed.status_code == 200, changed.text
            finally:
                release.set()
            result = pending.result(timeout=10)
        assert result.status_code == 409, result.text
        detail = admin.get(f'/api/sources/{source_id}').json()
        assert detail['events'] == []
        if operation == 'permissions':
            assert detail['source']['enabled_categories'] == ['account_changes']
        else:
            assert detail['source']['status'] == ('revoked' if operation == 'revoke' else 'disconnected')
    app.state.store.conn.close()
