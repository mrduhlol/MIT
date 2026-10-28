"""Collector security boundaries and real verified-TLS transport on loopback."""
from argparse import Namespace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading

import pytest

from agent import soc_agent as agent


@pytest.fixture
def state(tmp_path):
    return agent.secure_directory(tmp_path / 'private')


def config():
    return {'url': 'https://localhost:8443', 'mode': 'simulated', 'server_id': 'srv-test', 'agent_token': 'never-print-this-secret', 'ca_cert': None}


def acknowledgment(payload):
    return {'server_id': 'srv-test', 'accepted_events': len(payload['events']), 'duplicate': False}


@pytest.mark.parametrize('url', ['http://localhost:8000', 'https://user:secret@localhost', 'https://localhost/path', 'https://localhost?token=secret', 'https://localhost/#fragment'])
def test_requires_https_origin_without_embedded_secrets(url):
    with pytest.raises(agent.AgentError):
        agent.validate_url(url)


def test_private_state_rejects_symlinks_and_unsafe_permissions(state, tmp_path):
    agent.write_private(state / 'credentials.json', config())
    assert (state.stat().st_mode & 0o777) == 0o700
    assert ((state / 'credentials.json').stat().st_mode & 0o777) == 0o600
    assert agent.read_json(state / 'credentials.json')['agent_token'] == 'never-print-this-secret'
    (state / 'credentials.json').chmod(0o644)
    with pytest.raises(agent.AgentError, match='0600'):
        agent.read_private(state / 'credentials.json')
    (tmp_path / 'linked').symlink_to(state, target_is_directory=True)
    with pytest.raises(agent.AgentError, match='symlink'):
        agent.secure_directory(tmp_path / 'linked')
    (state / 'linked.json').symlink_to(state / 'credentials.json')
    with pytest.raises(agent.AgentError):
        agent.write_private(state / 'linked.json', {})
    with pytest.raises(agent.AgentError):
        agent.read_private(state / 'linked.json')


def test_pending_retry_keeps_exact_batch_and_advances_only_after_ack(state):
    sent = []

    def fail(_url, _path, payload, **_kwargs):
        sent.append(payload)
        raise agent.AgentError('Temporary network failure')

    with pytest.raises(agent.AgentError):
        agent.upload_once(state, config(), sender=fail)
    assert (state / 'pending.json').exists()
    assert not (state / 'state.json').exists()

    def success(_url, _path, payload, **_kwargs):
        sent.append(payload)
        return acknowledgment(payload)

    agent.upload_once(state, config(), sender=success)
    assert sent[0] == sent[1]
    assert not (state / 'pending.json').exists()
    assert (state / 'state.json').exists()
    agent.upload_once(state, config(), sender=success)
    assert sent[2]['batch_id'] != sent[0]['batch_id']
    assert {e['id'] for e in sent[2]['events']}.isdisjoint(e['id'] for e in sent[0]['events'])


def test_invalid_acknowledgment_keeps_pending_data(state):
    with pytest.raises(agent.AgentError, match='acknowledgment'):
        agent.upload_once(state, config(), sender=lambda *args, **kwargs: {'server_id': 'wrong'})
    assert (state / 'pending.json').exists()
    assert not (state / 'state.json').exists()


def test_real_metrics_use_proc_and_simulated_mode_never_reads_proc(tmp_path, monkeypatch):
    (tmp_path / 'stat').write_text('cpu 10 0 5 85 0 0 0 0\n')
    (tmp_path / 'meminfo').write_text('MemTotal: 1024 kB\nMemAvailable: 256 kB\n')
    (tmp_path / 'uptime').write_text('1234.5 999.0\n')
    (tmp_path / 'loadavg').write_text('0.50 0.40 0.30 1/10 42\n')
    metrics = agent.collect_metrics(tmp_path, sample_seconds=0)
    assert metrics['memory_total_bytes'] == 1024 * 1024
    assert metrics['memory_used_bytes'] == 768 * 1024 and metrics['memory_percent'] == 75
    assert metrics['uptime_seconds'] == 1234.5 and metrics['load_1m'] == .5
    monkeypatch.setattr(agent, 'collect_metrics', lambda: pytest.fail('Simulated mode read real metrics'))
    pending = agent.prepare_batch(config(), {'cursors': {}})
    assert len(pending['batch']['events']) == 3
    with pytest.raises(agent.AgentError, match='cannot read real'):
        agent.prepare_batch(config(), {}, events_file='/not/read')


def test_tail_partial_lines_rotation_truncation_and_bounds(tmp_path):
    source = tmp_path / 'telemetry.jsonl'
    source.write_text('first\npartial')
    rows, cursor = agent.read_tail(source)
    assert rows == ['first'] and cursor['offset'] == len('first\n')
    with source.open('a') as handle:
        handle.write('-complete\n')
    rows, cursor = agent.read_tail(source, cursor)
    assert rows == ['partial-complete']
    source.write_text('new\n')
    rows, cursor = agent.read_tail(source, cursor)
    assert rows == ['new']
    source.rename(tmp_path / 'rotated')
    source.write_text('replacement\n')
    assert agent.read_tail(source, cursor)[0] == ['replacement']
    source.write_text('x' * 100_000 + '\nvalid\n')
    rows, cursor = agent.read_tail(source)
    assert rows == [] and cursor['offset'] <= agent.MAX_READ
    rows, _ = agent.read_tail(source, cursor)
    assert rows == ['valid']
    source.write_text('one\n' * 200)
    assert len(agent.read_tail(source)[0]) == 100


def test_log_sanitization_drops_tokens_and_never_forwards_raw_auth_lines():
    raw = {'source': 'email', 'identity': 'user', 'ip': '192.0.2.1', 'host': 'attacker-selected', 'agent_token': 'secret',
           'details': {'body': 'token=secret Bearer private.jwt.value password=hunter2', 'password': 'hunter2', 'api_key': 'secret', 'sender_domain': 'example.invalid'}}
    event = agent.sanitize_event(raw)
    assert event and 'host' not in event and 'agent_token' not in event
    serialized = json.dumps(event)
    assert 'hunter2' not in serialized and 'private.jwt.value' not in serialized and 'token=secret' not in serialized
    lines = ['sshd[5]: Failed password for invalid user alice from 192.0.2.2 port 22 ssh2 secret-extra',
             'sshd[5]: Failed password for alice from 192.0.2.2 port 22 ssh2',
             'sshd[5]: Accepted publickey for bob from 2001:db8::2 port 22 ssh2']
    events = agent.auth_events(lines)
    assert len(events) == 2
    assert events[0]['details']['failed_attempts'] == 2
    assert 'secret-extra' not in json.dumps(events) and 'sshd' not in json.dumps(events)


@pytest.fixture(scope='module')
def tls_server(tmp_path_factory):
    directory = tmp_path_factory.mktemp('agent-tls')
    key, cert = directory / 'key.pem', directory / 'cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.headers.get('Authorization')))
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path == '/redirect':
                self.send_response(307)
                self.send_header('Location', '/credential-leak')
                self.end_headers()
                return
            result = {'server_id': 'srv-test', 'agent_token': 'private-agent-token'} if self.path.endswith('/enroll') else acknowledgment(payload)
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'https://localhost:{server.server_port}', str(cert), received
    server.shutdown()
    server.server_close()
    thread.join()


def test_verified_tls_enrollment_upload_and_secret_output(tls_server, state, capsys):
    url, cert, received = tls_server
    token_file = state / 'enrollment.txt'
    token_file.write_text('one-use-private-token')
    token_file.chmod(0o600)
    args = Namespace(url=url, ca_cert=cert, hostname='test-host', mode='simulated', token_file=str(token_file))
    agent.enroll(args, state)
    credentials = agent.read_json(state / 'credentials.json')
    assert credentials['agent_token'] == 'private-agent-token'
    result = agent.upload_once(state, credentials)
    assert result['accepted_events'] == 3
    assert received[-1] == ('/api/agent/ingest', 'Bearer private-agent-token')
    output = capsys.readouterr()
    assert 'private-agent-token' not in output.out + output.err
    assert 'one-use-private-token' not in output.out + output.err


def test_tls_requires_trusted_ca_and_matching_hostname(tls_server):
    url, cert, _ = tls_server
    with pytest.raises(agent.AgentError, match='Verified HTTPS'):
        agent.post_json(url, '/api/agent/enroll', {})
    with pytest.raises(agent.AgentError, match='Verified HTTPS'):
        agent.post_json(url.replace('localhost', '127.0.0.1'), '/api/agent/enroll', {}, ca_cert=cert)


def test_redirect_never_forwards_bearer(tls_server):
    url, cert, received = tls_server
    start = len(received)
    with pytest.raises(agent.AgentError, match='redirect refused'):
        agent.post_json(url, '/redirect', {}, ca_cert=cert, token='do-not-forward')
    assert received[start:] == [('/redirect', 'Bearer do-not-forward')]


def test_auth_log_timestamps_are_not_rebased_and_windows_do_not_merge():
    from datetime import timedelta
    observed = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    base = 'sshd[5]: Failed password for alice from 192.0.2.2 port 22 ssh2'
    old = (observed-timedelta(days=2)).isoformat() + ' ' + base
    future = (observed+timedelta(minutes=10)).isoformat() + ' ' + base
    recent = (observed-timedelta(minutes=1)).isoformat() + ' ' + base
    earlier = (observed-timedelta(minutes=8)).isoformat() + ' ' + base
    events = agent.auth_events([old, future, recent, earlier, base])
    assert len(events) == 3
    logs = [event for event in events if event['details']['timestamp_basis'] == 'log']
    assert {event['timestamp'] for event in logs} == {(observed-timedelta(minutes=1)).isoformat(), (observed-timedelta(minutes=8)).isoformat()}
    assert all(event['details']['failed_attempts'] == 1 for event in events)
    assert sum(event['details']['timestamp_basis'] == 'collection' for event in events) == 1


def test_syslog_timestamp_uses_local_zone_and_rejects_old_records():
    from datetime import timedelta
    observed = datetime.now(timezone.utc)
    recent = (observed-timedelta(minutes=10)).astimezone()
    parsed, basis = agent.auth_timestamp(recent.strftime('%b %d %H:%M:%S') + ' sshd: message', observed)
    assert basis == 'log'
    assert abs((parsed-recent.astimezone(timezone.utc)).total_seconds()) < 1
    old = (observed-timedelta(days=3)).astimezone()
    assert agent.auth_timestamp(old.strftime('%b %d %H:%M:%S') + ' sshd: message', observed) is None


def test_redacts_private_key_blocks_and_quoted_credentials():
    text = '{"password": "hidden phrase", "token": "hidden-token"} Authorization: Basic abc123=='
    result = agent.scrub_text(text)
    for secret in ('hidden phrase', 'hidden-token', 'abc123'):
        assert secret not in result
    for key in ('-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-key-material\n-----END OPENSSH PRIVATE KEY-----',
                '-----BEGIN RSA PRIVATE KEY-----\ntruncated-private-material'):
        assert 'private-key-material' not in agent.scrub_text(key)
        assert 'truncated-private-material' not in agent.scrub_text(key)
