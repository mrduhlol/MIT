#!/usr/bin/env python3
"""Outbound-only Linux telemetry collector. No commands, listener, or containment."""
from __future__ import annotations

import argparse
import fcntl
import getpass
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
import uuid

MAX_READ = 65_536
MAX_LINES = 100
MAX_LINE = 4096
DETAIL_FIELDS = {'body', 'sender_domain', 'claimed_domain', 'new_device', 'travel_kmh', 'mfa_denials', 'result', 'failed_attempts', 'periodic', 'rare_destination', 'bytes_out', 'destination', 'encoded_payload'}


class AgentError(Exception):
    """Safe operator-facing message; never includes response bodies or credentials."""


class AuthenticationError(AgentError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def secure_directory(path):
    path = Path(path).expanduser().absolute()
    for item in [path, *path.parents]:
        if item.is_symlink():
            raise AgentError('State paths must not contain symlinks.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise AgentError('State directory must be owned by this user with mode 0700.')
    return path


def read_private(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise AgentError('Credential and state files must be regular, owned by this user, and mode 0600.')
            content = handle.read(1_048_577)
            if len(content) > 1_048_576:
                raise AgentError('Private state file exceeds the size limit.')
            return content
    except OSError:
        raise AgentError('Cannot securely read the requested private file.') from None


def write_private(path, value):
    path = Path(path)
    if path.is_symlink():
        raise AgentError('Refusing to overwrite a symlink.')
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, separators=(',', ':'), allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_json(path, default=None):
    if not Path(path).exists() and not Path(path).is_symlink():
        return default
    try:
        return json.loads(read_private(path))
    except (ValueError, TypeError):
        raise AgentError('Private state is invalid JSON; refusing to discard it.') from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise AgentError('Server URL must be an HTTPS origin without credentials, path, query, or fragment.')
    try:
        parsed.port
    except ValueError:
        raise AgentError('Invalid HTTPS port.') from None
    return url.rstrip('/')


def post_json(url, path, payload, *, ca_cert=None, token=None):
    origin = validate_url(url)
    context = ssl.create_default_context(cafile=ca_cert)
    # Default verification, hostname checking, no environment proxy, no redirects.
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = json.dumps(payload, allow_nan=False, separators=(',', ':')).encode()
    if len(body) > 1_000_000:
        raise AgentError('Telemetry batch exceeds the upload size limit.')
    request = Request(origin + path, data=body, headers=headers, method='POST')
    try:
        with opener.open(request, timeout=15) as response:
            content = response.read(65_537)
            if len(content) > 65_536:
                raise AgentError('Server response exceeds the size limit.')
            return json.loads(content)
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise AuthenticationError('Enrollment or agent authorization was rejected. Request fresh enrollment or check revocation.') from None
        if 300 <= exc.code < 400:
            raise AgentError('Server redirect refused; credentials were not forwarded.') from None
        if exc.code in (400, 409, 413, 422):
            raise AuthenticationError(f'Server rejected the batch (HTTP {exc.code}); pending data retained for operator review.') from None
        raise AgentError(f'Server request failed (HTTP {exc.code}); pending data retained.') from None
    except (URLError, TimeoutError, ssl.SSLError, OSError):
        raise AgentError('Verified HTTPS request failed. Check connectivity, hostname, certificate trust, and clock; pending data retained.') from None
    except (ValueError, TypeError):
        raise AgentError('Server returned an invalid JSON response; pending data retained.') from None


def cpu_ticks(proc):
    values = [int(value) for value in (proc / 'stat').read_text().splitlines()[0].split()[1:9]]
    return sum(values), values[3] + (values[4] if len(values) > 4 else 0)


def collect_metrics(proc=Path('/proc'), sample_seconds=.2):
    first = cpu_ticks(proc)
    time.sleep(sample_seconds)
    second = cpu_ticks(proc)
    total = second[0] - first[0]
    idle = second[1] - first[1]
    memory = {}
    for line in (proc / 'meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        memory[key] = int(value.strip().split()[0]) * 1024
    memory_total = memory['MemTotal']
    available = memory.get('MemAvailable', memory.get('MemFree', 0))
    used = max(0, min(memory_total, memory_total - available))
    return {'cpu_percent': round(max(0, min(100, 100*(total-idle)/total)) if total > 0 else 0, 2),
            'memory_percent': round(100*used/memory_total, 2), 'memory_used_bytes': used,
            'memory_total_bytes': memory_total, 'load_1m': float((proc / 'loadavg').read_text().split()[0]),
            'uptime_seconds': float((proc / 'uptime').read_text().split()[0])}


def read_tail(path, cursor=None):
    """Bounded, complete-line reads. Rotation/truncation starts the replacement at zero."""
    cursor = cursor or {}
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        raise AgentError('Cannot read the explicitly configured telemetry file.') from None
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise AgentError('Telemetry inputs must be regular files, not devices, pipes, or symlinks.')
        same = cursor.get('device') == info.st_dev and cursor.get('inode') == info.st_ino
        offset = cursor.get('offset', 0) if same and cursor.get('offset', 0) <= info.st_size else 0
        dropping = bool(cursor.get('dropping', False)) if same and offset else False
        handle.seek(offset)
        lines, consumed = [], 0
        while consumed < MAX_READ and len(lines) < MAX_LINES:
            start = handle.tell()
            raw = handle.readline(min(MAX_LINE + 1, MAX_READ-consumed))
            if not raw:
                break
            consumed += len(raw)
            complete = raw.endswith(b'\n')
            if dropping or len(raw) > MAX_LINE:
                dropping = not complete
                continue
            if not complete:
                handle.seek(start)  # Never consume a partial final line.
                break
            lines.append(raw.decode('utf-8', errors='replace').strip())
        next_cursor = {'device': info.st_dev, 'inode': info.st_ino, 'offset': handle.tell(), 'dropping': dropping}
    return lines, next_cursor


def scrub_text(value):
    text = str(value)
    # Remove key blocks before truncation, including truncated private-key blocks.
    text = re.sub(r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)', '[PRIVATE KEY REDACTED]', text)
    text = text[:1000]
    text = re.sub(r'(?i)\b(?:bearer\s+|basic\s+)[A-Za-z0-9._~+/=-]+', '[AUTHORIZATION REDACTED]', text)
    pattern = r"(?i)\b(password|passwd|token|api[_-]?key|secret)[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    return re.sub(pattern, r'\1=[REDACTED]', text)


def sanitize_event(value):
    if not isinstance(value, dict) or value.get('source') not in ('email', 'auth', 'network'):
        return None
    details = value.get('details')
    if not isinstance(details, dict):
        return None
    allowed = {}
    for key, item in details.items():
        if key not in DETAIL_FIELDS or item is None or not isinstance(item, (str, bool, int, float)):
            continue
        if isinstance(item, float) and not math.isfinite(item):
            continue
        allowed[key] = scrub_text(item) if isinstance(item, str) else item
    try:
        address = str(ipaddress.ip_address(value.get('ip', '127.0.0.1')))
        timestamp = value.get('timestamp', utc_now())
        parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - parsed).total_seconds()
        if not -300 <= age <= 86400:
            return None
    except (ValueError, TypeError, AttributeError):
        return None
    return {'id': str(uuid.uuid4()), 'timestamp': parsed.astimezone(timezone.utc).isoformat(),
            'source': value['source'], 'identity': scrub_text(value.get('identity', 'unknown'))[:100],
            'ip': address, 'details': allowed}


def auth_timestamp(line, observed_at):
    """Parse known prefixes; untimestamped input is explicitly collection-based."""
    iso = re.match(r'^(\d{4}-\d{2}-\d{2}T\S+)', line)
    syslog = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    basis = 'log' if iso or syslog else 'collection'
    try:
        if iso:
            timestamp = datetime.fromisoformat(iso.group(1).replace('Z', '+00:00'))
            if timestamp.tzinfo is None:
                return None
            timestamp = timestamp.astimezone(timezone.utc)
        elif syslog:
            # Syslog has no year/zone. Infer the current or immediately previous
            # year in this machine's local zone; reject anything outside 24h.
            local_now = observed_at.astimezone()
            parsed = datetime.strptime(f'{local_now.year} {syslog.group(1)}', '%Y %b %d %H:%M:%S')
            timestamp = parsed.astimezone(timezone.utc)
            if (timestamp-observed_at).total_seconds() > 300:
                timestamp = parsed.replace(year=local_now.year-1).astimezone(timezone.utc)
        else:
            timestamp = observed_at
        if not -300 <= (observed_at-timestamp).total_seconds() <= 86400:
            return None
        return timestamp, basis
    except (ValueError, OverflowError):
        return None


def auth_events(lines):
    aggregated = {}
    observed_at = datetime.now(timezone.utc)
    for line in lines:
        match = re.search(r'\b(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?([A-Za-z0-9_.@-]{1,100}) from ([0-9a-fA-F:.]+)\b', line)
        if not match:
            continue
        outcome, identity, address = match.groups()
        parsed = auth_timestamp(line, observed_at)
        if parsed is None:
            continue
        timestamp, basis = parsed
        try:
            address = str(ipaddress.ip_address(address))
        except ValueError:
            continue
        key = (identity, address, outcome.startswith('Failed'), int(timestamp.timestamp()) // 300, basis)
        bucket = aggregated.setdefault(key, {'count': 0, 'timestamp': timestamp})
        bucket['count'] += 1
        bucket['timestamp'] = max(bucket['timestamp'], timestamp)
    return [{'id': str(uuid.uuid4()), 'timestamp': bucket['timestamp'].isoformat(), 'source': 'auth', 'identity': identity, 'ip': address,
             'details': {'result': 'failed' if failed else 'success', 'failed_attempts': bucket['count'] if failed else 0, 'timestamp_basis': basis}}
            for (identity, address, failed, _window, basis), bucket in aggregated.items()]


def simulated_sample():
    timestamp = utc_now()
    rows = [
        {'source': 'email', 'details': {'body': 'Please verify your account to retain access.', 'sender_domain': 'account-check.invalid', 'claimed_domain': 'demo.example'}},
        {'source': 'auth', 'details': {'new_device': True, 'travel_kmh': 4200, 'mfa_denials': 8, 'result': 'success'}},
        {'source': 'network', 'details': {'periodic': True, 'rare_destination': True, 'bytes_out': 85_000_000, 'destination': '198.51.100.42'}},
    ]
    events = [{**row, 'id': str(uuid.uuid4()), 'timestamp': timestamp, 'identity': 'demo.user', 'ip': '192.0.2.25'} for row in rows]
    metrics = {'cpu_percent': 24.0, 'memory_percent': 37.5, 'memory_used_bytes': 3_221_225_472,
               'memory_total_bytes': 8_589_934_592, 'load_1m': .42, 'uptime_seconds': 3600.0}
    return metrics, events


def prepare_batch(config, state, *, events_file=None, auth_log=None):
    next_state = json.loads(json.dumps(state))
    cursors = next_state.setdefault('cursors', {})
    if config['mode'] == 'simulated':
        if events_file or auth_log:
            raise AgentError('Simulated mode cannot read real telemetry files.')
        metrics, events = simulated_sample()
    else:
        metrics, events = collect_metrics(), []
        # One source per cycle when both configured keeps the batch <=100 while
        # retaining complete per-source cursors and fair alternating coverage.
        sources = [('jsonl', events_file), ('auth', auth_log)]
        sources = [(kind, path) for kind, path in sources if path]
        if sources:
            index = state.get('source_index', 0) % len(sources)
            kind, path = sources[index]
            key = kind + ':' + str(Path(path).expanduser().absolute())
            lines, cursor = read_tail(Path(path).expanduser(), cursors.get(key))
            if kind == 'auth':
                events = auth_events(lines)
            else:
                for line in lines:
                    try:
                        value = sanitize_event(json.loads(line))
                        if value:
                            events.append(value)
                    except (ValueError, TypeError):
                        continue
            cursors[key] = cursor
            next_state['source_index'] = index + 1
    return {'batch': {'batch_id': str(uuid.uuid4()), 'collected_at': utc_now(), 'metrics': metrics, 'events': events}, 'next_state': next_state}


def upload_once(directory, config, *, events_file=None, auth_log=None, sender=post_json):
    pending_path = directory / 'pending.json'
    pending = read_json(pending_path)
    if pending is None:
        state = read_json(directory / 'state.json', {'cursors': {}})
        pending = prepare_batch(config, state, events_file=events_file, auth_log=auth_log)
        write_private(pending_path, pending)  # Stable ID and exact payload before I/O.
    response = sender(config['url'], '/api/agent/ingest', pending['batch'], ca_cert=config.get('ca_cert'), token=config['agent_token'])
    if (not isinstance(response, dict) or response.get('server_id') != config['server_id']
            or type(response.get('duplicate')) is not bool
            or type(response.get('accepted_events')) is not int
            or response['accepted_events'] != (0 if response['duplicate'] else len(pending['batch']['events']))):
        raise AgentError('Server acknowledgment does not match this batch; pending data retained.')
    write_private(directory / 'state.json', pending['next_state'])
    pending_path.unlink()
    return response


def enroll(args, directory):
    if (directory / 'credentials.json').exists() or (directory / 'credentials.json').is_symlink():
        raise AgentError('This state directory is already enrolled; use a new private state directory.')
    url = validate_url(args.url)
    token = read_private(Path(args.token_file).expanduser()).strip() if args.token_file else getpass.getpass('One-use enrollment token: ').strip()
    if not token or len(token) > 4096:
        raise AgentError('Enrollment token is missing or invalid.')
    ca_cert = str(Path(args.ca_cert).expanduser().absolute()) if args.ca_cert else None
    result = post_json(url, '/api/agent/enroll', {'enrollment_token': token, 'hostname': args.hostname, 'mode': args.mode}, ca_cert=ca_cert)
    if not isinstance(result, dict) or not isinstance(result.get('server_id'), str) or not isinstance(result.get('agent_token'), str) or not result['agent_token']:
        raise AgentError('Enrollment response is missing required credentials.')
    write_private(directory / 'credentials.json', {'url': url, 'ca_cert': ca_cert, 'hostname': args.hostname,
        'mode': args.mode, 'server_id': result['server_id'], 'agent_token': result['agent_token']})
    print('Enrollment complete. Credentials saved privately; no remote commands or containment are enabled.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    enroll_parser = commands.add_parser('enroll', help='Exchange a one-use token over verified HTTPS')
    enroll_parser.add_argument('--url', required=True)
    enroll_parser.add_argument('--ca-cert')
    enroll_parser.add_argument('--hostname', default=socket.gethostname())
    enroll_parser.add_argument('--mode', choices=['simulated', 'real'], required=True)
    enroll_parser.add_argument('--token-file', help='Owner-only 0600 token file; otherwise prompt without echo')
    run_parser = commands.add_parser('run', help='Send outbound telemetry only')
    run_parser.add_argument('--once', action='store_true')
    run_parser.add_argument('--interval', type=int, default=30)
    run_parser.add_argument('--events-file')
    run_parser.add_argument('--auth-log')
    for child in (enroll_parser, run_parser):
        child.add_argument('--state-dir', default='~/.local/state/ai-defense')
    args = parser.parse_args(argv)
    try:
        directory = secure_directory(args.state_dir)
        lock_path = directory / 'agent.lock'
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            raise AgentError('Another agent is using this state directory.') from None
        try:
            if args.command == 'enroll':
                enroll(args, directory)
                return 0
            if args.interval < 30:
                raise AgentError('Collection interval must be at least 30 seconds.')
            config = read_json(directory / 'credentials.json')
            if not isinstance(config, dict) or not all(isinstance(config.get(key), str) and config[key] for key in ('url', 'agent_token', 'server_id', 'mode')) or config.get('mode') not in ('real', 'simulated'):
                raise AgentError('Enroll this state directory before running the collector.')
            validate_url(config['url'])
            while True:
                try:
                    upload_once(directory, config, events_file=args.events_file, auth_log=args.auth_log)
                    print('Telemetry acknowledged. No remote actions were executed.', flush=True)
                except AuthenticationError:
                    raise
                except AgentError as exc:
                    if args.once:
                        raise
                    print(str(exc), file=sys.stderr, flush=True)
                if args.once:
                    return 0
                time.sleep(args.interval)
        finally:
            os.close(lock_fd)
    except KeyboardInterrupt:
        return 0
    except (AgentError, OSError, ValueError, KeyError, TypeError) as exc:
        print(str(exc) if isinstance(exc, AgentError) else 'Agent configuration or local collection failed; credentials were not logged.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
