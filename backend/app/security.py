"""Local admin bootstrap and bounded request handling for remote telemetry."""
import hashlib
import ipaddress
import json
import secrets
import threading
import time
from collections import OrderedDict, deque
from urllib.parse import urlsplit


class Limits:
    def __init__(self):
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, key, limit):
        clock = time.monotonic()
        with self.lock:
            self.entries.setdefault(key, deque())
            values = self.entries[key]
            while values and values[0] <= clock - 60:
                values.popleft()
            self.entries.move_to_end(key)
            while len(self.entries) > 2048:
                self.entries.popitem(last=False)
            if len(values) >= limit:
                return False
            values.append(clock)
            return True


class APISecurity:
    """Pure ASGI middleware: cap streamed bodies before any JSON/schema parsing."""
    def __init__(self, app, state, test_context=False):
        self.app = app
        self.state = state
        self.test_context = test_context
        self.limits = Limits()

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith('/api/'):
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope['headers']}
        path = scope['path']

        async def reject(status, message):
            body = json.dumps({'detail': message}).encode()
            await send({'type': 'http.response.start', 'status': status, 'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
            await send({'type': 'http.response.body', 'body': body})

        origin = headers.get(b'origin', b'').decode('latin-1')
        if origin:
            try:
                parsed = urlsplit(origin)
                own_origin = scope.get('scheme', 'http') + '://' + headers.get(b'host', b'').decode('latin-1')
                permitted = parsed.scheme in ('http', 'https') and not parsed.username and not parsed.password and (
                    parsed.hostname in ('localhost', '127.0.0.1', '::1') or origin == own_origin)
            except ValueError:
                permitted = False
            if not permitted:
                return await reject(403, 'Cross-origin API requests are not allowed.')

        agent_route = path in ('/api/agent/enroll', '/api/agent/ingest')
        if agent_route and scope.get('scheme') != 'https':
            return await reject(403, 'Agent enrollment and telemetry require HTTPS.')
        if path == '/api/session':
            host = (scope.get('client') or ('', 0))[0]
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = self.test_context and host == 'testclient'
            if not local:
                return await reject(403, 'Admin session bootstrap is available only from loopback.')
        elif path != '/api/health' and not agent_route:
            token = headers.get(b'x-soc-token', b'').decode('latin-1')
            if not token or len(token) > 256 or not secrets.compare_digest(token.encode('latin-1'), self.state.token.encode()):
                return await reject(403, 'A valid local SOC admin session token is required.')

        if path.startswith('/api/sources') and scope['method'] in ('POST', 'PUT', 'PATCH'):
            if not self.limits.allow('source-write:global', 60):
                return await reject(429, 'Source connection rate limit exceeded; retry in a minute.')

        if path == '/api/agent/enroll':
            host = (scope.get('client') or ('unknown', 0))[0]
            if not self.limits.allow('enroll:' + host, 20) or not self.limits.allow('enroll:global', 200):
                return await reject(429, 'Enrollment rate limit exceeded; retry in a minute.')
        elif path == '/api/agent/ingest':
            auth = headers.get(b'authorization', b'')
            if not auth.startswith(b'Bearer ') or len(auth) > 300:
                return await reject(401, 'A valid agent credential is required.')
            host = (scope.get('client') or ('unknown', 0))[0]
            key = hashlib.sha256(auth).hexdigest()
            if not self.limits.allow('ingest:' + key, 120) or not self.limits.allow('ingest-ip:' + host, 600):
                return await reject(429, 'Telemetry rate limit exceeded; retry in a minute.')

        if scope['method'] in ('POST', 'PUT', 'PATCH'):
            try:
                declared = int(headers.get(b'content-length', b'0'))
            except ValueError:
                return await reject(400, 'Invalid content length.')
            if declared > 1024 * 1024 or declared < 0:
                return await reject(413, 'Request body is limited to 1 MiB.')
            chunks = []
            size = 0
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                chunk = message.get('body', b'')
                size += len(chunk)
                if size > 1024 * 1024:
                    return await reject(413, 'Request body is limited to 1 MiB.')
                if chunk:
                    chunks.append(chunk)
                if not message.get('more_body', False):
                    break
            body = b''.join(chunks)
            sent = False
            async def bounded_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {'type': 'http.request', 'body': body, 'more_body': False}
                return await receive()
            receiver = bounded_receive
        else:
            receiver = receive

        async def no_cache(message):
            if message['type'] == 'http.response.start':
                message['headers'] = [(k, v) for k, v in message.get('headers', []) if k.lower() != b'cache-control'] + [(b'cache-control', b'no-store')]
            await send(message)
        await self.app(scope, receiver, no_cache)
