"""Credential-scoped telemetry enrollment. No remote command/containment channel."""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import secrets
import re
import uuid
from urllib.parse import urlsplit
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator


def utcnow():
    return datetime.now(timezone.utc)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def timestamp(value):
    if not isinstance(value, str) or len(value) > 50:
        raise ValueError('An RFC3339 timestamp is required.')
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})', value):
        raise ValueError('An RFC3339 timestamp is required.')
    try:
        parsed = datetime.fromisoformat(value.replace('z', '+00:00').replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('An RFC3339 timestamp is required.') from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('Timestamp must include a timezone.')
    parsed = parsed.astimezone(timezone.utc)
    current = utcnow()
    if parsed < current - timedelta(hours=24) or parsed > current + timedelta(minutes=5):
        raise ValueError('Telemetry must be at most 24 hours old and no more than 5 minutes in the future.')
    return parsed.isoformat()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)


class ServerRequest(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    hostname: str = Field(min_length=1, max_length=253, pattern=r'^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$')
    website_url: str | None = Field(default=None, max_length=2048)
    mode: Literal['simulated', 'real']

    @field_validator('name')
    @classmethod
    def name_valid(cls, value):
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError('A visible server name is required.')
        return value.strip()

    @field_validator('hostname')
    @classmethod
    def hostname_valid(cls, value):
        return value.lower()

    @field_validator('website_url')
    @classmethod
    def url_valid(cls, value):
        if value is None or value == '':
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password or any(ord(c) < 32 for c in value):
            raise ValueError('Use an http(s) URL without embedded credentials. It is a display label only.')
        return value


class EnrollRequest(StrictModel):
    enrollment_token: str = Field(min_length=32, max_length=256)
    hostname: str = Field(min_length=1, max_length=253)
    mode: Literal['simulated', 'real']


class Metrics(StrictModel):
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    memory_used_bytes: int = Field(ge=0, le=2**63-1, strict=True)
    memory_total_bytes: int = Field(gt=0, le=2**63-1, strict=True)
    load_1m: float = Field(ge=0, le=1_000_000)
    uptime_seconds: float = Field(ge=0, le=10**12)

    @field_validator('cpu_percent', 'memory_percent', 'load_1m', 'uptime_seconds', mode='before')
    @classmethod
    def number_only(cls, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError('A finite JSON number is required.')
        return value

    @model_validator(mode='after')
    def memory_bounds(self):
        if self.memory_used_bytes > self.memory_total_bytes:
            raise ValueError('Used memory exceeds total memory.')
        return self


class Details(StrictModel):
    body: str | None = Field(default=None, max_length=1000)
    timestamp_basis: Literal['log', 'collection'] | None = None
    sender_domain: str | None = Field(default=None, max_length=253)
    claimed_domain: str | None = Field(default=None, max_length=253)
    new_device: StrictBool | None = None
    travel_kmh: float | None = Field(default=None, ge=0, le=1_000_000, strict=True)
    mfa_denials: int | None = Field(default=None, ge=0, le=100000, strict=True)
    result: str | None = Field(default=None, max_length=40)
    failed_attempts: int | None = Field(default=None, ge=0, le=100000, strict=True)
    periodic: StrictBool | None = None
    rare_destination: StrictBool | None = None
    bytes_out: int | None = Field(default=None, ge=0, le=2**63-1, strict=True)
    destination: str | None = Field(default=None, max_length=253)
    encoded_payload: StrictBool | None = None


class TelemetryEvent(StrictModel):
    id: str = Field(min_length=1, max_length=80, pattern=r'^[A-Za-z0-9_.:-]+$')
    timestamp: str
    source: Literal['email', 'auth', 'network']
    identity: str = Field(min_length=1, max_length=160)
    ip: str = Field(min_length=1, max_length=45)
    details: Details

    @field_validator('timestamp')
    @classmethod
    def time_valid(cls, value):
        return timestamp(value)

    @field_validator('ip')
    @classmethod
    def ip_valid(cls, value):
        return str(ipaddress.ip_address(value))

    @field_validator('identity')
    @classmethod
    def identity_valid(cls, value):
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError('A visible identity is required.')
        return value


class IngestRequest(StrictModel):
    batch_id: str = Field(min_length=1, max_length=80, pattern=r'^[A-Za-z0-9_.:-]+$')
    collected_at: str
    metrics: Metrics
    events: list[TelemetryEvent] = Field(max_length=100)

    @field_validator('collected_at')
    @classmethod
    def time_valid(cls, value):
        return timestamp(value)


def initialize(store):
    with store.lock:
        store.conn.executescript('''
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL, website_url TEXT,
                mode TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT, metrics TEXT,
                enrollment_hash TEXT UNIQUE, enrollment_expires_at TEXT, credential_hash TEXT UNIQUE,
                revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS server_batches (
                server_id TEXT NOT NULL, batch_id TEXT NOT NULL, received_at TEXT NOT NULL, payload_hash TEXT,
                PRIMARY KEY(server_id,batch_id));
            CREATE TABLE IF NOT EXISTS server_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL,
                timestamp TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS server_event_keys (
                server_id TEXT NOT NULL, external_id TEXT NOT NULL, event_id TEXT NOT NULL,
                PRIMARY KEY(server_id,external_id));
        ''')
        batch_columns = {r['name'] for r in store.conn.execute('PRAGMA table_info(server_batches)')}
        if 'payload_hash' not in batch_columns:
            store.conn.execute('ALTER TABLE server_batches ADD COLUMN payload_hash TEXT')
        columns = {r['name'] for r in store.conn.execute('PRAGMA table_info(events)')}
        if 'server_id' not in columns:
            store.conn.execute('ALTER TABLE events ADD COLUMN server_id TEXT')
        store.conn.execute('CREATE INDEX IF NOT EXISTS events_server_idx ON events(server_id)')
        store.conn.commit()


def public_server(store, row, events=None, incidents=None):
    # Explicit allowlist: hashes and enrollment metadata are never returned.
    if events is None or incidents is None:
        dashboard = store.dashboard()
        events, incidents = dashboard['events'], dashboard['incidents']
    own = [e for e in events if e.get('server_id') == row['id']]
    status = 'revoked' if row['revoked'] else 'pending'
    if not row['revoked'] and row['last_seen_at'] and row['credential_hash']:
        status = 'online' if (utcnow() - datetime.fromisoformat(row['last_seen_at'])).total_seconds() <= 120 else 'offline'
    return {key: row[key] for key in ('id', 'name', 'hostname', 'website_url', 'mode', 'last_seen_at', 'created_at')} | {
        'status': status, 'metrics': json.loads(row['metrics']) if row['metrics'] else None,
        'event_count': len(own), 'threat_count': sum(bool(e['suspicious']) for e in own),
        'incident_ids': [i['id'] for i in incidents if i.get('server_id') == row['id']]}


def install_routes(app, authorize):
    store = app.state.store
    initialize(store)
    router = APIRouter()

    def get_server(db, server_id):
        row = db.execute('SELECT * FROM servers WHERE id=?', (server_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'Server not found.')
        return row

    def issue_enrollment(db, server_id):
        token = secrets.token_urlsafe(48)
        expires = (utcnow() + timedelta(minutes=10)).isoformat()
        db.execute('UPDATE servers SET enrollment_hash=?,enrollment_expires_at=?,credential_hash=NULL,revoked=0,last_seen_at=NULL WHERE id=?',
            (digest(token), expires, server_id))
        return token, expires

    def https_only(request: Request):
        if request.url.scheme != 'https':
            raise HTTPException(403, 'Agent enrollment and telemetry require HTTPS.')

    def agent_identity(request: Request, authorization: str | None = Header(default=None)):
        https_only(request)
        if not authorization or not authorization.startswith('Bearer ') or len(authorization) > 300:
            raise HTTPException(401, 'A valid agent credential is required.')
        token = authorization[7:]
        with store.lock:
            row = store.conn.execute('SELECT id FROM servers WHERE credential_hash=? AND revoked=0', (digest(token),)).fetchone()
        if row is None:
            raise HTTPException(401, 'A valid agent credential is required.')
        return {'server_id': row['id'], 'credential_hash': digest(token)}

    @router.post('/api/servers', dependencies=[Depends(authorize)])
    def create_server(body: ServerRequest):
        server_id = 'srv-' + uuid.uuid4().hex
        with store.transaction() as db:
            db.execute('INSERT INTO servers(id,name,hostname,website_url,mode,created_at) VALUES (?,?,?,?,?,?)',
                (server_id, body.name, body.hostname, body.website_url, body.mode, utcnow().isoformat()))
            token, expires = issue_enrollment(db, server_id)
            store.audit(db, 'analyst', 'server_registered', f'{server_id}: registered {body.mode} telemetry collector. No remote access or commands configured.')
            result = public_server(store, get_server(db, server_id))
        return {'server': result, 'enrollment_token': token, 'expires_at': expires}

    @router.get('/api/servers', dependencies=[Depends(authorize)])
    def list_servers():
        with store.lock:
            dashboard = store.dashboard()
            return {'servers': [public_server(store, row, dashboard['events'], dashboard['incidents'])
                for row in store.conn.execute('SELECT * FROM servers ORDER BY created_at DESC')]}

    @router.get('/api/servers/{server_id}', dependencies=[Depends(authorize)])
    def server_detail(server_id: str):
        with store.lock:
            row = get_server(store.conn, server_id)
            dashboard = store.dashboard()
            return {'server': public_server(store, row, dashboard['events'], dashboard['incidents']),
                'events': [e for e in dashboard['events'] if e.get('server_id') == server_id],
                'incidents': [i for i in dashboard['incidents'] if i.get('server_id') == server_id],
                'metric_history': [{'timestamp': r['timestamp'], **json.loads(r['payload'])} for r in store.conn.execute(
                    'SELECT timestamp,payload FROM server_metrics WHERE server_id=? ORDER BY id ASC', (server_id,))]}

    @router.post('/api/servers/{server_id}/enrollment', dependencies=[Depends(authorize)])
    def rotate(server_id: str):
        with store.transaction() as db:
            get_server(db, server_id)
            token, expires = issue_enrollment(db, server_id)
            store.audit(db, 'analyst', 'server_enrollment_rotated', f'{server_id}: prior enrollment and agent credentials invalidated.')
            result = public_server(store, get_server(db, server_id))
        return {'server': result, 'enrollment_token': token, 'expires_at': expires}

    @router.post('/api/servers/{server_id}/revoke', dependencies=[Depends(authorize)])
    def revoke(server_id: str):
        with store.transaction() as db:
            get_server(db, server_id)
            db.execute('UPDATE servers SET revoked=1,enrollment_hash=NULL,enrollment_expires_at=NULL,credential_hash=NULL WHERE id=?', (server_id,))
            store.audit(db, 'analyst', 'server_credentials_revoked', f'{server_id}: telemetry credentials revoked; historical evidence retained.')
            result = public_server(store, get_server(db, server_id))
        return {'server': result}

    @router.post('/api/agent/enroll')
    def enroll(body: EnrollRequest, request: Request):
        https_only(request)
        with store.transaction() as db:
            row = db.execute('SELECT * FROM servers WHERE enrollment_hash=? AND revoked=0', (digest(body.enrollment_token),)).fetchone()
            if row is None or not row['enrollment_expires_at'] or datetime.fromisoformat(row['enrollment_expires_at']) < utcnow():
                raise HTTPException(401, 'Enrollment token is invalid, expired or already used.')
            if body.hostname.lower() != row['hostname'] or body.mode != row['mode']:
                raise HTTPException(403, 'Enrollment identity does not match registration.')
            token = secrets.token_urlsafe(48)
            db.execute('UPDATE servers SET enrollment_hash=NULL,enrollment_expires_at=NULL,credential_hash=? WHERE id=?', (digest(token), row['id']))
            store.audit(db, 'collector', 'server_enrolled', f"{row['id']}: scoped telemetry credential issued; no command capabilities.")
            return {'server_id': row['id'], 'agent_token': token}

    @router.post('/api/agent/ingest')
    def ingest(body: IngestRequest, principal=Depends(agent_identity)):
        with store.transaction() as db:
            row = get_server(db, principal['server_id'])
            # Revalidate under the transaction so a concurrent revocation wins.
            if row['revoked'] or row['credential_hash'] != principal['credential_hash']:
                raise HTTPException(401, 'A valid agent credential is required.')
            server_id = row['id']
            payload_hash = digest(json.dumps(body.model_dump(), sort_keys=True, separators=(',', ':')))
            receipt = db.execute('SELECT payload_hash FROM server_batches WHERE server_id=? AND batch_id=?', (server_id, body.batch_id)).fetchone()
            if receipt:
                if receipt['payload_hash'] != payload_hash:
                    raise HTTPException(409, 'Batch identifier already used with a different payload.')
                return {'accepted_events': 0, 'duplicate': True, 'server_id': server_id}
            received = utcnow().isoformat()
            db.execute('INSERT INTO server_batches(server_id,batch_id,received_at,payload_hash) VALUES (?,?,?,?)', (server_id, body.batch_id, received, payload_hash))
            accepted = 0
            for item in body.events:
                event_id = server_id + ':' + item.id
                inserted = db.execute('INSERT OR IGNORE INTO server_event_keys VALUES (?,?,?)', (server_id, item.id, event_id)).rowcount
                if not inserted:
                    continue
                event = item.model_dump(exclude_none=True)
                event.update(id=event_id, host=row['hostname'], server_id=server_id, telemetry_mode=row['mode'])
                event.update(store.detector.predict(event))
                accepted += db.execute('INSERT OR IGNORE INTO events(id,payload,server_id) VALUES (?,?,?)', (event_id, json.dumps(event), server_id)).rowcount
            metrics = json.dumps(body.metrics.model_dump())
            db.execute('UPDATE servers SET last_seen_at=?,metrics=? WHERE id=?', (received, metrics, server_id))
            db.execute('INSERT INTO server_metrics(server_id,timestamp,payload) VALUES (?,?,?)', (server_id, body.collected_at, metrics))
            db.execute('DELETE FROM server_metrics WHERE server_id=? AND id NOT IN (SELECT id FROM server_metrics WHERE server_id=? ORDER BY id DESC LIMIT 120)', (server_id, server_id))
            db.execute('DELETE FROM events WHERE server_id=? AND id NOT IN (SELECT id FROM events WHERE server_id=? ORDER BY rowid DESC LIMIT 5000)', (server_id, server_id))
            db.execute('DELETE FROM server_batches WHERE server_id=? AND rowid NOT IN (SELECT rowid FROM server_batches WHERE server_id=? ORDER BY rowid DESC LIMIT 1000)', (server_id, server_id))
            db.execute('DELETE FROM server_event_keys WHERE server_id=? AND rowid NOT IN (SELECT rowid FROM server_event_keys WHERE server_id=? ORDER BY rowid DESC LIMIT 10000)', (server_id, server_id))
            # Idempotency covers the most recent 1,000 batches / 10,000 event ids.
            # Event payloads and metric history are independently bounded.
            store.audit(db, 'collector', 'telemetry_received', f'{server_id}: accepted {accepted} events and one metrics sample.')
            return {'accepted_events': accepted, 'duplicate': False, 'server_id': server_id}

    app.include_router(router)
