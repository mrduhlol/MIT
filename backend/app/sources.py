"""Authenticated read-only data sources for the existing single-admin SOC workspace."""
from datetime import datetime
import json
import os
from pathlib import Path
import stat
import uuid

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request

from .connectors import CATEGORIES, ConnectorError, PermissionsRequest, WebsiteConfig, WebsiteConnector
from .servers import public_server, utcnow


def initialize(store):
    with store.lock:
        store.conn.executescript('''
            CREATE TABLE IF NOT EXISTS data_sources (
                id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
                base_url TEXT NOT NULL, events_url TEXT NOT NULL,
                encrypted_credential TEXT, mode TEXT NOT NULL,
                enabled_categories TEXT NOT NULL, available_categories TEXT NOT NULL,
                granted_permissions TEXT NOT NULL, status TEXT NOT NULL,
                created_at TEXT NOT NULL, last_success_at TEXT, last_event_at TEXT,
                error TEXT, revision INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS source_event_keys (
                source_id TEXT NOT NULL, external_id TEXT NOT NULL, event_id TEXT NOT NULL,
                PRIMARY KEY(source_id, external_id));
        ''')
        store.conn.commit()


def credential_cipher(store):
    supplied = os.environ.get('SOC_CREDENTIAL_KEY')
    if supplied:
        try:
            return Fernet(supplied.encode('ascii'))
        except (ValueError, UnicodeError):
            raise RuntimeError('SOC_CREDENTIAL_KEY must be a valid Fernet key.') from None
    if str(store.path) == ':memory:':
        return Fernet(Fernet.generate_key())
    directory = Path(store.path).resolve().parent / '.agent-state'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise RuntimeError('Credential key directory must be owned by this process user and not a symlink.')
    os.chmod(directory, 0o700)
    target = directory / 'connector.key'
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(Fernet.generate_key())
            handle.flush()
            os.fsync(handle.fileno())
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError('Credential key file must be owned by this process user with mode 0600.')
            return Fernet(handle.read(128))
    except (OSError, ValueError):
        raise RuntimeError('Cannot read the protected connector encryption key.') from None


def install_routes(app, authorize):
    store = app.state.store
    initialize(store)
    cipher = credential_cipher(store)
    # Injectable connector interface used by tests; production always uses verified HTTPS.
    app.state.website_connector = WebsiteConnector()
    router = APIRouter(prefix='/api/sources', dependencies=[Depends(authorize)])

    def https_only(request: Request):
        if request.url.scheme != 'https':
            raise HTTPException(403, 'Data-source connections and credential changes require HTTPS.')

    def row_for(source_id):
        with store.lock:
            row = store.conn.execute('SELECT * FROM data_sources WHERE id=?', (source_id,)).fetchone()
            if row is None:
                raise HTTPException(404, 'Website source not found.')
            return dict(row)

    def own_evidence(source_id, dashboard=None):
        dashboard = dashboard or store.dashboard()
        return ([event for event in dashboard['events'] if event.get('server_id') == source_id],
                [incident for incident in dashboard['incidents'] if incident.get('server_id') == source_id])

    def public_source(row, dashboard=None):
        events, incidents = own_evidence(row['id'], dashboard)
        status = row['status']
        if status == 'connected' and row['last_success_at'] and (utcnow() - datetime.fromisoformat(row['last_success_at'])).total_seconds() > 300:
            status = 'offline'
        return {key: row[key] for key in ('id', 'type', 'name', 'base_url', 'events_url', 'mode', 'created_at', 'last_success_at', 'last_event_at', 'error')} | {
            'status': status,
            'available_categories': json.loads(row['available_categories']),
            'granted_permissions': json.loads(row['granted_permissions']),
            'enabled_categories': json.loads(row['enabled_categories']),
            'last_heartbeat_at': None, 'event_count': len(events),
            'last_event_received_at': max((e['received_at'] for e in events if e.get('received_at')), default=None),
            'threat_count': sum(bool(event['suspicious']) for event in events),
            'incident_ids': [incident['id'] for incident in incidents],
            'collection': 'manual_poll', 'has_credential': bool(row['encrypted_credential']),
        }

    def server_source(row, dashboard):
        value = public_server(store, row, dashboard['events'], dashboard['incidents'])
        events, _ = own_evidence(row['id'], dashboard)
        categories = ['health_metrics', 'authentication', 'network', 'email']
        return {**value, 'type': 'simulated' if row['mode'] == 'simulated' else 'linux',
                'status': 'connected' if value['status'] == 'online' else value['status'],
                'available_categories': categories,
                'granted_permissions': ['telemetry:write'] if row['credential_hash'] and not row['revoked'] else [],
                'enabled_categories': categories,
                'last_success_at': row['last_seen_at'], 'last_heartbeat_at': row['last_seen_at'],
                'last_event_at': max((e['timestamp'] for e in events), default=None),
                'last_event_received_at': max((e['received_at'] for e in events if e.get('received_at')), default=None),
                'error': None, 'collection': 'agent_push',
                'permissions_note': 'Telemetry write permission is scoped to this source. Categories describe supported ingestion; local log-file access is configured on the host and is not remotely verified.'}

    def check(config, key, categories, expected_mode=None):
        try:
            result = app.state.website_connector.fetch(config, key)
            if not set(categories).issubset(result.permissions.granted):
                raise ConnectorError('The API key does not grant every selected event category.')
            if expected_mode is not None and result.telemetry_mode != expected_mode:
                raise ConnectorError('The API telemetry provenance changed. Register a separate source for this mode.')
            return result
        except ConnectorError as exc:
            raise HTTPException(502, str(exc)) from None

    def decrypt(row):
        if not row['encrypted_credential'] or row['status'] == 'revoked':
            raise HTTPException(409, 'Credentials have been revoked. Register a new source with a valid provider key.')
        try:
            return cipher.decrypt(row['encrypted_credential'].encode()).decode()
        except (InvalidToken, ValueError, UnicodeError):
            raise HTTPException(503, 'Stored credentials cannot be unlocked. Restore the original encryption key.') from None

    def validated_row(source_id, categories=None, allow_disconnected=True):
        row = row_for(source_id)
        if not allow_disconnected and row['status'] == 'disconnected':
            raise HTTPException(409, 'Source is disconnected. Resume it before collecting events.')
        key = decrypt(row)
        try:
            result = check(row, key, categories if categories is not None else json.loads(row['enabled_categories']), row['mode'])
        except HTTPException as exc:
            with store.transaction() as db:
                updated = db.execute("UPDATE data_sources SET status=CASE WHEN status='disconnected' THEN status ELSE 'error' END,error=? WHERE id=? AND revision=? AND status!='revoked'", (exc.detail, source_id, row['revision'])).rowcount
                if updated:
                    store.audit(db, 'connector', 'source_connection_failed', f'{source_id}: authentication, permissions, transport or response validation failed.')
            raise
        return row, result

    def unchanged(db, row):
        current = db.execute('SELECT revision,status FROM data_sources WHERE id=?', (row['id'],)).fetchone()
        if not current or current['revision'] != row['revision'] or current['status'] == 'revoked':
            raise HTTPException(409, 'Source changed during validation. Retry with the current configuration.')

    @router.get('')
    def list_sources():
        with store.lock:
            dashboard = store.dashboard()
            sources = [public_source(row, dashboard) for row in store.conn.execute('SELECT * FROM data_sources ORDER BY created_at DESC')]
            sources += [server_source(row, dashboard) for row in store.conn.execute('SELECT * FROM servers ORDER BY created_at DESC')]
            return {'sources': sorted(sources, key=lambda value: value['created_at'], reverse=True)}

    @router.post('/website/test', dependencies=[Depends(https_only)])
    def test_candidate(body: WebsiteConfig):
        try:
            result = check(body.model_dump(exclude={'api_key'}), body.api_key, body.categories)
        except HTTPException:
            with store.transaction() as db:
                store.audit(db, 'analyst', 'source_candidate_failed', 'Website API authentication or connection validation failed. No credentials saved.')
            raise
        with store.transaction() as db:
            store.audit(db, 'analyst', 'source_candidate_verified', 'Website API authentication and selected permissions verified. No credentials saved.')
        return {'valid': True, 'available_categories': result.permissions.available,
                'granted_permissions': result.permissions.granted, 'enabled_categories': body.categories,
                'event_count': sum(event.category in body.categories for event in result.events), 'mode': result.telemetry_mode}

    @router.post('/website', dependencies=[Depends(https_only)])
    def create_website(body: WebsiteConfig):
        try:
            result = check(body.model_dump(exclude={'api_key'}), body.api_key, body.categories)
        except HTTPException:
            with store.transaction() as db:
                store.audit(db, 'analyst', 'source_registration_failed', 'Website authentication or permissions rejected; source was not saved.')
            raise
        source_id, created = 'src-' + uuid.uuid4().hex, utcnow().isoformat()
        with store.transaction() as db:
            db.execute('''INSERT INTO data_sources(id,type,name,base_url,events_url,encrypted_credential,mode,
                       enabled_categories,available_categories,granted_permissions,status,created_at,last_success_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (source_id, 'website', body.name, body.base_url, body.events_url,
                        cipher.encrypt(body.api_key.encode()).decode(), result.telemetry_mode,
                        json.dumps(body.categories), json.dumps(result.permissions.available), json.dumps(result.permissions.granted),
                        'connected', created, created))
            store.audit(db, 'analyst', 'source_registered', f'{source_id}: authenticated website API registered; {result.telemetry_mode} telemetry, read-only manual polling.')
        return {'source': public_source(row_for(source_id))}

    @router.get('/{source_id}')
    def source_detail(source_id: str):
        with store.lock:
            dashboard = store.dashboard()
            row = store.conn.execute('SELECT * FROM data_sources WHERE id=?', (source_id,)).fetchone()
            if row:
                value = public_source(row, dashboard)
            else:
                row = store.conn.execute('SELECT * FROM servers WHERE id=?', (source_id,)).fetchone()
                if not row:
                    raise HTTPException(404, 'Data source not found.')
                value = server_source(row, dashboard)
            events, incidents = own_evidence(source_id, dashboard)
            return {'source': value, 'events': events, 'incidents': incidents}

    def refresh(source_id, ingest=False, resume=False):
        row, result = validated_row(source_id, allow_disconnected=not ingest)
        accepted = 0
        received = utcnow().isoformat()
        with store.transaction() as db:
            unchanged(db, row)
            last_event = row['last_event_at']
            if ingest:
                enabled = json.loads(row['enabled_categories'])
                for item in result.events:
                    if item.category not in enabled:
                        continue
                    event_id = source_id + ':' + item.id
                    inserted = db.execute('INSERT OR IGNORE INTO source_event_keys VALUES (?,?,?)', (source_id, item.id, event_id)).rowcount
                    if not inserted:
                        continue
                    event = item.model_dump(exclude_none=True)
                    event.update(id=event_id, source='network' if item.category == 'application_security' else 'auth',
                                 host=row['base_url'], server_id=source_id, source_id=source_id, data_source_id=source_id,
                                 source_type='website', telemetry_mode=row['mode'], received_at=received)
                    event.update(store.detector.predict(event))
                    accepted += db.execute('INSERT OR IGNORE INTO events(id,payload,server_id) VALUES (?,?,?)', (event_id, json.dumps(event), source_id)).rowcount
                    last_event = max(last_event or item.timestamp, item.timestamp)
                db.execute('DELETE FROM events WHERE server_id=? AND id NOT IN (SELECT id FROM events WHERE server_id=? ORDER BY rowid DESC LIMIT 5000)', (source_id, source_id))
                db.execute('DELETE FROM source_event_keys WHERE source_id=? AND rowid NOT IN (SELECT rowid FROM source_event_keys WHERE source_id=? ORDER BY rowid DESC LIMIT 10000)', (source_id, source_id))
            status = 'connected' if resume or row['status'] != 'disconnected' else 'disconnected'
            db.execute('UPDATE data_sources SET status=?,last_success_at=?,last_event_at=?,available_categories=?,granted_permissions=?,error=NULL,revision=revision+1 WHERE id=?',
                       (status, received, last_event, json.dumps(result.permissions.available), json.dumps(result.permissions.granted), source_id))
            store.audit(db, 'connector', 'source_polled' if ingest else 'source_resumed' if resume else 'source_verified',
                        f'{source_id}: authenticated permissions verified; {accepted} selected events accepted. No containment executed.')
        return {'source': public_source(row_for(source_id)), 'accepted_events': accepted, 'valid': True}

    @router.post('/{source_id}/test', dependencies=[Depends(https_only)])
    def test_source(source_id: str):
        with store.lock:
            server = store.conn.execute('SELECT * FROM servers WHERE id=?', (source_id,)).fetchone()
            if server:
                value = server_source(server, store.dashboard())
                return {'source': value, 'valid': value['status'] == 'connected',
                        'verification': 'Authenticated heartbeat received within 120 seconds.' if value['status'] == 'connected' else 'No current authenticated heartbeat. Check the installed agent; no remote commands are sent.'}
        return refresh(source_id)

    @router.post('/{source_id}/poll', dependencies=[Depends(https_only)])
    def poll_source(source_id: str):
        return refresh(source_id, ingest=True)

    @router.post('/{source_id}/resume', dependencies=[Depends(https_only)])
    def resume_source(source_id: str):
        return refresh(source_id, resume=True)

    @router.patch('/{source_id}/permissions', dependencies=[Depends(https_only)])
    @router.post('/{source_id}/permissions', dependencies=[Depends(https_only)])
    def permissions(source_id: str, body: PermissionsRequest):
        row, result = validated_row(source_id, body.categories)
        with store.transaction() as db:
            unchanged(db, row)
            db.execute("UPDATE data_sources SET enabled_categories=?,available_categories=?,granted_permissions=?,last_success_at=?,status=CASE WHEN status='disconnected' THEN status ELSE 'connected' END,error=NULL,revision=revision+1 WHERE id=?",
                       (json.dumps(body.categories), json.dumps(result.permissions.available), json.dumps(result.permissions.granted), utcnow().isoformat(), source_id))
            store.audit(db, 'analyst', 'source_permissions_changed', f'{source_id}: locally enabled categories changed after provider grant verification; provider permissions were not escalated.')
        return {'source': public_source(row_for(source_id))}

    @router.post('/{source_id}/disconnect', dependencies=[Depends(https_only)])
    def disconnect(source_id: str):
        row_for(source_id)
        with store.transaction() as db:
            db.execute("UPDATE data_sources SET status='disconnected',revision=revision+1 WHERE id=? AND status!='revoked'", (source_id,))
            store.audit(db, 'analyst', 'source_disconnected', f'{source_id}: polling disabled; historical evidence retained.')
        return {'source': public_source(row_for(source_id))}

    @router.post('/{source_id}/revoke', dependencies=[Depends(https_only)])
    def revoke(source_id: str):
        row_for(source_id)
        with store.transaction() as db:
            db.execute("UPDATE data_sources SET status='revoked',encrypted_credential=NULL,granted_permissions='[]',revision=revision+1,error=NULL WHERE id=?", (source_id,))
            store.audit(db, 'analyst', 'source_credentials_revoked', f'{source_id}: local stored credential removed. Revoke the original API key at the website provider too.')
        return {'source': public_source(row_for(source_id))}

    app.include_router(router)
