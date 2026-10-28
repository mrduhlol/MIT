"""SQLite-backed demo state. Containment only changes this isolated database."""
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
import hashlib
import json
import sqlite3
import time
import uuid

from .detection import Detector

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data'


def now():
    return datetime.now(timezone.utc).isoformat()


def correlate(events):
    """Temporal connected components; labels and fixture ordering are not features."""
    events = sorted(events, key=lambda e: (e['timestamp'], e['id']))
    parents = list(range(len(events)))

    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    for i, first in enumerate(events):
        for j in range(i + 1, len(events)):
            second = events[j]
            if (datetime.fromisoformat(second['timestamp']) - datetime.fromisoformat(first['timestamp'])).total_seconds() > 1800:
                break
            if any(first.get(key) and first[key] == second.get(key) for key in ('identity', 'host', 'ip')):
                parents[find(j)] = find(i)
    groups = {}
    for i, event in enumerate(events):
        groups.setdefault(find(i), []).append(event)
    incidents = []
    for group in groups.values():
        alerts = [e for e in group if e['suspicious']]
        if not alerts:
            continue
        categories = sorted({item['category'] for e in alerts for item in e['evidence']})
        sources = sorted({e['source'] for e in alerts})
        identities = sorted({e['identity'] for e in group})
        hosts = sorted({e['host'] for e in group})
        transfer = any(item['feature'] == 'transfer' for e in alerts for item in e['evidence'])
        priority = min(100, 40 + 10 * len(categories) + 5 * len(sources) + (15 if transfer else 0))
        severity = 'critical' if priority >= 85 else 'high' if priority >= 65 else 'medium'
        title = ('Credential theft and outbound transfer' if transfer and 'credential compromise' in categories else
                 'Agent manipulation and detection evasion' if 'prompt injection' in categories else
                 'Suspicious account access' if 'credential compromise' in categories else 'Suspicious activity campaign')
        incident_id = 'inc-' + alerts[0]['id'].removeprefix('evt-')
        incidents.append({'id': incident_id, 'title': title, 'severity': severity,
            'confidence': max(e['confidence'] for e in alerts), 'status': 'open',
            'summary': f"{len(alerts)} suspicious events across {', '.join(sources)} telemetry are linked by shared identities, hosts, or source IPs within 30-minute adjacent-event windows. Observed behaviors: {', '.join(categories)}. Shared infrastructure is evidence of association, not proof of a single attacker.",
            'event_ids': [e['id'] for e in group], 'identities': identities, 'hosts': hosts,
            'categories': categories, 'first_seen': group[0]['timestamp'], 'last_seen': group[-1]['timestamp'], 'priority': priority})
    return sorted(incidents, key=lambda i: (-i['priority'], i['first_seen']))


class Store:
    def __init__(self, path):
        self.path = str(path)
        self.training = json.loads((DATA / 'train.json').read_text())
        self.detector = Detector(self.training)
        self.fixtures = json.loads((DATA / 'replay.json').read_text())
        self.evaluation = json.loads((DATA / 'evaluation.json').read_text())
        if self.path != ':memory:':
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # A retained connection makes :memory: useful to tests; access is lock-protected.
        import threading
        self.lock = threading.RLock()
        self.patrol_lock = threading.Lock()
        self.started_monotonic = time.monotonic()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, incident_id TEXT NOT NULL,
                kind TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
                verification TEXT, UNIQUE(incident_id, kind, target));
            CREATE TABLE IF NOT EXISTS sandbox (kind TEXT NOT NULL, target TEXT NOT NULL, PRIMARY KEY(kind,target));
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
        ''')
        self.conn.commit()
        with self.transaction() as db:
            if not db.execute("SELECT 1 FROM meta WHERE key='initialized'").fetchone():
                self.set_meta(db, 'initialized', True)
                self.set_meta(db, 'cursor', 0)
                self.ingest(db, self.fixtures)
                self.set_meta(db, 'cursor', len(self.fixtures))
                self.audit(db, 'system', 'demo_initialized', 'Loaded synthetic replay fixtures. No containment executed.')
            self.set_meta(db, 'metrics', self.evaluate())
            if self.get_meta(db, 'agent_settings') is None:
                self.set_meta(db, 'agent_settings', {'enabled': False, 'interval_seconds': 300, 'next_run_at': None})
            if self.get_meta(db, 'agent_runs') is None:
                self.set_meta(db, 'agent_runs', [])

    @contextmanager
    def transaction(self):
        with self.lock:
            self.conn.execute('BEGIN IMMEDIATE')
            try:
                yield self.conn
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise

    def set_meta(self, db, key, value):
        db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, json.dumps(value)))

    def get_meta(self, db, key):
        row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row['value']) if row else None

    def audit(self, db, actor, action, detail):
        db.execute('INSERT INTO audit(timestamp,actor,action,detail) VALUES (?,?,?,?)', (now(), actor, action, detail))

    def ingest(self, db, rows):
        start = time.perf_counter_ns()
        for fixture in rows:
            event = {k: v for k, v in fixture.items() if k != 'label'}
            event.update(self.detector.predict(event))
            db.execute('INSERT OR IGNORE INTO events VALUES (?,?)', (event['id'], json.dumps(event)))
        events = [json.loads(row['payload']) for row in db.execute('SELECT payload FROM events')]
        correlate(events)
        self.set_meta(db, 'last_batch', {'events': len(rows), 'latency_ms': (time.perf_counter_ns() - start) / 1_000_000,
            'scope': 'Classification, SQLite inserts and correlation within transaction; excludes commit, HTTP transport and rendering.'})

    def evaluate(self):
        result = self.detector.evaluate(self.evaluation)
        result['evaluated_at'] = now()
        result['training_samples'] = len(self.training)
        # Dedicated in-memory DB: evaluation cannot mutate the active simulation.
        benchmark = sqlite3.connect(':memory:')
        benchmark.execute('CREATE TABLE events (id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
        start = time.perf_counter_ns()
        for fixture in self.evaluation:
            event = {k: v for k, v in fixture.items() if k != 'label'}
            event.update(self.detector.predict(event))
            benchmark.execute('INSERT INTO events VALUES (?,?)', (event['id'], json.dumps(event)))
        benchmark.commit()
        events = [json.loads(row[0]) for row in benchmark.execute('SELECT payload FROM events')]
        correlate(events)
        result['batch_latency_ms'] = (time.perf_counter_ns() - start) / 1_000_000
        result['batch_size'] = len(events)
        result['batch_latency_scope'] = f'One {len(events)}-event batch: classification, in-memory SQLite persistence/commit/read and correlation; excludes HTTP, disk I/O and browser rendering.'
        benchmark.close()
        return result

    def dashboard(self):
        with self.lock:
            db = self.conn
            events = sorted([json.loads(row['payload']) for row in db.execute('SELECT payload FROM events')], key=lambda e: e['timestamp'])
            actions = [dict(row) for row in db.execute('SELECT * FROM actions ORDER BY rowid')]
            incidents = correlate(events)
            for incident in incidents:
                related = [a for a in actions if a['incident_id'] == incident['id']]
                approved = [a for a in related if a['status'] == 'approved']
                if approved:
                    incident['status'] = 'contained' if all(a['status'] == 'approved' for a in related) else 'partially contained'
                elif any(a['status'] == 'pending' for a in related):
                    incident['status'] = 'awaiting approval'
            state = [dict(row) for row in db.execute('SELECT * FROM sandbox')]
            metrics = self.get_meta(db, 'metrics')
            metrics['last_batch'] = self.get_meta(db, 'last_batch')
            return {'events': events, 'incidents': incidents, 'actions': actions,
                'audit': [dict(row) for row in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')],
                'metrics': metrics, 'sandbox': {'isolated_hosts': [s['target'] for s in state if s['kind'] == 'isolate_host'],
                    'revoked_identities': [s['target'] for s in state if s['kind'] == 'revoke_sessions']},
                'replay': {'cursor': self.get_meta(db, 'cursor'), 'total': len(self.fixtures)},
                'model': 'Local Bernoulli naive Bayes · explainable feature evidence'}

    def replay(self, mode):
        with self.transaction() as db:
            cursor = self.get_meta(db, 'cursor')
            end = min(cursor + 1, len(self.fixtures)) if mode == 'step' else len(self.fixtures)
            self.ingest(db, self.fixtures[cursor:end])
            self.set_meta(db, 'cursor', end)
            self.audit(db, 'analyst', 'replay', f'Replayed {end-cursor} synthetic events ({mode}).')
        return self.dashboard()

    def reset(self):
        with self.transaction() as db:
            db.execute('DELETE FROM events')
            db.execute('DELETE FROM actions')
            db.execute('DELETE FROM sandbox')
            self.set_meta(db, 'cursor', 0)
            self.set_meta(db, 'last_batch', None)
            self.audit(db, 'analyst', 'simulation_reset', 'Cleared replay events, proposed responses, and isolated sandbox state; audit history preserved.')
        return self.dashboard()

    def investigate(self, incident_id):
        with self.transaction() as db:
            dashboard = self.dashboard()
            incident = next((i for i in dashboard['incidents'] if i['id'] == incident_id), None)
            if incident is None:
                raise KeyError(incident_id)
            evidence = []
            for event in dashboard['events']:
                if event['id'] in incident['event_ids']:
                    for item in event['evidence']:
                        evidence.append({'event_id': event['id'], 'explanation': f"{event['timestamp']} · {event['identity']} on {event['host']}: {item['explanation']}"})
            targets = [('isolate_host', h) for h in incident['hosts']]
            if 'credential compromise' in incident['categories']:
                targets.extend(('revoke_sessions', identity) for identity in incident['identities'])
            for kind, target in targets:
                action_id = 'act-' + hashlib.sha256(f'{incident_id}:{kind}:{target}'.encode()).hexdigest()[:12]
                reason = (f'Isolate {target} in the local simulation to interrupt suspicious communication.' if kind == 'isolate_host'
                    else f'Revoke simulated sessions for {target} to limit suspected credential misuse.')
                db.execute('INSERT OR IGNORE INTO actions(id,incident_id,kind,target,status,reason) VALUES (?,?,?,?,?,?)',
                    (action_id, incident_id, kind, target, 'pending', reason))
            self.audit(db, 'local-model', 'incident_investigated', f'{incident_id}: evidence reviewed and response proposals prepared. No containment executed.')
            actions = [dict(r) for r in db.execute('SELECT * FROM actions WHERE incident_id=?', (incident_id,))]
            return {'summary': incident['summary'], 'evidence': evidence, 'recommendations': actions,
                'limitations': ['Local trained statistical model with deterministic evidence synthesis; no remote LLM.',
                    'Confidence is an uncalibrated model probability. Synthetic fixtures do not measure production effectiveness.',
                    'Phishing style cannot establish AI authorship. Shared entities can join unrelated events.',
                    'Recommendations only change isolated SQLite state after an explicit individual approval.']}

    def decide(self, action_id, decision, confirmed, actor, reason):
        if decision == 'approve' and not confirmed:
            raise PermissionError('Explicit confirmation is required for each simulated containment action.')
        with self.transaction() as db:
            row = db.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
            if row is None:
                raise KeyError(action_id)
            if row['status'] != 'pending':
                raise ValueError('This action already has a decision and cannot execute again.')
            status = 'approved' if decision == 'approve' else 'rejected'
            verification = 'Rejected by analyst; no simulated containment executed.'
            if status == 'approved':
                if row['kind'] not in ('isolate_host', 'revoke_sessions'):
                    raise ValueError('Unsupported sandbox operation.')
                self.audit(db, actor, 'action_approved', f'{action_id}: {reason}')
                db.execute('INSERT OR IGNORE INTO sandbox VALUES (?,?)', (row['kind'], row['target']))
                verified = db.execute('SELECT 1 FROM sandbox WHERE kind=? AND target=?', (row['kind'], row['target'])).fetchone()
                if not verified:
                    raise RuntimeError('Sandbox state verification failed; transaction rolled back.')
                verification = f"Verified in isolated SQLite sandbox: {row['kind']} applied to {row['target']}. No real system changed."
                self.audit(db, 'sandbox', 'response_verified', f'{action_id}: {verification}')
            else:
                self.audit(db, actor, 'action_rejected', f'{action_id}: {reason}')
            db.execute('UPDATE actions SET status=?,verification=? WHERE id=?', (status, verification, action_id))
            return dict(db.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone())


    def agent_settings(self):
        with self.lock:
            return self.get_meta(self.conn, 'agent_settings')

    def configure_agent(self, enabled, interval_seconds):
        with self.transaction() as db:
            settings = {'enabled': enabled, 'interval_seconds': interval_seconds,
                'next_run_at': (datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)).isoformat() if enabled else None}
            self.set_meta(db, 'agent_settings', settings)
            self.audit(db, 'analyst', 'agent_schedule_updated',
                f"Synthetic patrol {'enabled' if enabled else 'paused'}; interval {interval_seconds} seconds. Containment still requires individual approval.")
        return self.agent()

    def agent(self):
        with self.lock:
            settings = self.get_meta(self.conn, 'agent_settings')
            runs = self.get_meta(self.conn, 'agent_runs')
            events = [json.loads(row['payload']) for row in self.conn.execute('SELECT payload FROM events')]
            labels = {'email': 'Email gateway', 'auth': 'Authentication', 'network': 'Network flows'}
            coverage = []
            for source, label in labels.items():
                rows = [e for e in events if e['source'] == source]
                coverage.append({'source': source, 'label': label, 'status': 'simulated', 'events': len(rows),
                    'last_event_at': max((e['timestamp'] for e in rows), default=None)})
            return {'mode': 'simulation', 'site': {'name': 'Demo website', 'environment': 'Local sandbox', 'collector_status': 'simulated'},
                'status': 'running' if self.patrol_lock.locked() else 'scheduled' if settings['enabled'] else 'paused',
                'enabled': settings['enabled'], 'interval_seconds': settings['interval_seconds'],
                'last_run_at': runs[0]['completed_at'] if runs else None, 'next_run_at': settings['next_run_at'],
                'runs': runs, 'coverage': coverage, 'uptime_seconds': round(time.monotonic() - self.started_monotonic, 2)}

    def patrol(self, trigger='manual'):
        if not self.patrol_lock.acquire(blocking=False):
            raise RuntimeError('A patrol is already running.')
        started = now()
        clock = time.perf_counter_ns()
        run = {'id': 'run-' + uuid.uuid4().hex[:12], 'started_at': started, 'completed_at': None,
            'duration_ms': 0, 'events_analyzed': 0, 'incidents_found': 0, 'suspicious_events': 0,
            'trigger': trigger, 'status': 'completed'}
        try:
            try:
                with self.transaction() as db:
                    # Recheck under the database lock so pausing wins over a stale
                    # scheduler wake-up. No catch-up loops or overlapping runs.
                    settings = self.get_meta(db, 'agent_settings')
                    if trigger == 'scheduled':
                        due = settings['next_run_at']
                        if not settings['enabled'] or not due or datetime.fromisoformat(due) > datetime.now(timezone.utc):
                            return None
                    events = [json.loads(row['payload']) for row in db.execute('SELECT payload FROM events')]
                    analyzed = [{**e, **self.detector.predict(e)} for e in events]
                    incidents = correlate(analyzed)
                    run.update(events_analyzed=len(events), incidents_found=len(incidents),
                        suspicious_events=sum(e['suspicious'] for e in analyzed))
                # Investigation has its own transaction. It creates only pending
                # recommendations and preserves every prior analyst decision.
                run['investigated_incidents'] = 0
                run['pending_recommendations'] = 0
                for incident in incidents:
                    investigation = self.investigate(incident['id'])
                    run['investigated_incidents'] += 1
                    run['pending_recommendations'] += sum(a['status'] == 'pending' for a in investigation['recommendations'])
                with self.transaction() as db:
                    self._record_patrol(db, run, clock)
            except Exception as exc:
                run['status'] = 'failed'
                run['error'] = str(exc)[:300]
                with self.transaction() as db:
                    self._record_patrol(db, run, clock)
            return run
        finally:
            self.patrol_lock.release()

    def _record_patrol(self, db, run, clock):
        run['completed_at'] = now()
        run['duration_ms'] = round((time.perf_counter_ns() - clock) / 1_000_000, 3)
        runs = self.get_meta(db, 'agent_runs')
        self.set_meta(db, 'agent_runs', [run, *runs][:100])
        settings = self.get_meta(db, 'agent_settings')
        settings['next_run_at'] = (datetime.now(timezone.utc) + timedelta(seconds=settings['interval_seconds'])).isoformat() if settings['enabled'] else None
        self.set_meta(db, 'agent_settings', settings)
        self.audit(db, 'synthetic-agent', 'patrol_' + run['status'],
            f"{run['id']} ({run['trigger']}): {run['events_analyzed']} events analyzed, {run['incidents_found']} incidents found. {run.get('pending_recommendations', 0)} pending recommendations after investigation. No actions approved or executed.")

    def analytics(self, window_minutes):
        with self.lock:
            all_events = [json.loads(row['payload']) for row in self.conn.execute('SELECT payload FROM events')]
            isolated = {row['target'] for row in self.conn.execute("SELECT target FROM sandbox WHERE kind='isolate_host'")}
        buckets = 24 if window_minutes == 1440 else 12
        bucket_seconds = window_minutes * 60 // buckets
        anchor = max((datetime.fromisoformat(e['timestamp']) for e in all_events), default=None)
        start = anchor - timedelta(minutes=window_minutes) if anchor else None
        events = [e for e in all_events if start <= datetime.fromisoformat(e['timestamp']) <= anchor] if anchor else []
        series = [{'timestamp': (start + timedelta(seconds=i*bucket_seconds)).isoformat(), 'events': 0,
                   'suspicious': 0, 'auth_failures': 0, 'bytes_out': 0} for i in range(buckets)] if start else []
        sources = {source: {'source': source, 'total': 0, 'suspicious': 0} for source in ('email', 'auth', 'network')}
        categories = {}
        hosts = {}
        totals = {'events': 0, 'suspicious': 0, 'bytes_out': 0, 'auth_failures': 0}
        for event in events:
            details = event['details']
            auth_failures = (int(details.get('result', '').lower() in ('failure', 'failed', 'denied')) + max(0, int(details.get('mfa_denials', 0)))) if event['source'] == 'auth' else 0
            bytes_out = max(0, int(details.get('bytes_out', 0))) if event['source'] == 'network' else 0
            measures = {'events': 1, 'suspicious': int(event['suspicious']), 'bytes_out': bytes_out, 'auth_failures': auth_failures}
            index = min(buckets - 1, int((datetime.fromisoformat(event['timestamp']) - start).total_seconds() // bucket_seconds))
            for key, value in measures.items():
                totals[key] += value
                series[index][key] += value
            sources[event['source']]['total'] += 1
            sources[event['source']]['suspicious'] += int(event['suspicious'])
            if event['suspicious']:
                for category in {item['category'] for item in event['evidence']}:
                    categories[category] = categories.get(category, 0) + 1
            host = hosts.setdefault(event['host'], {'host': event['host'], 'identities': set(), 'events': 0,
                'suspicious': 0, 'last_seen': event['timestamp'], 'status': 'observed'})
            host['identities'].add(event['identity'])
            host['events'] += 1
            host['suspicious'] += int(event['suspicious'])
            host['last_seen'] = max(host['last_seen'], event['timestamp'])
        for host in hosts.values():
            host['identities'] = sorted(host['identities'])
            host['status'] = 'isolated' if host['host'] in isolated else 'attention' if host['suspicious'] else 'observed'
        return {'window_minutes': window_minutes, 'anchor_at': anchor.isoformat() if anchor else None,
            'start_at': start.isoformat() if start else None, 'bucket_seconds': bucket_seconds, 'series': series,
            'sources': list(sources.values()), 'categories': [{'category': key, 'count': value} for key, value in sorted(categories.items())],
            'hosts': sorted(hosts.values(), key=lambda h: (-h['suspicious'], h['host'])), 'totals': totals,
            'scope': 'Synthetic telemetry window anchored to the latest event timestamp, not wall-clock time. Auth failures sum denied MFA prompts and failed/denied login events. Categories count each category once per suspicious event. Empty telemetry has no time anchor or buckets.'}
