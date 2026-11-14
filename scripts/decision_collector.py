"""DAXXER decision collector v0.1. WSGI app; no execution authority."""
import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ledger import Invalid, canonical, now, parse

LOG = logging.getLogger('decision-collector')
LIMIT = 16384
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
KINDS = {'intent', 'decision', 'action', 'outcome', 'correction'}
FIELDS = {'schema_version', 'event_id', 'decision_id', 'project_id', 'directive_id',
          'related_record_ids', 'occurred_at', 'actor', 'source', 'kind', 'purpose',
          'rationale', 'decision', 'expected_result', 'authority_ref', 'action',
          'execution_status', 'outcome', 'evidence_refs', 'unknowns',
          'classification', 'simulated', 'corrects_event_id'}


class Rejected(ValueError):
    def __init__(self, code, status=422):
        super().__init__(code)
        self.code, self.status = code, status


def timestamp(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise Rejected('timezone_timestamp_required') from None


def validate(event):
    if type(event) is not dict or set(event) != FIELDS:
        raise Rejected('event_fields_invalid')
    if event['schema_version'] != '0.1' or type(event['kind']) is not str or event['kind'] not in KINDS:
        raise Rejected('event_version_or_kind_invalid')
    for key in ('event_id', 'decision_id', 'project_id', 'directive_id', 'source'):
        if type(event[key]) is not str or not ID.fullmatch(event[key]):
            raise Rejected('identifier_invalid')
    timestamp(event['occurred_at'])
    if type(event['actor']) is not dict or set(event['actor']) != {'id', 'type'}:
        raise Rejected('actor_invalid')
    if event['actor']['type'] not in ('human', 'agent', 'system'):
        raise Rejected('actor_invalid')
    if type(event['actor']['id']) is not str or not ID.fullmatch(event['actor']['id']):
        raise Rejected('actor_invalid')
    for key in ('purpose', 'rationale', 'decision', 'expected_result', 'authority_ref', 'action', 'outcome'):
        value = event[key]
        if value is not None and (type(value) is not str or not value.strip() or len(value) > 2000):
            raise Rejected('text_invalid')
    for key in ('related_record_ids', 'evidence_refs', 'unknowns'):
        values = event[key]
        if type(values) is not list or len(values) > 32 or any(type(v) is not str or not v.strip() or len(v) > 512 for v in values):
            raise Rejected('references_invalid')
    if event['classification'] not in ('stated', 'observed', 'inferred', 'unknown') or type(event['simulated']) is not bool:
        raise Rejected('classification_invalid')
    if event['execution_status'] not in (None, 'attempted', 'succeeded', 'failed', 'unknown'):
        raise Rejected('execution_status_invalid')
    if event['kind'] == 'intent' and not all(event[k] for k in ('purpose', 'expected_result')):
        raise Rejected('intent_required')
    if event['kind'] == 'decision' and not all(event[k] for k in ('decision', 'rationale', 'authority_ref')):
        raise Rejected('decision_required')
    if event['kind'] == 'action' and (not event['action'] or event['execution_status'] is None):
        raise Rejected('action_required')
    if event['kind'] == 'outcome' and event['outcome'] is not None and not event['evidence_refs']:
        raise Rejected('outcome_evidence_required')
    if event['kind'] == 'correction':
        if type(event['corrects_event_id']) is not str or not ID.fullmatch(event['corrects_event_id']) or not event['rationale']:
            raise Rejected('correction_target_required')
    elif event['corrects_event_id'] is not None:
        raise Rejected('correction_kind_required')
    if len(canonical(event)) > LIMIT:
        raise Rejected('payload_too_large', 413)
    return event


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY, source TEXT NOT NULL, event_id TEXT NOT NULL,
                    decision_id TEXT NOT NULL, received_at TEXT NOT NULL, body TEXT NOT NULL,
                    UNIQUE(source,event_id));
                CREATE INDEX IF NOT EXISTS decision_idx ON events(source,decision_id);
                CREATE TRIGGER IF NOT EXISTS immutable_update BEFORE UPDATE ON events
                  BEGIN SELECT RAISE(ABORT,'append only'); END;
                CREATE TRIGGER IF NOT EXISTS immutable_delete BEFORE DELETE ON events
                  BEGIN SELECT RAISE(ABORT,'append only'); END;
                CREATE TABLE IF NOT EXISTS heartbeats (
                    source TEXT PRIMARY KEY, received_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS failures (
                    seq INTEGER PRIMARY KEY, received_at TEXT NOT NULL,
                    source TEXT, code TEXT NOT NULL);
            ''')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def append(self, event):
        validate(event)
        body = canonical(event).decode('utf-8')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM events WHERE source=? AND event_id=?',
                             (event['source'], event['event_id'])).fetchone()
            if old:
                if old['body'] != body:
                    raise Rejected('event_id_conflict', 409)
                return {'event_id': old['event_id'], 'received_at': old['received_at'], 'duplicate': True}
            # One decision belongs to one source; no source can attach to another source's history.
            rows = db.execute('SELECT body FROM events WHERE source=? AND decision_id=?',
                              (event['source'], event['decision_id'])).fetchall()
            for row in rows:
                prior = json.loads(row['body'])
                if any(event[k] != prior[k] for k in ('project_id', 'directive_id', 'simulated')):
                    raise Rejected('decision_context_conflict', 409)
                if event['kind'] != 'correction' and prior['kind'] == event['kind']:
                    raise Rejected('stage_already_recorded', 409)
            target = event['corrects_event_id']
            if target:
                row = db.execute('SELECT decision_id FROM events WHERE source=? AND event_id=?', (event['source'], target)).fetchone()
                if row and row['decision_id'] != event['decision_id']:
                    raise Rejected('correction_decision_mismatch', 409)
            # Forward references are accepted but remain visibly unresolved in status.
            pending = db.execute('SELECT body FROM events WHERE source=?', (event['source'],)).fetchall()
            if any(json.loads(r['body'])['corrects_event_id'] == event['event_id'] and
                   json.loads(r['body'])['decision_id'] != event['decision_id'] for r in pending):
                raise Rejected('correction_decision_mismatch', 409)
            received = now()
            db.execute('INSERT INTO events(source,event_id,decision_id,received_at,body) VALUES(?,?,?,?,?)',
                       (event['source'], event['event_id'], event['decision_id'], received, body))
            return {'event_id': event['event_id'], 'received_at': received, 'duplicate': False}

    def heartbeat(self, source):
        with self.db() as db:
            db.execute('INSERT INTO heartbeats VALUES(?,?) ON CONFLICT(source) DO UPDATE SET received_at=excluded.received_at', (source, now()))

    def failure(self, source, code):
        # No body, token, rationale, exception text or arbitrary user-supplied source is logged.
        LOG.warning('ingestion_failure source=%s code=%s', source or 'unauthenticated', code)
        with self.db() as db:
            db.execute('INSERT INTO failures(received_at,source,code) VALUES(?,?,?)', (now(), source, code))

    def status(self, sources, stale_seconds, clock=None):
        current = datetime.now(timezone.utc).timestamp() if clock is None else clock
        with self.db() as db:
            rows = db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT 1000').fetchall()
            beats = {r['source']: r['received_at'] for r in db.execute('SELECT * FROM heartbeats')}
            failures = [dict(r) for r in db.execute('SELECT received_at,source,code FROM failures ORDER BY seq DESC LIMIT 50')]
            count = db.execute('SELECT count(*) FROM events').fetchone()[0]
            # Summaries use complete history even when recent-event display is bounded.
            history = [json.loads(r[0]) for r in db.execute('SELECT body FROM events ORDER BY seq')]
        groups = {}
        for e in history:
            groups.setdefault((e['source'], e['decision_id']), []).append(e)
        decisions = []
        for (source, did), events in groups.items():
            stages = {e['kind']: e for e in events if e['kind'] != 'correction'}
            missing = [k for k in ('intent', 'decision', 'action', 'outcome') if k not in stages]
            if 'outcome' in stages and stages['outcome']['outcome'] is None:
                missing.append('known_outcome')
            if 'outcome' in stages and stages['outcome']['execution_status'] not in ('succeeded', 'failed'):
                missing.append('outcome_final_status')
            ids = {e['event_id'] for e in events}
            unresolved = [e['corrects_event_id'] for e in events if e['corrects_event_id'] and e['corrects_event_id'] not in ids]
            chronology = True
            times = [timestamp(stages[k]['occurred_at']) for k in ('intent', 'decision', 'action', 'outcome') if k in stages]
            if times != sorted(times):
                chronology = False
            stated = all(e['classification'] in ('stated', 'observed') for e in stages.values())
            # Authority references are recorded assertions, never an authorization check.
            # Corrections remain reviewable annotations; they cannot silently rewrite projections.
            decisions.append({'source': source, 'decision_id': did, 'missing': missing,
                              'complete': not missing and chronology and stated and not unresolved and not any(e['kind'] == 'correction' for e in events),
                              'chronology_valid': chronology, 'inference_or_unknown': not stated,
                              'correction_count': sum(e['kind'] == 'correction' for e in events),
                              'unresolved_corrections': unresolved, 'simulated': events[0]['simulated']})
        return {'schema_version': '0.1', 'events_count': count,
                'events': [dict(r, body=json.loads(r['body'])) for r in rows],
                'decisions': decisions,
                'sources': [{'source': s, 'last_heartbeat': beats.get(s),
                             'stale': s not in beats or current - timestamp(beats[s]) > stale_seconds} for s in sorted(sources)],
                'recent_failures': failures, 'display_limit': 1000}

    def backup(self, destination):
        target = Path(destination)
        if target.exists() or target.resolve() == self.path.resolve():
            raise Rejected('backup_destination_must_be_new')
        target.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            out = sqlite3.connect(target)
            try:
                db.backup(out)
                if out.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise Rejected('backup_integrity_failed')
            finally:
                out.close()
        return {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}


def load_credentials(raw):
    value = parse(raw)
    if type(value) is not dict or not value:
        raise ValueError('source credentials required')
    if any(not ID.fullmatch(s) or type(v) is not str or not re.fullmatch('[0-9a-f]{64}', v) for s, v in value.items()):
        raise ValueError('credentials must map source IDs to SHA256 token digests')
    if len(set(value.values())) != len(value):
        raise ValueError('source credentials must be unique')
    return value


class App:
    def __init__(self, store, credentials, reader_digest, stale_seconds=180):
        if not credentials or not re.fullmatch('[0-9a-f]{64}', reader_digest) or reader_digest in credentials.values():
            raise ValueError('distinct reader digest required')
        self.store, self.credentials = store, credentials
        self.reader_digest, self.stale_seconds = reader_digest, stale_seconds

    def __call__(self, environ, start_response):
        source = None
        def reply(status, payload):
            body = canonical(payload)
            start_response(str(status) + ' ' + {200:'OK',201:'Created',401:'Unauthorized',404:'Not Found',405:'Method Not Allowed',409:'Conflict',413:'Payload Too Large',422:'Unprocessable Entity',503:'Service Unavailable'}[status],
                           [('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(body))),
                            ('Cache-Control','no-store'), ('X-Content-Type-Options','nosniff')])
            return [body]
        try:
            path, method = environ.get('PATH_INFO'), environ.get('REQUEST_METHOD')
            if path == '/healthz' and method == 'GET':
                with self.store.db() as db:
                    db.execute('SELECT count(*) FROM events').fetchone()
                return reply(200, {'ok': True})
            auth = environ.get('HTTP_AUTHORIZATION', '')
            if not auth.startswith('Bearer ') or len(auth) > 512:
                raise Rejected('unauthorized', 401)
            digest = hashlib.sha256(auth[7:].encode()).hexdigest()
            reader = hmac.compare_digest(digest, self.reader_digest)
            for name, expected in self.credentials.items():
                if hmac.compare_digest(digest, expected):
                    source = name
            if path == '/v1/activity' and method == 'GET':
                if not reader:
                    raise Rejected('unauthorized', 401)
                return reply(200, self.store.status(self.credentials, self.stale_seconds))
            if path not in ('/v1/events', '/v1/heartbeat'):
                raise Rejected('not_found', 404)
            if method != 'POST':
                raise Rejected('method_not_allowed', 405)
            if source is None:
                raise Rejected('unauthorized', 401)
            if environ.get('CONTENT_TYPE', '').split(';')[0].strip() != 'application/json':
                raise Rejected('json_required')
            try:
                length = int(environ.get('CONTENT_LENGTH', '0'))
            except ValueError:
                raise Rejected('length_invalid') from None
            if not 0 < length <= LIMIT:
                raise Rejected('payload_too_large', 413)
            raw = environ['wsgi.input'].read(length)
            if len(raw) != length:
                raise Rejected('incomplete_body')
            event = parse(raw.decode('utf-8'))
            if path == '/v1/heartbeat':
                if event != {'source': source}:
                    raise Rejected('source_scope_mismatch', 401)
                self.store.heartbeat(source)
                return reply(200, {'accepted': True})
            if type(event) is not dict or event.get('source') != source:
                raise Rejected('source_scope_mismatch', 401)
            result = self.store.append(event)
            return reply(200 if result['duplicate'] else 201, result)
        except (Rejected, Invalid, UnicodeError, RecursionError) as exc:
            code = exc.code if isinstance(exc, Rejected) else 'invalid_json'
            try:
                self.store.failure(source, code)
            except sqlite3.Error:
                LOG.error('failure_audit_unavailable')
                return reply(503, {'error':'storage_unavailable'})
            return reply(exc.status if isinstance(exc, Rejected) else 422, {'error':code})
        except sqlite3.Error:
            LOG.error('storage_unavailable')
            return reply(503, {'error':'storage_unavailable'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['serve', 'backup'])
    parser.add_argument('--destination')
    args = parser.parse_args()
    store = Store(os.environ.get('LEDGER_DB', 'runtime/decision-ledger.sqlite3'))
    if args.command == 'backup':
        if not args.destination:
            parser.error('--destination required')
        print(json.dumps(store.backup(args.destination)))
        return
    credentials = load_credentials(os.environ['LEDGER_SOURCE_DIGESTS'])
    app = App(store, credentials, os.environ['LEDGER_READER_DIGEST'], int(os.environ.get('LEDGER_STALE_SECONDS', '180')))
    from waitress import serve
    serve(app, host=os.environ.get('LEDGER_BIND', '127.0.0.1'), port=int(os.environ.get('PORT', '8080')),
          threads=4, max_request_body_size=LIMIT, channel_timeout=30,
          connection_limit=32, clear_untrusted_proxy_headers=True)


if __name__ == '__main__':
    main()
