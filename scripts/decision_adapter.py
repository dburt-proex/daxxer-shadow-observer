"""Exactly one integration: reviewed Shadow Observer episode append."""
import argparse
import hashlib
import json
import os
import sqlite3
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from decision_collector import validate
from ledger import Invalid, Ledger, canonical, now, parse


def event(decision_id, source, kind, context, **values):
    result = dict(schema_version='0.1', event_id=decision_id + ':' + kind,
                  decision_id=decision_id, source=source, kind=kind, occurred_at=now(),
                  actor={'id':'shadow-reviewed-record-adapter','type':'system'},
                  purpose=None, rationale=None, decision=None, expected_result=None,
                  authority_ref=None, action=None, execution_status=None, outcome=None,
                  related_record_ids=[], evidence_refs=[], unknowns=[], classification='observed',
                  simulated=False, corrects_event_id=None)
    result.update(context)
    result.update(values)
    return validate(result)


class Outbox:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS outbox(event_id TEXT PRIMARY KEY, body TEXT NOT NULL, sent INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT)')

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('PRAGMA synchronous=FULL')
        try:
            with db:
                yield db
        finally:
            db.close()

    def enqueue(self, value):
        validate(value)
        body = canonical(value).decode()
        with self.db() as db:
            old = db.execute('SELECT body FROM outbox WHERE event_id=?',(value['event_id'],)).fetchone()
            if old and old[0] != body:
                raise ValueError('outbox_event_conflict')
            db.execute('INSERT OR IGNORE INTO outbox(event_id,body) VALUES(?,?)',(value['event_id'],body))

    def flush(self, send):
        with self.db() as db:
            rows = db.execute('SELECT event_id,body FROM outbox WHERE sent=0 ORDER BY rowid').fetchall()
        for eid, body in rows:
            try:
                receipt = send(json.loads(body))
                if receipt.get('event_id') != eid or not receipt.get('received_at'):
                    raise ValueError('invalid_receipt')
            except Exception:
                # Exceptions can contain URLs or secrets; retain only a constant category.
                with self.db() as db:
                    db.execute('UPDATE outbox SET attempts=attempts+1,last_error=? WHERE event_id=?', ('submission_failed',eid))
                return False
            with self.db() as db:
                db.execute('UPDATE outbox SET sent=1,attempts=attempts+1,last_error=NULL WHERE event_id=?',(eid,))
        return True

    def status(self):
        with self.db() as db:
            return [dict(zip(('event_id','sent','attempts','last_error'),r)) for r in db.execute('SELECT event_id,sent,attempts,last_error FROM outbox ORDER BY rowid')]


class Client:
    def __init__(self, url, token):
        parts = urlparse(url)
        if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('','/'):
            raise ValueError('collector URL must be an origin')
        if parts.scheme != 'https' and not (parts.scheme == 'http' and parts.hostname in ('127.0.0.1','::1')):
            raise ValueError('HTTPS required except numeric loopback')
        self.url, self.token = url.rstrip('/'), token
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def post(self, path, value):
        request = urllib.request.Request(self.url + path, data=canonical(value),
                  headers={'Content-Type':'application/json', 'Authorization':'Bearer '+self.token}, method='POST')
        with self.opener.open(request, timeout=10) as response:
            return parse(response.read(16385).decode())

    def send(self, value):
        return self.post('/v1/events', value)

    def heartbeat(self, source):
        return self.post('/v1/heartbeat', {'source':source})


def record_reviewed(ledger, outbox, send, decision_id, record_id, payload, context, source='shadow-reviewed-record'):
    """No automatic intent inference; explicit caller-supplied purpose and authority."""
    if set(context) != {'project_id','directive_id','purpose','rationale','expected_result','authority_ref','simulated'}:
        raise ValueError('context fields invalid')
    if not context.get('authority_ref') or not context.get('purpose') or not context.get('rationale'):
        raise ValueError('explicit purpose, rationale and authority required')
    if len(decision_id) > 110:
        raise ValueError('decision ID too long')
    # Bind retries to the same reviewed payload, without transferring the payload.
    payload_hash = hashlib.sha256(canonical(payload)).hexdigest()
    context = dict(context, related_record_ids=[record_id, 'sha256:'+payload_hash])
    # Existing outbox is a deliberate stop: replay delivery, never re-execute an uncertain action.
    if outbox.status():
        raise ValueError('existing_run: flush outbox and inspect local ledger; do not re-execute')
    outbox.enqueue(event(decision_id, source, 'intent', context, classification='stated'))
    outbox.enqueue(event(decision_id, source, 'decision', context, classification='stated', decision='append reviewed episode to local experience ledger'))
    if not outbox.flush(send):
        raise ValueError('collector_unavailable: action not executed; replay outbox then start a new decision')
    outbox.enqueue(event(decision_id, source, 'action', context, action='Ledger.append episode', execution_status='attempted'))
    if not outbox.flush(send):
        raise ValueError('action_record_unacknowledged: action not executed; inspect before retry')
    try:
        receipt = ledger.append('episode', record_id, payload)
    except (Invalid, OSError, ValueError):
        outbox.enqueue(event(decision_id, source, 'outcome', context,
                       execution_status='failed', outcome=None,
                       unknowns=['append may have failed before or after durable write; inspect local ledger'],
                       classification='unknown'))
        outbox.flush(send)
        raise
    outbox.enqueue(event(decision_id, source, 'outcome', context, execution_status='succeeded',
                   outcome='local reviewed episode append returned a durable record receipt',
                   evidence_refs=['shadow-record:'+receipt['record_id'], 'sha256:'+receipt['content_hash']],
                   unknowns=['episode real-world outcome remains whatever its reviewed payload states']))
    delivered = outbox.flush(send)
    return {'record_id': receipt['record_id'], 'content_hash': receipt['content_hash'], 'outcome_delivered':delivered}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['record','flush','status','heartbeat'])
    parser.add_argument('--outbox', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--context', type=Path)
    parser.add_argument('--record-id')
    parser.add_argument('--decision-id')
    args = parser.parse_args()
    if args.command == 'status':
        if not args.outbox: parser.error('--outbox required')
        print(json.dumps(Outbox(args.outbox).status()))
        return
    client = Client(os.environ['LEDGER_URL'], os.environ['LEDGER_SOURCE_TOKEN'])
    if args.command == 'heartbeat':
        print(json.dumps(client.heartbeat('shadow-reviewed-record')))
        return
    if not args.outbox: parser.error('--outbox required')
    box = Outbox(args.outbox)
    if args.command == 'flush':
        if not box.flush(client.send): raise SystemExit(1)
    else:
        if not all((args.input,args.context,args.record_id,args.decision_id)):
            parser.error('record requires --input --context --record-id --decision-id')
        payload = parse(args.input.read_text(encoding='utf-8'))
        context = parse(args.context.read_text(encoding='utf-8'))
        # Restrict caller fields; context cannot overwrite identity, stage, timestamps or source.
        if set(context) != {'project_id','directive_id','purpose','rationale','expected_result','authority_ref','simulated'}:
            raise ValueError('context fields invalid')
        print(json.dumps(record_reviewed(Ledger(), box, client.send,args.decision_id,args.record_id,payload,context)))


if __name__ == '__main__':
    main()
