"""Synthetic local acceptance; never accesses real records or external hosts."""
import copy
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from wsgiref.simple_server import make_server, WSGIRequestHandler
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from decision_collector import App, Store, Rejected, load_credentials, timestamp, validate
from decision_adapter import Client, Outbox, event, record_reviewed
from ledger import Ledger, STREAMS, canonical, now
from test_ledger import fixture

TOKEN = 'synthetic-source-token-not-a-real-secret'
READER = 'synthetic-reader-token-not-a-real-secret'
SOURCE = 'shadow-reviewed-record'
CONTEXT = dict(project_id='test-project', directive_id='test-directive',
               purpose='test reviewed episode recording', rationale='synthetic acceptance test',
               expected_result='durable append receipt', authority_ref='synthetic-local-test-only', simulated=True)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[1] / 'work'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'collector.sqlite3'
        self.store = Store(self.path)
        self.creds = {SOURCE:hashlib.sha256(TOKEN.encode()).hexdigest(), 'other-source':hashlib.sha256(b'other-test-token').hexdigest()}
        self.app = App(self.store, self.creds, hashlib.sha256(READER.encode()).hexdigest())

    def make(self, kind='intent', did='decision1', **kw):
        return event(did, SOURCE, kind, CONTEXT, **kw)

    def request(self, path, payload=None, token=TOKEN, method='POST', raw=None):
        body = raw if raw is not None else canonical(payload)
        environ = dict(PATH_INFO=path, REQUEST_METHOD=method, CONTENT_TYPE='application/json',
                       CONTENT_LENGTH=str(len(body)), HTTP_AUTHORIZATION='Bearer '+token,
                       **{'wsgi.input':io.BytesIO(body)})
        status = []
        response = b''.join(self.app(environ, lambda s,h:status.append(int(s.split()[0]))))
        return status[0], json.loads(response)

    def status(self):
        return self.store.status(self.creds, 180)

    def test_records_survive_independent_process_restart(self):
        value = self.make()
        self.assertEqual(self.request('/v1/events',value)[0],201)
        script = "import sys; from decision_collector import Store; s=Store(sys.argv[1]); print(s.status(['shadow-reviewed-record'],180)['events_count'])"
        result = subprocess.run([sys.executable,'-B','-c',script,str(self.path)],
                   env=__import__('os').environ | {'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'scripts')},
                   capture_output=True,text=True,check=True)
        self.assertEqual(result.stdout.strip(),'1')

    def test_retry_idempotent_and_conflicting_reuse_rejected(self):
        value = self.make()
        self.assertEqual(self.request('/v1/events',value)[0],201)
        self.assertEqual(self.request('/v1/events',value)[0],200)
        value['purpose']='changed intent'
        self.assertEqual(self.request('/v1/events',value)[0],409)
        self.assertEqual(self.status()['events_count'],1)

    def test_concurrent_duplicates_commit_once(self):
        value = self.make()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _:self.store.append(value),range(8)))
        self.assertEqual(sum(not r['duplicate'] for r in results),1)
        self.assertEqual(self.status()['events_count'],1)

    def test_out_of_order_receipt_preserves_occurrence_order(self):
        values = [self.make('intent'),self.make('decision',decision='append'),
                  self.make('action',action='append',execution_status='attempted'),
                  self.make('outcome',outcome='appended',execution_status='succeeded',evidence_refs=['test:receipt'])]
        for v in reversed(values): self.store.append(v)
        self.assertTrue(self.status()['decisions'][0]['complete'])
        self.assertEqual(self.status()['events_count'],4)

    def test_missing_and_explicit_unknown_outcome_stay_incomplete(self):
        self.store.append(self.make())
        self.assertIn('outcome',self.status()['decisions'][0]['missing'])
        self.store.append(self.make('outcome',execution_status='unknown',unknowns=['not observed']))
        self.assertIn('known_outcome',self.status()['decisions'][0]['missing'])
        self.assertFalse(self.status()['decisions'][0]['complete'])

    def test_unauthorized_and_source_spoof_rejected_without_sensitive_logs(self):
        value = self.make(purpose='sensitive test purpose')
        self.assertEqual(self.request('/v1/events',value,token='invalid')[0],401)
        value['source']='other-source'
        self.assertEqual(self.request('/v1/events',value)[0],401)
        self.assertEqual(self.status()['events_count'],0)
        failures = json.dumps(self.status()['recent_failures'])
        self.assertNotIn('sensitive',failures)
        self.assertNotIn(TOKEN,failures)

    def test_reader_cannot_write_and_writer_cannot_read_activity(self):
        self.assertEqual(self.request('/v1/events',self.make(),token=READER)[0],401)
        self.assertEqual(self.request('/v1/activity',token=TOKEN,method='GET')[0],401)
        self.assertEqual(self.request('/v1/activity',token=READER,method='GET')[0],200)

    def test_rejected_json_visible_and_valid_submission_recovers(self):
        self.assertEqual(self.request('/v1/events',raw=b'{"duplicate":1,"duplicate":2}')[0],422)
        self.assertEqual(self.status()['recent_failures'][0]['code'],'invalid_json')
        self.assertEqual(self.request('/v1/events',self.make())[0],201)

    def test_correction_preserves_original_and_requires_review(self):
        original = self.make()
        self.store.append(original)
        correction = self.make('correction',corrects_event_id=original['event_id'],purpose='corrected purpose')
        self.store.append(correction)
        bodies = [r['body'] for r in self.status()['events']]
        self.assertIn(original,bodies)
        self.assertIn(correction,bodies)
        self.assertEqual(self.status()['decisions'][0]['correction_count'],1)
        self.assertFalse(self.status()['decisions'][0]['complete'])
        with self.store.db() as db:
            with self.assertRaises(sqlite3.IntegrityError): db.execute('UPDATE events SET body=?',('{}',))
            with self.assertRaises(sqlite3.IntegrityError): db.execute('DELETE FROM events')

    def test_forward_correction_visible_and_cross_decision_target_rejected(self):
        self.store.append(self.make('correction',corrects_event_id='future'))
        self.assertEqual(self.status()['decisions'][0]['unresolved_corrections'],['future'])
        other = self.make(did='other'); other['event_id']='future'
        with self.assertRaises(Rejected): self.store.append(other)

    def test_heartbeat_stale_detection_uses_server_receive_time(self):
        self.assertTrue(self.status()['sources'][1]['stale'])
        self.assertEqual(self.request('/v1/heartbeat',{'source':SOURCE})[0],200)
        sources = {s['source']:s for s in self.status()['sources']}
        self.assertFalse(sources[SOURCE]['stale'])
        future = datetime.now(timezone.utc).timestamp()+181
        self.assertTrue(all(s['stale'] for s in self.store.status(self.creds,180,future)['sources']))

    def test_backup_restores_history_and_rejects_overwrite(self):
        self.store.append(self.make())
        dest = self.root/'backup.sqlite3'
        self.store.backup(dest)
        restored = Store(dest)
        self.assertEqual(restored.status(self.creds,180)['events_count'],1)
        with self.assertRaises(Rejected): self.store.backup(dest)

    def test_storage_failure_returns_503_and_recovers(self):
        original = self.store.append
        def fail(_): raise sqlite3.OperationalError('synthetic IO failure')
        self.store.append=fail
        self.assertEqual(self.request('/v1/events',self.make())[0],503)
        self.store.append=original
        self.assertEqual(self.request('/v1/events',self.make())[0],201)

    def test_contract_rejects_invented_received_time_missing_authority_and_nan(self):
        value=self.make(); value['received_at']=now()
        self.assertEqual(self.request('/v1/events',value)[0],422)
        value=self.make('decision',decision='append'); value['authority_ref']=None
        self.assertEqual(self.request('/v1/events',value)[0],422)
        self.assertEqual(self.request('/v1/events',raw=b'{"x":NaN}')[0],422)

    def test_oversize_and_unsafe_client_transport(self):
        self.assertEqual(self.request('/v1/events',raw=b'x'*16385)[0],413)
        for url in ('http://example.com','https://user:pass@example.com','https://example.com?token=x'):
            with self.assertRaises(ValueError): Client(url,TOKEN)

    def test_outbox_failed_delivery_survives_restart_and_replays(self):
        path=self.root/'outbox.sqlite3'
        box=Outbox(path); box.enqueue(self.make())
        def fail(_): raise OSError('synthetic disconnect')
        self.assertFalse(box.flush(fail))
        self.assertEqual(Outbox(path).status()[0]['last_error'],'submission_failed')
        self.assertTrue(Outbox(path).flush(self.store.append))
        self.assertEqual(Outbox(path).status()[0]['sent'],1)

    def test_lost_ack_replay_does_not_duplicate(self):
        box=Outbox(self.root/'outbox.sqlite3'); box.enqueue(self.make())
        def lost(value): self.store.append(value); raise OSError('response lost')
        self.assertFalse(box.flush(lost))
        self.assertTrue(box.flush(self.store.append))
        self.assertEqual(self.status()['events_count'],1)

    def local_ledger(self):
        root=self.root/'shadow'; (root/'data').mkdir(parents=True)
        for name in STREAMS.values(): (root/'data'/name).write_bytes(b'')
        return Ledger(root),fixture(root)

    def test_one_existing_workflow_intent_to_outcome(self):
        ledger,payload=self.local_ledger()
        box=Outbox(self.root/'outbox.sqlite3')
        observed=[]
        def send(value):
            observed.append((value['kind'],len(ledger.load())))
            return self.store.append(value)
        receipt=record_reviewed(ledger,box,send,'workflow1','synthetic-record',payload,CONTEXT)
        self.assertEqual(observed,[('intent',0),('decision',0),('action',0),('outcome',1)])
        self.assertTrue(receipt['outcome_delivered'])
        self.assertTrue(self.status()['decisions'][0]['complete'])
        self.assertTrue(self.status()['decisions'][0]['simulated'])
        self.assertEqual(ledger.summary()['incomplete_episodes'],1)

    def test_workflow_stops_if_intent_not_acknowledged(self):
        ledger,payload=self.local_ledger(); box=Outbox(self.root/'outbox.sqlite3')
        def fail(_): raise OSError('offline')
        with self.assertRaises(ValueError): record_reviewed(ledger,box,fail,'workflow1','synthetic-record',payload,CONTEXT)
        self.assertEqual(len(ledger.load()),0)

    def test_real_loopback_http_adapter_and_server_restart(self):
        class QuietHandler(WSGIRequestHandler):
            def log_message(self, *args): pass
        server = make_server('127.0.0.1',0,self.app,handler_class=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            client=Client('http://127.0.0.1:'+str(server.server_port),TOKEN)
            value=self.make()
            try:
                first = client.send(value)
            except urllib.error.URLError as exc:
                if getattr(exc.reason, 'winerror', None) == 10013:
                    self.skipTest('environment denies loopback socket access (WinError 10013)')
                raise
            self.assertFalse(first['duplicate'])
            client.heartbeat(SOURCE)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        # New WSGI server and store instance, same durable database.
        app=App(Store(self.path),self.creds,hashlib.sha256(READER.encode()).hexdigest())
        server=make_server('127.0.0.1',0,app,handler_class=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        try:
            client=Client('http://127.0.0.1:'+str(server.server_port),TOKEN)
            self.assertTrue(client.send(value)['duplicate'])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=5)

    def test_malformed_kind_is_rejected_without_server_exception(self):
        value=self.make(); value['kind']=[]
        self.assertEqual(self.request('/v1/events',value)[0],422)

    def test_workflow_retry_cannot_reexecute_uncertain_action(self):
        ledger,payload=self.local_ledger(); box=Outbox(self.root/'outbox.sqlite3')
        record_reviewed(ledger,box,self.store.append,'workflow1','synthetic-record',payload,CONTEXT)
        with self.assertRaises(ValueError): record_reviewed(ledger,box,self.store.append,'workflow1','synthetic-record',payload,CONTEXT)
        self.assertEqual(len(ledger.load()),1)

    def test_invalid_episode_records_unknown_failed_outcome(self):
        ledger,payload=self.local_ledger(); box=Outbox(self.root/'outbox.sqlite3'); del payload['objective']
        with self.assertRaises(ValueError): record_reviewed(ledger,box,self.store.append,'workflow1','synthetic-record',payload,CONTEXT)
        self.assertFalse(self.status()['decisions'][0]['complete'])
        outcome = next(r['body'] for r in self.status()['events'] if r['body']['kind']=='outcome')
        self.assertIsNone(outcome['outcome'])


if __name__=='__main__': unittest.main()
