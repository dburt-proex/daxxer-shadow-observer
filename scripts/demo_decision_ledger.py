"""Reproducible synthetic demo; creates only a new disposable local workspace."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from test_ledger import fixture
from decision_adapter import Outbox, record_reviewed
from decision_collector import Store
from ledger import Ledger, STREAMS


def main():
    scratch=Path(__file__).resolve().parents[1]/'work'
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as temp:
        root=Path(temp); (root/'shadow'/'data').mkdir(parents=True)
        for name in STREAMS.values(): (root/'shadow'/'data'/name).write_bytes(b'')
        ledger=Ledger(root/'shadow'); store=Store(root/'collector.sqlite3')
        context=dict(project_id='synthetic-project',directive_id='synthetic-acceptance',
                     purpose='Record one reviewed synthetic episode',rationale='Prove recording trace locally',
                     expected_result='Durable local episode receipt',authority_ref='synthetic-test-only',simulated=True)
        receipt=record_reviewed(ledger,Outbox(root/'outbox.sqlite3'),store.append,
                               'synthetic-demo','synthetic-episode',fixture(root/'shadow'),context)
        report=store.status(['shadow-reviewed-record'],180)
        print(json.dumps({'simulated':True,'receipt':receipt,'decision':report['decisions'][0],
                          'stages':[r['body']['kind'] for r in reversed(report['events'])],
                          'local_episode_summary':ledger.summary()},indent=2))


if __name__=='__main__': main()
