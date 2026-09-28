"""Synthetic fixtures only; tests never open or modify the real DAXXER repo."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ledger import GATES, Invalid, Ledger, ROOT, STREAMS, canonical, check, digest, now, record_hash, schema


def fixture(root):
    artifact = root / 'evidence.txt'
    artifact.write_text('Synthetic observed outcome.\n', encoding='utf-8')
    evidence = {'evidence_id': 'E1', 'source': 'synthetic test', 'artifact': 'evidence.txt',
                'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(), 'captured_at': now(), 'method': 'synthetic fixture'}
    return {'episode_id': 'TEST-1', 'timestamp': now(), 'status': 'incomplete',
            'objective': 'Synthetic test', 'project': 'TEST ONLY', 'task_type': 'read-only assessment',
            'context': {'claims': [{'classification': 'FACT', 'text': 'Synthetic fact', 'evidence_refs': ['E1']}],
                        'constraints': ['No external actions'], 'authority': ['Read only'], 'evidence': [evidence]},
            'shadow': {'current_state': 'Test fixture', 'recommended_action': 'Inspect', 'operation': 'read_only',
                       'expected_result': 'Evidence', 'gate': 'ALLOW', 'required_evidence': ['E1'], 'confidence': 0.75},
            'actual': {'decision': None, 'decision_by': None, 'gate': None, 'action_taken': None},
            'outcome': {'result': None, 'success': None, 'verification_method': None, 'verified': False,
                        'verified_by': None, 'evidence_refs': []},
            'evaluation': {'recommendation_correct': None, 'gate_correct': None, 'reasoning_issue': None,
                           'correction': None, 'lesson': None},
            'training_review': {'reviewer': None, 'reviewer_role': 'unreviewed', 'context_sufficient': False,
                                'no_secrets': False, 'no_ambiguous_claims': False, 'reusable_lesson': False, 'correction_hashes': []},
            'dataset_split': 'learning', 'provenance': {'producer': 'test-agent', 'model': None, 'operator': None,
                                                       'workspace': str(root), 'source_conversation': None, 'capture_method': 'synthetic'}}


def complete(payload):
    p = copy.deepcopy(payload)
    p['status'] = 'completed'
    p['actual'] = {'decision': 'Inspect', 'decision_by': 'test-human', 'gate': 'ALLOW', 'action_taken': 'Inspected'}
    p['outcome'] = {'result': 'Observed', 'success': True, 'verification_method': 'Synthetic independent check',
                    'verified': True, 'verified_by': 'test-verifier', 'evidence_refs': ['E1']}
    p['evaluation'].update(recommendation_correct=True, gate_correct=True, lesson='Check evidence')
    p['training_review'].update(reviewer='test-human', reviewer_role='human', context_sufficient=True,
                                 no_secrets=True, no_ambiguous_claims=True, reusable_lesson=True)
    return p


class LedgerTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / 'work'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'data').mkdir()
        for name in STREAMS.values():
            (self.root / 'data' / name).write_bytes(b'')
        self.ledger = Ledger(self.root)
        self.p = fixture(self.root)

    def add(self, payload=None, record_id='r1'):
        return self.ledger.append('episode', record_id, self.p if payload is None else payload)

    def rewrite(self, records):
        # Deliberate tampering confined to disposable test fixtures.
        for kind in STREAMS:
            self.ledger.stream(kind).write_bytes(b''.join(canonical(r) + b'\n' for r in records if r['kind'] == kind))

    def test_valid_episode_and_report_counts(self):
        record = self.add()
        self.assertFalse(record['training_eligibility']['eligible'])
        self.assertEqual(self.ledger.summary()['incomplete_episodes'], 1)

    def test_missing_required_field(self):
        del self.p['objective']
        with self.assertRaises(Invalid): self.add()

    def test_invalid_gate(self):
        self.p['shadow']['gate'] = 'OK'
        with self.assertRaises(Invalid): self.add()

    def test_confidence_bounds_and_types(self):
        for value in (-0.1, 1.1, True, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(Invalid):
                self.p['shadow']['confidence'] = value
                self.add()

    def test_duplicate_episode_and_record_id(self):
        self.add()
        with self.assertRaises(Invalid): self.add(record_id='r2')
        self.p['episode_id'] = 'TEST-2'
        with self.assertRaises(Invalid): self.add()

    def test_malformed_jsonl(self):
        self.ledger.stream('episode').write_bytes(b'{invalid}\n')
        with self.assertRaises(Invalid): self.ledger.load()

    def test_duplicate_json_keys_and_nonfinite(self):
        for raw in (b'{"a":1,"a":2}\n', b'{"a":NaN}\n', b'\n'):
            self.ledger.stream('episode').write_bytes(raw)
            with self.assertRaises(Invalid): self.ledger.load()

    def test_hash_is_deterministic_and_order_independent(self):
        self.assertEqual(digest({'b': 2, 'a': 1}), digest({'a': 1, 'b': 2}))
        self.assertEqual(digest({'a': 1}), hashlib.sha256(b'{"a":1}').hexdigest())
        r = self.add()
        self.assertEqual(record_hash(r), r['content_hash'])

    def test_incomplete_not_eligible_even_with_review(self):
        p = complete(self.p)
        p['status'] = 'incomplete'
        p['outcome']['verified'] = False
        self.assertFalse(self.add(p)['training_eligibility']['eligible'])

    def test_completed_requires_actual_outcome(self):
        self.p['status'] = 'completed'
        with self.assertRaises(Invalid): self.add()

    def test_verified_requires_verifier_and_evidence(self):
        for field, value in [('verified_by', None), ('evidence_refs', []), ('verification_method', None)]:
            p = complete(self.p)
            p['outcome'][field] = value
            with self.subTest(field=field), self.assertRaises(Invalid): self.add(p)

    def test_human_review_and_independent_verifier_required(self):
        for field in ('reviewer_role', 'no_secrets', 'no_ambiguous_claims', 'context_sufficient', 'reusable_lesson'):
            p = complete(self.p)
            p['training_review'][field] = 'agent' if field == 'reviewer_role' else False
            r = self.add(p)
            self.assertFalse(r['training_eligibility']['eligible'])
            self.rewrite([])
        p = complete(self.p)
        p['outcome']['verified_by'] = 'test-agent'
        self.assertFalse(self.add(p)['training_eligibility']['eligible'])

    def test_held_out_is_never_eligible(self):
        p = complete(self.p)
        p['dataset_split'] = 'held_out'
        self.assertFalse(self.add(p)['training_eligibility']['eligible'])

    def test_completed_reviewed_episode_can_be_eligible(self):
        self.assertTrue(self.add(complete(self.p))['training_eligibility']['eligible'])

    def test_outcome_appends_preserves_original_bytes(self):
        first = self.add()
        original = self.ledger.stream('episode').read_bytes()
        updated = self.ledger.append('outcome', 'r2', complete(self.p), first['content_hash'])
        self.assertEqual(original, self.ledger.stream('episode').read_bytes())
        self.assertEqual(updated['previous_hash'], first['content_hash'])
        self.assertEqual(self.ledger.summary()['completed_episodes'], 1)

    def test_outcome_cannot_rewrite_prediction_or_remove_evidence(self):
        first = self.add()
        p = complete(self.p)
        p['shadow']['recommended_action'] = 'Changed after outcome'
        with self.assertRaises(Invalid): self.ledger.append('outcome', 'r2', p, first['content_hash'])
        p = complete(self.p)
        p['context']['claims'][0]['text'] = 'Rewritten fact'
        with self.assertRaises(Invalid): self.ledger.append('outcome', 'r2', p, first['content_hash'])

    def test_correction_invalidates_until_reviewed(self):
        first = self.add(complete(self.p))
        correction = {'episode_id': 'TEST-1', 'correction': 'Clarification', 'lesson': 'Check again',
                      'reviewer': 'test-human', 'evidence': self.p['context']['evidence']}
        c = self.ledger.append('correction', 'r2', correction, first['content_hash'])
        self.assertEqual(self.ledger.summary()['training_eligible_episodes'], 0)
        updated = complete(self.p)
        updated['training_review']['correction_hashes'] = [c['content_hash']]
        self.ledger.append('outcome', 'r3', updated, first['content_hash'])
        self.assertEqual(self.ledger.summary()['training_eligible_episodes'], 1)

    def test_orphan_and_stale_outcomes_rejected(self):
        with self.assertRaises(Invalid): self.ledger.append('outcome', 'r2', complete(self.p), '0' * 64)
        first = self.add()
        self.ledger.append('outcome', 'r2', complete(self.p), first['content_hash'])
        with self.assertRaises(Invalid): self.ledger.append('outcome', 'r3', complete(self.p), first['content_hash'])

    def test_tampering_detected(self):
        r = self.add()
        r['payload']['objective'] = 'Tampered'
        self.rewrite([r])
        with self.assertRaises(Invalid): self.ledger.load()

    def test_forged_eligibility_detected_even_after_rehash(self):
        r = self.add()
        r['training_eligibility'] = {'eligible': True, 'reasons': []}
        r['content_hash'] = record_hash(r)
        self.rewrite([r])
        with self.assertRaises(Invalid): self.ledger.load()

    def test_evidence_changed_missing_or_traversal(self):
        self.add()
        (self.root / 'evidence.txt').write_text('Changed')
        with self.assertRaises(Invalid): self.ledger.load()
        self.rewrite([])
        self.p['context']['evidence'][0]['artifact'] = '../outside.txt'
        with self.assertRaises(Invalid): self.add()

    def test_unknown_evidence_and_fact_without_reference(self):
        for refs in ([], ['UNKNOWN']):
            self.p['context']['claims'][0]['evidence_refs'] = refs
            with self.assertRaises(Invalid): self.add()

    def test_missing_stream_and_torn_write_fail_closed(self):
        self.ledger.stream('episode').write_bytes(b'{}')
        with self.assertRaises(Invalid): self.ledger.load()
        self.ledger.stream('episode').unlink()
        with self.assertRaises(OSError): self.ledger.load()

    def test_lock_blocks_second_process_without_append(self):
        code = 'from ledger import Ledger;\nwith Ledger(__import__("sys").argv[1]).lock(): pass'
        with self.ledger.lock():
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.root)], cwd=ROOT / 'scripts', capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.ledger.load(), [])

    def test_gate_boundaries(self):
        for operation, gate in GATES.items():
            self.p['shadow'].update(operation=operation, gate=gate)
            self.add(record_id=operation)
            self.rewrite([])
            self.p['shadow']['gate'] = 'HALT' if gate == 'ALLOW' else 'ALLOW'
            with self.assertRaises(Invalid): self.add()

    def test_unknown_fields_and_naive_timestamps(self):
        self.p['unexpected'] = True
        with self.assertRaises(Invalid): self.add()
        del self.p['unexpected']
        self.p['timestamp'] = '2026-09-18T12:00:00'
        with self.assertRaises(Invalid): self.add()

    def test_chain_gap_and_wrong_stream(self):
        r = self.add()
        r['sequence'] = 3
        r['content_hash'] = record_hash(r)
        self.rewrite([r])
        with self.assertRaises(Invalid): self.ledger.load()
        self.ledger.stream('episode').write_bytes(b'')
        self.ledger.stream('outcome').write_bytes(canonical(r) + b'\n')
        with self.assertRaises(Invalid): self.ledger.load()

    def test_schema_validator_rejects_unsupported_keywords(self):
        with self.assertRaises(Invalid): check('x', {'imaginaryKeyword': True})


if __name__ == '__main__':
    unittest.main()
