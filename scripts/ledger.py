"""Local append-only shadow ledger. Python 3.11+, standard library only."""
import copy
import hashlib
import json
import math
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from storage import StorageError, file_lock, safe_path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / 'schemas'
STREAMS = {'episode': 'episodes.jsonl', 'outcome': 'outcomes.jsonl', 'correction': 'corrections.jsonl'}
GATES = {'read_only': 'ALLOW', 'component_write': 'ALLOW',
         'existing_repo_write': 'REVIEW', 'existing_project_tests': 'REVIEW',
         'external_action': 'REVIEW', 'publish': 'HALT', 'deploy': 'HALT',
         'delete': 'HALT', 'credentials': 'HALT', 'permissions': 'HALT', 'secrets': 'HALT'}


class Invalid(StorageError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def record_hash(record):
    return digest({k: v for k, v in record.items() if k != 'content_hash'})


def parse(text):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise Invalid('duplicate JSON key')
            result[key] = value
        return result
    def bad_constant(_):
        raise Invalid('non-finite JSON number')
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, RecursionError) as exc:
        raise Invalid('invalid JSON (content suppressed)') from exc


def check(value, schema, root=None, location='$'):
    """Validate the explicit JSON Schema subset used by these versioned schemas."""
    root = root or schema
    known = {'$schema', '$defs', '$ref', 'title', 'type', 'properties', 'required',
             'additionalProperties', 'items', 'minItems', 'uniqueItems', 'minLength',
             'pattern', 'format', 'minimum', 'maximum', 'enum', 'const', 'oneOf'}
    if set(schema) - known:
        raise Invalid('unsupported schema keyword')
    if '$ref' in schema:
        name = schema['$ref'].removeprefix('#/$defs/')
        check(value, root['$defs'][name], root, location)
    if 'oneOf' in schema:
        matches = 0
        for choice in schema['oneOf']:
            try:
                check(value, choice, root, location)
                matches += 1
            except Invalid:
                pass
        if matches != 1:
            raise Invalid(location + ': expected exactly one schema match')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise Invalid(location + ': invalid constant')
    if 'enum' in schema and not any(type(value) is type(v) and value == v for v in schema['enum']):
        raise Invalid(location + ': invalid enum')
    types = schema.get('type', [])
    if isinstance(types, str):
        types = [types]
    checks = {'object': type(value) is dict, 'array': type(value) is list,
              'string': type(value) is str, 'boolean': type(value) is bool,
              'null': value is None, 'integer': type(value) is int,
              'number': type(value) in (int, float) and math.isfinite(value)}
    if types and not any(checks.get(t, False) for t in types):
        raise Invalid(location + ': wrong type')
    if type(value) is dict:
        if set(schema.get('required', [])) - value.keys():
            raise Invalid(location + ': missing required field')
        props = schema.get('properties', {})
        if schema.get('additionalProperties') is False and value.keys() - props.keys():
            raise Invalid(location + ': unknown field')
        for key in value.keys() & props.keys():
            check(value[key], props[key], root, location + '.' + key)
    if type(value) is list:
        if len(value) < schema.get('minItems', 0):
            raise Invalid(location + ': too few items')
        if schema.get('uniqueItems') and len({canonical(v) for v in value}) != len(value):
            raise Invalid(location + ': duplicate items')
        for item in value:
            check(item, schema.get('items', {}), root, location + '[]')
    if type(value) is str:
        if len(value.strip()) < schema.get('minLength', 0):
            raise Invalid(location + ': empty string')
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            raise Invalid(location + ': invalid pattern')
        if schema.get('format') == 'date-time':
            try:
                parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    raise ValueError()
            except ValueError as exc:
                raise Invalid(location + ': timezone-aware timestamp required') from exc
    if type(value) in (int, float):
        if not math.isfinite(value) or value < schema.get('minimum', -math.inf) or value > schema.get('maximum', math.inf):
            raise Invalid(location + ': outside bounds')


def schema(name):
    return parse((SCHEMAS / name).read_text(encoding='utf-8'))


def contained(root, relative):
    try:
        return safe_path(root, relative)
    except StorageError as exc:
        raise Invalid(str(exc)) from exc


def evidence_check(items, root):
    ids = set()
    for item in items:
        if item['evidence_id'] in ids:
            raise Invalid('duplicate evidence ID')
        ids.add(item['evidence_id'])
        target = contained(root, item['artifact'])
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != item['sha256']:
            raise Invalid('missing or changed evidence artifact')
    return ids


def episode_check(payload, root):
    check(payload, schema('episode.schema.json'))
    if payload['shadow']['gate'] != GATES[payload['shadow']['operation']]:
        raise Invalid('shadow gate conflicts with v0.1 operation boundary')
    ids = evidence_check(payload['context']['evidence'], root)
    for claim in payload['context']['claims']:
        if not set(claim['evidence_refs']) <= ids:
            raise Invalid('unknown claim evidence reference')
        if claim['classification'] == 'FACT' and not claim['evidence_refs']:
            raise Invalid('FACT requires evidence')
    outcome = payload['outcome']
    if not set(outcome['evidence_refs']) <= ids:
        raise Invalid('unknown outcome evidence reference')
    known = all(payload['actual'][key] is not None for key in payload['actual']) and outcome['result'] is not None and outcome['success'] is not None
    if payload['status'] == 'completed' and not known:
        raise Invalid('completed episode requires actual decision, action and outcome')
    if outcome['verified'] and (payload['status'] != 'completed' or not outcome['verification_method'] or not outcome['verified_by'] or not outcome['evidence_refs']):
        raise Invalid('verified outcome requires completion and verification evidence')


def eligibility(payload, corrections):
    reasons = []
    if payload['status'] != 'completed':
        reasons.append('episode incomplete')
    if not payload['outcome']['verified']:
        reasons.append('outcome unverified')
    if payload['dataset_split'] == 'held_out':
        reasons.append('held-out evaluation data')
    review = payload['training_review']
    if review['reviewer_role'] != 'human' or not review['reviewer']:
        reasons.append('explicit human training review required')
    for key in ('context_sufficient', 'no_secrets', 'no_ambiguous_claims', 'reusable_lesson'):
        if not review[key]:
            reasons.append(key + ' not attested')
    if set(review['correction_hashes']) != set(corrections):
        reasons.append('corrections require review')
    if not payload['evaluation']['lesson']:
        reasons.append('reusable lesson missing')
    if payload['evaluation']['gate_correct'] is None or payload['evaluation']['recommendation_correct'] is None:
        reasons.append('evaluation incomplete')
    if not payload['outcome']['verified_by'] or payload['outcome']['verified_by'] == payload['provenance']['producer']:
        reasons.append('independent outcome verifier required')
    return {'eligible': not reasons, 'reasons': reasons}


class Ledger:
    def __init__(self, root=ROOT):
        self.root = Path(root).resolve()

    def stream(self, kind):
        return contained(self.root, 'data/' + STREAMS[kind])

    @contextmanager
    def lock(self):
        path = contained(self.root, 'data/.writer.lock')
        try:
            with file_lock(path):
                yield
        except StorageError as exc:
            raise Invalid(str(exc)) from exc

    def load(self):
        records = []
        contract = schema('record.schema.json')
        for kind in STREAMS:
            path = self.stream(kind)
            raw = path.read_bytes()
            if raw and not raw.endswith(b'\n'):
                raise Invalid(STREAMS[kind] + ': missing final newline / possible torn write')
            try:
                lines = raw.decode('utf-8').splitlines()
            except UnicodeError as exc:
                raise Invalid('invalid UTF-8') from exc
            previous_sequence = 0
            for number, line in enumerate(lines, 1):
                try:
                    record = parse(line)
                    check(record, contract)
                    if record['kind'] != kind or record['sequence'] <= previous_sequence:
                        raise Invalid('wrong stream or non-monotonic stream sequence')
                    previous_sequence = record['sequence']
                    records.append(record)
                except Invalid as exc:
                    raise Invalid(f'{STREAMS[kind]}:{number}: {exc}') from exc
        records.sort(key=lambda r: r['sequence'])
        self.validate_records(records)
        return records

    def validate_records(self, records):
        latest, corrections, ids = {}, {}, set()
        previous = None
        for sequence, record in enumerate(records, 1):
            if record['sequence'] != sequence or record['previous_hash'] != previous:
                raise Invalid('broken global sequence or hash chain')
            if record['record_id'] in ids:
                raise Invalid('duplicate record ID')
            ids.add(record['record_id'])
            if record_hash(record) != record['content_hash']:
                raise Invalid('content hash mismatch')
            payload = record['payload']
            eid = payload['episode_id']
            kind = record['kind']
            if kind == 'correction':
                check(payload, schema('record.schema.json')['$defs']['correction'], schema('record.schema.json'))
                if eid not in latest or record['supersedes'] != latest[eid]['content_hash']:
                    raise Invalid('correction target missing or stale')
                evidence_check(payload['evidence'], self.root)
                corrections[eid].append(record['content_hash'])
                expected = {'eligible': False, 'reasons': ['correction annotation is not a training episode']}
            else:
                episode_check(payload, self.root)
                if kind == 'episode':
                    if eid in latest or record['supersedes'] is not None:
                        raise Invalid('duplicate episode ID or invalid initial revision')
                    corrections[eid] = []
                else:
                    if eid not in latest or record['supersedes'] != latest[eid]['content_hash']:
                        raise Invalid('outcome target missing or stale')
                    old = latest[eid]['payload']
                    for key in ('episode_id', 'timestamp', 'objective', 'project', 'task_type', 'shadow', 'provenance', 'dataset_split'):
                        if payload[key] != old[key]:
                            raise Invalid('outcome cannot rewrite original context or recommendation')
                    for key in ('claims', 'constraints', 'authority', 'evidence'):
                        if payload['context'][key][:len(old['context'][key])] != old['context'][key]:
                            raise Invalid('outcome may only append context')
                expected = eligibility(payload, corrections[eid])
                latest[eid] = record
            if record['training_eligibility'] != expected:
                raise Invalid('training eligibility does not match deterministic rules')
            previous = record['content_hash']
        return latest, corrections

    def append(self, kind, record_id, payload, supersedes=None):
        if kind not in STREAMS:
            raise Invalid('unknown record kind')
        with self.lock():
            records = self.load()
            _, corrections = self.validate_records(records)
            if kind == 'correction':
                training = {'eligible': False, 'reasons': ['correction annotation is not a training episode']}
            else:
                episode_check(payload, self.root)
                training = eligibility(payload, corrections.get(payload['episode_id'], []))
            record = {'schema_version': '0.1', 'record_id': record_id, 'kind': kind,
                      'sequence': len(records) + 1, 'recorded_at': now(),
                      'previous_hash': records[-1]['content_hash'] if records else None,
                      'supersedes': supersedes, 'payload': copy.deepcopy(payload),
                      'training_eligibility': training}
            record['content_hash'] = record_hash(record)
            check(record, schema('record.schema.json'))
            self.validate_records(records + [record])
            encoded = canonical(record) + b'\n'
            with self.stream(kind).open('ab', buffering=0) as handle:
                if handle.write(encoded) != len(encoded):
                    raise Invalid('short append; stop and preserve ledger for recovery')
                os.fsync(handle.fileno())
            return record

    def summary(self):
        records = self.load()
        latest, corrections = self.validate_records(records)
        episodes = [r['payload'] for r in latest.values()]
        return {'episodes_captured': len(episodes),
                'completed_episodes': sum(p['status'] == 'completed' for p in episodes),
                'incomplete_episodes': sum(p['status'] == 'incomplete' for p in episodes),
                'verified_outcomes': sum(p['outcome']['verified'] for p in episodes),
                'corrections': sum(r['kind'] == 'correction' for r in records),
                'training_eligible_episodes': sum(eligibility(p, corrections[p['episode_id']])['eligible'] for p in episodes),
                'validation_errors': 0, 'records': len(records),
                'head_hash': records[-1]['content_hash'] if records else None}
