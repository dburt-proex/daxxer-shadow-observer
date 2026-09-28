"""Append an episode, outcome revision, or correction; never executes its action."""
import argparse
import json
from pathlib import Path
from ledger import Invalid, Ledger, parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='reviewed UTF-8 JSON payload')
    parser.add_argument('--kind', choices=['episode', 'outcome', 'correction'], default='episode')
    parser.add_argument('--record-id', required=True)
    parser.add_argument('--supersedes', help='latest episode/outcome content hash; required for updates')
    args = parser.parse_args()
    try:
        record = Ledger().append(args.kind, args.record_id, parse(args.input.read_text(encoding='utf-8')), args.supersedes)
        print(json.dumps({'record_id': record['record_id'], 'content_hash': record['content_hash'], 'training_eligibility': record['training_eligibility']}))
        return 0
    except (Invalid, OSError, UnicodeError) as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, Invalid) else type(exc).__name__))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
