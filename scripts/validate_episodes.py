"""Validate all streams, revisions, hashes, local evidence and eligibility."""
import json
from ledger import Invalid, Ledger


def main():
    try:
        print(json.dumps(Ledger().summary(), indent=2))
        return 0
    except (Invalid, OSError, UnicodeError) as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, Invalid) else type(exc).__name__))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
