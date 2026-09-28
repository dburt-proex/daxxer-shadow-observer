"""Generate the report only after complete dataset validation succeeds."""
from ledger import Invalid, Ledger, ROOT, contained, eligibility, now


def generate(root=ROOT):
    root = __import__('pathlib').Path(root)
    ledger = Ledger(root)
    with ledger.lock():
        summary = ledger.summary()
        text = '# DAXXER Experience Summary\n\nGenerated: ' + now() + '\n\n'
        text += '| Metric | Value |\n|---|---|\n'
        text += ''.join(f'| {k.replace("_", " ")} | {v} |\n' for k, v in summary.items())
        latest, corrections = ledger.validate_records(ledger.load())
        text += '\n## Episode state\n\n'
        for record in latest.values():
            p = record['payload']
            text += f"- {p['episode_id']}: {p['status']}; gate {p['shadow']['gate']}; training eligible {eligibility(p, corrections[p['episode_id']])['eligible']}.\n"
        text += '\nUnknown outcomes remain unknown. Verification and human-review fields are local attestations, not authenticated identities. Hashes detect changes relative to a preserved trusted head; they are not signatures. No action execution, training, deployment or authority escalation.\n'
        target = contained(root, 'reports/experience-summary.md')
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = contained(root, 'reports/experience-summary.tmp')
        temporary.write_text(text, encoding='utf-8', newline='\n')
        __import__('os').replace(temporary, target)
    return target


def main():
    try:
        generate()
        print('reports/experience-summary.md generated; validation passed')
        return 0
    except (Invalid, OSError, UnicodeError) as exc:
        print('ERROR: ' + (str(exc) if isinstance(exc, Invalid) else type(exc).__name__))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
