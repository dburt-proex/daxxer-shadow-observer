# Review of GitHub and earlier component

Reviewed 2026-09-28 using the GitHub connector and a fresh local clone.
Repository: https://github.com/dburt-proex/daxxer-shadow-observer
Reviewed main: b5d9d196d8e73fb3fab440970ca96291bdd1afa7.
Tree: README.md only, one newline. Open issues: zero at review time.
There was no implementation, roadmap or test suite on GitHub.

The earlier isolated local ledger supplied the initial schemas, validation,
prompts and test foundation. Personal datasets and evidence were not imported.

## Findings addressed in this build

- Missing repository implementation: added the bounded ledger, observer,
  automatic reviewer, CLI, tests, documentation and CI.
- Crash-sensitive exclusive-file locks: replaced with OS advisory locks and
  added scan/control/review serialization.
- Weak queue contracts and late validation: validate shape, content hashes,
  observation identity, routes, authority and recomputed VIL before append.
- Directory links and deleted scan cursors: reject links/junctions throughout
  paths; use lexical cursors and rotate source order.
- Unnecessary baseline text reads/history ingestion: baseline uses metadata
  only and refuses state-capacity overflow.
- Raw rejected content and inline credentials: rejected content remains null;
  added broader credential patterns and coverage for inline JSON/variables.
- Potential forced termination during append: graceful stop only, verified
  OS identity, explicit stop-pending errors and no force fallback.
- Windows virtual-environment launcher identity: launch the stdlib observer
  through the base interpreter and record OS executable/creation identity.
- Candidate-only intake with no operating loop: automatic incomplete episode
  snapshots, rules/local-model review, unknown outcomes and strict training rules.

## Residual limits

No OS sandbox, authenticated identities, signed or externally anchored log,
guaranteed secret detection, model accuracy guarantee or authority executor.
Metadata deduplication uses source ID/root/path/size/mtime; edits deliberately
preserving size and timestamp can be missed. Config edits require OFF first.
Source walks remain polling, not a filesystem event journal: intermediate
changes and deletions are not reconstructed. File count limits bound captured
work, but traversal of large directory trees can take time. Local-file
check/open races against a hostile concurrent filesystem actor are not
eliminated. Missing/unreadable sources and model failures produce errors.
