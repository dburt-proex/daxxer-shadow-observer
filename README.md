# DAXXER Shadow Operator + Experience Ledger

A local observer you turn ON when you want to capture work and OFF when you do
not. It observes explicitly configured folders, ranks safe changes with VIL,
and records incomplete experience episodes automatically. It never executes
recommendations. Python 3.11+; standard library only.

## Start here

From PowerShell in this repository:

```powershell
python --version
.\shadow.cmd init
.\shadow.cmd on
.\shadow.cmd status
.\shadow.cmd off
.\shadow.cmd validate
.\shadow.cmd summary
```

On other platforms, use `python3 -B scripts/shadow.py <command>`.
The default source is `inbox/`. Put non-sensitive work notes there. The default
reviewer uses deterministic rules, with no model download, account or API bill.
ON starts a background process; it does not install a login/startup service.
OFF waits for a verified process to exit gracefully. An in-flight local model
request may delay shutdown; if OFF returns an error, inspect STATUS and retry.
There is no forced kill. If the process dies or the machine restarts, turn it ON again.

## Optional local model

With Ollama already running on this machine and a local model installed:

```powershell
.\shadow.cmd off
.\shadow.cmd model --name qwen3.5:4b
.\shadow.cmd on
```

This writes ignored `config/reviewer.local.json`. `shadow.cmd rules` switches
back while OFF. No automatic downloads or cloud fallback. The adapter uses
[Ollama's chat API](https://docs.ollama.com/api/chat) on
`127.0.0.1:11434`, disables proxy routing and redirects, checks local model
metadata, bounds inputs/outputs, and rejects tool calls. Model interpretations
and lessons are provisional; their truth and practical quality are not certified.

## What it observes

Review `config/shadow-config.json` while OFF to configure additional approved
sources. Each source needs a unique ID, absolute path, depth/file limits and a
metadata/content choice. `${COMPONENT_ROOT}/inbox` is portable. Prefer
`metadata_only: true` for project folders and `first_run_mode: baseline` to
ignore existing history. Content capture is appropriate for a deliberately
curated inbox. Files over the content limit or outside allowed extensions yield
metadata only. Hidden paths, secret-like names, symlinks, Windows junctions and
excluded dependency/output folders are skipped.

It does not observe screens, browser history, keystrokes, messages or every daily
operation automatically. Only the configured source folders are in scope.
Editing this configuration is the explicit one-time source approval.
Do not put sensitive material in approved content sources: secret filtering is
heuristic, and metadata can itself reveal sensitive filenames.

## How the loop works

1. Safety/source scope filters run before candidate retention.
2. VIL is the minimum of weighted usefulness and weighted verifiability.
3. Candidates route to retained, pending or rejected hash-chained queues.
4. The configured rules/local-model reviewer captures retained and pending
   candidates as incomplete episodes with immutable evidence snapshots.
5. Actual decisions, outcomes and verification remain unknown until supplied
   through reviewed append-only revisions. Rejected content is never retained.
6. Reports update after newly recorded episodes; `summary` refreshes on demand.

VIL's weights and thresholds are an explicit intake profile, not a validated
business metric. Independent corroboration is not measured by this observer;
it uses a zero scoring floor and cannot claim corroboration from a config value.
A retained candidate is useful to review, not a verified fact or approval.

## Records and training

`data/episodes.jsonl`, `outcomes.jsonl` and `corrections.jsonl` share a global
sequence and SHA-256 chain. Sorted UTF-8 compact JSON with non-finite values
forbidden defines canonical hashing. Records include provenance, evidence
hashes, decisions, verification and deterministic training-eligibility reasons.
Queue records use a separate global chain across their three routes.

Use an authorized agent to prepare an episode/outcome/correction payload:

```powershell
.\shadow.cmd record --input work\reviewed-payload.json --record-id your-unique-id
.\shadow.cmd record --input work\reviewed-outcome.json --record-id outcome-id --kind outcome --supersedes LATEST_EPISODE_HASH
```

See `schemas/episode.schema.json` and `schemas/record.schema.json` for the exact
payload contract. Outcomes cannot rewrite original predictions; corrections
are annotations. Training requires completion, hash-checked outcome evidence,
a distinct verifier, completed evaluation, reusable lesson, human attestation
and review of all corrections. Held-out episodes are excluded. Automatic
capture never claims human approval or training eligibility. No training,
retrieval indexing, model promotion or autonomy escalation is implemented.

## Boundaries and recovery

ALLOW: approved reads and component writes. REVIEW: existing-project changes,
project tests and consequential external recommendations. HALT: secrets,
deletion, credential/permission changes, publication and deployment. These
boundaries constrain this component; no action executor exists. The local
model has no tools. Host/OS permissions still determine actual containment.

Live data, evidence, queues, inbox, runtime state, reports and local config are
ignored by Git. Source and tests are separate from personal experience records.
Schema versions remain ledger 0.1 and observer 0.2. Existing local ledgers are
not migrated or imported automatically.

On corruption: OFF, preserve all original stream/evidence bytes and a trusted
head receipt, and investigate copies. Do not truncate, rewrite or silently
repair records. OS locks release after crashes; lock files may remain normally.
Hashes are not signatures and cannot detect a fully rewritten history or
deleted valid suffix without an independently preserved trusted head.
To retire the component, turn it OFF and archive the whole repository and its
ignored local records. No external service or startup entry requires undoing.

## Verification

```powershell
python -B -W error::ResourceWarning -m unittest discover -s tests -v
.\shadow.cmd validate
.\shadow.cmd summary
git diff --check
```

Tests use disposable sources and model mocks. Live model quality, GitHub CI,
other operating systems and long-duration operation require separate evidence.
See [bounded acceptance scope](docs/SPEC.md), [review](docs/REVIEW.md) and
[architecture](docs/ARCHITECTURE.md). Local executed evidence is in
`reports/build-verification.md` and `reports/experience-summary.md`.
