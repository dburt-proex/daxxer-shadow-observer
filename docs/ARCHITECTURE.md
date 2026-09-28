# Architecture

```text
Approved source folders (read only)
    -> safety filter -> bounded observation
    -> VIL usefulness capped by verifiability
    -> pending / retained / rejected queues (global intake chain)
    -> rules or loopback local-model reviewer (no tools)
    -> immutable evidence + incomplete episode (ledger chain)
    -> reviewed outcome/correction revisions
    -> training eligibility + experience summary
```

`shadow.cmd` calls `scripts/shadow.py`. `shadowctl.py` owns process controls.
`shadow_runtime.py` owns source enumeration/intake. `vil.py` ranks candidates.
`reviewer.py` produces snapshots and constrained model advice. `ledger.py`
owns strict schema validation, hashes, revisions and training eligibility.
`storage.py` provides contained paths and OS locks.

Control states: OFF (absent/stopped), ON (live verified process), stale (dead
recorded PID), unverified (identity mismatch), error (failed scan/model or
heartbeat). CLI exit 0 means the command's checks passed; 1 means failure,
degraded operation or attention needed; argument errors use argparse exit 2.
ON verifies identity; later STATUS also reports last scan/error/heartbeat.
OFF may return 1 while an in-flight operation exits and must not claim success.

Only source content selected by configuration reaches the local reviewer.
Model text is classified as interpretation; gate remains REVIEW. Neither
VIL nor model output can fill actual/outcome/human-review fields.

Storage is local plaintext. Two separate global SHA-256 chains cover intake
and episode/outcome/correction records. Evidence snapshots are immutable,
hash-checked and component-relative. Personal files are ignored by Git.
Different ledgers (CASA, Runwall, DiffWall, Operator Intelligence) are not
integrated or merged into this one.
