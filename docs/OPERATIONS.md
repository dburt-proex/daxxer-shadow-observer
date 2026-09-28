# Daily operation

One-time setup: Python 3.11+, `shadow.cmd init`, approved source configuration.
Optionally configure an already installed local model using
`shadow.cmd model --name MODEL`. No package installation is required for the
rules reviewer. Keep personal source paths and reviewer overrides local.

Daily controls:

| Need | Command |
|---|---|
| Observe approved folders | `shadow.cmd on` |
| See process health/reviewer/last scan | `shadow.cmd status` |
| Stop observation | `shadow.cmd off` |
| Explicit one-time scan while OFF | `shadow.cmd scan` |
| Retry unrecorded candidates | `shadow.cmd review` |
| Check all record/evidence chains | `shadow.cmd validate` |
| Refresh experience report | `shadow.cmd summary` |
| Full local release receipt | `python -B scripts/verify.py` |

Only ON/OFF are needed for routine automatic capture after source setup.
Outcome verification and human training approval remain deliberate steps.
Read `reports/experience-summary.md` for captured experience counts.

If STATUS is stale, OFF reconciles a dead recorded process without killing
anything. If STATUS is unverified, investigate the recorded PID and preserve
state; no termination is authorized. On model failure, episodes remain
unrecorded and the candidate is retried; the system never invents success or
falls back to a cloud model. OFF can take up to the outstanding model timeout;
an initial pending/error return requires checking STATUS and retrying OFF.

Live data is local plaintext and ignored by Git. Back up all data streams,
queues, evidence and a trusted head receipt together while OFF. Archive a copy
before any recovery work. Retention/deletion and existing-ledger migration are
manual, separately authorized operations. No automatic cleanup or rollover.
