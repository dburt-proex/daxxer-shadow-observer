# Decision Ledger v0.1 verification

Executed locally November 14, 2026, Windows / Python 3.11.15, synthetic records
only. Hosted deployment, real-record transmission and long-duration operation
were not performed. The installed Observer copy was read only.

## Acceptance evidence

Reproduce from repository root:

```powershell
# Keep disposable tests under the authorized workspace on restricted Windows hosts.
$env:TMP = Join-Path (Get-Location) 'work'
$env:TEMP = $env:TMP
python -B -W error::ResourceWarning -m unittest discover -s tests -p test_decision_collector.py -v
python -B scripts/demo_decision_ledger.py
python -B -W error::ResourceWarning -m unittest discover -s tests -v
git diff --check
```

| Requirement | Executed evidence | Result |
|---|---|---|
| Persistence through restart | Independent Python process reopens committed SQLite records | Pass |
| Duplicate protection | Exact retry, lost acknowledgement replay, 8 concurrent retries | Pass |
| Out-of-order delivery | Outcome received first; stable grouping and occurrence chronology | Pass |
| Missing outcomes | Missing stage and explicit null outcome remain incomplete | Pass |
| Unauthorized rejection | Invalid token, source spoof, reader-write and writer-read attempts | Pass |
| Visible/recoverable failures | Invalid JSON audit, DB failure 503, durable outbox replay | Pass |
| Preserve corrections | Original body retained; SQL update/delete rejected; unresolved targets visible | Pass |
| Disconnected source | Server-time heartbeat + advanced test clock marks stale after threshold | Pass |
| One workflow trace | Existing Ledger.append on synthetic episode; intent/decision/action before append; receipt afterward | Pass |
| Backup/restore | Consistent SQLite backup reopened at a new path; overwrite refused | Pass |
| Real HTTP process restart | Loopback smoke test | Blocked by WinError 10013 in this environment; explicitly skipped only for that denial |

New suite: 23 test cases, of which 22 exercise local acceptance paths and one
requires loopback HTTP. No other failures are converted into skips.

The synthetic demo produces four stages in order and a complete *recording*
decision. The resulting Observer episode remains incomplete with zero verified
outcomes and zero training eligibility. This deliberately separates successful
ledger recording from the underlying episode's still-unknown real-world result.

## Regression and environment limits

The first broad run encountered sandbox temporary-directory restrictions. A
second run with TMP/TEMP under repository `work/` ran 101 tests: 100 passed,
one existing test errored because OS process identity was unavailable:
`test_shadow_runtime.ShadowRuntimeTests.test_on_status_off_controls_only_verified_observer`.
The source was not changed to weaken that identity requirement.

Two additional tests were then added (malformed kind and real loopback HTTP).
The final full-suite result is recorded in `DECISION_LEDGER_TEST_RESULTS.txt`.
Final result: **103 tests: 101 passed, 1 environment error, 1 environment skip**
in 49.192 seconds. New collector/adapter coverage: **22 passed, 1 socket skip**.
The error is the unchanged Observer process-identity test named above. The
synthetic demo completed successfully and `git diff --check` passed.
The two environment-dependent gaps must be rerun on an unrestricted approved
host before release/deployment acceptance. The entire regression suite is not
claimed green.

The pinned Waitress production-server dependency could not be installed:
the available Python lacks pip, and `uv pip` failed DNS resolution for PyPI.
Its release/version and wheel checksum were verified against official PyPI.
The WSGI callable was exercised directly, not through installed Waitress.
Neither the provider Blueprint nor Linux service has been executed. The
Render configuration needs provider validation and hosted acceptance after
approval. No production readiness guarantee is asserted.

## Review boundaries

An isolated local Git repository preserves the complete upstream source
snapshot. The files were prepared and tested locally before submission to GitHub.
No merge, release or deployment occurred during verification. All implementation code,
technical plan and deployment proposals remain together in that repository.

No source timers, background services, alerts, account changes, purchases,
permissions changes, real-record imports or external record transfers were
activated. The collector is suitable for the proposed small single-instance
pilot subject to the listed unverified deployment gates. Its unbounded history
projection and SQLite disk need capacity review before larger deployments.

Integrity is application-level append-only storage, not tamper-proof storage.
Authority, actor, occurrence time and evidence references are authenticated
source assertions; the collector does not independently verify their truth.
It preserves unknowns and does not execute actions or grant permission.
