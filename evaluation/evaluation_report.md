# Evaluation report

## Readiness

**Submission status: NO-GO.** The independent replay processed all 518 requests and reproduced 381 contract-valid, evidence-cited candidate rows; 137 requests remain unresolved. The 381 rows are preserved in `results/partial_validated_rows_not_for_submission.csv` with a manifest at `evaluation/partial_replay_manifest.json`. A case-by-case fallback classification for all 137 blockers is at `evaluation/fallback_case_classification.json`. These files are diagnostic only and are not substitutes for the required root `output.csv`. The official writer correctly rejects fewer than 518 rows, and root `output.csv` remains absent.

| Metric | Result |
|---|---:|
| Case-level deletion-status accuracy | Not measured; no complete prediction file |
| Step-level / field-level accuracy | Not measured |
| Ordered sequence accuracy | Not measured |
| Contract-valid candidate rows preserved | 381 of 518 |
| Unresolved requests | 137 of 518 |
| 32-case sample replay | Blocked at `case_01`; case26 also blocks when replayed alone |
| Full independent replay | All 518 processed; 381 valid candidates, 137 unresolved |
| Root `output.csv` | Not generated |
| Official submission readiness | NO-GO |

## Case 26: verification-only intent

The task contract distinguishes deletion authorization from authorization to verify a deletion: `NOT_APPLICABLE` applies when neither deletion nor deletion verification is authorized, and `COMPLETE` contains evidence-backed verification steps only. The request says to check the latest state and confirm the profile is gone and remaining records cannot identify the requester. It authorizes a read-only verification audit; it does not authorize new deletion, redaction, or other remediation.

An integration-owned semantic adapter now represents this as `Intent.VERIFY_ONLY`. It requires verification language, prior-report/request context, a deletion-state postcondition, and no new or negated destructive directive. Explicit new deletion stays `DELETE`; negated deletion stays `NOT_DELETE`; a general data question and unclear requests stay `AMBIGUOUS`. The pipeline permits identity resolution and evidence search for `VERIFY_ONLY`, but it does not serialize remediation or a deletion verdict unless the policy engine proves a compliant state. The web journey likewise returns no status or steps and reports the unresolved state. No remediation is executed.

The sample row expects six `VERIFICATION` steps, all citing `evidence_92`. That file was captured at 2026-09-15 11:44:55 UTC, before the 12:00 UTC audit cutoff, and contains records for all six named resource IDs. However, the account and analytics rows in that export do not establish that those resources belong to `user_26`:

- `account_5684` has a 404 response and a null profile, but the cutoff-valid row has no subject/customer reference. The activity entry `activity_3600` names the resource and reports a failed deletion attempt; it does not link the resource to this subject.
- `analytics_4566` has a null customer reference and aggregate cohort metrics, but the cutoff-valid row does not establish that this is the subject's record. `activity_3603` reports an anonymization action but is an activity claim, not subject linkage or state proof.
- `evidence_02` later names these resources with `user_26`, but its manifest capture is 2026-09-17, after the audit cutoff, so it cannot support this answer.

The other four sample resources (`audit_record_5416`, `support_4715`, `data_flow_6244`, and `backup_3120`) are discoverable with subject-linked evidence. The actual search returns four observations. The policy engine raises `Cannot establish COMPLETE without evidence-backed verification`; the pipeline blocks instead of emitting the sample's unsupported `COMPLETE` row. Thus, the sample's *verification-only step structure* is correct and needs no fresh destructive operations, but the available cutoff-valid evidence does not support all six subject-specific claims.

## Prototype feature verification

A local HTTP smoke test confirmed `GET /` serves the application and its visible feature navigation, and `GET /api/cases` returns 550 real sample/evaluation requests. `POST /api/verify` case16 returned an `INCOMPLETE` decision, seven graph nodes, five evidence-backed edges, two risk cards, and an `INDETERMINATE` Rebirth finding. A `POST /api/what-if` returned `simulation_only: true` and left the decision `INCOMPLETE`; `deletion_executed` remained false.

Case15 returned an `INCOMPLETE` decision with a high-severity active-flow risk. The trace-linked resource `data_flow_9846` cites `evidence_01`, trace `tr-9750867`, identifier locator `line:85`, and resource locator `line:88`. Its graph has seven nodes and five edges; Rebirth remains `INDETERMINATE`. No external deployment was performed; the local launch command is `python3 -m code.web_app --port 8000`.

## Regression and integration validation

- **Full unittest discovery after root test reorganization:** `./scripts/run_tests.sh` ran 167 tests: 163 passed, 3 skipped, and 1 errored. The sole error is `test_sample_dataset_identity_and_policy_scenarios`, which stops at `case_01` because no cutoff-valid evidence links the resolved subject to a resource. This is the known fail-closed sample blocker, not a test-discovery or intent-classifier regression.
- **Explainability safeguard:** M3's verified safeguard is now integrated: COMPLETE verification citations must resolve to indexed evidence records; activity-only and identity-audit-only citations are rejected. Focused explainability and adapter tests: 12 passed.
- **Case26 isolated replay:** intent is `VERIFY_ONLY`, identity resolves uniquely to `user_26`, four observations are found, and policy blocks before producing a row. The regression confirms no unsupported `COMPLETE` row or remediation is returned.
- **Independent 518-request replay:** 381 candidate rows passed per-row contract, evidence-reference, and audit-cutoff validation; 137 requests remain unresolved. The unresolved cases and reasons are retained in `evaluation/replay_diagnostics.json` and `evaluation/unresolved_case_audit.json`.
- **Partial artifact:** `results/partial_validated_rows_not_for_submission.csv` has 381 sorted, unique rows with the exact header. Its sidecar records the replay count, validation checks, and source-diagnostic hashes. It is diagnostic only.
- **Official output:** root `output.csv` was not generated. The official writer rejects partial row counts, as required.
- Web integration tests exercised case selection, verification, and the read-only What-If endpoint. What-If does not execute remediation or mutate the audit decision.

## Local integrated HTTP benchmark

A localhost `POST /api/verify` benchmark used public sample `case_16`:

| Measurement | Result |
|---|---:|
| Cold first request, including lazy evidence-index loading | 831.74 ms |
| Warm requests | 20 |
| Warm aggregate request time | 4,160.88 ms |
| Warm average latency | 208.04 ms |
| Warm p95 latency | 211.82 ms |
| Warm throughput | 4.81 requests/sec |
| Warm request exceptions | 0 |
| Evidence loading in warm batch | Excluded; index was preloaded |

This measures the local integrated HTTP endpoint and backend serialization. It excludes browser rendering and deployment/network latency. The separately supplied component baseline of 117.6 ms average, 227.5 ms p95, and 8.50 requests/sec is not a full-application benchmark and was not reproduced here.

## Team-authored evaluation cases

1. A direct account-deletion instruction remains `DELETE`.
2. A verification request about a prior report with a deletion-state outcome becomes `VERIFY_ONLY`, without authorizing new remediation.
3. A general question about currently held data remains ambiguous and authorizes neither deletion nor verification.
4. Case33 export linkage through activity alone does not establish resource state; post-cutoff evidence is excluded.
5. Case15 trace-linked flow evidence preserves the trace, file, timestamps, and locators without inventing propagation endpoints.
6. Rebirth with missing baseline or incomplete snapshots remains `INDETERMINATE`; it never becomes `NO_REAPPEARANCE` from missing data.

## Remaining blockers

The final case-by-case reassessment classifies all 137 unresolved requests: 129 need additional cutoff-valid evidence and 8 need extraction of potentially relevant PNG artifacts. All 137 are authorized `DELETE` requests with unique identity resolution; none can be changed to `NOT_APPLICABLE` to bypass an evidence gap. The existing contract can represent a supported `COMPLETE` or `INCOMPLETE` result, but no full row is currently established. There are zero cases identified as inherently unrepresentable or requiring organizer clarification.

A parser/policy cross-check loaded 94 evidence records (82 `PARSED`, 1 `PARTIAL`, 11 `UNSUPPORTED`), rechecked the linked cutoff-valid segments for every missing fact, and found zero additional facts satisfying the current adapter's exact resource, subject-linkage, and semantic gates. It also found zero subject-linked, resource-specific parsed records omitted from the current citations. Twelve unknown resource instances were passed through the existing adapter; none changed to a known state. Case480 already has the explicit `restore_blockable=true` fact and a separate blocked-restore observation from evidence_45, but the corresponding backup archive remains uncertain and the case still has missing retention and shared-context facts.

The final full replay processed all 518 requests and returned **381 valid rows / 137 unresolved**. It preserved the diagnostics and partial artifact and did not create root `output.csv`. No additional implementation defect was confirmed, so no policy or evidence mapping was changed.

- Case26 needs cutoff-valid evidence linking `account_5684` and `analytics_4566` to the resolved subject, or an authoritative correction to the sample reference. Post-cutoff evidence and resource IDs alone are insufficient.
- Case33 and other unresolved cases require evidence-backed resource state or policy facts; unknown state is not proof of violation or compliance.
- The output contract has no row status for an unresolved verification-only audit. `INCOMPLETE` requires supported findings and a complete remediation plan, which cannot be invented for `VERIFY_ONLY`.
- Rebirth remains `INDETERMINATE` where baseline deletion verification, expected-system scope, or complete cutoff-valid snapshot coverage is missing.

The shortest safe path to submission is to obtain the missing participant-visible, cutoff-valid evidence (and OCR-capable extraction for the eight PNG candidates), then rerun and validate all 518 requests. Until then, submit neither the partial artifact as `output.csv` nor a claim of completed evaluation.
