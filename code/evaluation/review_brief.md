# Review-round brief

## Architecture

Each deletion request passes through intent authorization, current and historical identity resolution, cutoff-bounded evidence discovery, policy evaluation, and output validation. The web review uses the same identity, evidence, and policy modules for a selected case, then builds the Ghost Data Map, risk explanations, evidence timeline, What-If preview, and Rebirth Detection payload.

`VERIFY_ONLY` is a separate read-only authorization. It allows identity and evidence lookup but cannot authorize new destructive remediation. A verification-only case produces a verdict only when cutoff-valid evidence proves the compliant state. What-If remains a pure preview; it does not execute actions or mutate the audit decision.

Rebirth `NO_REAPPEARANCE` requires a supported baseline, evidence-backed deletion verification, declared expected-system scope, and complete cutoff-valid snapshots for every expected system. Missing inputs remain `INDETERMINATE`.

## Member contributions

- **Member 1 — Identity and intent:** current/historical identifier resolution and identity provenance; deletion intent classification.
- **Member 2 — Evidence and graph:** manifest ingestion, format extraction, as-of search, trace-linked active flows, and Ghost Data Map serialization.
- **Member 3 — Policy and explanation:** policy evaluation, remediation ordering, risk explanations, read-only What-If, and evidence-gated Rebirth Detection.
- **Member 4 — Integration:** shared contracts, orchestration, output validation, web application, integration adapters, regression tests, evaluation notes, and packaging.

## Demo

Start from the repository root:

```bash
python3 -m code.web_app --port 8000
```

Open `http://127.0.0.1:8000/`. Visible navigation links directly to the Ghost Data Map, Evidence Timeline, Risks & What-If, and Rebirth Trail sections. Case16 runs against the actual pipeline and presents its `INCOMPLETE` result, evidence-backed resources, 7-node/5-edge graph, two risk cards, timeline, and `INDETERMINATE` Rebirth result. What-If controls show proposed outcomes only.

Case15 shows the trace-linked active flow with its evidence provenance. It does not draw unsupported propagation endpoints.

Case26 is classified `VERIFY_ONLY`. Its isolated pipeline run searches evidence but does not return a deletion status or remediation steps because the cutoff-valid evidence does not link two sample resources to the subject. This is an honest unresolved result, not a successful deletion claim.

## Validation and blockers

- Full unittest discovery ran 128 tests: 127 passed and one sample-replay error at case01 (no cutoff-valid subject-to-resource evidence).
- The isolated case26 regression passes and confirms the verification-only guard.
- Final full replay processed 518 requests: 381 valid candidate rows, 137 unresolved; no new rows became valid. The parsed-evidence/policy remapping check found zero additional facts passing the existing exact-linkage/cutoff rules. The 137 case-by-case blockers are classified in `fallback_case_classification.json`; 129 need additional cutoff-valid evidence and 8 need PNG extraction. The partial CSV remains diagnostic only; root `output.csv` is absent.
- The 32-case sample cannot yet be replayed end to end. Case26's sample row is structurally verification-only, but `account_5684` and `analytics_4566` lack cutoff-valid subject linkage. Case33 also lacks cutoff-valid export-state evidence.
- Rebirth findings without baseline verification or complete snapshots remain `INDETERMINATE`.

The local HTTP prototype was verified: 20 warm case16 `/api/verify` requests averaged 208.04 ms (p95 211.82 ms, 4.81 requests/sec, 0 errors; index preloaded). The cold first request, including evidence loading, was 831.74 ms. This is a local endpoint benchmark, not a deployed/browser benchmark. No deployment URL is configured. The application and single-case demo are usable. Submission is not ready until the unresolved evidence gaps are addressed and the official validator accepts exactly 518 supported rows in root `output.csv`. The partial CSV is diagnostic only and must not be submitted as the official output.
