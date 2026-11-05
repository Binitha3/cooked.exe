# Rebirth Detection

## Architecture
`code.rebirth_detection.detect_rebirth` compares caller-supplied historical `RecordEvidence` baselines, explicit `DeletionVerification` results and later `RecordEvidence` observations. It consumes shared `ResolvedSubject`, `IdentityIdentifier` and `EvidenceIndex` contracts. It is a pure analysis function: it does not parse source files, mutate systems or execute remediation.

## Inputs
All datetimes must be timezone-aware. `RecordEvidence` names system/resource/category, observed time, identifiers and evidence IDs. `DeletionVerification` must explicitly state ABSENT, REDACTED or ANONYMIZED and cite indexed evidence. `CauseEvidence` includes a cause enum string, affected resource, event time and evidence IDs. `SnapshotCoverage` is an upstream assertion of complete inspection, with system, snapshot time, enumerated resources, evidence IDs and `complete=True`. `expected_systems` must enumerate every in-scope system for an absence conclusion.

## Outputs and classifications
The result is a tuple of `RebirthFinding`; each includes stable ID, source/reappeared resource references, supporting evidence IDs, match rationale/confidence, cause (or null), action recommendation, follow-up verification and chronologically sorted `Temporal Rebirth Trail` entries.
* CONFIRMED_REAPPEARANCE: exact identifier set match plus eligible explicit deletion verification.
* POSSIBLE_REAPPEARANCE: partial identifier overlap or exact match without deletion verification.
* NO_REAPPEARANCE: no match and complete, evidence-backed coverage for every expected system.
* INDETERMINATE: insufficient baseline, verification, evidence or declared coverage.

## Matching, cause and cutoff
Evidence references not in `EvidenceIndex` or captured after `audit_at` are ignored. Observations after cutoff are ignored. A cause is returned only if its cutoff-eligible extracted evidence text names the operation class and both original and reappeared resource IDs. Conflicting supported causes return null. Timing or record similarity alone is never causal evidence. The caller must not interpret null cause as proof that no cause exists.

## Limitations and Member 4 integration
Coverage completeness and evidence extraction are upstream assertions; this checkout has no evidence-processing or policy module. Use the function as an additive post-investigation analysis. Build typed inputs from parser outputs, pass the case `audit_at`, an index containing provenance for all evidence IDs, and a complete `expected_systems` list. Serialize each finding using dataclass fields and enum `.value`; the frontend payload is specified by `schema/rebirth-finding.schema.json`. The checked-in example is explicitly synthetic; repository data has no parsed rebirth finding fixture, so it makes no factual production claim.

Run tests: `python -B -m unittest tests.test_rebirth_detection -v`.
