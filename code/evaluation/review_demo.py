"""Run a single evidence-backed review demo without writing output.csv.

From the repository root:
    python3 -m code.evaluation.review_demo
"""

from __future__ import annotations

import json
from pathlib import Path

from code.contracts import AuditStep
from code.main import (
    build_rows,
    load_feature_modules,
    read_activity,
    read_deletion_rules,
    read_identity_audit,
    read_identities,
    read_requests_file,
)
from code.output import _load_evidence_reference_catalog, validate_evidence_references


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DATASET_ROOT = REPOSITORY_ROOT / "dataset"
DEMO_CASE_ID = "case_16"


def main() -> None:
    requests = read_requests_file(
        DATASET_ROOT / "sample_deletion_requests.csv",
        expected_count=32,
    )
    request = next((item for item in requests if item.case_id == DEMO_CASE_ID), None)
    if request is None:
        raise SystemExit(f"Demo request not found: {DEMO_CASE_ID}")

    rows = build_rows(
        [request],
        read_identities(DATASET_ROOT),
        read_identity_audit(DATASET_ROOT),
        read_activity(DATASET_ROOT),
        read_deletion_rules(DATASET_ROOT),
        DATASET_ROOT,
        load_feature_modules(),
    )
    row = rows[0]
    steps = [AuditStep(**item) for item in json.loads(row.steps_json)]
    catalog = _load_evidence_reference_catalog(
        REPOSITORY_ROOT / "output.csv",
        DATASET_ROOT,
    )
    validate_evidence_references(steps, set(catalog))

    citations = []
    for evidence_id in sorted({step.evidence_id for step in steps if step.evidence_id}):
        captured_at = catalog[evidence_id]
        if captured_at is None or captured_at > request.audit_at:
            raise SystemExit(f"Evidence {evidence_id} is missing a valid at-cutoff timestamp")
        citations.append({"evidence_id": evidence_id, "captured_at": captured_at.isoformat()})

    print(f"case_id: {row.case_id}")
    print(f"deletion_status: {row.deletion_status.value}")
    print("evidence: " + json.dumps(citations, ensure_ascii=False))
    print("steps_json: " + row.steps_json)
    print("output.csv: not written")


if __name__ == "__main__":
    main()
