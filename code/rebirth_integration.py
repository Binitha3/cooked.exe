"""Conservative adapter from the live audit pipeline into Rebirth Detection.

This adapter only promotes actual, cutoff-valid resource observations and
evidence-backed policy verification steps. It never creates a complete
snapshot claim or expected system scope from a partial discovery result.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from enum import Enum
import re
from typing import Any, Iterable, Mapping, Sequence

from .contracts import (
    AuditDecision,
    DeletionStatus,
    EvidenceIndex,
    IdentityIdentifier,
    Operation,
    ObservedState,
    Phase,
    ResolvedSubject,
    ResourceObservation,
)
from .rebirth_detection import (
    CauseEvidence,
    DeletionVerification,
    RecordEvidence,
    RebirthFinding,
    SnapshotCoverage,
    detect_rebirth,
)


_VERIFICATION_STATE = {
    ObservedState.ABSENT: "ABSENT",
    ObservedState.REDACTED: "REDACTED",
    ObservedState.ANONYMIZED: "ANONYMIZED",
}
_CAUSE_PATTERNS = {
    "BACKUP_RESTORATION": re.compile(r"\b(?:restore|restored|restoration)\b", re.I),
    "SYNCHRONIZATION": re.compile(r"\b(?:sync|synced|synchroniz(?:e|ed|ation)|replicat(?:e|ed|ion))\b", re.I),
    "ACCIDENTAL_REIMPORT": re.compile(r"\b(?:import|imported|re-import|reimport|ingest(?:ed|ion))\b", re.I),
}


def build_rebirth_frontend_payload(
    subject: ResolvedSubject,
    requested_at: datetime,
    observations: Sequence[ResourceObservation],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
    decision: AuditDecision | None = None,
    coverage: Iterable[SnapshotCoverage] = (),
    expected_systems: Iterable[str] = (),
) -> dict[str, Any]:
    """Build rebirth findings from actual investigation objects.

    The caller may provide upstream coverage only when it was explicitly
    established from complete snapshots. The current evidence parser does not
    emit such coverage assertions, so the web pipeline passes an empty set.
    """
    if subject.user_id is None or subject.resolution_status.value != "UNIQUE":
        return {
            "schema_version": "1.0",
            "analysis_status": "NOT_EVALUATED",
            "findings": [],
            "input_summary": {
                "baseline_records": 0,
                "deletion_verifications": 0,
                "later_records": 0,
                "complete_snapshots": 0,
                "expected_systems": [],
                "scope_established": False,
            },
            "message": "Rebirth detection requires a uniquely resolved deletion subject.",
        }

    records_by_id = evidence_index.records_by_id
    accepted_observations = [
        observation for observation in observations
        if observation.observation_timestamp is not None
        and observation.observation_timestamp <= audit_at
        and observation.observed_state is ObservedState.PRESENT
        and observation.data_category.casefold() != "data_flow"
        and observation.identifiers
        and _valid_evidence_ids(observation.evidence_references, records_by_id, audit_at)
    ]
    baseline: list[RecordEvidence] = []
    later: list[RecordEvidence] = []
    for observation in accepted_observations:
        evidence_ids = _valid_evidence_ids(observation.evidence_references, records_by_id, audit_at)
        if not evidence_ids:
            continue
        item = RecordEvidence(
            system_id=observation.system_id,
            resource_id=observation.resource_id,
            observed_at=observation.observation_timestamp,
            identifiers=tuple(observation.identifiers),
            evidence_ids=evidence_ids,
            data_category=observation.data_category,
            legitimate_retention=_evidence_backed_retention(
                decision, observation, evidence_ids,
            ),
        )
        if observation.observation_timestamp < requested_at:
            baseline.append(item)
        elif observation.observation_timestamp > requested_at:
            later.append(item)

    deletion_verifications = _deletion_verifications(observations, records_by_id, audit_at)
    coverage_items = tuple(coverage)
    expected = tuple(sorted({item for item in expected_systems if item}))
    causes = _supported_causes(baseline, later, evidence_index, audit_at)
    findings = detect_rebirth(
        subject=subject,
        baseline=baseline,
        deletion_verifications=deletion_verifications,
        later_observations=later,
        evidence=evidence_index,
        audit_at=audit_at,
        causes=causes,
        coverage=coverage_items,
        expected_systems=expected,
    )
    return {
        "schema_version": "1.0",
        "analysis_status": "EVALUATED",
        "findings": [_jsonable(finding) for finding in findings],
        "input_summary": {
            "baseline_records": len(baseline),
            "deletion_verifications": len(deletion_verifications),
            "later_records": len(later),
            "complete_snapshots": len(coverage_items),
            "expected_systems": list(expected),
            "observed_systems": sorted({item.system_id for item in observations}),
            "scope_established": bool(expected),
        },
        "message": (
            "NO_REAPPEARANCE requires complete evidence-backed snapshot coverage for every expected system."
            if not coverage_items or not expected
            else "Findings use only cutoff-valid indexed evidence and explicit verification inputs."
        ),
    }


def _valid_evidence_ids(
    evidence_ids: Sequence[str], records: Mapping[str, Any], audit_at: datetime,
) -> tuple[str, ...]:
    return tuple(sorted({
        evidence_id for evidence_id in evidence_ids
        if evidence_id in records and records[evidence_id].captured_at <= audit_at
    }))


def _evidence_backed_retention(
    decision: AuditDecision | None,
    observation: ResourceObservation,
    evidence_ids: Sequence[str],
) -> bool:
    if decision is None:
        return False
    return any(
        step.phase is Phase.VERIFICATION
        and step.operation is Operation.VERIFY_RECORD_PRESENT
        and step.system_id == observation.system_id
        and step.resource_id == observation.resource_id
        and step.evidence_id in evidence_ids
        for step in decision.steps
    )


def _deletion_verifications(
    observations: Sequence[ResourceObservation],
    records: Mapping[str, Any],
    audit_at: datetime,
) -> tuple[DeletionVerification, ...]:
    result: list[DeletionVerification] = []
    for observation in observations:
        verified_state = _VERIFICATION_STATE.get(observation.observed_state)
        if (verified_state is None or observation.observation_timestamp is None
                or observation.observation_timestamp > audit_at):
            continue
        evidence_ids = _valid_evidence_ids(observation.evidence_references, records, audit_at)
        if not evidence_ids:
            continue
        for evidence_id in evidence_ids:
            result.append(DeletionVerification(
                system_id=observation.system_id,
                resource_id=observation.resource_id,
                verified_at=observation.observation_timestamp,
                evidence_ids=(evidence_id,),
                verified_state=verified_state,
            ))
    return tuple(result)


def _supported_causes(
    baseline: Sequence[RecordEvidence],
    later: Sequence[RecordEvidence],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
) -> tuple[CauseEvidence, ...]:
    """Emit cause candidates only from one indexed segment naming both rows."""
    records = evidence_index.records_by_id
    result: dict[tuple[str, str, str, datetime, str], CauseEvidence] = {}
    for old in baseline:
        for new in later:
            for evidence_id, record in records.items():
                if record.captured_at > audit_at:
                    continue
                for segment in record.structured_fields.get("records", ()):
                    if not isinstance(segment, Mapping):
                        continue
                    occurred_at = _segment_time(segment)
                    if occurred_at is None or not old.observed_at < occurred_at <= new.observed_at:
                        continue
                    content = " ".join((
                        str(segment.get("extracted_content", "")),
                        str(segment.get("fields", {})),
                    ))
                    if not _contains_resource(content, old.resource_id) or not _contains_resource(content, new.resource_id):
                        continue
                    for cause, pattern in _CAUSE_PATTERNS.items():
                        if pattern.search(content):
                            item = CauseEvidence(
                                cause=cause,
                                system_id=new.system_id,
                                resource_id=new.resource_id,
                                occurred_at=occurred_at,
                                evidence_ids=(evidence_id,),
                            )
                            result[(cause, item.system_id, item.resource_id, occurred_at, evidence_id)] = item
    return tuple(result[key] for key in sorted(result))


def _segment_time(segment: Mapping[str, Any]) -> datetime | None:
    value = segment.get("record_timestamp")
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value
    for candidate in segment.get("timestamp_candidates", ()):
        if not isinstance(candidate, Mapping):
            continue
        parsed = candidate.get("parsed")
        if isinstance(parsed, datetime) and parsed.tzinfo is not None:
            return parsed
    return None


def _contains_resource(content: str, resource_id: str) -> bool:
    return re.search(rf"(?<![\w]){re.escape(resource_id)}(?![\w])", content, re.I) is not None


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


__all__ = ["build_rebirth_frontend_payload"]
