"""Shared, implementation-independent contracts for the deletion audit pipeline.

All timestamps are timezone-aware ``datetime`` values. Identifiers and resource
references are kept as strings so callers can preserve source-system values.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Sequence, TypeVar


class StringEnum(str, Enum):
    """An enum whose values serialize as the challenge's string vocabulary."""

    def __str__(self) -> str:
        return self.value


class DeletionStatus(StringEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ReportedStatus(StringEnum):
    """Untrusted workflow claim from the input request CSV."""

    COMPLETE = "COMPLETE"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    NOT_STARTED = "NOT_STARTED"


class Intent(StringEnum):
    DELETE = "DELETE"
    NOT_DELETE = "NOT_DELETE"
    AMBIGUOUS = "AMBIGUOUS"


class ResolutionStatus(StringEnum):
    UNIQUE = "UNIQUE"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class EvidenceParserStatus(StringEnum):
    PARSED = "PARSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"


class Phase(StringEnum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class Operation(StringEnum):
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class StepState(StringEnum):
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class ObservedState(StringEnum):
    """State used during evidence analysis; UNKNOWN is not an output state."""

    UNKNOWN = "UNKNOWN"
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


ALLOWED_OPERATION_STATES: Mapping[tuple[Phase, Operation], StepState] = {
    (Phase.FINDING, Operation.REPORT_REMAINING_RECORD): StepState.PRESENT,
    (Phase.FINDING, Operation.REPORT_EXPOSED_PII): StepState.PRESENT,
    (Phase.FINDING, Operation.REPORT_ACTIVE_DATA_FLOW): StepState.ACTIVE,
    (Phase.FINDING, Operation.REPORT_RESTORE_RISK): StepState.ACTIVE,
    (Phase.REMEDIATION, Operation.DISABLE_DATA_FLOW): StepState.DISABLED,
    (Phase.REMEDIATION, Operation.BLOCK_RESTORE): StepState.BLOCKED,
    (Phase.REMEDIATION, Operation.DELETE_RECORD): StepState.ABSENT,
    (Phase.REMEDIATION, Operation.REDACT_RECORD): StepState.REDACTED,
    (Phase.REMEDIATION, Operation.ANONYMIZE_RECORD): StepState.ANONYMIZED,
    (Phase.VERIFICATION, Operation.VERIFY_RECORD_ABSENT): StepState.ABSENT,
    (Phase.VERIFICATION, Operation.VERIFY_RECORD_PRESENT): StepState.PRESENT,
    (Phase.VERIFICATION, Operation.VERIFY_RECORD_REDACTED): StepState.REDACTED,
    (Phase.VERIFICATION, Operation.VERIFY_RECORD_ANONYMIZED): StepState.ANONYMIZED,
    (Phase.VERIFICATION, Operation.VERIFY_DATA_FLOW_DISABLED): StepState.DISABLED,
    (Phase.VERIFICATION, Operation.VERIFY_RESTORE_BLOCKED): StepState.BLOCKED,
}

OUTPUT_COLUMNS: tuple[str, str, str] = ("case_id", "deletion_status", "steps_json")
OPERATION_ORDER: Mapping[Phase, tuple[Operation, ...]] = {
    Phase.FINDING: (
        Operation.REPORT_REMAINING_RECORD,
        Operation.REPORT_EXPOSED_PII,
        Operation.REPORT_ACTIVE_DATA_FLOW,
        Operation.REPORT_RESTORE_RISK,
    ),
    Phase.REMEDIATION: (
        Operation.DISABLE_DATA_FLOW,
        Operation.BLOCK_RESTORE,
        Operation.DELETE_RECORD,
        Operation.REDACT_RECORD,
        Operation.ANONYMIZE_RECORD,
    ),
    Phase.VERIFICATION: (
        Operation.VERIFY_RECORD_ABSENT,
        Operation.VERIFY_RECORD_PRESENT,
        Operation.VERIFY_RECORD_REDACTED,
        Operation.VERIFY_RECORD_ANONYMIZED,
        Operation.VERIFY_DATA_FLOW_DISABLED,
        Operation.VERIFY_RESTORE_BLOCKED,
    ),
}
AUDIT_STEP_FIELDS: tuple[str, ...] = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: ReportedStatus
    reported_at: datetime | None
    audit_at: datetime
    request_text: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "reported_status", _coerce_enum(ReportedStatus, self.reported_status, "reported_status"))
        _require_text(self.case_id, "case_id")
        _require_text(self.email, "email")
        _require_text(self.request_text, "request_text")
        _require_datetime(self.requested_at, "requested_at")
        _require_optional_datetime(self.reported_at, "reported_at")
        _require_datetime(self.audit_at, "audit_at")


@dataclass(frozen=True)
class IntentDecision:
    intent: Intent
    rationale: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "intent", _coerce_enum(Intent, self.intent, "intent"))
        _require_text(self.rationale, "rationale", allow_empty=True)


@dataclass(frozen=True)
class IdentityIdentifier:
    identifier_type: str
    value: str
    valid_from: datetime | None = None
    valid_to: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.identifier_type, "identifier_type")
        _require_text(self.value, "identifier value")
        _require_optional_datetime(self.valid_from, "valid_from")
        _require_optional_datetime(self.valid_to, "valid_to")
        if self.valid_from and self.valid_to and self.valid_to < self.valid_from:
            raise ValueError("valid_to must not precede valid_from")


@dataclass(frozen=True)
class IdentityProvenance:
    source: str
    audit_id: str | None = None
    event_time: datetime | None = None
    field_name: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.source, "source")
        _require_optional_text(self.audit_id, "audit_id")
        _require_optional_datetime(self.event_time, "event_time")
        _require_optional_text(self.field_name, "field_name")


@dataclass(frozen=True)
class ResolvedSubject:
    resolution_status: ResolutionStatus
    user_id: str | None
    current_identifiers: tuple[IdentityIdentifier, ...] = ()
    historical_identifiers: tuple[IdentityIdentifier, ...] = ()
    identity_provenance: tuple[IdentityProvenance, ...] = ()
    resolution_explanation: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "resolution_status", _coerce_enum(ResolutionStatus, self.resolution_status, "resolution_status"))
        _require_optional_text(self.user_id, "user_id")
        _require_text(self.resolution_explanation, "resolution_explanation", allow_empty=True)
        if self.resolution_status is ResolutionStatus.UNIQUE and self.user_id is None:
            raise ValueError("a UNIQUE subject requires user_id")
        if self.resolution_status is not ResolutionStatus.UNIQUE and self.user_id is not None:
            raise ValueError("AMBIGUOUS and UNRESOLVED subjects must not assert user_id")


@dataclass(frozen=True)
class IdentityRecord:
    """Current user snapshot normalized from ``user_identities.csv``."""

    user_id: str
    identifiers: tuple[IdentityIdentifier, ...]
    updated_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.user_id, "user_id")
        _require_datetime(self.updated_at, "updated_at")


@dataclass(frozen=True)
class IdentityAuditEvent:
    """One historical identity-field change with its source audit ID."""

    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str | None
    new_value: str | None

    def __post_init__(self) -> None:
        for name in ("audit_id", "user_id", "field_name"):
            _require_text(getattr(self, name), name)
        _require_datetime(self.event_time, "event_time")
        _require_optional_text(self.old_value, "old_value")
        _require_optional_text(self.new_value, "new_value")


@dataclass(frozen=True)
class EvidenceManifestEntry:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.file_id, "file_id")
        _require_text(self.file_path, "file_path")
        _require_text(self.origin, "origin")
        _require_datetime(self.captured_at, "captured_at")


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    relative_path: str
    origin: str
    captured_at: datetime
    record_timestamp: datetime | None
    format: str
    locator: str
    extracted_content: str
    structured_fields: Mapping[str, Any] = field(default_factory=dict)
    parser_status: EvidenceParserStatus = EvidenceParserStatus.PARSED
    confidence: float | None = None

    @property
    def file_id(self) -> str:
        """Alias used when the evidence ID is the manifest file ID."""
        return self.evidence_id

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser_status", _coerce_enum(EvidenceParserStatus, self.parser_status, "parser_status"))
        for name in ("evidence_id", "relative_path", "origin", "format", "locator"):
            _require_text(getattr(self, name), name)
        _require_datetime(self.captured_at, "captured_at")
        _require_optional_datetime(self.record_timestamp, "record_timestamp")
        _require_text(self.extracted_content, "extracted_content", allow_empty=True)
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
                raise ValueError("confidence must be a number or None")
            if not 0.0 <= self.confidence <= 1.0:
                raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class EvidenceIndex:
    records: tuple[EvidenceRecord, ...] = ()
    by_identifier: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    by_resource_id: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    by_system_id: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    by_searchable_text: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        evidence_ids = [record.evidence_id for record in self.records]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("EvidenceIndex records must have unique evidence_id values")
        allowed_ids = set(evidence_ids)
        for index_name in ("by_identifier", "by_resource_id", "by_system_id", "by_searchable_text"):
            index = getattr(self, index_name)
            for key, refs in index.items():
                _require_text(key, f"{index_name} key")
                if not all(ref in allowed_ids for ref in refs):
                    raise ValueError(f"{index_name} may only reference indexed evidence records")

    @property
    def records_by_id(self) -> Mapping[str, EvidenceRecord]:
        return {record.evidence_id: record for record in self.records}


@dataclass(frozen=True)
class ActivityEvent:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str | None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("activity_id", "event_type", "source_system", "target_system", "resource_id"):
            _require_text(getattr(self, name), name)
        _require_datetime(self.event_time, "event_time")
        _require_optional_text(self.reported_result, "reported_result")


@dataclass(frozen=True)
class ResourceRelationship:
    relationship: str
    system_id: str
    resource_id: str
    details: str = ""

    def __post_init__(self) -> None:
        _require_text(self.relationship, "relationship")
        _require_text(self.system_id, "system_id")
        _require_text(self.resource_id, "resource_id")
        _require_text(self.details, "relationship details", allow_empty=True)


@dataclass(frozen=True)
class ResourceObservation:
    system_id: str
    resource_id: str
    data_category: str
    observed_state: ObservedState
    identifiers: tuple[IdentityIdentifier, ...] = ()
    observation_timestamp: datetime | None = None
    evidence_references: tuple[str, ...] = ()
    relationships: tuple[ResourceRelationship, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_state", _coerce_enum(ObservedState, self.observed_state, "observed_state"))
        for name in ("system_id", "resource_id", "data_category"):
            _require_text(getattr(self, name), name)
        _require_optional_datetime(self.observation_timestamp, "observation_timestamp")
        for evidence_ref in self.evidence_references:
            _require_text(evidence_ref, "evidence reference")


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str

    def __post_init__(self) -> None:
        for name in ("rule_id", "data_category", "condition", "required_action"):
            _require_text(getattr(self, name), name)


@dataclass(frozen=True)
class AuditStep:
    step_no: int
    phase: Phase
    system_id: str
    resource_id: str
    operation: Operation
    state: StepState
    evidence_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "phase", _coerce_enum(Phase, self.phase, "phase"))
        object.__setattr__(self, "operation", _coerce_enum(Operation, self.operation, "operation"))
        object.__setattr__(self, "state", _coerce_enum(StepState, self.state, "state"))
        if isinstance(self.step_no, bool) or not isinstance(self.step_no, int) or self.step_no < 1:
            raise ValueError("step_no must be a positive integer")
        _require_text(self.system_id, "system_id")
        _require_text(self.resource_id, "resource_id")
        _require_text(self.evidence_id, "evidence_id", allow_empty=True)
        expected_state = ALLOWED_OPERATION_STATES.get((self.phase, self.operation))
        if expected_state is None:
            raise ValueError(f"operation {self.operation.value} is not allowed in phase {self.phase.value}")
        if self.state is not expected_state:
            raise ValueError(
                f"{self.operation.value} in {self.phase.value} requires state {expected_state.value}"
            )
        if self.phase is Phase.FINDING and not self.evidence_id:
            raise ValueError("finding steps must cite evidence")

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase.value,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "state": self.state.value,
            "evidence_id": self.evidence_id,
        }


@dataclass(frozen=True)
class AuditDecision:
    deletion_status: DeletionStatus
    steps: tuple[AuditStep, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "deletion_status", _coerce_enum(DeletionStatus, self.deletion_status, "deletion_status"))
        _validate_step_sequence(self.steps)
        if self.deletion_status is DeletionStatus.NOT_APPLICABLE and self.steps:
            raise ValueError("NOT_APPLICABLE decisions must have no steps")
        if self.deletion_status is DeletionStatus.COMPLETE:
            if not self.steps:
                raise ValueError("COMPLETE decisions require evidence-backed verification steps")
            if any(step.phase is not Phase.VERIFICATION for step in self.steps):
                raise ValueError("COMPLETE decisions may contain only verification steps")
            if any(not step.evidence_id for step in self.steps):
                raise ValueError("COMPLETE verification steps must cite evidence")
        if self.deletion_status is DeletionStatus.INCOMPLETE:
            required_phases = {Phase.FINDING, Phase.REMEDIATION, Phase.VERIFICATION}
            present_phases = {step.phase for step in self.steps}
            if not required_phases.issubset(present_phases):
                raise ValueError("INCOMPLETE decisions require findings, remediation, and future verification")
            for step in self.steps:
                if step.phase is Phase.FINDING and not step.evidence_id:
                    raise ValueError("INCOMPLETE findings must cite evidence")
                if step.phase in (Phase.REMEDIATION, Phase.VERIFICATION) and step.evidence_id:
                    raise ValueError("INCOMPLETE remediation and future verification must use empty evidence_id")


@dataclass(frozen=True)
class OutputRow:
    case_id: str
    deletion_status: DeletionStatus
    steps_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "deletion_status", _coerce_enum(DeletionStatus, self.deletion_status, "deletion_status"))
        _require_text(self.case_id, "case_id")
        try:
            data = json.loads(self.steps_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("steps_json must contain a valid JSON array") from exc
        if not isinstance(data, list):
            raise ValueError("steps_json must contain a JSON array")
        steps: list[AuditStep] = []
        for item in data:
            if not isinstance(item, dict) or set(item) != set(AUDIT_STEP_FIELDS):
                raise ValueError(f"each step must contain exactly: {', '.join(AUDIT_STEP_FIELDS)}")
            steps.append(AuditStep(**item))
        AuditDecision(self.deletion_status, tuple(steps))

    @classmethod
    def from_decision(cls, case_id: str, decision: AuditDecision) -> OutputRow:
        return cls(
            case_id=case_id,
            deletion_status=decision.deletion_status,
            steps_json=steps_to_json(decision.steps),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status.value,
            "steps_json": self.steps_json,
        }


def steps_to_json(steps: Sequence[AuditStep]) -> str:
    """Serialize ordered steps using only the exact output fields."""
    _validate_step_sequence(steps)
    return json.dumps([step.to_dict() for step in steps], ensure_ascii=False, separators=(",", ":"))


def _validate_step_sequence(steps: Sequence[AuditStep]) -> None:
    phase_order = {Phase.FINDING: 0, Phase.REMEDIATION: 1, Phase.VERIFICATION: 2}
    operation_order = {
        phase: {operation: rank for rank, operation in enumerate(operations)}
        for phase, operations in OPERATION_ORDER.items()
    }
    if any(step.step_no != index for index, step in enumerate(steps, start=1)):
        raise ValueError("step numbers must be consecutive, starting at 1")
    sort_keys = [
        (phase_order[step.phase], operation_order[step.phase][step.operation], step.system_id, step.resource_id)
        for step in steps
    ]
    if sort_keys != sorted(sort_keys):
        raise ValueError(
            "steps must be ordered by phase, operation, system_id, and resource_id"
        )


def validate_evidence_references(steps: Sequence[AuditStep], known_evidence_ids: set[str]) -> None:
    """Raise when a cited source ID is absent from the participant-visible evidence catalog.

    Callers should build ``known_evidence_ids`` from manifest file IDs plus activity
    and audit IDs, since all three are valid challenge evidence references.
    """
    for step in steps:
        if step.evidence_id and step.evidence_id not in known_evidence_ids:
            raise ValueError(f"unknown evidence reference: {step.evidence_id}")


EnumType = TypeVar("EnumType", bound=StringEnum)


def _coerce_enum(enum_type: type[EnumType], value: Any, field_name: str) -> EnumType:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise ValueError(f"{field_name} must be one of: {allowed}") from exc


def _require_text(value: Any, name: str, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or (not allow_empty and not value):
        requirement = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{name} must be {requirement}")


def _require_optional_text(value: Any, name: str) -> None:
    if value is not None:
        _require_text(value, name)


def _require_datetime(value: Any, name: str) -> None:
    if not isinstance(value, datetime):
        raise ValueError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _require_optional_datetime(value: Any, name: str) -> None:
    if value is not None:
        _require_datetime(value, name)


__all__ = [
    "ALLOWED_OPERATION_STATES",
    "AUDIT_STEP_FIELDS",
    "OPERATION_ORDER",
    "OUTPUT_COLUMNS",
    "ActivityEvent",
    "AuditDecision",
    "AuditStep",
    "DeletionRequest",
    "DeletionRule",
    "DeletionStatus",
    "EvidenceIndex",
    "EvidenceManifestEntry",
    "EvidenceParserStatus",
    "EvidenceRecord",
    "IdentityAuditEvent",
    "IdentityIdentifier",
    "IdentityProvenance",
    "IdentityRecord",
    "Intent",
    "IntentDecision",
    "ObservedState",
    "Operation",
    "OutputRow",
    "Phase",
    "ReportedStatus",
    "ResolutionStatus",
    "ResolvedSubject",
    "ResourceObservation",
    "ResourceRelationship",
    "StepState",
    "steps_to_json",
    "validate_evidence_references",
]
