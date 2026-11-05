"""CLI orchestrator for the Ghost Data Still Exists audit pipeline.

Feature decisions remain owned by Members 1-3. This module loads participant
inputs, calls those public interfaces, and validates the finished CSV before it
atomically replaces the repository-root output.csv.
"""

from __future__ import annotations

import csv
import importlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    # Support the documented ``python3 code/main.py`` invocation while keeping
    # imports package-qualified for tests and other modules.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from code.contracts import (
    ActivityEvent,
    AuditStep,
    AuditDecision,
    DeletionRequest,
    DeletionRule,
    DeletionStatus,
    EvidenceIndex,
    IdentityAuditEvent,
    IdentityIdentifier,
    IdentityRecord,
    Intent,
    IntentDecision,
    ObservedState,
    Operation,
    OutputRow,
    Phase,
    ResourceObservation,
    ReportedStatus,
    ResolutionStatus,
    ResolvedSubject,
    ResourceRelationship,
    validate_evidence_references,
)
from code.output import (
    ValidationReport,
    _load_evidence_reference_catalog,
    validate_output,
    write_output,
)
from code.request_intent import classify_request_intent


class PipelineBlockedError(RuntimeError):
    """The pipeline cannot safely produce a complete output file."""


@dataclass(frozen=True)
class FeatureModules:
    identity_resolution: Any
    evidence_processing: Any
    policy_engine: Any


def load_feature_modules() -> FeatureModules:
    """Import only the member-owned implementations; never substitute stubs."""
    names = (
        "identity_resolution",
        "evidence_processing",
        "policy_engine",
    )
    loaded: dict[str, Any] = {}
    missing: list[str] = []
    for name in names:
        try:
            loaded[name] = importlib.import_module(f"code.{name}")
        except ModuleNotFoundError as exc:
            if exc.name in (f"code.{name}", "code"):
                missing.append(f"code/{name}.py")
            else:
                raise PipelineBlockedError(
                    f"Cannot load code/{name}.py because dependency {exc.name!r} is unavailable"
                ) from exc
    if missing:
        raise PipelineBlockedError(
            "Required member implementations are not available: " + ", ".join(missing)
        )

    expected = {
        "identity_resolution": ("classify_deletion_request", "resolve_identity"),
        "evidence_processing": ("load_evidence", "search_subject"),
        "policy_engine": ("evaluate",),
    }
    for module_name, functions in expected.items():
        module = loaded[module_name]
        absent = [function for function in functions if not callable(getattr(module, function, None))]
        if absent:
            raise PipelineBlockedError(
                f"code/{module_name}.py is present but missing callable interface(s): "
                + ", ".join(absent)
            )
    return FeatureModules(**loaded)


def read_requests(dataset_root: Path) -> list[DeletionRequest]:
    return read_requests_file(dataset_root / "deletion_requests.csv", expected_count=518)


def read_requests_file(path: Path, expected_count: int) -> list[DeletionRequest]:
    """Read a request CSV with an explicit expected row count (full or sample)."""
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
        if reader.fieldnames != expected:
            raise ValueError(f"{path} must have columns exactly: {','.join(expected)}")
        requests = [
            DeletionRequest(
                case_id=row["case_id"],
                email=row["email"],
                requested_at=_parse_timestamp(row["requested_at"]),
                reported_status=ReportedStatus(row["reported_status"]),
                reported_at=_parse_optional_timestamp(row["reported_at"]),
                audit_at=_parse_timestamp(row["audit_at"]),
                request_text=row["request_text"],
            )
            for row in reader
        ]
    if len(requests) != expected_count:
        raise ValueError(f"Expected {expected_count} deletion requests, found {len(requests)}")
    case_ids = [request.case_id for request in requests]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("deletion_requests.csv contains duplicate case_id values")
    return requests


def read_identities(dataset_root: Path) -> list[IdentityRecord]:
    path = dataset_root / "user_identities.csv"
    records: list[IdentityRecord] = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = ["user_id", "name", "email", "phone", "email_hash", "updated_at"]
        if reader.fieldnames != expected:
            raise ValueError(f"{path} must have columns exactly: {','.join(expected)}")
        for row in reader:
            identifiers = tuple(
                IdentityIdentifier(kind, row[field_name])
                for field_name, kind in (
                    ("name", "name"),
                    ("email", "email"),
                    ("phone", "phone"),
                    ("email_hash", "email_hash"),
                )
                if row[field_name]
            )
            records.append(
                IdentityRecord(
                    user_id=row["user_id"],
                    identifiers=identifiers,
                    updated_at=_parse_timestamp(row["updated_at"]),
                )
            )
    return records


def read_identity_audit(dataset_root: Path) -> list[IdentityAuditEvent]:
    path = dataset_root / "user_audit_log.csv"
    events: list[IdentityAuditEvent] = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"]
        if reader.fieldnames != expected:
            raise ValueError(f"{path} must have columns exactly: {','.join(expected)}")
        for row in reader:
            events.append(
                IdentityAuditEvent(
                    audit_id=row["audit_id"],
                    user_id=row["user_id"],
                    event_time=_parse_timestamp(row["event_time"]),
                    field_name=row["field_name"],
                    old_value=row["old_value"] or None,
                    new_value=row["new_value"] or None,
                )
            )
    return events


def read_activity(dataset_root: Path) -> list[ActivityEvent]:
    path = dataset_root / "system_activity.csv"
    events: list[ActivityEvent] = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"]
        if reader.fieldnames != expected:
            raise ValueError(f"{path} must have columns exactly: {','.join(expected)}")
        for row in reader:
            events.append(
                ActivityEvent(
                    activity_id=row["activity_id"],
                    event_time=_parse_timestamp(row["event_time"]),
                    event_type=row["event_type"],
                    source_system=row["source_system"],
                    target_system=row["target_system"],
                    resource_id=row["resource_id"],
                    reported_result=row["reported_result"] or None,
                    details={"raw": row["details"]},
                )
            )
    return events


def read_deletion_rules(dataset_root: Path) -> list[DeletionRule]:
    path = dataset_root / "deletion_rules.csv"
    rules: list[DeletionRule] = []
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        expected = ["rule_id", "data_category", "condition", "required_action"]
        if reader.fieldnames != expected:
            raise ValueError(f"{path} must have columns exactly: {','.join(expected)}")
        rules = [DeletionRule(**row) for row in reader]
    return rules


def build_rows(
    requests: Sequence[DeletionRequest],
    identities: Sequence[IdentityRecord],
    audit_log: Sequence[IdentityAuditEvent],
    activity: Sequence[ActivityEvent],
    rules: Sequence[DeletionRule],
    dataset_root: Path,
    modules: FeatureModules | None = None,
    evidence_index: EvidenceIndex | None = None,
    evidence_load_error: str | None = None,
) -> list[OutputRow]:
    """Run the ordered request→identity→evidence→policy flow for every case."""
    feature_modules = modules or load_feature_modules()
    intents: dict[str, IntentDecision] = {}
    for request in requests:
        try:
            decision = classify_request_intent(
                request.request_text,
                feature_modules.identity_resolution.classify_deletion_request,
            )
        except Exception as exc:
            raise PipelineBlockedError(f"case {request.case_id}: intent classification failed: {exc}") from exc
        if not isinstance(decision, IntentDecision):
            raise PipelineBlockedError(f"case {request.case_id}: classifier returned a non-IntentDecision")
        if decision.intent is Intent.AMBIGUOUS:
            raise PipelineBlockedError(
                f"case {request.case_id}: deletion intent is ambiguous; no output was written"
            )
        intents[request.case_id] = decision

    resolved: dict[str, ResolvedSubject] = {}
    for request in requests:
        if intents[request.case_id].intent is Intent.NOT_DELETE:
            continue
        try:
            subject = feature_modules.identity_resolution.resolve_identity(
                request.email,
                request.requested_at,
                request.audit_at,
                _identity_rows_for_resolver(identities),
                _identity_audit_rows_for_resolver(audit_log),
            )
        except Exception as exc:
            raise PipelineBlockedError(f"case {request.case_id}: identity resolution failed: {exc}") from exc
        if not isinstance(subject, ResolvedSubject):
            raise PipelineBlockedError(f"case {request.case_id}: identity resolver returned an invalid result")
        _require_unique_subject(request.case_id, subject)
        resolved[request.case_id] = subject

    authorized = [request for request in requests if request.case_id in resolved]
    loaded_evidence_index = evidence_index
    if authorized:
        if loaded_evidence_index is None and evidence_load_error:
            raise PipelineBlockedError(f"evidence loading failed: {evidence_load_error}")
        if loaded_evidence_index is None:
            try:
                loaded_evidence_index = feature_modules.evidence_processing.load_evidence(
                    dataset_root / "evidence_files.csv",
                    dataset_root,
                )
            except Exception as exc:
                raise PipelineBlockedError(f"evidence loading failed: {exc}") from exc
        if not isinstance(loaded_evidence_index, EvidenceIndex):
            raise PipelineBlockedError("evidence loader returned a non-EvidenceIndex result")

    rows: list[OutputRow] = []
    for request in requests:
        intent = intents[request.case_id]
        if intent.intent is Intent.NOT_DELETE:
            rows.append(_not_applicable_row(request.case_id))
            continue

        if loaded_evidence_index is None:
            raise PipelineBlockedError("No evidence index was loaded for an authorized deletion request")
        try:
            observations = feature_modules.evidence_processing.search_subject(
                resolved[request.case_id],
                request.audit_at,
                loaded_evidence_index,
                activity,
            )
        except Exception as exc:
            raise PipelineBlockedError(f"case {request.case_id}: evidence search failed: {exc}") from exc
        if not isinstance(observations, list) or any(
            not isinstance(observation, ResourceObservation) for observation in observations
        ):
            raise PipelineBlockedError(
                f"case {request.case_id}: evidence search must return list[ResourceObservation]"
            )
        observations = _adapt_trace_linked_active_flows(observations, request.audit_at)
        observations = _adapt_evidence_to_policy(
            observations,
            loaded_evidence_index,
            request.audit_at,
            resolved[request.case_id],
        )
        if not observations:
            raise PipelineBlockedError(
                f"case {request.case_id}: no cutoff-valid evidence links the resolved subject to a resource; "
                "the audit cannot assert absence from an empty search result"
            )
        try:
            decision = feature_modules.policy_engine.evaluate(observations, rules)
        except Exception as exc:
            if intent.intent is Intent.VERIFY_ONLY:
                raise PipelineBlockedError(
                    f"case {request.case_id}: verification-only audit could not establish a compliant state; "
                    f"no new remediation is authorized: {exc}"
                ) from exc
            raise PipelineBlockedError(f"case {request.case_id}: policy evaluation failed: {exc}") from exc
        if not isinstance(decision, AuditDecision):
            raise PipelineBlockedError(f"case {request.case_id}: policy engine returned an invalid result")
        if intent.intent is Intent.VERIFY_ONLY and decision.deletion_status is not DeletionStatus.COMPLETE:
            raise PipelineBlockedError(
                f"case {request.case_id}: verification-only audit did not prove COMPLETE; "
                "no new remediation is authorized"
            )
        if (
            intent.intent is Intent.VERIFY_ONLY
            and _request_requires_profile_absence(request.request_text)
            and not any(
                step.phase is Phase.VERIFICATION
                and step.operation is Operation.VERIFY_RECORD_ABSENT
                and step.system_id in {"account_service", "profile_service"}
                for step in decision.steps
            )
        ):
            raise PipelineBlockedError(
                f"case {request.case_id}: verification-only audit lacks evidence-backed proof "
                "that the requested primary profile is absent; no new remediation is authorized"
            )
        rows.append(OutputRow.from_decision(request.case_id, decision))

    rows.sort(key=lambda row: row.case_id)
    return rows


def _adapt_trace_linked_active_flows(
    observations: Sequence[ResourceObservation], audit_at: datetime,
) -> list[ResourceObservation]:
    """Add Member 3's flow marker only for fully supported Member 2 trace joins.

    The original TRACE_CORRELATED_EVIDENCE relationship is retained verbatim,
    including its trace ID, evidence reference, timestamps, and line locators.
    A generic trace relationship never becomes a flow marker on its own.
    """
    adapted: list[ResourceObservation] = []
    for observation in observations:
        if (
            observation.data_category.casefold() != "data_flow"
            or observation.observed_state.value != "ACTIVE"
            or not observation.resource_id.casefold().startswith("data_flow_")
            or not observation.evidence_references
            or observation.observation_timestamp is None
            or observation.observation_timestamp > audit_at
        ):
            adapted.append(observation)
            continue

        marker_already_present = any(
            relationship.relationship.casefold().strip()
            in {"sync_flow", "import_flow", "data_flow", "active_sync", "active_import"}
            for relationship in observation.relationships
        )
        if marker_already_present:
            adapted.append(observation)
            continue

        verified_link = None
        for relationship in observation.relationships:
            if relationship.relationship.casefold().strip() != "trace_correlated_evidence":
                continue
            if relationship.system_id != observation.system_id or relationship.resource_id != observation.resource_id:
                continue
            try:
                details = json.loads(relationship.details)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(details, dict):
                continue
            evidence_id = details.get("evidence_id")
            trace_id = details.get("trace_id")
            locators = (details.get("identifier_locator"), details.get("resource_locator"))
            fields = details.get("supported_fields")
            if (
                details.get("correlation") != "same_file_trace_id"
                or not isinstance(trace_id, str) or not trace_id.strip()
                or evidence_id not in observation.evidence_references
                or details.get("supported_state") != "ACTIVE"
                or not all(isinstance(locator, str) and locator.strip() for locator in locators)
                or not isinstance(fields, dict)
                or not _explicit_true(fields.get("enabled"))
                or not _explicit_true(fields.get("scheduler_registered"))
            ):
                continue
            timestamps = (details.get("identifier_record_timestamp"), details.get("resource_record_timestamp"))
            try:
                parsed_timestamps = tuple(_parse_timestamp(value) for value in timestamps)
            except (TypeError, ValueError):
                continue
            if any(timestamp > audit_at for timestamp in parsed_timestamps):
                continue
            verified_link = relationship
            break

        if verified_link is None:
            adapted.append(observation)
            continue

        # Keep the detailed trace relationship unchanged; this additional
        # marker is the narrow adapter understood by the policy engine.
        marker = ResourceRelationship(
            relationship="data_flow",
            system_id=verified_link.system_id,
            resource_id=verified_link.resource_id,
            details=verified_link.details,
        )
        adapted.append(replace(observation, relationships=observation.relationships + (marker,)))
    return adapted


_RESOURCE_CATEGORIES = {
    "account": "USER_PROFILE",
    "analytics": "ANALYTICS_PROFILE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "backup": "BACKUP_ARCHIVE",
    "data_flow": "DATA_FLOW",
    "export": "USER_EXPORT",
    "search": "SEARCH_INDEX_ENTRY",
    "support": "SUPPORT_MESSAGE",
}
_DIRECT_IDENTIFIER_TYPES = {"name", "full_name", "email", "phone", "email_hash"}
_TRUE_VALUES = {"true", "yes", "1"}
_FALSE_VALUES = {"false", "no", "0", "blocked", "disabled"}
_AMBIGUOUS_FIELD_VALUE = object()


def _adapt_evidence_to_policy(
    observations: Sequence[ResourceObservation],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
    subject: ResolvedSubject,
) -> list[ResourceObservation]:
    """Translate directly observed source fields into policy facts.

    The evidence records remain untouched. Every added category, state, and
    conditional fact is derived from the exact resource segment cited by the
    observation, and its relationship details retain the file ID, locator,
    capture time, record time, cutoff, and source fields used.
    """
    records_by_id = evidence_index.records_by_id
    adapted: list[ResourceObservation] = []
    restore_controls: dict[tuple[str, str, tuple[str, ...]], ResourceObservation] = {}

    for observation in observations:
        category = observation.data_category
        state = observation.observed_state
        relationships = list(observation.relationships)
        direct_identifier_values = {
            identifier.value.casefold()
            for identifier in (*subject.current_identifiers, *subject.historical_identifiers)
            if identifier.identifier_type.casefold() in _DIRECT_IDENTIFIER_TYPES
        }
        user_ids = {subject.user_id.casefold()} if subject.user_id else set()
        user_ids.update(
            identifier.value.casefold()
            for identifier in (*subject.current_identifiers, *subject.historical_identifiers)
            if identifier.identifier_type.casefold() == "user_id"
        )
        matching_segments: list[tuple[Any, Mapping[str, Any], Mapping[str, Any], datetime | None]] = []
        profile_state_candidates: list[tuple[datetime | None, ObservedState]] = []
        audit_state_candidates: list[tuple[datetime | None, ObservedState]] = []
        export_state_candidates: list[tuple[datetime | None, ObservedState]] = []
        analytics_state_candidates: list[tuple[datetime | None, ObservedState]] = []
        backup_state_candidates: list[tuple[datetime | None, ObservedState]] = []

        for evidence_id in observation.evidence_references:
            record = records_by_id.get(evidence_id)
            if record is None or record.captured_at > audit_at:
                continue
            segments = record.structured_fields.get("records", ())
            if not isinstance(segments, (list, tuple)):
                continue
            for segment in segments:
                if not isinstance(segment, Mapping):
                    continue
                fields = segment.get("fields")
                if not isinstance(fields, Mapping):
                    continue
                segment_resource_ids = {
                    str(value).strip()
                    for _path, name, value in _nested_policy_field_entries(fields)
                    if name == "resource_id" and value not in (None, "")
                }
                # Some log formats place the service record inside a quoted
                # message. Match only when that exact segment names this one
                # resource, avoiding accidental joins across nested records.
                if segment_resource_ids != {observation.resource_id}:
                    continue
                source_time = (
                    _source_record_time(fields)
                    or (segment.get("record_timestamp") if isinstance(segment.get("record_timestamp"), datetime) else None)
                    or record.record_timestamp
                    or observation.observation_timestamp
                )
                if source_time is not None and source_time > audit_at:
                    continue
                matching_segments.append((record, segment, fields, source_time))

        if not matching_segments:
            adapted.append(observation)
            continue

        if category.casefold() == "unknown":
            normalized_resource_id = observation.resource_id.casefold()
            category = next((
                mapped_category
                for prefix, mapped_category in sorted(
                    _RESOURCE_CATEGORIES.items(), key=lambda item: len(item[0]), reverse=True
                )
                if normalized_resource_id.startswith(prefix + "_")
            ), category)

        def add_fact(
            fact_name: str,
            fact_value: bool,
            record: Any,
            segment: Mapping[str, Any],
            source_time: datetime | None,
            supporting_fields: Mapping[str, Any],
        ) -> None:
            proof = {
                "evidence_id": record.evidence_id,
                "relative_path": record.relative_path,
                "origin": record.origin,
                "captured_at": record.captured_at.isoformat(),
                "record_timestamp": source_time.isoformat() if source_time else None,
                "audit_at": audit_at.isoformat(),
                "locator": str(segment.get("locator") or record.locator),
                "source_fields": dict(supporting_fields),
            }
            relationships.append(ResourceRelationship(
                relationship=f"policy_fact:{fact_name}={'true' if fact_value else 'false'}",
                system_id=observation.system_id,
                resource_id=observation.resource_id,
                details=json.dumps(proof, ensure_ascii=False, sort_keys=True),
            ))

        for record, segment, fields, source_time in matching_segments:
            nested_fields = _nested_policy_field_entries(fields)

            if category == "USER_PROFILE":
                profile_state = _profile_lookup_state(fields)
                if profile_state is not None:
                    profile_state_candidates.append((source_time, profile_state))

            elif category == "SEARCH_INDEX_ENTRY" and state is ObservedState.UNKNOWN:
                # A cutoff-valid readback log that explicitly reports a hit
                # proves a remaining index entry. Negative or unfamiliar
                # results stay UNKNOWN; they do not prove absence.
                search_result = _unique_field_value(nested_fields, {"result"})
                if isinstance(search_result, str) and search_result.strip().casefold() in {"hit", "found"}:
                    state = ObservedState.PRESENT

            elif category == "SECURITY_AUDIT_LOG":
                audit_read_event = _unique_field_value(nested_fields, {"event"})
                audit_row_count = _unique_field_value(nested_fields, {"rows", "row_count", "total_rows"})
                if (
                    state is ObservedState.UNKNOWN
                    and isinstance(audit_read_event, str)
                    and audit_read_event.strip().casefold() == "audit_record_read_completed"
                    and audit_row_count is not _AMBIGUOUS_FIELD_VALUE
                ):
                    try:
                        row_count = int(audit_row_count)
                    except (TypeError, ValueError):
                        row_count = 0
                    if row_count > 0:
                        audit_state_candidates.append((source_time, ObservedState.PRESENT))

                retention_entries = [
                    (path, value) for path, name, value in nested_fields
                    if name in {"retention_until", "retained_until"} and value not in (None, "")
                ]
                retention_times = set()
                for _path, value in retention_entries:
                    try:
                        parsed = _parse_optional_timestamp(str(value))
                    except ValueError:
                        continue
                    if parsed is not None:
                        retention_times.add(parsed)
                if len(retention_times) == 1:
                    retention_time = next(iter(retention_times))
                    add_fact(
                        "within_retention_period",
                        retention_time >= audit_at,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, {
                            "resource_id", "subject_reference", "user_id", "event_code",
                            "retention_until", "retained_until",
                        }),
                    )

            elif category == "SUPPORT_MESSAGE":
                customer_refs = [
                    value for _path, name, value in nested_fields
                    if name in {"customer_reference", "subject_reference", "user_id"}
                    and value not in (None, "")
                ]
                direct_subject_refs = [
                    value for _path, name, value in nested_fields
                    if name in {
                        "email", "customer_email", "requester_email", "email_hash",
                        "phone", "requester_phone", "name", "requester_name", "full_name",
                    }
                    and value not in (None, "")
                ]
                linked_subject = (
                    any(str(value).casefold() in user_ids for value in customer_refs)
                    or any(str(value).casefold() in direct_identifier_values for value in direct_subject_refs)
                )
                messages = [
                    str(value) for _path, name, value in nested_fields
                    if name in {"message_excerpt", "message_text", "excerpt", "conversation_text"}
                    and value not in (None, "")
                ]
                normalized_message = " ".join(messages).casefold()
                explicit_order_context = bool(re.search(r"\border(?:\s+(?:update|details|status|number|reference|issue|query))?\b", normalized_message))
                denied_context = bool(re.search(r"\b(?:no|not|never|without)\b.{0,32}\border\b", normalized_message))
                has_context_fields = any(value not in (None, "") for _path, name, value in nested_fields
                                         if name in {"order_id", "order_reference", "agent_id", "agent_reference"})
                shared_context_values = _unique_explicit_boolean(nested_fields, {"shared_context"})
                context_fact: bool | None = shared_context_values
                if context_fact is None and not denied_context and (explicit_order_context or has_context_fields):
                    context_fact = True
                if linked_subject and context_fact is not None and (not denied_context or context_fact is False):
                    add_fact(
                        "shared_context",
                        context_fact,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, {
                            "resource_id", "customer_reference", "subject_reference", "user_id",
                            "message_excerpt", "message_text", "excerpt", "conversation_text",
                            "order_id", "order_reference", "agent_id", "agent_reference", "shared_context",
                            "email", "customer_email", "requester_email", "email_hash", "phone",
                            "requester_phone", "name", "requester_name", "full_name",
                        }),
                    )

                pii_fields = ("requester_email", "requester_name", "requester_phone")
                pii_values_absent = all(
                    any(name == key for _path, key, _value in nested_fields)
                    and all(value in (None, "") for _path, key, value in nested_fields if key == name)
                    for name in pii_fields
                )
                exposes_identifier = any(value and value in normalized_message for value in direct_identifier_values)
                if pii_values_absent and not exposes_identifier:
                    state = ObservedState.REDACTED

            elif category == "USER_EXPORT":
                export_read_event = _unique_field_value(nested_fields, {"event"})
                export_available = _unique_field_value(nested_fields, {"available"})
                if (
                    state is ObservedState.UNKNOWN
                    and isinstance(export_read_event, str)
                    and export_read_event.strip().casefold() in {
                        "export_metadata_read_completed", "export_download_check_completed",
                    }
                    and _explicit_true(export_available)
                ):
                    export_state_candidates.append((source_time, ObservedState.PRESENT))

            elif category == "ANALYTICS_PROFILE":
                subject_value_names = {
                    "user_id", "customer_reference", "subject_reference", "email", "phone",
                    "email_hash", "name", "full_name", "direct_identifiers",
                }
                subject_value_entries = [
                    (path, value) for path, name, value in nested_fields
                    if name in subject_value_names and value not in (None, "")
                    and not isinstance(value, (Mapping, list, tuple))
                ]
                explicit_subject_values = {str(value).casefold() for _path, value in subject_value_entries}
                if explicit_subject_values & (user_ids | direct_identifier_values):
                    add_fact(
                        "attributable",
                        True,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, subject_value_names | {"attributable"}),
                    )
                    if state is ObservedState.UNKNOWN:
                        analytics_state_candidates.append((source_time, ObservedState.PRESENT))
                lookup_event = _unique_field_value(nested_fields, {"event"})
                lookup_result = _unique_field_value(nested_fields, {"result"})
                # Some analytics scanners report a direct identifier match as
                # ``matched_value`` instead of an email/user field. Treat it
                # as attribution only when the same resource record explicitly
                # identifies an identity-scan event, the value exactly matches
                # a resolved subject identifier, and direct_identifiers is true.
                matched_value = _unique_field_value(nested_fields, {"matched_value"})
                direct_identifier_flag = _unique_field_value(nested_fields, {"direct_identifiers"})
                if (
                    isinstance(lookup_event, str)
                    and lookup_event.strip().casefold() == "analytics_identity_scan"
                    and isinstance(matched_value, str)
                    and matched_value.strip().casefold() in direct_identifier_values
                    and _explicit_true(direct_identifier_flag)
                ):
                    add_fact(
                        "attributable",
                        True,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, {
                            "resource_id", "event", "matched_value", "direct_identifiers", "detector",
                        }),
                    )
                    if state is ObservedState.UNKNOWN:
                        analytics_state_candidates.append((source_time, ObservedState.PRESENT))
                if (
                    state is ObservedState.UNKNOWN
                    and isinstance(lookup_event, str)
                    and lookup_event.strip().casefold() == "record_lookup"
                    and isinstance(lookup_result, str)
                    and lookup_result.strip().casefold() == "identifiable"
                ):
                    analytics_state_candidates.append((source_time, ObservedState.PRESENT))

            elif category == "DATA_FLOW":
                enabled = _unique_field_value(nested_fields, {"enabled"})
                if _explicit_false(enabled):
                    state = ObservedState.DISABLED
                    proof = {
                        "evidence_id": record.evidence_id,
                        "relative_path": record.relative_path,
                        "origin": record.origin,
                        "captured_at": record.captured_at.isoformat(),
                        "record_timestamp": source_time.isoformat() if source_time else None,
                        "audit_at": audit_at.isoformat(),
                        "locator": str(segment.get("locator") or record.locator),
                        "source_fields": _policy_source_fields(fields, {
                            "resource_id", "customer_reference", "subject_reference", "user_id",
                            "connector_name", "enabled", "last_delivery_status",
                        }),
                    }
                    relationships.append(ResourceRelationship(
                        "data_flow", observation.system_id, observation.resource_id,
                        json.dumps(proof, ensure_ascii=False, sort_keys=True),
                    ))

            elif category == "BACKUP_ARCHIVE":
                restore_allowed = _unique_field_value(nested_fields, {"restore_allowed"})
                backup_read_event = _unique_field_value(nested_fields, {"event"})
                archive_present = _unique_field_value(nested_fields, {"archive_present"})
                if (
                    state is ObservedState.UNKNOWN
                    and isinstance(backup_read_event, str)
                    and backup_read_event.strip().casefold() == "restore_policy_read_completed"
                    and _explicit_true(archive_present)
                ):
                    backup_state_candidates.append((source_time, ObservedState.PRESENT))
                explicit_blockable = _unique_explicit_boolean(nested_fields, {"restore_blockable"})
                restore_is_blocked = _explicit_false(restore_allowed)
                if explicit_blockable is not None:
                    add_fact(
                        "restore_blockable",
                        explicit_blockable,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, {
                            "resource_id", "customer_reference", "subject_reference", "user_id",
                            "archive_key", "restore_allowed", "restore_blockable",
                        }),
                    )
                elif restore_is_blocked:
                    add_fact(
                        "restore_blockable",
                        True,
                        record,
                        segment,
                        source_time,
                        _policy_source_fields(fields, {
                            "resource_id", "customer_reference", "subject_reference", "user_id",
                            "archive_key", "restore_allowed",
                        }),
                    )
                if restore_is_blocked:
                    details = json.dumps({
                        "evidence_id": record.evidence_id,
                        "relative_path": record.relative_path,
                        "origin": record.origin,
                        "captured_at": record.captured_at.isoformat(),
                        "record_timestamp": source_time.isoformat() if source_time else None,
                        "audit_at": audit_at.isoformat(),
                        "locator": str(segment.get("locator") or record.locator),
                        "source_fields": _policy_source_fields(fields, {
                            "resource_id", "customer_reference", "subject_reference", "user_id",
                            "archive_key", "restore_allowed", "restore_blockable",
                        }),
                    }, ensure_ascii=False, sort_keys=True)
                    key = (observation.system_id, observation.resource_id, (record.evidence_id,))
                    restore_controls[key] = ResourceObservation(
                        system_id=observation.system_id,
                        resource_id=observation.resource_id,
                        data_category="RESTORE_FLOW",
                        observed_state=ObservedState.BLOCKED,
                        identifiers=observation.identifiers,
                        observation_timestamp=source_time,
                        evidence_references=(record.evidence_id,),
                        relationships=(ResourceRelationship(
                            "restore_path", observation.system_id, observation.resource_id, details,
                        ),),
                    )

        if category == "USER_PROFILE" and profile_state_candidates:
            state = _latest_state_candidate(profile_state_candidates, state)
        elif category == "SECURITY_AUDIT_LOG" and audit_state_candidates:
            state = _latest_state_candidate(audit_state_candidates, state)
        elif category == "USER_EXPORT" and export_state_candidates:
            state = _latest_state_candidate(export_state_candidates, state)
        elif category == "ANALYTICS_PROFILE" and analytics_state_candidates:
            state = _latest_state_candidate(analytics_state_candidates, state)
        elif category == "BACKUP_ARCHIVE" and backup_state_candidates:
            state = _latest_state_candidate(backup_state_candidates, state)

        adapted.append(replace(
            observation,
            data_category=category,
            observed_state=state,
            relationships=tuple(relationships),
        ))

    adapted.extend(restore_controls.values())
    return adapted


def _source_record_time(fields: Mapping[str, Any]) -> datetime | None:
    entries = _nested_policy_field_entries(fields)
    for name in ("observed_at", "event_time", "record_timestamp", "updated_at", "captured_at"):
        for _path, key, value in entries:
            if key != name or not isinstance(value, str) or not value.strip():
                continue
            try:
                return _parse_timestamp(value)
            except ValueError:
                continue
    return None


def _nested_policy_field_entries(value: Any, path: str = "") -> list[tuple[str, str, Any]]:
    """Flatten a resource segment while retaining each source-field path."""
    entries: list[tuple[str, str, Any]] = []

    def walk(current: Any, current_path: str) -> None:
        if isinstance(current, Mapping):
            for key, child in current.items():
                child_path = f"{current_path}.{key}" if current_path else str(key)
                walk(child, child_path)
        elif isinstance(current, (list, tuple)):
            for index, child in enumerate(current):
                walk(child, f"{current_path}[{index}]")
        elif current_path:
            leaf = current_path.rsplit(".", 1)[-1].split("[", 1)[0].casefold()
            entries.append((current_path, leaf, current))

    walk(value, path)
    return entries


def _policy_source_fields(fields: Mapping[str, Any], names: set[str]) -> dict[str, Any]:
    wanted = {name.casefold() for name in names}
    return {
        path: value
        for path, name, value in _nested_policy_field_entries(fields)
        if name in wanted
    }


def _unique_field_value(entries: Sequence[tuple[str, str, Any]], names: set[str]) -> Any:
    selected = [value for _path, name, value in entries if name in {n.casefold() for n in names}]
    if not selected:
        return None
    canonical = {json.dumps(value, ensure_ascii=False, sort_keys=True, default=str) for value in selected}
    if len(canonical) != 1:
        return _AMBIGUOUS_FIELD_VALUE
    return selected[0]


def _unique_explicit_boolean(entries: Sequence[tuple[str, str, Any]], names: set[str]) -> bool | None:
    parsed: set[bool] = set()
    matched = False
    for _path, name, value in entries:
        if name not in {n.casefold() for n in names}:
            continue
        matched = True
        if value is True or (isinstance(value, str) and value.strip().casefold() in _TRUE_VALUES):
            parsed.add(True)
        elif value is False or (isinstance(value, str) and value.strip().casefold() in _FALSE_VALUES):
            parsed.add(False)
    return next(iter(parsed)) if matched and len(parsed) == 1 else None


def _explicit_false(value: Any) -> bool:
    return value is False or (
        isinstance(value, str) and value.strip().casefold() in _FALSE_VALUES
    )


def _profile_lookup_state(fields: Mapping[str, Any]) -> ObservedState | None:
    entries = _nested_policy_field_entries(fields)
    event = _unique_field_value(entries, {"event"})
    record_type = _unique_field_value(entries, {"record_type"})
    result = _unique_field_value(entries, {"result"})
    if (
        isinstance(event, str)
        and event.strip().casefold() == "record_lookup"
        and isinstance(record_type, str)
        and record_type.strip().casefold() == "user_profile"
        and isinstance(result, str)
    ):
        normalized_result = result.strip().casefold()
        if normalized_result == "found":
            return ObservedState.PRESENT
        if normalized_result == "not_found":
            return ObservedState.ABSENT

    status = _unique_field_value(entries, {"http_status", "status_code"})
    rows = _unique_field_value(entries, {"rows", "row_count", "total_rows"})
    if status is _AMBIGUOUS_FIELD_VALUE or rows is _AMBIGUOUS_FIELD_VALUE:
        return None
    try:
        status_code = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status_code = None
    try:
        row_count = int(rows) if rows not in (None, "") else None
    except (TypeError, ValueError):
        row_count = None
    profile_entries = [value for _path, name, value in entries if name == "profile"]
    profile_explicitly_null = bool(profile_entries) and all(value is None for value in profile_entries)
    if status_code in {404, 410} and (row_count == 0 or profile_explicitly_null):
        return ObservedState.ABSENT
    if status_code == 200 and (row_count is not None and row_count > 0 or any(value is not None for value in profile_entries)):
        return ObservedState.PRESENT
    return None


def _latest_state_candidate(
    candidates: Sequence[tuple[datetime | None, ObservedState]],
    current_state: ObservedState,
) -> ObservedState:
    dated = [(stamp, state) for stamp, state in candidates if stamp is not None]
    if dated:
        latest = max(stamp for stamp, _state in dated)
        relevant = [state for stamp, state in dated if stamp == latest]
    else:
        relevant = [state for _stamp, state in candidates]
    unique = set(relevant)
    if len(unique) == 1:
        return next(iter(unique))
    return ObservedState.UNKNOWN


def _request_requires_profile_absence(request_text: str) -> bool:
    """Require direct primary-profile absence evidence when the request asks for it."""
    return bool(re.search(r"\b(?:account|profile)\b", request_text, re.IGNORECASE))


def _explicit_true(value: Any) -> bool:
    return value is True or (
        isinstance(value, str) and value.strip().casefold() in {"true", "yes", "1"}
    )


def _not_applicable_row(case_id: str) -> OutputRow:
    return OutputRow.from_decision(
        case_id,
        AuditDecision(DeletionStatus.NOT_APPLICABLE, ()),
    )


def _identity_rows_for_resolver(identities: Sequence[IdentityRecord]) -> list[dict[str, object]]:
    """Adapt shared identity records to Member 1's mapping-row input contract."""
    rows: list[dict[str, object]] = []
    for identity in identities:
        row: dict[str, object] = {
            "user_id": identity.user_id,
            "updated_at": identity.updated_at.isoformat(),
        }
        for identifier in identity.identifiers:
            row[identifier.identifier_type] = identifier.value
        rows.append(row)
    return rows


def _identity_audit_rows_for_resolver(
    audit_log: Sequence[IdentityAuditEvent],
) -> list[dict[str, object]]:
    """Adapt shared identity audit events to Member 1's mapping-row input contract."""
    return [
        {
            "audit_id": event.audit_id,
            "user_id": event.user_id,
            "event_time": event.event_time.isoformat(),
            "field_name": event.field_name,
            "old_value": event.old_value,
            "new_value": event.new_value,
        }
        for event in audit_log
    ]


def _require_unique_subject(case_id: str, subject: ResolvedSubject) -> ResolvedSubject:
    if subject.resolution_status is not ResolutionStatus.UNIQUE or subject.user_id is None:
        raise PipelineBlockedError(
            f"case {case_id}: identity resolution is {subject.resolution_status.value}; "
            "no deletion audit can be safely asserted"
        )
    return subject


def collect_independent_rows(requests, build_one, validate_one):
    """Build and validate each request independently, retaining all blockers.

    ``build_one`` receives one request and returns one candidate row. Exceptions
    are recorded against that request; they never prevent later requests from
    being processed.
    """
    rows: list[OutputRow] = []
    unresolved: list[dict[str, str]] = []
    for request in requests:
        try:
            row = build_one(request)
            validate_one(row, request)
            rows.append(row)
        except Exception as exc:
            reason = str(exc).strip() or type(exc).__name__
            unresolved.append(
                {
                    "case_id": request.case_id,
                    "stage": _diagnostic_stage(reason),
                    "blocker_reason": reason,
                    "exception_type": type(exc).__name__,
                }
            )
    rows.sort(key=lambda row: row.case_id)
    return rows, unresolved


def _diagnostic_stage(reason: str) -> str:
    lowered = reason.casefold()
    if "intent" in lowered or "authorization" in lowered:
        return "authorization_and_intent"
    if "identity" in lowered:
        return "identity_resolution"
    if (
        "policy evaluation failed" in lowered
        or "insufficient evidence to decide policy" in lowered
        or "cannot establish complete" in lowered
        or "verification-only audit" in lowered
    ):
        return "policy_evaluation"
    if (
        "evidence loading failed" in lowered
        or "evidence search failed" in lowered
        or "no cutoff-valid evidence" in lowered
        or "evidence reference catalog" in lowered
        or "unknown evidence reference" in lowered
    ):
        return "evidence_discovery"
    if "evidence" in lowered or "resource" in lowered or "cutoff" in lowered:
        return "evidence_discovery"
    if "policy" in lowered or "remediation" in lowered:
        return "policy_evaluation"
    return "row_validation_or_pipeline"


def validate_candidate_row(
    row: OutputRow,
    request: DeletionRequest,
    evidence_catalog: Mapping[str, datetime | None] | None,
    evidence_catalog_error: str | None = None,
) -> None:
    """Validate one row against the shared output contract and its audit cutoff."""
    if not isinstance(row, OutputRow):
        raise TypeError("pipeline did not return an OutputRow")
    if row.case_id != request.case_id:
        raise ValueError(f"candidate case_id {row.case_id!r} does not match request {request.case_id!r}")

    # Reconstruct to re-run exact JSON, field, status, sequence, phase,
    # operation/state, and step-number validations at the integration boundary.
    OutputRow(row.case_id, row.deletion_status, row.steps_json)
    step_data = json.loads(row.steps_json)
    steps = tuple(AuditStep(**item) for item in step_data)
    if evidence_catalog is None:
        if any(step.evidence_id for step in steps):
            raise ValueError(f"evidence reference catalog unavailable: {evidence_catalog_error or 'unknown error'}")
        return

    validate_evidence_references(steps, set(evidence_catalog))
    for step in steps:
        if not step.evidence_id:
            continue
        evidence_time = evidence_catalog[step.evidence_id]
        if evidence_time is None:
            raise ValueError(f"evidence {step.evidence_id} has no timestamp for audit cutoff validation")
        if evidence_time > request.audit_at:
            raise ValueError(f"evidence {step.evidence_id} is later than audit_at")


def _write_replay_diagnostics(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_pipeline(repo_root: Path | None = None) -> ValidationReport:
    """Replay all requests independently and write output.csv only on full success."""
    root = repo_root or Path(__file__).resolve().parents[1]
    dataset_root = root / "dataset"
    requests = read_requests(dataset_root)
    output_path = root / "output.csv"
    diagnostics_path = root / "code" / "evaluation" / "replay_diagnostics.json"

    try:
        modules = load_feature_modules()
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        activity = read_activity(dataset_root)
        rules = read_deletion_rules(dataset_root)
    except Exception as exc:
        reason = f"shared pipeline setup failed: {type(exc).__name__}: {exc}"
        unresolved = [
            {
                "case_id": request.case_id,
                "stage": "shared_pipeline_setup",
                "blocker_reason": reason,
                "exception_type": type(exc).__name__,
            }
            for request in requests
        ]
        _write_replay_diagnostics(
            diagnostics_path,
            {
                "schema_version": "deadbyte-replay-diagnostics.v1",
                "request_count": len(requests),
                "valid_row_count": 0,
                "unresolved_count": len(unresolved),
                "output_status": "not_generated_shared_setup_failed",
                "unresolved_cases": unresolved,
            },
        )
        return ValidationReport(False, (reason, f"See {diagnostics_path}"), 0)

    evidence_index: EvidenceIndex | None = None
    evidence_load_error: str | None = None
    try:
        evidence_index = modules.evidence_processing.load_evidence(
            dataset_root / "evidence_files.csv",
            dataset_root,
        )
        if not isinstance(evidence_index, EvidenceIndex):
            raise TypeError("evidence loader returned a non-EvidenceIndex result")
    except Exception as exc:
        evidence_load_error = f"{type(exc).__name__}: {exc}"

    evidence_catalog: Mapping[str, datetime | None] | None
    evidence_catalog_error: str | None = None
    try:
        evidence_catalog = _load_evidence_reference_catalog(output_path, dataset_root)
    except Exception as exc:
        evidence_catalog = None
        evidence_catalog_error = f"{type(exc).__name__}: {exc}"

    def build_one(request: DeletionRequest) -> OutputRow:
        case_rows = build_rows(
            [request],
            identities,
            audit_log,
            activity,
            rules,
            dataset_root,
            modules,
            evidence_index,
            evidence_load_error,
        )
        if len(case_rows) != 1:
            raise PipelineBlockedError(f"case {request.case_id}: pipeline returned {len(case_rows)} rows")
        return case_rows[0]

    rows, unresolved = collect_independent_rows(
        requests,
        build_one,
        lambda row, request: validate_candidate_row(
            row, request, evidence_catalog, evidence_catalog_error
        ),
    )

    # Guard against an integration bug that changes case identity, duplicates a
    # row, or omits a request even if each individual row looked valid.
    request_ids = [request.case_id for request in requests]
    row_ids = [row.case_id for row in rows]
    global_errors: list[str] = []
    if len(row_ids) != len(set(row_ids)):
        global_errors.append("candidate rows contain duplicate case_id values")
    missing_ids = sorted(set(request_ids) - set(row_ids) - {item["case_id"] for item in unresolved})
    if missing_ids:
        global_errors.append("requests were neither produced nor diagnosed: " + ", ".join(missing_ids))
    if set(row_ids) & {item["case_id"] for item in unresolved}:
        global_errors.append("a request was both produced and marked unresolved")

    if global_errors:
        unresolved.extend(
            {
                "case_id": case_id,
                "stage": "replay_integrity",
                "blocker_reason": "; ".join(global_errors),
                "exception_type": "ReplayIntegrityError",
            }
            for case_id in request_ids
        )
        rows = []

    if unresolved or len(rows) != 518 or row_ids != sorted(row_ids):
        if not unresolved and (len(rows) != 518 or row_ids != sorted(row_ids)):
            reason = f"full replay requires 518 sorted rows; found {len(rows)}"
            unresolved = [
                {
                    "case_id": request.case_id,
                    "stage": "replay_integrity",
                    "blocker_reason": reason,
                    "exception_type": "ReplayIntegrityError",
                }
                for request in requests
            ]
            rows = []
        _write_replay_diagnostics(
            diagnostics_path,
            {
                "schema_version": "deadbyte-replay-diagnostics.v1",
                "request_count": len(requests),
                "valid_row_count": len(rows),
                "unresolved_count": len(unresolved),
                "output_status": "not_generated_unresolved_cases",
                "unresolved_cases": unresolved,
            },
        )
        return ValidationReport(
            False,
            (f"{len(rows)} valid rows; {len(unresolved)} unresolved cases", f"See {diagnostics_path}"),
            len(rows),
        )

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".csv",
            prefix=".output-pending-",
            dir=root,
            delete=False,
            encoding="utf-8",
            newline="",
        ) as temporary:
            temp_path = Path(temporary.name)
        write_output(rows, temp_path)
        report = validate_output(temp_path, requests, dataset_root)
        if not report.valid:
            failure = "; ".join(report.errors)
            unresolved = [
                {
                    "case_id": request.case_id,
                    "stage": "full_output_validation",
                    "blocker_reason": failure,
                    "exception_type": "OutputValidationError",
                }
                for request in requests
            ]
            _write_replay_diagnostics(
                diagnostics_path,
                {
                    "schema_version": "deadbyte-replay-diagnostics.v1",
                    "request_count": len(requests),
                    "valid_row_count": 0,
                    "unresolved_count": len(unresolved),
                    "output_status": "not_generated_full_validation_failed",
                    "full_output_validation_errors": list(report.errors),
                    "unresolved_cases": unresolved,
                },
            )
            return ValidationReport(False, report.errors + (f"See {diagnostics_path}",), 0)

        temp_path.replace(output_path)
        _write_replay_diagnostics(
            diagnostics_path,
            {
                "schema_version": "deadbyte-replay-diagnostics.v1",
                "request_count": len(requests),
                "valid_row_count": len(rows),
                "unresolved_count": 0,
                "output_status": "generated_and_validated",
                "output_path": str(output_path),
                "unresolved_cases": [],
            },
        )
        return report
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def _parse_timestamp(value: str) -> datetime:
    if not value:
        raise ValueError("required timestamp is blank")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_optional_timestamp(value: str) -> datetime | None:
    return _parse_timestamp(value) if value else None


def main() -> int:
    try:
        report = run_pipeline()
    except (PipelineBlockedError, OSError, ValueError) as exc:
        print(f"Pipeline blocked: {exc}", file=sys.stderr)
        return 2
    if not report.valid:
        print("Replay incomplete: " + "; ".join(report.errors), file=sys.stderr)
        return 2
    print(f"Validated {report.rows_checked} output rows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
