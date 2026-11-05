"""Evidence-backed graph serialization for the DEADBYTE Ghost Data Map.

The public JSON contract is :func:`build_ghost_data_map` -> a versioned mapping
with ``nodes`` and ``edges`` arrays. It uses shared observation/evidence
contracts and never treats activity ``reported_result`` as a resource state.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from code.contracts import (
    ActivityEvent,
    EvidenceIndex,
    EvidenceRecord,
    ObservedState,
    ResourceObservation,
)

SCHEMA_VERSION = "ghost-data-map.v1"


def build_ghost_data_map(
    observations: Sequence[ResourceObservation],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
    activity: Sequence[ActivityEvent] = (),
) -> dict[str, Any]:
    """Build a deterministic, cutoff-filtered graph for subject observations.

    Resource nodes are included only when at least one cited evidence file or
    activity event can be verified in the supplied index/stream at ``audit_at``.
    Activity events are rendered as explicitly reported claims; they do not
    assert a copy occurred or an active flow remains. A directed active flow
    path is emitted only when eligible evidence explicitly names both endpoint
    systems and the matching flow resource is supported as ACTIVE.
    """
    _require_aware(audit_at, "audit_at")
    records = evidence_index.records_by_id
    eligible_events = {
        event.activity_id: event for event in activity if event.event_time <= audit_at
    }
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    accepted: list[tuple[ResourceObservation, str, tuple[str, ...]]] = []
    warnings: list[dict[str, str]] = []

    for observation in observations:
        if observation.observation_timestamp and observation.observation_timestamp > audit_at:
            warnings.append({
                "code": "OBSERVATION_AFTER_AUDIT_AT",
                "resource_id": observation.resource_id,
            })
            continue
        valid_refs = _valid_observation_references(
            observation, records, eligible_events, audit_at,
        )
        if not valid_refs:
            warnings.append({
                "code": "OBSERVATION_WITHOUT_CUTOFF_VALID_EVIDENCE",
                "resource_id": observation.resource_id,
            })
            continue
        resource_node_id = _resource_node_id(observation.system_id, observation.resource_id)
        accepted.append((observation, resource_node_id, valid_refs))
        system_node_id = _system_node_id(observation.system_id)
        _merge_system_node(nodes, system_node_id, observation.system_id, valid_refs)
        provenance = _observation_provenance(
            observation, valid_refs, records, eligible_events, audit_at,
        )
        _extend_unique(
            provenance,
            _relationship_provenance(observation, valid_refs, records, audit_at),
        )
        provenance = _merge_provenance(provenance)
        _merge_resource_node(
            nodes, resource_node_id, observation, valid_refs, provenance,
            _restore_risk_supported(observation, valid_refs, records, audit_at),
        )
        _add_edge(edges, {
            "source_node_id": system_node_id,
            "destination_node_id": resource_node_id,
            "edge_type": "OBSERVED_IN",
            "relationship_type": "OBSERVED_IN",
            "active_state": None,
            "support_status": "EVIDENCE_BACKED",
            "evidence_ids": list(valid_refs),
            "trace_ids": _trace_ids_from_provenance(provenance),
            "source_locators": _locators_from_provenance(provenance),
            "timestamp": _iso(observation.observation_timestamp),
            "captured_at": _captured_at(provenance),
            "record_timestamps": _record_timestamps(provenance),
            "audit_at": audit_at.isoformat(),
            "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
            "resource_id": observation.resource_id,
        })

    _add_activity_edges(
        edges, nodes, accepted, eligible_events, records, audit_at,
    )
    _add_explicit_flow_edges(
        edges, nodes, accepted, records, audit_at,
    )
    _add_explicit_resource_dependencies(
        edges, nodes, accepted, records, audit_at,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "audit_at": audit_at.isoformat(),
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": [edges[key] for key in sorted(edges)],
        "warnings": sorted(warnings, key=lambda item: (item["code"], item["resource_id"])),
    }


def serialize_ghost_data_map(graph: Mapping[str, Any]) -> str:
    """Serialize the public graph contract as deterministic compact JSON."""
    if graph.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported Ghost Data Map schema: {graph.get('schema_version')!r}")
    return json.dumps(graph, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_ghost_data_map_payload(
    observations: Sequence[ResourceObservation],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
    activity: Sequence[ActivityEvent] = (),
) -> str:
    """Build and serialize the frontend payload from pipeline outputs.

    This adapter accepts the existing shared-contract outputs unchanged. It
    does not resolve subjects, infer relationships, or evaluate policy.
    """
    return serialize_ghost_data_map(
        build_ghost_data_map(observations, evidence_index, audit_at, activity)
    )


def _valid_observation_references(
    observation: ResourceObservation,
    records: Mapping[str, EvidenceRecord],
    events: Mapping[str, ActivityEvent],
    audit_at: datetime,
) -> tuple[str, ...]:
    valid: set[str] = set()
    for reference in observation.evidence_references:
        event = events.get(reference)
        if event is not None and event.event_time <= audit_at:
            valid.add(reference)
            continue
        record = records.get(reference)
        if record is None or record.captured_at > audit_at:
            continue
        if _segments_for_observation(observation, record, audit_at):
            valid.add(reference)
    return tuple(sorted(valid))


def _segments_for_observation(
    observation: ResourceObservation,
    record: EvidenceRecord,
    audit_at: datetime,
) -> list[Mapping[str, Any]]:
    candidates = [
        segment for segment in record.structured_fields.get("records", ())
        if isinstance(segment, Mapping)
        and _segment_within_cutoff(segment, audit_at)
        and _segment_has_resource(segment.get("fields", {}), observation.resource_id)
    ]
    if observation.observation_timestamp is not None:
        matching_time = [
            segment for segment in candidates
            if _segment_observation_timestamp(segment) == observation.observation_timestamp
        ]
        if matching_time:
            return matching_time
    trace_segments = [
        resource_segment
        for _details, _source_segment, resource_segment in _verified_trace_links(observation, record, audit_at)
    ]
    if trace_segments:
        return trace_segments
    return candidates if len(candidates) == 1 else []


def _segment_within_cutoff(segment: Mapping[str, Any], audit_at: datetime) -> bool:
    for candidate in segment.get("timestamp_candidates", ()):
        if not isinstance(candidate, Mapping):
            continue
        timestamp = _parse_datetime(candidate.get("parsed"))
        if timestamp is not None and timestamp > audit_at:
            return False
    record_timestamp = _parse_datetime(segment.get("record_timestamp"))
    return record_timestamp is None or record_timestamp <= audit_at


def _observation_provenance(
    observation: ResourceObservation,
    references: Sequence[str],
    records: Mapping[str, EvidenceRecord],
    events: Mapping[str, ActivityEvent],
    audit_at: datetime,
) -> list[dict[str, Any]]:
    provenance: list[dict[str, Any]] = []
    for reference in references:
        record = records.get(reference)
        if record is not None:
            matches = _segments_for_observation(observation, record, audit_at)
            provenance.append({
                "evidence_id": reference,
                "captured_at": record.captured_at.isoformat(),
                "record_timestamps": sorted({
                    timestamp.isoformat()
                    for segment in matches
                    for timestamp in _segment_timestamps(segment)
                }),
                "source_locators": sorted({str(segment.get("locator", "")) for segment in matches if segment.get("locator")}),
                "trace_ids": sorted({trace for segment in matches for trace in _trace_ids(segment.get("fields", {}))}),
            })
            continue
        event = events.get(reference)
        if event is not None:
            provenance.append({
                "evidence_id": reference,
                "captured_at": None,
                "record_timestamps": [event.event_time.isoformat()],
                "source_locators": [],
                "trace_ids": _trace_ids(event.details),
            })
    return provenance


def _relationship_provenance(
    observation: ResourceObservation,
    valid_references: Sequence[str],
    records: Mapping[str, EvidenceRecord],
    audit_at: datetime,
) -> list[dict[str, Any]]:
    valid_ids = set(valid_references)
    result = []
    for evidence_id in sorted(valid_ids):
        record = records.get(evidence_id)
        if record is None:
            continue
        for details, source_segment, resource_segment in _verified_trace_links(observation, record, audit_at):
            result.append({
                "evidence_id": evidence_id,
                "captured_at": record.captured_at.isoformat(),
                "record_timestamps": sorted({
                    timestamp.isoformat()
                    for segment in (source_segment, resource_segment)
                    for timestamp in _segment_timestamps(segment)
                }),
                "source_locators": sorted({
                    str(source_segment.get("locator", "")),
                    str(resource_segment.get("locator", "")),
                } - {""}),
                "trace_ids": [str(details["trace_id"])],
            })
    return result


def _verified_trace_links(
    observation: ResourceObservation,
    record: EvidenceRecord,
    audit_at: datetime,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]]:
    result = []
    segments = [
        segment for segment in record.structured_fields.get("records", ())
        if isinstance(segment, Mapping) and _segment_within_cutoff(segment, audit_at)
    ]
    for relationship in observation.relationships:
        if relationship.relationship != "TRACE_CORRELATED_EVIDENCE":
            continue
        try:
            details = json.loads(relationship.details)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(details, Mapping) or details.get("evidence_id") != record.evidence_id:
            continue
        trace_id = str(details.get("trace_id", ""))
        source_locator = str(details.get("identifier_locator", ""))
        resource_locator = str(details.get("resource_locator", ""))
        source_segments = [segment for segment in segments if str(segment.get("locator", "")) == source_locator]
        resource_segments = [segment for segment in segments if str(segment.get("locator", "")) == resource_locator]
        for source_segment in source_segments:
            if trace_id not in _trace_ids(source_segment.get("fields", {})):
                continue
            source_time = _segment_timestamp(source_segment)
            if source_time is not None and source_time > audit_at:
                continue
            for resource_segment in resource_segments:
                if (trace_id not in _trace_ids(resource_segment.get("fields", {}))
                        or not _segment_has_resource(resource_segment.get("fields", {}), observation.resource_id)):
                    continue
                resource_time = _segment_timestamp(resource_segment)
                if resource_time is not None and resource_time > audit_at:
                    continue
                result.append((details, source_segment, resource_segment))
    return result


def _merge_system_node(
    nodes: dict[str, dict[str, Any]], node_id: str, system_id: str, evidence_ids: Sequence[str],
) -> None:
    current = nodes.get(node_id)
    if current is None:
        current = {
            "node_id": node_id,
            "node_type": "SYSTEM",
            "system_id": system_id,
            "resource_id": None,
            "resource_type": "SYSTEM",
            "observed_state": ObservedState.UNKNOWN.value,
            "visual_state": "SYSTEM",
            "risk_classification": None,
            "evidence_ids": [],
        }
        nodes[node_id] = current
    current["evidence_ids"] = sorted(set(current["evidence_ids"]) | set(evidence_ids))


def _merge_resource_node(
    nodes: dict[str, dict[str, Any]],
    node_id: str,
    observation: ResourceObservation,
    evidence_ids: Sequence[str],
    provenance: list[dict[str, Any]],
    restore_risk: bool,
) -> None:
    current = nodes.get(node_id)
    if current is None:
        current = {
            "node_id": node_id,
            "node_type": "RESOURCE",
            "system_id": observation.system_id,
            "resource_id": observation.resource_id,
            "resource_type": observation.data_category,
            "observed_state": observation.observed_state.value,
            "visual_state": _visual_state(observation.observed_state, observation.data_category),
            "risk_classification": _risk_classification(observation, restore_risk),
            "evidence_ids": [],
            "provenance": [],
        }
        nodes[node_id] = current
    states = {current["observed_state"], observation.observed_state.value}
    current["observed_state"] = next(iter(states)) if len(states) == 1 else "CONFLICTING"
    current["visual_state"] = (
        _visual_state(observation.observed_state, observation.data_category)
        if current["observed_state"] != "CONFLICTING" else "CONFLICTING"
    )
    current["evidence_ids"] = sorted(set(current["evidence_ids"]) | set(evidence_ids))
    _extend_unique(current["provenance"], provenance)
    if current["risk_classification"] is None:
        current["risk_classification"] = _risk_classification(observation, restore_risk)


def _visual_state(state: ObservedState, resource_type: str) -> str:
    if state is ObservedState.PRESENT:
        return "REMAINING_RECORD"
    if state is ObservedState.ABSENT:
        return "VERIFIED_ABSENT"
    if state is ObservedState.ANONYMIZED:
        return "ANONYMIZED_RECORD"
    if state is ObservedState.REDACTED:
        return "REDACTED_RECORD"
    if state is ObservedState.ACTIVE and resource_type.casefold() == "data_flow":
        return "ACTIVE_FLOW"
    if state is ObservedState.DISABLED and resource_type.casefold() == "data_flow":
        return "FLOW_INACTIVE"
    if state is ObservedState.BLOCKED:
        return "RESTORE_BLOCKED"
    return state.value


def _risk_classification(observation: ResourceObservation, restore_risk: bool) -> str | None:
    if observation.observed_state is ObservedState.ACTIVE and observation.data_category.casefold() == "data_flow":
        return "ACTIVE_DATA_FLOW"
    if restore_risk:
        return "RESTORE_RISK"
    return None


def _restore_risk_supported(
    observation: ResourceObservation,
    evidence_ids: Sequence[str],
    records: Mapping[str, EvidenceRecord],
    audit_at: datetime,
) -> bool:
    resource_is_backup = (
        observation.resource_id.casefold().startswith("backup_")
        or "backup" in observation.data_category.casefold()
    )
    if not resource_is_backup:
        return False
    for evidence_id in evidence_ids:
        record = records.get(evidence_id)
        if record is None or record.captured_at > audit_at:
            continue
        for segment in _segments_for_observation(observation, record, audit_at):
            fields = {
                key.casefold().split(".")[-1]: value
                for key, value, _path in _walk_scalars(segment.get("fields", {}))
            }
            if not any(str(value).strip().casefold() == observation.resource_id.casefold()
                       for value in fields.values()):
                continue
            eligible = fields.get("restore_eligible", fields.get("eligible"))
            blocked = fields.get("restore_blocked", fields.get("deletion_block"))
            if _explicit_true(eligible) and _explicit_false(blocked):
                return True
    return False


def _add_activity_edges(
    edges: dict[str, dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    accepted: Sequence[tuple[ResourceObservation, str, tuple[str, ...]]],
    events: Mapping[str, ActivityEvent],
    records: Mapping[str, EvidenceRecord],
    audit_at: datetime,
) -> None:
    for event in events.values():
        related = [
            (observation, node_id, refs)
            for observation, node_id, refs in accepted
            if observation.resource_id.casefold() == event.resource_id.casefold()
            and observation.system_id.casefold() == event.target_system.casefold()
        ]
        if not related:
            related = [
                (observation, node_id, refs)
                for observation, node_id, refs in accepted
                if event.activity_id in refs
            ]
        if not related:
            continue
        source_id = _system_node_id(event.source_system)
        target_id = _system_node_id(event.target_system)
        _merge_system_node(nodes, source_id, event.source_system, (event.activity_id,))
        _merge_system_node(nodes, target_id, event.target_system, (event.activity_id,))
        corroborating_ids = sorted({
            reference
            for observation, _node_id, refs in related
            if observation.observed_state is ObservedState.PRESENT
            and observation.observation_timestamp is not None
            and observation.observation_timestamp >= event.event_time
            for reference in refs if reference in records
        })
        metadata = _references_metadata(corroborating_ids, records, related, audit_at)
        _add_edge(edges, {
            "source_node_id": source_id,
            "destination_node_id": target_id,
            "edge_type": "REPORTED_ACTIVITY_CLAIM",
            "relationship_type": event.event_type,
            "active_state": None,
            "support_status": "REPORTED_ACTIVITY",
            "evidence_ids": sorted({event.activity_id, *corroborating_ids}),
            "trace_ids": sorted(set(_trace_ids(event.details)) | set(metadata["trace_ids"])),
            "source_locators": metadata["source_locators"],
            "timestamp": event.event_time.isoformat(),
            "captured_at": metadata["captured_at"],
            "record_timestamps": metadata["record_timestamps"],
            "audit_at": audit_at.isoformat(),
            "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
            "resource_id": event.resource_id,
            "target_resource_observed": bool(corroborating_ids),
        })


def _add_explicit_flow_edges(
    edges: dict[str, dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    accepted: Sequence[tuple[ResourceObservation, str, tuple[str, ...]]],
    records: Mapping[str, EvidenceRecord],
    audit_at: datetime,
) -> None:
    for observation, flow_node_id, references in accepted:
        if (observation.observed_state not in {ObservedState.ACTIVE, ObservedState.DISABLED}
                or observation.data_category.casefold() != "data_flow"):
            continue
        for evidence_id in references:
            record = records.get(evidence_id)
            if record is None or record.captured_at > audit_at:
                continue
            for segment in _segments_for_observation(observation, record, audit_at):
                fields = segment.get("fields", {})
                flow_state = _explicit_flow_state(fields, observation.resource_id)
                expected_state = "ACTIVE" if observation.observed_state is ObservedState.ACTIVE else "INACTIVE"
                if flow_state != expected_state:
                    continue
                source_system = _field_value(fields, {"source_system", "from_system", "upstream_system", "source_service"})
                target_system = _field_value(fields, {"target_system", "destination_system", "to_system", "downstream_system", "target_service"})
                if not isinstance(source_system, str) or not source_system.strip():
                    continue
                if not isinstance(target_system, str) or not target_system.strip():
                    continue
                source_system = source_system.strip()
                target_system = target_system.strip()
                source_node = _system_node_id(source_system)
                target_node = _system_node_id(target_system)
                _merge_system_node(nodes, source_node, source_system, (evidence_id,))
                _merge_system_node(nodes, target_node, target_system, (evidence_id,))
                details = _segment_metadata(record, segment, audit_at)
                edge_type = "ACTIVE_DATA_FLOW" if flow_state == "ACTIVE" else "INACTIVE_DATA_FLOW"
                edges_common = {
                    "edge_type": edge_type,
                    "relationship_type": edge_type,
                    "active_state": flow_state,
                    "support_status": "EVIDENCE_BACKED",
                    "evidence_ids": [evidence_id],
                    "trace_ids": list(_trace_ids(fields)),
                    "source_locators": [str(segment.get("locator", ""))] if segment.get("locator") else [],
                    "timestamp": _iso(_segment_timestamp(segment)),
                    "captured_at": [{"evidence_id": evidence_id, "captured_at": details["captured_at"]}],
                    "record_timestamps": details["record_timestamps"],
                    "audit_at": audit_at.isoformat(),
                    "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
                    "resource_id": observation.resource_id,
                }
                _add_edge(edges, {
                    **edges_common,
                    "source_node_id": source_node,
                    "destination_node_id": flow_node_id,
                    "path_leg": "SOURCE_TO_FLOW",
                })
                _add_edge(edges, {
                    **edges_common,
                    "source_node_id": flow_node_id,
                    "destination_node_id": target_node,
                    "path_leg": "FLOW_TO_DESTINATION",
                })


def _add_explicit_resource_dependencies(
    edges: dict[str, dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    accepted: Sequence[tuple[ResourceObservation, str, tuple[str, ...]]],
    records: Mapping[str, EvidenceRecord],
    audit_at: datetime,
) -> None:
    """Link resource nodes only when one eligible evidence row names both."""
    node_ids_by_resource: dict[str, list[str]] = defaultdict(list)
    for node_id, node in nodes.items():
        if node["node_type"] == "RESOURCE":
            node_ids_by_resource[str(node["resource_id"]).casefold()].append(node_id)
    emitted: set[tuple[str, str, str, str, str]] = set()

    pair_specs = (
        ("backup_resource_id", ("restore_target_resource_id", "restored_resource_id", "target_resource_id"), "BACKUP_RESTORE_DEPENDENCY"),
        ("snapshot_resource_id", ("restored_resource_id", "restore_target_resource_id", "target_resource_id"), "SNAPSHOT_DEPENDENCY"),
        ("source_resource_id", ("target_resource_id", "destination_resource_id", "downstream_resource_id"), "RESOURCE_DEPENDENCY"),
        ("upstream_resource_id", ("downstream_resource_id", "target_resource_id"), "RESOURCE_DEPENDENCY"),
    )
    for observation, _node_id, evidence_refs in accepted:
        for evidence_id in evidence_refs:
            record = records.get(evidence_id)
            if record is None or record.captured_at > audit_at:
                continue
            for segment in _segments_for_observation(observation, record, audit_at):
                fields = segment.get("fields", {})
                for source_key, target_keys, relation_type in pair_specs:
                    source_resource = _field_value(fields, {source_key})
                    target_resource = _field_value(fields, set(target_keys))
                    if not isinstance(source_resource, str) or not source_resource.strip():
                        continue
                    if not isinstance(target_resource, str) or not target_resource.strip():
                        continue
                    source_system = _field_value(fields, {"source_system", "from_system", "upstream_system"})
                    target_system = _field_value(fields, {"target_system", "destination_system", "to_system", "downstream_system"})
                    source_node = _resolve_resource_node(node_ids_by_resource, nodes, source_resource, source_system)
                    target_node = _resolve_resource_node(node_ids_by_resource, nodes, target_resource, target_system)
                    if source_node is None or target_node is None:
                        continue
                    relation_key = (
                        evidence_id, str(segment.get("locator", "")), relation_type,
                        source_node, target_node,
                    )
                    if relation_key in emitted:
                        continue
                    emitted.add(relation_key)
                    details = _segment_metadata(record, segment, audit_at)
                    risk = "RESTORE_RISK" if relation_type in {"BACKUP_RESTORE_DEPENDENCY", "SNAPSHOT_DEPENDENCY"} else None
                    _add_edge(edges, {
                        "source_node_id": source_node,
                        "destination_node_id": target_node,
                        "edge_type": relation_type,
                        "relationship_type": relation_type,
                        "active_state": None,
                        "risk_classification": risk,
                        "support_status": "EVIDENCE_BACKED",
                        "evidence_ids": [evidence_id],
                        "trace_ids": list(_trace_ids(fields)),
                        "source_locators": details["source_locators"],
                        "timestamp": _iso(_segment_timestamp(segment)),
                        "captured_at": [{"evidence_id": evidence_id, "captured_at": record.captured_at.isoformat()}],
                        "record_timestamps": details["record_timestamps"],
                        "audit_at": audit_at.isoformat(),
                        "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
                        "resource_id": target_resource,
                        "related_resource_id": source_resource,
                    })


def _resolve_resource_node(
    node_ids_by_resource: Mapping[str, Sequence[str]],
    nodes: Mapping[str, Mapping[str, Any]],
    resource_id: str,
    system_id: Any,
) -> str | None:
    candidates = list(node_ids_by_resource.get(resource_id.casefold(), ()))
    if isinstance(system_id, str) and system_id.strip():
        candidates = [node_id for node_id in candidates if nodes[node_id]["system_id"].casefold() == system_id.strip().casefold()]
    return candidates[0] if len(candidates) == 1 else None


def _references_metadata(
    references: Sequence[str],
    records: Mapping[str, EvidenceRecord],
    related: Sequence[tuple[ResourceObservation, str, tuple[str, ...]]],
    audit_at: datetime,
) -> dict[str, Any]:
    provenance = [
        detail
        for observation, _node_id, _refs in related
        for detail in _observation_provenance(observation, references, records, {}, audit_at)
    ]
    provenance = _merge_provenance(provenance)
    return {
        "captured_at": _captured_at(provenance),
        "record_timestamps": _record_timestamps(provenance),
        "source_locators": _locators_from_provenance(provenance),
        "trace_ids": _trace_ids_from_provenance(provenance),
    }


def _segment_metadata(record: EvidenceRecord, segment: Mapping[str, Any], audit_at: datetime) -> dict[str, Any]:
    timestamp = _segment_timestamp(segment)
    return {
        "captured_at": record.captured_at.isoformat(),
        "record_timestamps": [
            {"evidence_id": record.evidence_id, "timestamp": value.isoformat()}
            for value in _segment_timestamps(segment)
        ],
        "source_locators": [str(segment.get("locator", ""))] if segment.get("locator") else [],
        "trace_ids": _trace_ids(segment.get("fields", {})),
        "audit_at": audit_at.isoformat(),
    }


def _segment_has_resource(fields: Any, resource_id: str) -> bool:
    return any(str(value).strip().casefold() == resource_id.casefold()
               for _key, value, _path in _walk_scalars(fields))


def _field_value(fields: Any, names: set[str]) -> Any:
    matches = [value for key, value, _path in _walk_scalars(fields) if key.casefold().split(".")[-1] in names]
    return matches[-1] if matches else None


def _explicit_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().casefold() in {"true", "yes", "1"})


def _explicit_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().casefold() in {"false", "no", "0", "disabled"})


def _explicit_flow_state(fields: Any, resource_id: str) -> str | None:
    if not resource_id.casefold().startswith("data_flow_"):
        return None
    enabled = _field_value(fields, {"enabled"})
    registered = _field_value(fields, {"scheduler_registered"})
    if _explicit_true(enabled) and _explicit_true(registered):
        return "ACTIVE"
    if _explicit_false(enabled) or _explicit_false(registered):
        return "INACTIVE"
    return None


def _trace_ids(fields: Any) -> tuple[str, ...]:
    return tuple(sorted({
        str(value).strip()
        for key, value, _path in _walk_scalars(fields)
        if key.casefold().split(".")[-1] in {"trace_id", "traceid"}
        and str(value).strip()
    }))


def _trace_ids_from_provenance(provenance: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({trace for item in provenance for trace in item.get("trace_ids", ())})


def _locators_from_provenance(provenance: Sequence[Mapping[str, Any]]) -> list[str]:
    return sorted({locator for item in provenance for locator in item.get("source_locators", ())})


def _captured_at(provenance: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    values = {
        (str(item["evidence_id"]), str(item["captured_at"]))
        for item in provenance if item.get("captured_at")
    }
    return [{"evidence_id": evidence_id, "captured_at": captured_at}
            for evidence_id, captured_at in sorted(values)]


def _record_timestamps(provenance: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    result = set()
    for item in provenance:
        for timestamp in item.get("record_timestamps", ()):
            result.add((str(item["evidence_id"]), str(timestamp)))
    return [{"evidence_id": evidence_id, "timestamp": timestamp}
            for evidence_id, timestamp in sorted(result)]


def _extend_unique(target: list[Any], values: Sequence[Any]) -> None:
    serialized = {_stable_json(item) for item in target}
    for value in values:
        key = _stable_json(value)
        if key not in serialized:
            target.append(value)
            serialized.add(key)
    target.sort(key=_stable_json)


def _merge_provenance(provenance: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    combined: dict[tuple[str, str | None], dict[str, Any]] = {}
    for item in provenance:
        evidence_id = str(item.get("evidence_id", ""))
        captured_at = str(item["captured_at"]) if item.get("captured_at") else None
        key = (evidence_id, captured_at)
        target = combined.setdefault(key, {
            "evidence_id": evidence_id,
            "captured_at": captured_at,
            "record_timestamps": [],
            "source_locators": [],
            "trace_ids": [],
        })
        for field in ("record_timestamps", "source_locators", "trace_ids"):
            target[field] = sorted(set(target[field]) | {str(value) for value in item.get(field, ())})
    return [combined[key] for key in sorted(combined)]


def _add_edge(edges: dict[str, dict[str, Any]], edge: dict[str, Any]) -> None:
    identity = {
        key: edge.get(key)
        for key in ("source_node_id", "destination_node_id", "edge_type", "relationship_type", "evidence_ids", "timestamp", "resource_id", "path_leg")
    }
    edge_id = "edge:" + hashlib.sha256(_stable_json(identity).encode("utf-8")).hexdigest()[:24]
    edges.setdefault(edge_id, {"edge_id": edge_id, **edge})


def _system_node_id(system_id: str) -> str:
    return "system:" + quote(system_id, safe="")


def _resource_node_id(system_id: str, resource_id: str) -> str:
    return "resource:" + quote(system_id, safe="") + ":" + quote(resource_id, safe="")


def _walk_scalars(value: Any, path: str = ()):
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk_scalars(item, (*path, str(key)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk_scalars(item, (*path, str(index)))
    elif isinstance(value, (str, int, float, bool)):
        yield (path[-1] if path else ""), value, ".".join(path)


def _segment_timestamp(segment: Mapping[str, Any]) -> datetime | None:
    timestamp = _parse_datetime(segment.get("record_timestamp"))
    if timestamp is not None:
        return timestamp
    candidates = []
    for candidate in segment.get("timestamp_candidates", ()):
        if isinstance(candidate, Mapping):
            parsed = _parse_datetime(candidate.get("parsed"))
            if parsed is not None:
                candidates.append(parsed)
    return max(candidates) if candidates and len(set(candidates)) == 1 else None


def _segment_timestamps(segment: Mapping[str, Any]) -> tuple[datetime, ...]:
    values = set()
    timestamp = _parse_datetime(segment.get("record_timestamp"))
    if timestamp is not None:
        values.add(timestamp)
    for candidate in segment.get("timestamp_candidates", ()):
        if isinstance(candidate, Mapping):
            parsed = _parse_datetime(candidate.get("parsed"))
            if parsed is not None:
                values.add(parsed)
    return tuple(sorted(values))


def _segment_observation_timestamp(segment: Mapping[str, Any]) -> datetime | None:
    values = _segment_timestamps(segment)
    return max(values) if values else None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


__all__ = [
    "SCHEMA_VERSION",
    "build_ghost_data_map",
    "build_ghost_data_map_payload",
    "serialize_ghost_data_map",
]
