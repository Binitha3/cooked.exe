"""Standard-library tests for the stable Ghost Data Map graph contract."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone

from code.contracts import (
    ActivityEvent,
    EvidenceIndex,
    EvidenceRecord,
    ObservedState,
    ResourceObservation,
    ResourceRelationship,
)
from code.ghost_data_map import (
    SCHEMA_VERSION,
    build_ghost_data_map_payload,
    build_ghost_data_map,
    serialize_ghost_data_map,
)


UTC = timezone.utc
AUDIT_AT = datetime(2026, 9, 1, 12, 5, tzinfo=UTC)


def segment(locator: str, timestamp: datetime, fields: dict) -> dict:
    values = dict(fields)
    values.setdefault("event_time", timestamp.isoformat())
    return {
        "locator": locator,
        "record_timestamp": timestamp,
        "timestamp_candidates": [{
            "field": "event_time", "raw": timestamp.isoformat(),
            "parsed": timestamp.isoformat(), "status": "parsed",
        }],
        "extracted_content": json.dumps(values, sort_keys=True),
        "fields": values,
        "parser_status": "PARSED",
        "confidence": 1.0,
    }


def evidence(evidence_id: str, captured_at: datetime, *segments: dict) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        relative_path=f"evidence/{evidence_id}.log",
        origin="test_fixture",
        captured_at=captured_at,
        record_timestamp=None,
        format="log",
        locator="file",
        extracted_content="\n".join(item["extracted_content"] for item in segments),
        structured_fields={"records": list(segments)},
    )


def observation(
    system_id: str,
    resource_id: str,
    state: ObservedState,
    evidence_ids: tuple[str, ...],
    timestamp: datetime | None,
    category: str = "USER_PROFILE",
    relationships: tuple[ResourceRelationship, ...] = (),
) -> ResourceObservation:
    return ResourceObservation(
        system_id=system_id,
        resource_id=resource_id,
        data_category=category,
        observed_state=state,
        observation_timestamp=timestamp,
        evidence_references=evidence_ids,
        relationships=relationships,
    )


class GhostDataMapTests(unittest.TestCase):
    def test_explicit_active_flow_creates_versioned_two_leg_path_with_trace_provenance(self) -> None:
        started = AUDIT_AT - timedelta(minutes=4)
        heartbeat = AUDIT_AT - timedelta(minutes=3)
        record = evidence(
            "flow_evidence",
            AUDIT_AT - timedelta(minutes=2),
            segment("line:1", started, {
                "service": "integration_service", "trace_id": "trace-17",
                "event": "flow_lookup", "subject_key": "person@example.test",
            }),
            segment("line:2", heartbeat, {
                "service": "integration_service", "trace_id": "trace-17",
                "resource_id": "data_flow_47", "enabled": "true",
                "scheduler_registered": "true", "last_run": "success",
                "source_system": "primary_db", "target_system": "analytics_service",
            }),
        )
        trace_link = ResourceRelationship(
            "TRACE_CORRELATED_EVIDENCE", "integration_service", "data_flow_47",
            json.dumps({
                "evidence_id": "flow_evidence", "trace_id": "trace-17",
                "identifier_locator": "line:1", "resource_locator": "line:2",
                "identifier_record_timestamp": started.isoformat(),
                "resource_record_timestamp": heartbeat.isoformat(),
            }),
        )
        flow = observation(
            "integration_service", "data_flow_47", ObservedState.ACTIVE,
            ("flow_evidence",), heartbeat, "DATA_FLOW", (trace_link,),
        )

        graph = build_ghost_data_map([flow], EvidenceIndex(records=(record,)), AUDIT_AT)

        self.assertEqual(graph["schema_version"], SCHEMA_VERSION)
        nodes = {node["node_id"]: node for node in graph["nodes"]}
        flow_id = "resource:integration_service:data_flow_47"
        self.assertEqual(nodes[flow_id]["visual_state"], "ACTIVE_FLOW")
        self.assertEqual(nodes[flow_id]["risk_classification"], "ACTIVE_DATA_FLOW")
        observed_edge = next(edge for edge in graph["edges"] if edge["edge_type"] == "OBSERVED_IN")
        self.assertEqual(observed_edge["trace_ids"], ["trace-17"])
        self.assertEqual(observed_edge["source_locators"], ["line:1", "line:2"])
        flow_edges = [edge for edge in graph["edges"] if edge["edge_type"] == "ACTIVE_DATA_FLOW"]
        self.assertEqual({edge["path_leg"] for edge in flow_edges}, {"SOURCE_TO_FLOW", "FLOW_TO_DESTINATION"})
        self.assertTrue(all(edge["active_state"] == "ACTIVE" for edge in flow_edges))
        self.assertTrue(all(edge["evidence_ids"] == ["flow_evidence"] for edge in flow_edges))
        self.assertTrue(all(edge["audit_at"] == AUDIT_AT.isoformat() for edge in graph["edges"]))
        self.assertEqual(json.loads(serialize_ghost_data_map(graph)), graph)

    def test_active_flow_without_explicit_endpoints_has_no_propagation_path(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        record = evidence(
            "flow_without_endpoints", AUDIT_AT - timedelta(seconds=30),
            segment("line:1", timestamp, {
                "resource_id": "data_flow_8", "enabled": "true",
                "scheduler_registered": "true", "last_run": "success",
            }),
        )
        flow = observation(
            "integration_service", "data_flow_8", ObservedState.ACTIVE,
            ("flow_without_endpoints",), timestamp, "DATA_FLOW",
        )

        graph = build_ghost_data_map([flow], EvidenceIndex(records=(record,)), AUDIT_AT)

        self.assertEqual(len(graph["nodes"]), 2)
        self.assertEqual([edge["edge_type"] for edge in graph["edges"]], ["OBSERVED_IN"])

    def test_explicitly_disabled_flow_has_inactive_edges(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        record = evidence(
            "disabled_flow", AUDIT_AT - timedelta(seconds=30),
            segment("line:1", timestamp, {
                "resource_id": "data_flow_9", "enabled": "false",
                "scheduler_registered": "false", "source_system": "primary_db",
                "target_system": "search_service",
            }),
        )
        flow = observation(
            "integration_service", "data_flow_9", ObservedState.DISABLED,
            ("disabled_flow",), timestamp, "DATA_FLOW",
        )

        graph = build_ghost_data_map([flow], EvidenceIndex(records=(record,)), AUDIT_AT)

        inactive_edges = [edge for edge in graph["edges"] if edge["edge_type"] == "INACTIVE_DATA_FLOW"]
        self.assertEqual(len(inactive_edges), 2)
        self.assertTrue(all(edge["active_state"] == "INACTIVE" for edge in inactive_edges))

    def test_activity_relationship_is_reported_not_asserted_as_active_or_certain_copy(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        event_time = timestamp - timedelta(minutes=1)
        record = evidence(
            "target_snapshot", AUDIT_AT - timedelta(seconds=30),
            segment("sql:table:analytics:row:1", timestamp, {
                "system_id": "analytics_service", "resource_id": "analytics_52",
                "email": "person@example.test",
            }),
        )
        target = observation(
            "analytics_service", "analytics_52", ObservedState.PRESENT,
            ("target_snapshot",), timestamp, "ANALYTICS_PROFILE",
        )
        event = ActivityEvent(
            "activity_copy", event_time, "COPY_RECORD", "primary_db",
            "analytics_service", "analytics_52", "SUCCESS", {"trace_id": "copy-2"},
        )

        graph = build_ghost_data_map([target], EvidenceIndex(records=(record,)), AUDIT_AT, [event])

        edge = next(edge for edge in graph["edges"] if edge["edge_type"] == "REPORTED_ACTIVITY_CLAIM")
        self.assertEqual(edge["relationship_type"], "COPY_RECORD")
        self.assertIsNone(edge["active_state"])
        self.assertEqual(edge["support_status"], "REPORTED_ACTIVITY")
        self.assertTrue(edge["target_resource_observed"])
        self.assertEqual(edge["evidence_ids"], ["activity_copy", "target_snapshot"])
        self.assertNotIn("SUCCESS", json.dumps(edge))

    def test_missing_evidence_does_not_create_resources_or_edges(self) -> None:
        missing = observation(
            "unknown_service", "unknown_1", ObservedState.PRESENT,
            ("not-in-index",), AUDIT_AT - timedelta(seconds=1),
        )

        graph = build_ghost_data_map([missing], EvidenceIndex(), AUDIT_AT)

        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["warnings"][0]["code"], "OBSERVATION_WITHOUT_CUTOFF_VALID_EVIDENCE")

    def test_cutoff_excludes_late_capture_late_record_and_late_activity(self) -> None:
        record = evidence(
            "late_capture", AUDIT_AT + timedelta(seconds=1),
            segment("line:1", AUDIT_AT - timedelta(seconds=1), {"resource_id": "profile_1"}),
        )
        late_record = evidence(
            "late_record", AUDIT_AT - timedelta(seconds=1),
            segment("line:2", AUDIT_AT + timedelta(seconds=1), {"resource_id": "profile_2"}),
        )
        observations = [
            observation("profile_service", "profile_1", ObservedState.PRESENT, ("late_capture",), AUDIT_AT - timedelta(seconds=1)),
            observation("profile_service", "profile_2", ObservedState.PRESENT, ("late_record",), AUDIT_AT - timedelta(seconds=1)),
        ]
        late_event = ActivityEvent(
            "activity_future", AUDIT_AT + timedelta(seconds=1), "SYNC_RECORD",
            "profile_service", "analytics_service", "profile_2", "SUCCESS",
        )

        graph = build_ghost_data_map(observations, EvidenceIndex(records=(record, late_record)), AUDIT_AT, [late_event])

        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])

    def test_cutoff_includes_capture_record_and_activity_exactly_at_boundary(self) -> None:
        record = evidence(
            "boundary_evidence", AUDIT_AT,
            segment("line:1", AUDIT_AT, {"resource_id": "profile_boundary"}),
        )
        target = observation(
            "profile_service", "profile_boundary", ObservedState.PRESENT,
            ("boundary_evidence",), AUDIT_AT,
        )
        event = ActivityEvent(
            "boundary_activity", AUDIT_AT, "SYNC_RECORD", "primary_db",
            "profile_service", "profile_boundary", "SUCCESS",
        )

        graph = build_ghost_data_map([target], EvidenceIndex(records=(record,)), AUDIT_AT, [event])

        resource = next(node for node in graph["nodes"] if node["node_type"] == "RESOURCE")
        self.assertEqual(resource["evidence_ids"], ["boundary_evidence"])
        provenance = resource["provenance"][0]
        self.assertEqual(provenance["captured_at"], AUDIT_AT.isoformat())
        self.assertEqual(provenance["record_timestamps"], [AUDIT_AT.isoformat()])
        claim = next(edge for edge in graph["edges"] if edge["edge_type"] == "REPORTED_ACTIVITY_CLAIM")
        self.assertEqual(claim["timestamp"], AUDIT_AT.isoformat())
        self.assertEqual(claim["audit_at"], AUDIT_AT.isoformat())


    def test_disconnected_resources_stay_disconnected_and_states_remain_distinct(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        records = (
            evidence("present_file", AUDIT_AT - timedelta(seconds=30), segment("line:1", timestamp, {"resource_id": "profile_present"})),
            evidence("absent_file", AUDIT_AT - timedelta(seconds=30), segment("line:1", timestamp, {"resource_id": "profile_absent"})),
            evidence("anon_file", AUDIT_AT - timedelta(seconds=30), segment("line:1", timestamp, {"resource_id": "analytics_anon"})),
            evidence("backup_file", AUDIT_AT - timedelta(seconds=30), segment("line:1", timestamp, {
                "resource_id": "backup_7", "eligible": "true", "deletion_block": "false",
            })),
        )
        observations = [
            observation("profile_service", "profile_present", ObservedState.PRESENT, ("present_file",), timestamp),
            observation("profile_service", "profile_absent", ObservedState.ABSENT, ("absent_file",), timestamp),
            observation("analytics_service", "analytics_anon", ObservedState.ANONYMIZED, ("anon_file",), timestamp),
            observation("backup_service", "backup_7", ObservedState.PRESENT, ("backup_file",), timestamp, "BACKUP_ARCHIVE"),
        ]

        graph = build_ghost_data_map(observations, EvidenceIndex(records=records), AUDIT_AT)

        resources = {node["resource_id"]: node for node in graph["nodes"] if node["node_type"] == "RESOURCE"}
        self.assertEqual(resources["profile_present"]["visual_state"], "REMAINING_RECORD")
        self.assertEqual(resources["profile_absent"]["visual_state"], "VERIFIED_ABSENT")
        self.assertEqual(resources["analytics_anon"]["visual_state"], "ANONYMIZED_RECORD")
        self.assertEqual(resources["backup_7"]["risk_classification"], "RESTORE_RISK")
        self.assertFalse(any(edge["edge_type"] != "OBSERVED_IN" for edge in graph["edges"]))

    def test_explicit_backup_restore_dependency_links_only_named_resources(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        record = evidence(
            "restore_dependency_file", AUDIT_AT - timedelta(seconds=30),
            segment("line:1", timestamp, {
                "backup_resource_id": "backup_7",
                "restore_target_resource_id": "profile_7",
                "source_system": "backup_service",
                "target_system": "account_service",
                "eligible": "true",
                "deletion_block": "false",
            }),
        )
        observations = [
            observation("backup_service", "backup_7", ObservedState.PRESENT, ("restore_dependency_file",), timestamp, "BACKUP_ARCHIVE"),
            observation("account_service", "profile_7", ObservedState.PRESENT, ("restore_dependency_file",), timestamp, "USER_PROFILE"),
        ]

        graph = build_ghost_data_map(observations, EvidenceIndex(records=(record,)), AUDIT_AT)

        dependencies = [edge for edge in graph["edges"] if edge["edge_type"] == "BACKUP_RESTORE_DEPENDENCY"]
        self.assertEqual(len(dependencies), 1)
        edge = dependencies[0]
        self.assertEqual(edge["source_node_id"], "resource:backup_service:backup_7")
        self.assertEqual(edge["destination_node_id"], "resource:account_service:profile_7")
        self.assertEqual(edge["risk_classification"], "RESTORE_RISK")
        self.assertEqual(edge["evidence_ids"], ["restore_dependency_file"])
        self.assertEqual(edge["related_resource_id"], "backup_7")
        self.assertIsNone(edge["active_state"])

    def test_backup_dependency_is_omitted_when_target_resource_is_not_evidenced(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        record = evidence(
            "backup_missing_target", AUDIT_AT - timedelta(seconds=30),
            segment("line:1", timestamp, {
                "backup_resource_id": "backup_8",
                "restore_target_resource_id": "profile_missing",
                "source_system": "backup_service",
                "target_system": "account_service",
                "eligible": "true",
                "deletion_block": "false",
            }),
        )
        backup = observation(
            "backup_service", "backup_8", ObservedState.PRESENT,
            ("backup_missing_target",), timestamp, "BACKUP_ARCHIVE",
        )

        graph = build_ghost_data_map([backup], EvidenceIndex(records=(record,)), AUDIT_AT)

        self.assertTrue(any(node.get("resource_id") == "backup_8" for node in graph["nodes"]))
        self.assertFalse(any(edge["edge_type"] == "BACKUP_RESTORE_DEPENDENCY" for edge in graph["edges"]))

    def test_pipeline_payload_adapter_matches_build_and_serialize(self) -> None:
        timestamp = AUDIT_AT - timedelta(minutes=1)
        record = evidence(
            "adapter_evidence", AUDIT_AT - timedelta(seconds=30),
            segment("line:1", timestamp, {"resource_id": "resource_1"}),
        )
        observations = [observation(
            "system_1", "resource_1", ObservedState.PRESENT,
            ("adapter_evidence",), timestamp,
        )]
        index = EvidenceIndex(records=(record,))

        payload = build_ghost_data_map_payload(observations, index, AUDIT_AT)

        self.assertEqual(
            payload,
            serialize_ghost_data_map(build_ghost_data_map(observations, index, AUDIT_AT)),
        )


if __name__ == "__main__":
    unittest.main()
