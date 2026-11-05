"""Dataset-backed integration through the existing evidence pipeline contracts."""

from __future__ import annotations

import json
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from code.contracts import (
    IdentityIdentifier,
    ResolutionStatus,
    ResolvedSubject,
)
from code.evidence_processing import load_activity, load_evidence, search_subject
from code.ghost_data_map import build_ghost_data_map_payload


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo and parsed.utcoffset() is not None else None
    return None


def _fixture_subject_flow(index):
    """Find a real subject-key/data-flow pair sharing a trace in one file."""
    for record in index.records:
        segments = record.structured_fields.get("records", ())
        if not isinstance(segments, list):
            continue
        for flow in segments:
            if not isinstance(flow, Mapping):
                continue
            fields = flow.get("fields", {})
            if not isinstance(fields, Mapping):
                continue
            resource_id = fields.get("resource_id")
            if not isinstance(resource_id, str) or not resource_id.startswith("data_flow_"):
                continue
            if str(fields.get("enabled", "")).casefold() not in {"true", "1", "yes"}:
                continue
            if str(fields.get("scheduler_registered", "")).casefold() not in {"true", "1", "yes"}:
                continue
            trace_id = fields.get("trace_id")
            if not isinstance(trace_id, str) or not trace_id:
                continue
            for subject_segment in segments:
                if not isinstance(subject_segment, Mapping):
                    continue
                subject_fields = subject_segment.get("fields", {})
                if not isinstance(subject_fields, Mapping):
                    continue
                subject_value = subject_fields.get("subject_key")
                if (
                    subject_fields.get("trace_id") != trace_id
                    or not isinstance(subject_value, str)
                    or "@" not in subject_value
                ):
                    continue
                times = [record.captured_at]
                for item in (flow, subject_segment):
                    stamp = _parse_time(item.get("record_timestamp"))
                    if stamp:
                        times.append(stamp)
                    for candidate in item.get("timestamp_candidates", ()):
                        if isinstance(candidate, Mapping):
                            stamp = _parse_time(candidate.get("parsed"))
                            if stamp:
                                times.append(stamp)
                return record.evidence_id, resource_id, trace_id, subject_value, max(times)
    return None


class GhostDataMapPipelineIntegrationTests(unittest.TestCase):
    def test_real_dataset_subject_search_serializes_provenance_safe_payload(self):
        repo_root = Path(__file__).resolve().parents[1]
        dataset_root = repo_root / "dataset"
        manifest_path = dataset_root / "evidence_files.csv"
        activity_path = dataset_root / "system_activity.csv"
        if not manifest_path.is_file() or not activity_path.is_file():
            self.skipTest("participant dataset fixtures are unavailable")

        evidence_index = load_evidence(manifest_path, dataset_root)
        activity = load_activity(activity_path)
        fixture = _fixture_subject_flow(evidence_index)
        self.assertIsNotNone(fixture, "dataset should contain a same-file subject/flow trace")
        evidence_id, resource_id, trace_id, subject_value, audit_at = fixture
        subject = ResolvedSubject(
            resolution_status=ResolutionStatus.UNIQUE,
            user_id="integration-fixture-subject",
            current_identifiers=(IdentityIdentifier("email", subject_value),),
        )

        observations = search_subject(subject, audit_at, evidence_index, activity)
        payload = build_ghost_data_map_payload(observations, evidence_index, audit_at, activity)
        graph = json.loads(payload)

        flow_nodes = [
            node for node in graph["nodes"]
            if node["node_type"] == "RESOURCE" and node["resource_id"] == resource_id
        ]
        self.assertTrue(flow_nodes)
        flow_node = flow_nodes[0]
        self.assertEqual(flow_node["observed_state"], "ACTIVE")
        self.assertIn(evidence_id, flow_node["evidence_ids"])
        provenance = [item for item in flow_node["provenance"] if item["evidence_id"] == evidence_id]
        self.assertTrue(provenance)
        self.assertIn(trace_id, provenance[0]["trace_ids"])
        self.assertGreaterEqual(len(provenance[0]["source_locators"]), 2)
        self.assertLessEqual(datetime.fromisoformat(graph["audit_at"]), audit_at)

        for edge in graph["edges"]:
            self.assertIn("audit_at", edge)
            self.assertIn("captured_at", edge)
            self.assertIn("record_timestamps", edge)
            self.assertLessEqual(datetime.fromisoformat(edge["audit_at"]), audit_at)
        self.assertEqual(graph["schema_version"], "ghost-data-map.v1")


if __name__ == "__main__":
    unittest.main()
