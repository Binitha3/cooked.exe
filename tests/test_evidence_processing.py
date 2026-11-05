"""Independent standard-library tests for evidence ingestion and discovery."""

from __future__ import annotations

import csv
import json
import importlib.util
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from code.contracts import (
    ActivityEvent,
    EvidenceParserStatus,
    IdentityIdentifier,
    ObservedState,
    ResolutionStatus,
    ResolvedSubject,
)
from code.evidence_processing import (
    ACTIVITY_COLUMNS,
    MANIFEST_COLUMNS,
    load_activity,
    load_evidence,
    search_identifier,
    search_record_time,
    search_resource_id,
    search_subject,
    search_system_id,
    search_text,
    search_time,
    _extract_image,
    _pdf_explicit_fields,
)


UTC = timezone.utc


def dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class EvidenceProcessingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.dataset = Path(self.temp.name)
        (self.dataset / "evidence").mkdir()
        self.manifest = self.dataset / "evidence_files.csv"

    def write_manifest(self, files: list[tuple[str, str, str, str, bytes]]) -> None:
        with self.manifest.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(MANIFEST_COLUMNS)
            for file_id, relative_path, origin, captured_at, content in files:
                path = self.dataset / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                writer.writerow((file_id, relative_path, origin, captured_at))

    def test_all_discovered_json_layouts_are_recursively_extracted(self) -> None:
        layouts = [
            {
                "exported_at": "2026-09-01T00:00:00Z", "source": "bundle",
                "snapshots": [{"system": "account_service", "records": [
                    {"resource_id": "account_1", "email": "a@example.test", "updated_at": "2026-08-31T23:00:00Z"},
                ]}],
            },
            {
                "exported_at": "2026-09-01T00:00:00Z", "source": "resource",
                "region": "eu-west", "service_exports": {"search_service": [
                    {"resource_id": "search_1", "email": "b@example.test"},
                ]},
            },
            {"exported_at": "2026-09-01T00:00:00Z", "origin": "ledger", "record_count": 1,
             "records": [{"resource_id": "audit_record_1", "subject_reference": "user_1"}]},
            {"captured_at": "2026-09-01T00:00:00Z", "source": "collection", "collection": "profiles",
             "records": [{"resource_id": "account_2", "user_id": "user_2"}]},
        ]
        files = [
            (f"file_{i}", f"evidence/{i}.json", "test", "2026-09-01T00:00:01Z",
             json.dumps(layout).encode())
            for i, layout in enumerate(layouts)
        ]
        self.write_manifest(files)
        index = load_evidence(self.manifest, self.dataset)
        self.assertEqual(len(index.records), 4)
        self.assertTrue(all(record.parser_status is EvidenceParserStatus.PARSED for record in index.records))
        self.assertEqual(len(search_identifier(index, "a@example.test")), 1)
        self.assertEqual(len(search_resource_id(index, "search_1")), 1)
        self.assertEqual(len(search_identifier(index, "user_2")), 1)
        for record in index.records:
            self.assertTrue(record.structured_fields["records"])
            self.assertTrue(record.structured_fields["raw_sha256"])

    def test_log_parsers_cover_key_value_json_pipe_syslog_and_missing_time(self) -> None:
        text = "\n".join([
            '2026-09-01T01:00:00Z level=INFO service=account_service event=lookup resource_id=account_1 lookup_key="a@example.test"',
            '2026-09-01T01:00:01Z {"severity":"DEBUG","service":"search_service","event":"index_query","resource_id":"search_1"}',
            '2026-09-01T01:00:02Z | DEBUG | log_router | tr-1 | export_started | resource_id=export_1',
            '2026-09-01T01:00:03Z <15>1 node-1 account_service tr-2 - - level=INFO event=delete resource_id=account_2',
            'line with no timestamp and no structured fields',
        ])
        self.write_manifest([("log1", "evidence/mixed.log", "test", "2026-09-01T01:01:00Z", text.encode())])
        index = load_evidence(self.manifest, self.dataset)
        record = index.records[0]
        segments = record.structured_fields["records"]
        self.assertEqual(len(segments), 5)
        self.assertEqual(segments[0]["fields"]["service"], "account_service")
        self.assertEqual(segments[1]["fields"]["event"], "index_query")
        self.assertEqual(segments[2]["fields"]["service"], "log_router")
        self.assertEqual(segments[3]["fields"]["syslog_app"], "account_service")
        self.assertEqual(segments[4]["record_timestamp"], None)
        self.assertEqual(segments[4]["fields"]["raw_line"], "line with no timestamp and no structured fields")
        self.assertEqual(record.parser_status, EvidenceParserStatus.PARTIAL)

    def test_system_names_are_not_fallback_resource_ids(self) -> None:
        text = "\n".join([
            '2026-09-01T01:00:00Z level=INFO service=account_service event=health_check',
            '2026-09-01T01:00:01Z level=INFO service=account_service event=profile_lookup_completed id=account_12 lookup_key="alice@example.test" rows=0 http_status=404',
        ])
        self.write_manifest([("system-resource", "evidence/lookup.log", "test", "2026-09-01T01:01:00Z", text.encode())])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_12",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T01:02:00Z"), index, [])

        self.assertEqual({item.resource_id for item in observations}, {"account_12"})
        self.assertNotIn("account_service", {item.resource_id for item in observations})

    def test_text_extractor_preserves_line_locators_and_missing_timestamp(self) -> None:
        text = "SHIFT HANDOVER\nSnapshot: 2026-09-01T02:00:00Z\n- 2026-09-01T02:01:00Z | account_service | account_8 | DELETE submitted\nNo timestamp here"
        self.write_manifest([("txt1", "evidence/handover.txt", "handover", "2026-09-01T02:02:00Z", text.encode())])
        record = load_evidence(self.manifest, self.dataset).records[0]
        segments = record.structured_fields["records"]
        self.assertTrue(any(segment["locator"] == "line:3" for segment in segments))
        structured = next(segment for segment in segments if segment["locator"] == "line:3")
        self.assertEqual(structured["fields"]["system_id"], "account_service")
        missing = next(segment for segment in segments if "No timestamp" in segment["extracted_content"])
        self.assertIsNone(missing["record_timestamp"])

    def test_sql_snapshot_extraction_and_read_only_query(self) -> None:
        sql = """-- Captured at: 2026-09-01T02:00:00Z
        PRAGMA foreign_keys=ON;
        BEGIN TRANSACTION;
        CREATE TABLE customer_data_primary (resource_id TEXT, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
        CREATE TABLE customer_data_replica (resource_id TEXT, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
        INSERT INTO customer_data_primary VALUES ('account_1','account_service','USER_PROFILE','{\"email\":\"a@example.test\"}','2026-09-01T01:00:00Z');
        INSERT INTO customer_data_replica VALUES ('account_1','account_service','USER_PROFILE','{\"email\":\"a@example.test\"}','2026-09-01T01:00:00Z');
        COMMIT;
        """
        self.write_manifest([("sql1", "evidence/replica.sql", "database", "2026-09-01T02:05:00Z", sql.encode())])
        index = load_evidence(self.manifest, self.dataset)
        record = index.records[0]
        self.assertEqual(record.parser_status, EvidenceParserStatus.PARSED)
        self.assertEqual(len(record.structured_fields["records"]), 2)
        self.assertEqual(record.structured_fields["records"][0]["locator"], "sql:table:customer_data_primary:row:1")
        self.assertEqual(len(search_identifier(index, "a@example.test")), 1)
        self.assertEqual(record.structured_fields["records"][0]["record_timestamp"], dt("2026-09-01T01:00:00Z"))
        # SQL snapshots are executed only in isolated memory, not against a file.
        self.assertFalse((self.dataset / "evidence" / "replica.db").exists())

    def test_forbidden_sql_and_malformed_json_are_isolated_and_preserved(self) -> None:
        files = [
            ("badjson", "evidence/bad.json", "test", "2026-09-01T00:00:00Z", b'{"broken":'),
            ("badsql", "evidence/bad.sql", "test", "2026-09-01T00:00:00Z", b"DROP TABLE nope;"),
            ("good", "evidence/good.txt", "test", "2026-09-01T00:00:00Z", b"kept record"),
        ]
        self.write_manifest(files)
        index = load_evidence(self.manifest, self.dataset)
        self.assertEqual(len(index.records), 3)
        bad_json = index.records_by_id["badjson"]
        self.assertEqual(bad_json.parser_status, EvidenceParserStatus.FAILED)
        self.assertIn("broken", bad_json.structured_fields["raw_source"])
        bad_sql = index.records_by_id["badsql"]
        self.assertEqual(bad_sql.parser_status, EvidenceParserStatus.FAILED)
        self.assertTrue(bad_sql.structured_fields["parser_errors"])
        self.assertEqual(index.records_by_id["good"].extracted_content, "kept record")

    def test_activity_csv_schema_and_reported_result_remain_claim_only(self) -> None:
        activity = self.dataset / "system_activity.csv"
        with activity.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(ACTIVITY_COLUMNS)
            writer.writerow(("activity_1", "2026-09-01T01:00:00Z", "DELETE_RECORD", "deletion_worker", "account_service", "account_1", "SUCCESS", "requester=a@example.test"))
        events = load_activity(activity)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].reported_result, "SUCCESS")
        self.assertEqual(events[0].details["requester"], "a@example.test")

    def test_provenance_and_capture_timestamp_are_separate(self) -> None:
        body = json.dumps({"records": [{
            "resource_id": "account_12", "system_id": "account_service",
            "email": "person@example.test", "updated_at": "2026-08-31T23:59:00Z",
        }]})
        self.write_manifest([("evidence_x", "evidence/snapshot.json", "snapshot_export", "2026-09-01T00:01:00Z", body.encode())])
        record = load_evidence(self.manifest, self.dataset).records[0]
        segment = record.structured_fields["records"][0]
        self.assertEqual(record.evidence_id, "evidence_x")
        self.assertEqual(record.relative_path, "evidence/snapshot.json")
        self.assertEqual(record.origin, "snapshot_export")
        self.assertEqual(record.captured_at, dt("2026-09-01T00:01:00Z"))
        self.assertEqual(record.record_timestamp, dt("2026-08-31T23:59:00Z"))
        self.assertEqual(segment["locator"], "json:$.records[0]")
        self.assertEqual(segment["timestamp_candidates"][0]["raw"], "2026-08-31T23:59:00Z")

    def test_conflicting_internal_timestamps_are_retained_and_not_collapsed(self) -> None:
        body = json.dumps({"records": [{
            "resource_id": "account_14", "system_id": "account_service",
            "email": "person@example.test", "created_at": "2026-08-30T00:00:00Z",
            "updated_at": "2026-08-31T00:00:00Z",
        }]})
        self.write_manifest([("conflict", "evidence/conflict.json", "snapshot", "2026-09-01T00:00:00Z", body.encode())])
        record = load_evidence(self.manifest, self.dataset).records[0]
        segment = record.structured_fields["records"][0]
        self.assertIsNone(record.record_timestamp)
        self.assertIsNone(segment["record_timestamp"])
        self.assertEqual({item["raw"] for item in segment["timestamp_candidates"]}, {
            "2026-08-30T00:00:00Z", "2026-08-31T00:00:00Z",
        })

    def test_exact_indexes_subject_discovery_and_both_time_cutoffs(self) -> None:
        entries = [
            ("before", "evidence/before.json", "snapshot", "2026-09-01T00:00:00Z", json.dumps({"records": [{"resource_id": "account_10", "system_id": "account_service", "email": "alice@example.test", "updated_at": "2026-09-01T00:05:00Z"}]}).encode()),
            ("future_record", "evidence/future.json", "snapshot", "2026-09-01T00:00:00Z", json.dumps({"records": [{"resource_id": "account_11", "system_id": "account_service", "email": "alice@example.test", "updated_at": "2026-09-01T01:30:00Z"}]}).encode()),
            ("future_capture", "evidence/later.json", "snapshot", "2026-09-01T02:00:00Z", json.dumps({"records": [{"resource_id": "account_12", "system_id": "account_service", "email": "alice@example.test", "updated_at": "2026-09-01T00:00:00Z"}]}).encode()),
            ("unrelated", "evidence/other.json", "snapshot", "2026-09-01T00:00:00Z", json.dumps({"records": [{"resource_id": "account_13", "system_id": "account_service", "email": "alice@example.test.attacker"}]}).encode()),
        ]
        self.write_manifest(entries)
        index = load_evidence(self.manifest, self.dataset)
        self.assertEqual([item.evidence_id for item in search_identifier(index, "ALICE@example.test")], ["before", "future_capture", "future_record"])
        self.assertEqual(len(search_resource_id(index, "account_10")), 1)
        self.assertEqual(len(search_system_id(index, "account_service")), 4)
        self.assertTrue(search_text(index, "alice@example.test"))
        self.assertEqual(len(search_time(index, end=dt("2026-09-01T00:00:00Z"))), 3)
        self.assertEqual([r.evidence_id for r in search_record_time(index, end=dt("2026-09-01T01:00:00Z"))], ["before", "future_capture"])

        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_10",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )
        audit_at = dt("2026-09-01T01:00:00Z")
        events = [ActivityEvent(
            "activity_1", dt("2026-09-01T00:30:00Z"), "SYNC_RECORD",
            "account_service", "analytics_platform", "account_10", "SUCCESS",
            {"email": "alice@example.test"},
        )]
        observations = search_subject(subject, audit_at, index, events)
        self.assertEqual({item.resource_id for item in observations}, {"account_10"})
        self.assertEqual(observations[0].evidence_references, ("before",))
        self.assertEqual(observations[0].observed_state, ObservedState.PRESENT)
        self.assertEqual(observations[0].relationships[0].relationship, "SYNC_RECORD")
        self.assertNotIn("SUCCESS", observations[0].relationships[0].details)

        ambiguous = ResolvedSubject(ResolutionStatus.AMBIGUOUS, None, current_identifiers=(IdentityIdentifier("email", "alice@example.test"),))
        self.assertEqual(search_subject(ambiguous, audit_at, index, events), [])

    def test_activity_only_observation_stays_unknown_even_on_delete_success(self) -> None:
        self.write_manifest([])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_1", (IdentityIdentifier("email", "a@example.test"),))
        event = ActivityEvent(
            "activity_delete", dt("2026-09-01T00:00:00Z"), "DELETE_RECORD",
            "deletion_worker", "account_service", "account_1", "SUCCESS",
            {"message": "processed a@example.test"},
        )
        observations = search_subject(subject, dt("2026-09-01T01:00:00Z"), index, [event])
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].observed_state, ObservedState.UNKNOWN)
        self.assertEqual(observations[0].evidence_references, ("activity_delete",))

    def test_same_file_trace_joins_subject_to_active_data_flow_with_provenance(self) -> None:
        log = "\n".join([
            '2026-09-01T12:00:00Z level=INFO service=integration_service trace_id=trace-alpha event=connector_config_read_started subject_key="alice@example.test"',
            "2026-09-01T12:01:00Z level=WARN service=integration_service trace_id=trace-alpha resource_id=data_flow_47 event=connector_heartbeat enabled=true scheduler_registered=true last_run=success",
            "2026-09-01T12:03:00Z level=WARN service=integration_service trace_id=trace-alpha resource_id=data_flow_future event=connector_heartbeat enabled=true scheduler_registered=true last_run=success",
        ])
        self.write_manifest([(
            "trace-evidence", "evidence/connector.log", "log_export",
            "2026-09-01T12:01:30Z", log.encode(),
        )])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE, "user_47",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T12:02:00Z"), index, [])

        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(observation.system_id, "integration_service")
        self.assertEqual(observation.resource_id, "data_flow_47")
        self.assertEqual(observation.data_category, "DATA_FLOW")
        self.assertEqual(observation.observed_state, ObservedState.ACTIVE)
        self.assertEqual(observation.evidence_references, ("trace-evidence",))
        self.assertEqual(observation.observation_timestamp, dt("2026-09-01T12:01:00Z"))
        self.assertEqual(tuple((item.identifier_type, item.value) for item in observation.identifiers), (("email", "alice@example.test"),))
        link = next(item for item in observation.relationships if item.relationship == "TRACE_CORRELATED_EVIDENCE")
        details = json.loads(link.details)
        self.assertEqual(details["trace_id"], "trace-alpha")
        self.assertEqual(details["identifier_locator"], "line:1")
        self.assertEqual(details["resource_locator"], "line:2")
        self.assertEqual(details["supported_state"], "ACTIVE")
        self.assertEqual(details["supported_fields"], {
            "enabled": "true", "scheduler_registered": "true", "last_run": "success",
        })

    def test_unrelated_trace_ids_are_not_joined(self) -> None:
        log = "\n".join([
            '2026-09-01T12:00:00Z level=INFO service=integration_service trace_id=trace-subject event=connector_config_read_started subject_key="alice@example.test"',
            "2026-09-01T12:01:00Z level=WARN service=integration_service trace_id=trace-other resource_id=data_flow_47 event=connector_heartbeat enabled=true scheduler_registered=true last_run=success",
        ])
        self.write_manifest([(
            "unrelated-traces", "evidence/unrelated.log", "log_export",
            "2026-09-01T12:02:00Z", log.encode(),
        )])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE, "user_47",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T12:02:00Z"), index, [])

        self.assertEqual(observations, [])

    def test_quoted_message_fields_and_same_request_id_link_resources(self) -> None:
        log = "\n".join([
            '2026-09-01T12:00:00Z requestId=req-42 level=DEBUG function=search_service '
            'message="instance=\\"search-1\\" event=\\"index_query_started\\" '
            'match_key=\\"alice@example.test\\" attempt=\\"1\\""',
            '2026-09-01T12:01:00Z requestId=req-42 level=INFO function=search_service '
            'message="instance=\\"search-1\\" resource_id=\\"search_42\\" '
            'event=\\"index_query_completed\\" result=\\"hit\\" shard=\\"3\\""',
            '2026-09-01T12:03:00Z requestId=req-42 level=INFO function=search_service '
            'message="instance=\\"search-1\\" resource_id=\\"search_future\\" '
            'event=\\"index_query_completed\\" result=\\"hit\\""',
        ])
        self.write_manifest([(
            "request-correlated", "evidence/request.log", "service_log",
            "2026-09-01T12:01:30Z", log.encode(),
        )])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE, "user_42",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T12:02:00Z"), index, [])

        self.assertEqual([(item.resource_id, item.observed_state) for item in observations], [
            ("search_42", ObservedState.UNKNOWN),
        ])
        relationship = next(
            item for item in observations[0].relationships
            if item.relationship == "REQUEST_ID_CORRELATED_EVIDENCE"
        )
        details = json.loads(relationship.details)
        self.assertEqual(details["correlation"], "same_file_request_id")
        self.assertEqual(details["request_id"], "req-42")
        self.assertEqual(details["evidence_id"], "request-correlated")
        self.assertEqual(details["identifier_locator"], "line:1")
        self.assertEqual(details["resource_locator"], "line:2")
        self.assertIsNone(details["supported_state"])
        self.assertEqual(index.records_by_id["request-correlated"].parser_status, EvidenceParserStatus.PARSED)

    def test_request_id_does_not_join_an_unrelated_resource_line(self) -> None:
        log = "\n".join([
            '2026-09-01T12:00:00Z requestId=req-subject level=DEBUG function=search_service '
            'message="match_key=\\"alice@example.test\\""',
            '2026-09-01T12:01:00Z requestId=req-other level=INFO function=search_service '
            'message="resource_id=\\"search_42\\" event=\\"index_query_completed\\" result=\\"hit\\""',
        ])
        self.write_manifest([(
            "unrelated-request", "evidence/unrelated-request.log", "service_log",
            "2026-09-01T12:02:00Z", log.encode(),
        )])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE, "user_42",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T12:02:00Z"), index, [])

        self.assertEqual(observations, [])

    def test_syslog_trace_token_in_procid_correlates_same_file_resource(self) -> None:
        log = "\n".join([
            '2026-09-01T12:00:00Z <15>1 node-1 search_service tr-42 - - '
            'level=DEBUG event=index_query_started match_key="alice@example.test"',
            '2026-09-01T12:01:00Z <14>1 node-1 search_service tr-42 - - '
            'level=INFO resource_id=search_42 event=index_query_completed result=hit',
        ])
        self.write_manifest([(
            "syslog-procid", "evidence/syslog.log", "syslog_archive",
            "2026-09-01T12:01:30Z", log.encode(),
        )])
        index = load_evidence(self.manifest, self.dataset)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE, "user_42",
            current_identifiers=(IdentityIdentifier("email", "alice@example.test"),),
        )

        observations = search_subject(subject, dt("2026-09-01T12:02:00Z"), index, [])

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].resource_id, "search_42")
        relationship = next(
            item for item in observations[0].relationships
            if item.relationship == "TRACE_CORRELATED_EVIDENCE"
        )
        details = json.loads(relationship.details)
        self.assertEqual(details["trace_id"], "tr-42")
        self.assertEqual(details["identifier_locator"], "line:1")
        self.assertEqual(details["resource_locator"], "line:2")

    def test_optional_image_and_pdf_extractors_fail_gracefully(self) -> None:
        files = [
            ("image", "evidence/image.png", "capture", "2026-09-01T00:00:00Z", b"not-a-png"),
            ("pdf", "evidence/document.pdf", "document", "2026-09-01T00:00:00Z", b"%PDF-1.4 invalid"),
        ]
        self.write_manifest(files)
        index = load_evidence(self.manifest, self.dataset)
        self.assertEqual(len(index.records), 2)
        for record in index.records:
            self.assertIn(record.parser_status, {
                EvidenceParserStatus.PARTIAL, EvidenceParserStatus.FAILED,
                EvidenceParserStatus.UNSUPPORTED,
            })
            self.assertIn("parser_errors", record.structured_fields)

    def test_pdf_labeled_resource_subject_and_timezone_explicit_dates(self) -> None:
        fields = _pdf_explicit_fields(
            "COMPLIANCE JOURNAL - SIGNED RECORD EXTRACT\n"
            "Event reference audit_record_003\n"
            "Subject reference user_03\n"
            "Recorded 25 Aug 2026 04\n03 UTC\n"
            "Retain until 25 Aug 2027 04\n03 UTC\n"
            "Storage class compliance-ledger\nIntegrity seal valid"
        )
        self.assertEqual(fields["resource_id"], "audit_record_003")
        self.assertEqual(fields["subject_reference"], "user_03")
        self.assertEqual(fields["recorded_at"], "2026-08-25T04:03:00+00:00")
        self.assertEqual(fields["retention_until"], "2027-08-25T04:03:00+00:00")
        self.assertEqual(fields["storage_class"], "compliance-ledger")
        self.assertEqual(fields["integrity_status"], "valid")

    def test_ambiguous_pdf_resource_or_timezone_does_not_become_policy_fact(self) -> None:
        fields = _pdf_explicit_fields(
            "Event reference audit_record_003\n"
            "Related record audit_record_004\n"
            "Subject reference user_03\n"
            "Retain until 25 Aug 2027"
        )
        self.assertNotIn("resource_id", fields)
        self.assertNotIn("retention_until", fields)
        self.assertEqual(fields["retention_until_text"], "25 Aug 2027")

    def test_image_ocr_preserves_confidence_and_pixel_locator(self) -> None:
        from PIL import Image
        from io import BytesIO

        image_stream = BytesIO()
        Image.new("RGB", (200, 100), "white").save(image_stream, format="PNG")
        fake_ocr = types.ModuleType("pytesseract")
        fake_ocr.Output = types.SimpleNamespace(DICT="dict")
        fake_ocr.image_to_data = lambda _image, output_type: {
            "text": ["subject", "user_03"], "conf": ["98", "88"],
            "block_num": [1, 1], "par_num": [1, 1], "line_num": [1, 1], "page_num": [1, 1],
            "left": [10, 80], "top": [20, 20], "width": [60, 50], "height": [15, 15],
        }
        errors: list[dict[str, str]] = []
        with patch.dict(sys.modules, {"pytesseract": fake_ocr}):
            segments = _extract_image(image_stream.getvalue(), errors)

        self.assertEqual(errors, [])
        self.assertEqual(len(segments), 1)
        segment = segments[0]
        self.assertEqual(segment["locator"], "image:bbox:10,20,130,35")
        self.assertEqual(segment["fields"]["bbox"], [10, 20, 130, 35])
        self.assertEqual(segment["fields"]["image_size"], [200, 100])
        self.assertAlmostEqual(segment["confidence"], 0.93)

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "pypdf is not available in this Python environment")
    def test_signed_retention_pdf_is_extractable_with_page_locator(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        index = load_evidence(repo_root / "dataset/evidence_files.csv", repo_root / "dataset")
        record = index.records_by_id["evidence_55"]
        self.assertEqual(record.parser_status, EvidenceParserStatus.PARSED)
        segment = record.structured_fields["records"][0]
        self.assertEqual(segment["locator"], "pdf:page:1")
        self.assertEqual(segment["fields"]["resource_id"], "audit_record_003")
        self.assertEqual(segment["fields"]["subject_reference"], "user_03")
        self.assertEqual(segment["fields"]["retention_until"], "2027-08-25T04:03:00+00:00")
        self.assertEqual(record.captured_at, dt("2026-09-05T06:30:00Z"))


if __name__ == "__main__":
    unittest.main()
