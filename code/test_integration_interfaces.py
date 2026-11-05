"""Contract/interface smoke tests for feature modules as they arrive."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import csv
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, get_type_hints
from dataclasses import replace

from code import contracts
from code.contracts import (
    AuditDecision,
    DeletionRequest,
    DeletionRule,
    DeletionStatus,
    EvidenceIndex,
    EvidenceRecord,
    IdentityIdentifier,
    Intent,
    IntentDecision,
    ObservedState,
    OutputRow,
    ReportedStatus,
    ResolutionStatus,
    ResolvedSubject,
    ResourceObservation,
    ResourceRelationship,
)
from code.output import EXPECTED_REQUEST_COUNT
from code.main import (
    PipelineBlockedError,
    _not_applicable_row,
    _require_unique_subject,
    _identity_audit_rows_for_resolver,
    _identity_rows_for_resolver,
    _adapt_evidence_to_policy,
    _adapt_trace_linked_active_flows,
    _diagnostic_stage,
    build_rows,
    collect_independent_rows,
    load_feature_modules,
    read_activity,
    read_deletion_rules,
    read_identity_audit,
    read_identities,
    read_requests,
    read_requests_file,
)
from code.request_intent import classify_request_intent


class FeatureInterfaceTests(unittest.TestCase):
    def test_output_contract_for_not_applicable_and_dataset_size(self):
        row = OutputRow.from_decision(
            "unit-case",
            AuditDecision(DeletionStatus.NOT_APPLICABLE, ()),
        )
        self.assertEqual(row.steps_json, "[]")
        self.assertEqual(EXPECTED_REQUEST_COUNT, 518)
        self.assertEqual(_not_applicable_row("unit-case").steps_json, "[]")

    def _member_modules_or_skip(self):
        try:
            return load_feature_modules()
        except PipelineBlockedError as exc:
            self.skipTest(str(exc))

    def _verify_only_pipeline_fixture(self, observations, evidence_ids):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        email = "requester@example.test"
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", email),),
        )
        request = DeletionRequest(
            "unit-verification",
            email,
            datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc),
            ReportedStatus.NOT_STARTED,
            None,
            audit_at,
            "I submitted a deletion request earlier. Please verify it completed and confirm my profile is gone.",
        )
        evidence_records = tuple(
            EvidenceRecord(
                evidence_id=evidence_id,
                relative_path=f"evidence/{evidence_id}.json",
                origin="isolated regression fixture",
                captured_at=audit_at,
                record_timestamp=audit_at,
                format="json",
                locator="json:$.records[0]",
                extracted_content=f"resource_id={evidence_id}; user_id=user_fixture",
            )
            for evidence_id in evidence_ids
        )

        def classify_deletion_request(_request_text):
            # The general request adapter must recognize verification-only
            # wording while the member classifier remains fail-closed.
            return IntentDecision(Intent.AMBIGUOUS, "base classifier did not authorize deletion")

        def resolve_identity(*_args):
            return subject

        def load_evidence(*_args):
            return EvidenceIndex(records=evidence_records)

        def search_subject(*_args):
            return list(observations)

        modules = SimpleNamespace(
            identity_resolution=SimpleNamespace(
                classify_deletion_request=classify_deletion_request,
                resolve_identity=resolve_identity,
            ),
            evidence_processing=SimpleNamespace(
                load_evidence=load_evidence,
                search_subject=search_subject,
            ),
            policy_engine=importlib.import_module("code.policy_engine"),
        )
        rules = [DeletionRule("fixture_rule", "USER_PROFILE", "Always", "DELETE")]
        return request, audit_at, modules, rules

    def test_historical_email_match_from_sample_audit_history(self):
        if importlib.util.find_spec("code.identity_resolution") is None:
            self.skipTest("code.identity_resolution is not available yet")
        identity_module = importlib.import_module("code.identity_resolution")
        repository_root = Path(__file__).resolve().parents[1]
        dataset_root = repository_root / "dataset"
        sample_requests = read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        historical_request = next(row for row in sample_requests if row.case_id == "case_10")
        historical_matches = [
            event for event in audit_log
            if event.field_name == "email" and event.old_value == historical_request.email
        ]
        self.assertTrue(historical_matches, "sample case_10 must exercise an actual historical email")
        resolved = identity_module.resolve_identity(
            historical_request.email,
            historical_request.requested_at,
            historical_request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        self.assertEqual(resolved.resolution_status, contracts.ResolutionStatus.UNIQUE)
        self.assertEqual(resolved.user_id, historical_matches[0].user_id)

    def test_case_15_identity_is_unique_from_cutoff_eligible_evidence(self):
        identity_module = importlib.import_module("code.identity_resolution")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_15"
        )
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        snapshot = next(row for row in identities if row.user_id == "user_15")
        subject_audits = [row for row in audit_log if row.user_id == "user_15"]

        self.assertEqual(request.email, "lucia-torres@gmail.com")
        self.assertLessEqual(snapshot.updated_at, request.audit_at)
        self.assertTrue(all(row.event_time <= request.audit_at for row in subject_audits))
        resolved = identity_module.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        self.assertEqual(resolved.resolution_status, contracts.ResolutionStatus.UNIQUE)
        self.assertEqual(resolved.user_id, "user_15")

    def test_case_15_explicit_account_closure_matches_sample_authorization(self):
        identity_module = importlib.import_module("code.identity_resolution")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_15"
        )
        with (dataset_root / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
            reference = next(row for row in csv.DictReader(handle) if row["case_id"] == "case_15")

        self.assertEqual(reference["deletion_status"], "INCOMPLETE")
        decision = identity_module.classify_deletion_request(request.request_text)
        self.assertEqual(decision.intent, Intent.DELETE)

    def test_sample_verification_only_wording_has_separate_intent(self):
        identity_module = importlib.import_module("code.identity_resolution")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_26"
        )
        with (dataset_root / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
            reference = next(row for row in csv.DictReader(handle) if row["case_id"] == "case_26")

        self.assertIn("check the latest state", request.request_text.casefold())
        self.assertIn("confirm", request.request_text.casefold())
        self.assertNotRegex(request.request_text.casefold(), r"\b(delete|erase|remove|close|purge)\b")
        self.assertEqual(
            classify_request_intent(request.request_text, identity_module.classify_deletion_request).intent,
            Intent.VERIFY_ONLY,
        )
        # The sample itself supplies a prior report context and asks for an
        # evidence-backed state check; it does not authorize new remediation.
        self.assertEqual(reference["deletion_status"], "COMPLETE")

    def test_case26_verification_only_stays_blocked_without_subject_linked_proof(self):
        modules = self._member_modules_or_skip()
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_26"
        )
        with (dataset_root / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
            reference = next(row for row in csv.DictReader(handle) if row["case_id"] == "case_26")

        expected_steps = json.loads(reference["steps_json"])
        expected_resources = {step["resource_id"] for step in expected_steps}
        # The reference is structurally valid under the exact output contract.
        OutputRow(reference["case_id"], reference["deletion_status"], reference["steps_json"])
        self.assertEqual(reference["deletion_status"], "COMPLETE")
        self.assertEqual(len(expected_steps), 6)
        self.assertTrue(all(step["phase"] == "VERIFICATION" for step in expected_steps))
        cited_ids = {step["evidence_id"] for step in expected_steps}
        self.assertEqual(cited_ids, {"evidence_92"})
        with (dataset_root / "evidence_files.csv").open(newline="", encoding="utf-8-sig") as handle:
            manifest = next(row for row in csv.DictReader(handle) if row["file_id"] == "evidence_92")
        captured_at = datetime.fromisoformat(manifest["captured_at"].replace("Z", "+00:00"))
        self.assertLessEqual(captured_at, request.audit_at)

        subject = modules.identity_resolution.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(read_identities(dataset_root)),
            _identity_audit_rows_for_resolver(read_identity_audit(dataset_root)),
        )
        evidence_index = modules.evidence_processing.load_evidence(
            dataset_root / "evidence_files.csv", dataset_root
        )
        evidence_record = evidence_index.records_by_id["evidence_92"]
        self.assertEqual(evidence_record.captured_at, captured_at)
        segment_by_resource = {
            segment.get("fields", {}).get("resource_id"): segment
            for segment in evidence_record.structured_fields.get("records", ())
            if isinstance(segment, dict)
        }
        self.assertTrue(expected_resources <= set(segment_by_resource))
        source_fields = {
            resource_id: segment_by_resource[resource_id]["fields"]
            for resource_id in expected_resources
        }
        for resource_id, fields in source_fields.items():
            stamp = datetime.fromisoformat(fields["observed_at"].replace("Z", "+00:00"))
            self.assertLessEqual(stamp, request.audit_at, resource_id)
        # The cited export directly supports these resource states. It does
        # not, by itself, associate account_5684 or analytics_4566 with this
        # resolved subject; that distinction is checked below and prevents
        # reproducing those two sample steps as user-specific verification.
        self.assertEqual(source_fields["account_5684"]["status_code"], 404)
        self.assertIsNone(source_fields["account_5684"]["profile"])
        self.assertEqual(source_fields["audit_record_5416"]["subject_reference"], subject.user_id)
        self.assertEqual(source_fields["support_4715"]["customer_reference"], subject.user_id)
        self.assertTrue(all(source_fields["support_4715"][field] is None for field in (
            "requester_email", "requester_name", "requester_phone",
        )))
        self.assertTrue(all(source_fields["analytics_4566"][field] is None for field in (
            "customer_reference", "email", "email_hash", "phone",
        )))
        self.assertEqual(source_fields["data_flow_6244"]["customer_reference"], subject.user_id)
        self.assertIs(source_fields["data_flow_6244"]["enabled"], False)
        self.assertEqual(source_fields["data_flow_6244"]["last_delivery_status"], "stopped")
        self.assertEqual(source_fields["backup_3120"]["customer_reference"], subject.user_id)
        self.assertIs(source_fields["backup_3120"]["restore_allowed"], False)

        observations = modules.evidence_processing.search_subject(
            subject, request.audit_at, evidence_index, read_activity(dataset_root)
        )
        observed_resources = {observation.resource_id for observation in observations}
        self.assertTrue(observed_resources & expected_resources)
        self.assertNotIn("account_5684", observed_resources)
        self.assertNotIn("analytics_4566", observed_resources)

        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        with self.assertRaisesRegex(
            PipelineBlockedError,
            "lacks evidence-backed proof that the requested primary profile is absent",
        ):
            build_rows(
                [request],
                identities,
                audit_log,
                read_activity(dataset_root),
                read_deletion_rules(dataset_root),
                dataset_root,
                modules,
            )

    def test_case26_policy_mapping_preserves_direct_facts_and_provenance(self):
        identity_module = importlib.import_module("code.identity_resolution")
        evidence_module = importlib.import_module("code.evidence_processing")
        policy_module = importlib.import_module("code.policy_engine")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_26"
        )
        subject = identity_module.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(read_identities(dataset_root)),
            _identity_audit_rows_for_resolver(read_identity_audit(dataset_root)),
        )
        index = evidence_module.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        observations = evidence_module.search_subject(subject, request.audit_at, index, read_activity(dataset_root))
        adapted = _adapt_evidence_to_policy(observations, index, request.audit_at, subject)
        by_resource = {}
        for observation in adapted:
            by_resource.setdefault(observation.resource_id, []).append(observation)

        self.assertEqual(by_resource["audit_record_5416"][0].data_category, "SECURITY_AUDIT_LOG")
        audit_facts = [item for item in by_resource["audit_record_5416"][0].relationships if item.relationship.startswith("policy_fact:")]
        self.assertTrue(any(item.relationship == "policy_fact:within_retention_period=true" for item in audit_facts))

        support = by_resource["support_4715"][0]
        self.assertEqual(support.data_category, "SUPPORT_MESSAGE")
        self.assertEqual(support.observed_state, ObservedState.REDACTED)
        self.assertTrue(any(item.relationship == "policy_fact:shared_context=true" for item in support.relationships))

        flow = by_resource["data_flow_6244"][0]
        self.assertEqual(flow.data_category, "DATA_FLOW")
        self.assertEqual(flow.observed_state, ObservedState.DISABLED)
        flow_marker = next(item for item in flow.relationships if item.relationship == "data_flow")
        flow_details = json.loads(flow_marker.details)
        self.assertEqual(flow_details["evidence_id"], "evidence_92")
        self.assertTrue(flow_details["origin"])
        self.assertEqual(flow_details["source_fields"]["customer_reference"], subject.user_id)
        self.assertIs(flow_details["source_fields"]["enabled"], False)

        backup = by_resource["backup_3120"][0]
        self.assertEqual(backup.data_category, "BACKUP_ARCHIVE")
        self.assertEqual(backup.observed_state, ObservedState.PRESENT)
        self.assertTrue(any(item.relationship == "policy_fact:restore_blockable=true" for item in backup.relationships))
        restore = next(item for item in by_resource["backup_3120"] if item.data_category == "RESTORE_FLOW")
        self.assertEqual(restore.observed_state, ObservedState.BLOCKED)
        restore_details = json.loads(restore.relationships[0].details)
        self.assertEqual(restore_details["evidence_id"], "evidence_92")
        self.assertTrue(restore_details["origin"])
        self.assertEqual(restore_details["source_fields"]["customer_reference"], subject.user_id)
        self.assertIs(restore_details["source_fields"]["restore_allowed"], False)

        facts = [
            relation
            for observation in adapted
            for relation in observation.relationships
            if relation.relationship.startswith("policy_fact:")
        ]
        self.assertTrue(facts)
        for relationship in facts:
            details = json.loads(relationship.details)
            self.assertEqual(details["evidence_id"], "evidence_92")
            self.assertTrue(details["origin"])
            self.assertTrue(details["relative_path"])
            self.assertLessEqual(datetime.fromisoformat(details["captured_at"]), request.audit_at)
            self.assertLessEqual(datetime.fromisoformat(details["record_timestamp"]), request.audit_at)
            self.assertEqual(datetime.fromisoformat(details["audit_at"]), request.audit_at)
            self.assertTrue(details["locator"])

        decision = policy_module.evaluate(adapted, read_deletion_rules(dataset_root))
        self.assertEqual({step.evidence_id for step in decision.steps}, {"evidence_92"})
        direct_resources = {"audit_record_5416", "support_4715", "data_flow_6244", "backup_3120"}
        self.assertTrue({step.resource_id for step in decision.steps} <= direct_resources)
        operations = {step.operation.value for step in decision.steps}
        self.assertTrue({
            "VERIFY_RECORD_PRESENT",
            "VERIFY_RECORD_REDACTED",
            "VERIFY_DATA_FLOW_DISABLED",
            "VERIFY_RESTORE_BLOCKED",
        } <= operations)
        self.assertNotIn("account_5684", by_resource)
        self.assertNotIn("analytics_4566", by_resource)

    def test_explicit_profile_lookup_not_found_maps_to_cited_absence(self):
        policy_module = importlib.import_module("code.policy_engine")
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        record = EvidenceRecord(
            evidence_id="lookup_evidence",
            relative_path="evidence/profile_lookup.log",
            origin="account_lookup_log",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="log",
            locator="file",
            extracted_content="profile lookup completed",
            structured_fields={
                "records": [{
                    "fields": {
                        "event": "profile_lookup_completed",
                        "http_status": "404",
                        "lookup_key": "person@example.test",
                        "resource_id": "account_901",
                        "rows": "0",
                    },
                    "record_timestamp": audit_at,
                    "locator": "line:2",
                    "timestamp_candidates": [{"raw": audit_at.isoformat(), "parsed": audit_at}],
                }],
            },
        )
        index = EvidenceIndex(records=(record,))
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_901",
            current_identifiers=(IdentityIdentifier("email", "person@example.test"),),
        )
        observation = ResourceObservation(
            system_id="account_service",
            resource_id="account_901",
            data_category="UNKNOWN",
            observed_state=ObservedState.UNKNOWN,
            identifiers=(IdentityIdentifier("email", "person@example.test"),),
            observation_timestamp=audit_at,
            evidence_references=("lookup_evidence",),
        )

        adapted = _adapt_evidence_to_policy([observation], index, audit_at, subject)
        decision = policy_module.evaluate(
            adapted,
            [DeletionRule("profile-delete", "USER_PROFILE", "Always", "DELETE")],
        )

        self.assertEqual(adapted[0].observed_state, ObservedState.ABSENT)
        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.steps), 1)
        self.assertEqual(decision.steps[0].operation.value, "VERIFY_RECORD_ABSENT")
        self.assertEqual(decision.steps[0].evidence_id, "lookup_evidence")

    def test_nested_sql_record_json_fields_map_only_explicit_policy_facts(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", "person@example.test"),),
        )
        resource_fields = {
            "audit_record_fixture": {
                "record_type": "SECURITY_AUDIT_LOG",
                "record_json_parsed": {
                    "subject_reference": "user_fixture",
                    "retention_until": "2030-12-31T23:59:59Z",
                },
            },
            "support_fixture": {
                "record_type": "SUPPORT_MESSAGE",
                "record_json_parsed": {
                    "customer_reference": "user_fixture",
                    "message_excerpt": "Customer asked about an order update.",
                    "requester_email": None,
                    "requester_name": None,
                    "requester_phone": None,
                },
            },
            "analytics_fixture": {
                "record_type": "ANALYTICS_PROFILE",
                "record_json_parsed": {"email": "person@example.test"},
            },
            "data_flow_fixture": {
                "record_type": "DATA_FLOW",
                "record_json_parsed": {
                    "customer_reference": "user_fixture",
                    "enabled": False,
                    "last_delivery_status": "stopped",
                },
            },
            "backup_fixture": {
                "record_type": "BACKUP_ARCHIVE",
                "record_json_parsed": {
                    "customer_reference": "user_fixture",
                    "restore_allowed": False,
                },
            },
        }
        records = tuple(
            EvidenceRecord(
                evidence_id=f"evidence_{resource_id}",
                relative_path=f"evidence/{resource_id}.sql",
                origin="participant_sql_snapshot",
                captured_at=audit_at,
                record_timestamp=audit_at,
                format="sql",
                locator=f"sql:table:records:row:{index}",
                extracted_content="",
                structured_fields={"records": [{
                    "fields": {"resource_id": resource_id, **fields},
                    "record_timestamp": audit_at,
                    "locator": f"sql:table:records:row:{index}",
                }]},
            )
            for index, (resource_id, fields) in enumerate(resource_fields.items(), 1)
        )
        evidence_index = EvidenceIndex(records=records)
        observations = [
            ResourceObservation(
                system_id={
                    "audit_record_fixture": "security_service",
                    "support_fixture": "support_platform",
                    "analytics_fixture": "analytics_platform",
                    "data_flow_fixture": "integration_service",
                    "backup_fixture": "backup_service",
                }[resource_id],
                resource_id=resource_id,
                data_category="UNKNOWN",
                observed_state=ObservedState.PRESENT if resource_id == "backup_fixture" else ObservedState.UNKNOWN,
                identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
                observation_timestamp=audit_at,
                evidence_references=(f"evidence_{resource_id}",),
            )
            for resource_id in resource_fields
        ]

        adapted = _adapt_evidence_to_policy(observations, evidence_index, audit_at, subject)
        by_resource = {item.resource_id: item for item in adapted if item.data_category != "RESTORE_FLOW"}
        self.assertEqual(by_resource["audit_record_fixture"].data_category, "SECURITY_AUDIT_LOG")
        self.assertTrue(any(r.relationship == "policy_fact:within_retention_period=true" for r in by_resource["audit_record_fixture"].relationships))
        self.assertTrue(any(r.relationship == "policy_fact:shared_context=true" for r in by_resource["support_fixture"].relationships))
        self.assertEqual(by_resource["support_fixture"].observed_state, ObservedState.REDACTED)
        self.assertTrue(any(r.relationship == "policy_fact:attributable=true" for r in by_resource["analytics_fixture"].relationships))
        self.assertEqual(by_resource["data_flow_fixture"].observed_state, ObservedState.DISABLED)
        self.assertTrue(any(r.relationship == "policy_fact:restore_blockable=true" for r in by_resource["backup_fixture"].relationships))
        restore = next(item for item in adapted if item.data_category == "RESTORE_FLOW")
        self.assertEqual(restore.observed_state, ObservedState.BLOCKED)
        for item in adapted:
            if item.data_category == "RESTORE_FLOW":
                continue
            for relation in item.relationships:
                if relation.relationship.startswith("policy_fact:"):
                    details = json.loads(relation.details)
                    self.assertTrue(any(key.startswith("record_json_parsed.") for key in details["source_fields"]))

    def test_policy_adapter_does_not_infer_missing_support_context(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        fields = {
            "resource_id": "support_fixture",
            "customer_reference": "user_fixture",
            "requester_email": None,
            "requester_name": None,
            "requester_phone": None,
            "message_excerpt": "Customer contacted support.",
            "observed_at": "2026-09-15T10:00:00Z",
        }
        record = EvidenceRecord(
            evidence_id="support_fixture_evidence",
            relative_path="evidence/support.json",
            origin="synthetic regression fixture",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="json",
            locator="file",
            extracted_content="",
            structured_fields={"records": [{"locator": "json:$.records[0]", "fields": fields}]},
        )
        observation = ResourceObservation(
            system_id="support_platform",
            resource_id="support_fixture",
            data_category="UNKNOWN",
            observed_state=ObservedState.PRESENT,
            identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
            observation_timestamp=audit_at,
            evidence_references=(record.evidence_id,),
        )
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", "requester@example.test"),),
        )
        adapted = _adapt_evidence_to_policy(
            [observation], EvidenceIndex(records=(record,)), audit_at, subject,
        )
        self.assertEqual(adapted[0].data_category, "SUPPORT_MESSAGE")
        self.assertEqual(adapted[0].observed_state, ObservedState.REDACTED)
        self.assertFalse(any(
            relationship.relationship.startswith("policy_fact:shared_context=")
            for relationship in adapted[0].relationships
        ))

        with self.assertRaisesRegex(ValueError, "Missing policy fact 'shared_context'"):
            importlib.import_module("code.policy_engine").evaluate(
                adapted,
                [DeletionRule(
                    "support_fixture_rule",
                    "SUPPORT_MESSAGE",
                    "Conversation contains shared customer, agent, or order context that must be retained",
                    "REDACT",
                )],
            )

    def test_policy_adapter_does_not_infer_missing_retention_period(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        record = EvidenceRecord(
            evidence_id="audit_without_retention_evidence",
            relative_path="evidence/audit.json",
            origin="participant audit snapshot",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="json",
            locator="json:$.records[0]",
            extracted_content="",
            structured_fields={"records": [{
                "locator": "json:$.records[0]",
                "record_timestamp": audit_at,
                "fields": {
                    "resource_id": "audit_record_without_retention",
                    "subject_reference": "user_fixture",
                    "event_code": "PRIVACY_REQUEST_ACCEPTED",
                    "observed_at": "2026-09-15T10:00:00Z",
                },
            }]},
        )
        observation = ResourceObservation(
            system_id="security_service",
            resource_id="audit_record_without_retention",
            data_category="UNKNOWN",
            observed_state=ObservedState.PRESENT,
            identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
            observation_timestamp=audit_at,
            evidence_references=(record.evidence_id,),
        )
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")

        adapted = _adapt_evidence_to_policy(
            [observation], EvidenceIndex(records=(record,)), audit_at, subject,
        )

        self.assertEqual(adapted[0].data_category, "SECURITY_AUDIT_LOG")
        self.assertFalse(any(
            relationship.relationship.startswith("policy_fact:within_retention_period=")
            for relationship in adapted[0].relationships
        ))
        with self.assertRaisesRegex(ValueError, "Missing policy fact 'within_retention_period'"):
            importlib.import_module("code.policy_engine").evaluate(
                adapted,
                [DeletionRule(
                    "audit_retention_fixture",
                    "SECURITY_AUDIT_LOG",
                    "Record is within the supplied retention period",
                    "RETAIN",
                )],
            )

    def test_audit_readback_positive_rows_maps_to_cited_presence_verification(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        evidence_id = "audit_readback_evidence"
        resource_id = "audit_record_readback"
        record = EvidenceRecord(
            evidence_id=evidence_id,
            relative_path="evidence/audit_readback.log",
            origin="participant audit readback",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="log",
            locator="line:17",
            extracted_content="",
            structured_fields={"records": [{
                "locator": "line:17",
                "record_timestamp": audit_at,
                "fields": {
                    "resource_id": resource_id,
                    "event": "audit_record_read_completed",
                    "rows": 1,
                    "event_time": audit_at.isoformat(),
                    "subject_reference": "user_fixture",
                    "event_code": "PRIVACY_REQUEST_ACCEPTED",
                },
            }]},
        )
        observation = ResourceObservation(
            system_id="security_service",
            resource_id=resource_id,
            data_category="SECURITY_AUDIT_LOG",
            observed_state=ObservedState.UNKNOWN,
            identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
            observation_timestamp=audit_at,
            evidence_references=(evidence_id,),
        )
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")

        adapted = _adapt_evidence_to_policy(
            [observation], EvidenceIndex(records=(record,)), audit_at, subject,
        )[0]
        decision = importlib.import_module("code.policy_engine").evaluate(
            [adapted],
            [DeletionRule("audit-retain", "SECURITY_AUDIT_LOG", "Always", "RETAIN")],
        )

        self.assertEqual(adapted.observed_state, ObservedState.PRESENT)
        self.assertEqual(adapted.evidence_references, (evidence_id,))
        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(len(decision.steps), 1)
        self.assertEqual(decision.steps[0].operation.value, "VERIFY_RECORD_PRESENT")
        self.assertEqual(decision.steps[0].evidence_id, evidence_id)

    def test_audit_readback_without_unambiguous_cutoff_positive_rows_stays_unknown(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")
        cases = (
            ("empty", {"event": "audit_record_read_completed", "rows": 0}, audit_at, ObservedState.UNKNOWN),
            ("started", {"event": "audit_record_read_started", "rows": 1}, audit_at, ObservedState.UNKNOWN),
            (
                "conflicting",
                {"event": "audit_record_read_completed", "rows": 1, "nested": {"rows": 2}},
                audit_at,
                ObservedState.UNKNOWN,
            ),
            (
                "post_cutoff",
                {"event": "audit_record_read_completed", "rows": 1, "event_time": "2026-09-15T12:01:00Z"},
                audit_at,
                ObservedState.UNKNOWN,
            ),
        )
        for name, fields, source_time, expected in cases:
            with self.subTest(name=name):
                resource_id = f"audit_record_{name}"
                evidence_id = f"evidence_{name}"
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant audit readback",
                    captured_at=audit_at,
                    record_timestamp=source_time,
                    format="log",
                    locator="line:18",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:18",
                        "record_timestamp": source_time,
                        "fields": {"resource_id": resource_id, **fields},
                    }]},
                )
                observation = ResourceObservation(
                    system_id="security_service",
                    resource_id=resource_id,
                    data_category="SECURITY_AUDIT_LOG",
                    observed_state=ObservedState.UNKNOWN,
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                self.assertEqual(adapted.observed_state, expected)

    def test_explicit_export_and_analytics_readbacks_map_to_cited_presence(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", "person@example.test"),),
        )
        policy_module = importlib.import_module("code.policy_engine")
        fixtures = (
            (
                "export",
                "USER_EXPORT",
                "export_fixture",
                {
                    "event": "export_download_check_completed",
                    "available": True,
                    "event_time": audit_at.isoformat(),
                },
                DeletionRule("export-delete", "USER_EXPORT", "Always", "DELETE"),
            ),
            (
                "analytics",
                "ANALYTICS_PROFILE",
                "analytics_fixture",
                {
                    "event": "analytics_profile_read_completed",
                    "email": "person@example.test",
                    "event_time": audit_at.isoformat(),
                },
                DeletionRule(
                    "analytics-anonymize",
                    "ANALYTICS_PROFILE",
                    "Record is still attributable to a user",
                    "ANONYMIZE",
                ),
            ),
        )

        for name, category, resource_id, source_fields, rule in fixtures:
            with self.subTest(category=category):
                evidence_id = f"evidence_{name}"
                fields = {"resource_id": resource_id, **source_fields}
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant system readback",
                    captured_at=audit_at,
                    record_timestamp=audit_at,
                    format="log",
                    locator="line:24",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:24",
                        "record_timestamp": audit_at,
                        "fields": fields,
                    }]},
                )
                observation = ResourceObservation(
                    system_id="export_service" if category == "USER_EXPORT" else "analytics_platform",
                    resource_id=resource_id,
                    data_category=category,
                    observed_state=ObservedState.UNKNOWN,
                    identifiers=(IdentityIdentifier("email", "person@example.test"),),
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                decision = policy_module.evaluate([adapted], [rule])

                self.assertEqual(adapted.observed_state, ObservedState.PRESENT)
                self.assertEqual(adapted.evidence_references, (evidence_id,))
                self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
                finding = next(
                    step for step in decision.steps
                    if step.operation.value in {"REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII"}
                )
                self.assertEqual(finding.evidence_id, evidence_id)

    def test_negative_export_and_unmatched_analytics_evidence_stay_unknown(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", "person@example.test"),),
        )
        scenarios = (
            ("export", "USER_EXPORT", "export_fixture", {
                "event": "export_download_check_completed", "available": False,
            }),
            ("analytics", "ANALYTICS_PROFILE", "analytics_fixture", {
                "event": "analytics_profile_read_completed", "email": "other@example.test",
            }),
        )
        for name, category, resource_id, source_fields in scenarios:
            with self.subTest(category=category):
                evidence_id = f"evidence_{name}_negative"
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant system readback",
                    captured_at=audit_at,
                    record_timestamp=audit_at,
                    format="log",
                    locator="line:25",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:25",
                        "record_timestamp": audit_at,
                        "fields": {"resource_id": resource_id, **source_fields},
                    }]},
                )
                observation = ResourceObservation(
                    system_id="export_service" if category == "USER_EXPORT" else "analytics_platform",
                    resource_id=resource_id,
                    data_category=category,
                    observed_state=ObservedState.UNKNOWN,
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)
                self.assertFalse(any(
                    relationship.relationship.startswith("policy_fact:attributable=")
                    for relationship in adapted.relationships
                ))

    def test_exact_analytics_identity_scan_match_maps_cutoff_valid_attribution(self):
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(item for item in read_requests(dataset_root) if item.case_id == "case_413")
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        activity = read_activity(dataset_root)
        rules = read_deletion_rules(dataset_root)
        modules = load_feature_modules()
        subject = modules.identity_resolution.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        self.assertEqual(subject.resolution_status, ResolutionStatus.UNIQUE)
        index = modules.evidence_processing.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        observations = modules.evidence_processing.search_subject(subject, request.audit_at, index, activity)
        observation = next(item for item in observations if item.resource_id == "analytics_4523")
        self.assertIn("evidence_39", observation.evidence_references)

        adapted = _adapt_evidence_to_policy([observation], index, request.audit_at, subject)[0]
        attribution = next(
            relation for relation in adapted.relationships
            if relation.relationship == "policy_fact:attributable=true"
        )
        proof = json.loads(attribution.details)
        self.assertEqual(proof["evidence_id"], "evidence_39")
        self.assertEqual(proof["locator"], "line:39")
        self.assertLessEqual(datetime.fromisoformat(proof["record_timestamp"]), request.audit_at)
        self.assertEqual(adapted.observed_state, ObservedState.PRESENT)

        decision = importlib.import_module("code.policy_engine").evaluate([adapted], rules)
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        finding = next(step for step in decision.steps if step.operation.value == "REPORT_EXPOSED_PII")
        self.assertEqual((finding.resource_id, finding.evidence_id), ("analytics_4523", "evidence_39"))

        rows = build_rows(
            [request], identities, audit_log, activity, rules, dataset_root, modules,
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].deletion_status, DeletionStatus.INCOMPLETE)
        OutputRow(rows[0].case_id, rows[0].deletion_status, rows[0].steps_json)

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "pypdf is not available in this Python environment")
    def test_case45_signed_pdf_proves_cutoff_valid_retained_record(self):
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(item for item in read_requests(dataset_root) if item.case_id == "case_45")
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        activity = read_activity(dataset_root)
        rules = read_deletion_rules(dataset_root)
        modules = load_feature_modules()
        rows = build_rows(
            [request], identities, audit_log, activity, rules,
            dataset_root, modules,
        )

        self.assertEqual(rows[0].deletion_status, DeletionStatus.COMPLETE)
        steps = json.loads(rows[0].steps_json)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["phase"], "VERIFICATION")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(steps[0]["state"], "PRESENT")
        self.assertEqual(steps[0]["resource_id"], "audit_record_003")
        self.assertEqual(steps[0]["evidence_id"], "evidence_55")

        index = modules.evidence_processing.load_evidence(
            dataset_root / "evidence_files.csv", dataset_root,
        )
        record = index.records_by_id["evidence_55"]
        self.assertLessEqual(record.captured_at, request.audit_at)
        self.assertEqual(record.structured_fields["records"][0]["locator"], "pdf:page:1")
        subject = modules.identity_resolution.resolve_identity(
            request.email, request.requested_at, request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        observations = modules.evidence_processing.search_subject(
            subject, request.audit_at, index, activity,
        )
        adapted = _adapt_evidence_to_policy(
            observations, index, request.audit_at, subject,
        )
        fact = next(
            rel for obs in adapted for rel in obs.relationships
            if rel.relationship == "policy_fact:within_retention_period=true"
        )
        proof = json.loads(fact.details)
        self.assertEqual(proof["evidence_id"], "evidence_55")
        self.assertEqual(proof["locator"], "pdf:page:1")
        self.assertLessEqual(datetime.fromisoformat(proof["record_timestamp"]), request.audit_at)

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "pypdf is not available in this Python environment")
    def test_case45_pdf_evidence_is_excluded_after_audit_cutoff(self):
        from code.evidence_processing import build_evidence_index

        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(item for item in read_requests(dataset_root) if item.case_id == "case_45")
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        modules = load_feature_modules()
        index = modules.evidence_processing.load_evidence(
            dataset_root / "evidence_files.csv", dataset_root,
        )
        subject = modules.identity_resolution.resolve_identity(
            request.email, request.requested_at, request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        record = index.records_by_id["evidence_55"]
        after_cutoff = replace(record, captured_at=request.audit_at + timedelta(seconds=1))
        excluded_index = build_evidence_index((after_cutoff,))
        observations = modules.evidence_processing.search_subject(
            subject, request.audit_at, excluded_index, (),
        )
        self.assertEqual(observations, [])

    def test_analytics_identity_scan_does_not_attribute_unmatched_or_non_direct_values(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", "person@example.test"),),
        )
        scenarios = (
            {"event": "analytics_identity_scan", "matched_value": "other@example.test", "direct_identifiers": "1"},
            {"event": "analytics_identity_scan", "matched_value": "person@example.test", "direct_identifiers": "0"},
        )
        for number, source_fields in enumerate(scenarios, 1):
            evidence_id = f"evidence_analytics_scan_negative_{number}"
            resource_id = f"analytics_scan_negative_{number}"
            record = EvidenceRecord(
                evidence_id=evidence_id,
                relative_path=f"evidence/{evidence_id}.log",
                origin="participant analytics scan fixture",
                captured_at=audit_at,
                record_timestamp=audit_at,
                format="log",
                locator="line:1",
                extracted_content="",
                structured_fields={"records": [{
                    "locator": "line:1",
                    "record_timestamp": audit_at,
                    "fields": {"resource_id": resource_id, **source_fields},
                }]},
            )
            observation = ResourceObservation(
                system_id="analytics_platform",
                resource_id=resource_id,
                data_category="ANALYTICS_PROFILE",
                observed_state=ObservedState.UNKNOWN,
                evidence_references=(evidence_id,),
            )
            adapted = _adapt_evidence_to_policy(
                [observation], EvidenceIndex(records=(record,)), audit_at, subject,
            )[0]
            self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)
            self.assertFalse(any(
                relation.relationship.startswith("policy_fact:attributable=")
                for relation in adapted.relationships
            ))

    def test_nested_log_resource_fields_reach_policy_with_cutoff_valid_citations(self):
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request_ids = ("case_263", "case_416", "case_417")
        requests_by_id = {
            request.case_id: request for request in read_requests(dataset_root)
            if request.case_id in request_ids
        }
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        activity = read_activity(dataset_root)
        rules = read_deletion_rules(dataset_root)
        modules = load_feature_modules()
        expected_findings = {
            "case_263": {("search_5331", "evidence_25"), ("analytics_515", "evidence_25")},
            "case_416": {("search_6600", "evidence_39")},
            "case_417": {("search_5479", "evidence_39"), ("account_4921", "evidence_39")},
        }

        for case_id in request_ids:
            with self.subTest(case_id=case_id):
                row = build_rows(
                    [requests_by_id[case_id]], identities, audit_log, activity,
                    rules, dataset_root, modules,
                )[0]
                self.assertEqual(row.deletion_status, DeletionStatus.INCOMPLETE)
                parsed = OutputRow(row.case_id, row.deletion_status, row.steps_json)
                findings = {
                    (step["resource_id"], step["evidence_id"])
                    for step in json.loads(parsed.steps_json)
                    if step["phase"] == "FINDING"
                }
                self.assertTrue(expected_findings[case_id] <= findings)

    def test_profile_lookup_results_map_to_evidence_backed_states(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")
        policy_module = importlib.import_module("code.policy_engine")
        rule = DeletionRule("profile-delete", "USER_PROFILE", "Always", "DELETE")

        for result, expected_state in (
            ("found", ObservedState.PRESENT),
            ("not_found", ObservedState.ABSENT),
        ):
            with self.subTest(result=result):
                evidence_id = f"profile_lookup_{result}"
                resource_id = f"account_{result}"
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant profile readback",
                    captured_at=audit_at,
                    record_timestamp=audit_at,
                    format="log",
                    locator="line:8",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:8",
                        "record_timestamp": audit_at,
                        "fields": {
                            "resource_id": resource_id,
                            "event": "record_lookup",
                            "record_type": "USER_PROFILE",
                            "result": result,
                            "subject_reference": "user_fixture",
                            "event_time": audit_at.isoformat(),
                        },
                    }]},
                )
                observation = ResourceObservation(
                    system_id="account_service",
                    resource_id=resource_id,
                    data_category="USER_PROFILE",
                    observed_state=ObservedState.UNKNOWN,
                    identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                decision = policy_module.evaluate([adapted], [rule])

                self.assertEqual(adapted.observed_state, expected_state)
                self.assertEqual(adapted.evidence_references, (evidence_id,))
                cited_step = next(
                    step for step in decision.steps
                    if step.evidence_id == evidence_id
                )
                self.assertEqual(cited_step.state.value, expected_state.value)

    def test_profile_unrecognized_or_post_cutoff_lookup_stays_unknown(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")
        scenarios = (
            ("unrecognized", "record_lookup", "profile", "found", audit_at),
            (
                "post_cutoff",
                "record_lookup",
                "user_profile",
                "found",
                datetime(2026, 9, 15, 12, 1, tzinfo=timezone.utc),
            ),
        )
        for name, event, record_type, result, source_time in scenarios:
            with self.subTest(name=name):
                evidence_id = f"profile_lookup_{name}"
                resource_id = f"account_{name}"
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant profile readback",
                    captured_at=audit_at,
                    record_timestamp=source_time,
                    format="log",
                    locator="line:9",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:9",
                        "record_timestamp": source_time,
                        "fields": {
                            "resource_id": resource_id,
                            "event": event,
                            "record_type": record_type,
                            "result": result,
                            "subject_reference": "user_fixture",
                            "event_time": source_time.isoformat(),
                        },
                    }]},
                )
                observation = ResourceObservation(
                    system_id="account_service",
                    resource_id=resource_id,
                    data_category="USER_PROFILE",
                    observed_state=ObservedState.UNKNOWN,
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)

    def test_backup_restore_readback_explicit_archive_presence(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        evidence_id = "backup_readback_evidence"
        resource_id = "backup_readback"
        record = EvidenceRecord(
            evidence_id=evidence_id,
            relative_path="evidence/backup_readback.log",
            origin="participant restore policy readback",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="log",
            locator="line:31",
            extracted_content="",
            structured_fields={"records": [{
                "locator": "line:31",
                "record_timestamp": audit_at,
                "fields": {
                    "resource_id": resource_id,
                    "event": "restore_policy_read_completed",
                    "archive_present": True,
                    "restore_allowed": False,
                    "customer_reference": "user_fixture",
                    "event_time": audit_at.isoformat(),
                },
            }]},
        )
        observation = ResourceObservation(
            system_id="backup_service",
            resource_id=resource_id,
            data_category="BACKUP_ARCHIVE",
            observed_state=ObservedState.UNKNOWN,
            identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
            observation_timestamp=audit_at,
            evidence_references=(evidence_id,),
        )
        adapted = _adapt_evidence_to_policy(
            [observation],
            EvidenceIndex(records=(record,)),
            audit_at,
            ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture"),
        )
        backup = next(item for item in adapted if item.data_category == "BACKUP_ARCHIVE")

        self.assertEqual(backup.observed_state, ObservedState.PRESENT)
        self.assertIn(evidence_id, backup.evidence_references)
        self.assertTrue(any(
            relationship.relationship == "policy_fact:restore_blockable=true"
            for relationship in backup.relationships
        ))

    def test_backup_readback_without_positive_archive_presence_stays_unknown(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        evidence_id = "backup_readback_negative_evidence"
        record = EvidenceRecord(
            evidence_id=evidence_id,
            relative_path="evidence/backup_readback_negative.log",
            origin="participant restore policy readback",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="log",
            locator="line:32",
            extracted_content="",
            structured_fields={"records": [{
                "locator": "line:32",
                "record_timestamp": audit_at,
                "fields": {
                    "resource_id": "backup_readback_negative",
                    "event": "restore_policy_read_completed",
                    "archive_present": False,
                    "event_time": audit_at.isoformat(),
                },
            }]},
        )
        observation = ResourceObservation(
            system_id="backup_service",
            resource_id="backup_readback_negative",
            data_category="BACKUP_ARCHIVE",
            observed_state=ObservedState.UNKNOWN,
            observation_timestamp=audit_at,
            evidence_references=(evidence_id,),
        )

        adapted = _adapt_evidence_to_policy(
            [observation],
            EvidenceIndex(records=(record,)),
            audit_at,
            ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture"),
        )[0]

        self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)

    def test_search_index_hit_and_found_results_map_to_cited_presence(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")
        rules = read_deletion_rules(Path(__file__).resolve().parents[1] / "dataset")
        policy_module = importlib.import_module("code.policy_engine")

        for result in ("hit", "found"):
            with self.subTest(result=result):
                resource_id = f"search_{result}"
                evidence_id = f"evidence_{result}"
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    relative_path=f"evidence/{evidence_id}.log",
                    origin="participant search readback",
                    captured_at=audit_at,
                    record_timestamp=audit_at,
                    format="log",
                    locator="line:12",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:12",
                        "record_timestamp": audit_at,
                        "fields": {
                            "resource_id": resource_id,
                            "subject_reference": "user_fixture",
                            "result": result,
                        },
                    }]},
                )
                observation = ResourceObservation(
                    system_id="search_service",
                    resource_id=resource_id,
                    data_category="SEARCH_INDEX_ENTRY",
                    observed_state=ObservedState.UNKNOWN,
                    identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
                    observation_timestamp=audit_at,
                    evidence_references=(evidence_id,),
                )

                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                decision = policy_module.evaluate([adapted], rules)

                self.assertEqual(adapted.observed_state, ObservedState.PRESENT)
                finding = next(step for step in decision.steps if step.operation.value == "REPORT_REMAINING_RECORD")
                self.assertEqual(finding.evidence_id, evidence_id)
                self.assertEqual(finding.resource_id, resource_id)

    def test_search_index_negative_or_conflicting_result_stays_unknown(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture")
        for name, fields in (
            ("negative", {"result": "not_found"}),
            ("conflicting", {"result": "hit", "nested": {"result": "miss"}}),
        ):
            with self.subTest(name=name):
                resource_id = f"search_{name}"
                record = EvidenceRecord(
                    evidence_id=f"evidence_{name}",
                    relative_path=f"evidence/{name}.log",
                    origin="participant search readback",
                    captured_at=audit_at,
                    record_timestamp=audit_at,
                    format="log",
                    locator="line:13",
                    extracted_content="",
                    structured_fields={"records": [{
                        "locator": "line:13",
                        "record_timestamp": audit_at,
                        "fields": {"resource_id": resource_id, "subject_reference": "user_fixture", **fields},
                    }]},
                )
                observation = ResourceObservation(
                    "search_service", resource_id, "SEARCH_INDEX_ENTRY", ObservedState.UNKNOWN,
                    identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
                    observation_timestamp=audit_at,
                    evidence_references=(record.evidence_id,),
                )
                adapted = _adapt_evidence_to_policy(
                    [observation], EvidenceIndex(records=(record,)), audit_at, subject,
                )[0]
                self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)

    def test_search_index_hit_after_cutoff_does_not_map_presence(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        later = datetime(2026, 9, 15, 12, 1, tzinfo=timezone.utc)
        record = EvidenceRecord(
            evidence_id="evidence_after_cutoff",
            relative_path="evidence/search_after_cutoff.log",
            origin="participant search readback",
            captured_at=later,
            record_timestamp=later,
            format="log",
            locator="line:14",
            extracted_content="",
            structured_fields={"records": [{
                "locator": "line:14",
                "record_timestamp": later,
                "fields": {"resource_id": "search_after_cutoff", "result": "hit"},
            }]},
        )
        observation = ResourceObservation(
            "search_service", "search_after_cutoff", "SEARCH_INDEX_ENTRY", ObservedState.UNKNOWN,
            observation_timestamp=audit_at,
            evidence_references=(record.evidence_id,),
        )

        adapted = _adapt_evidence_to_policy(
            [observation], EvidenceIndex(records=(record,)), audit_at,
            ResolvedSubject(ResolutionStatus.UNIQUE, "user_fixture"),
        )[0]

        self.assertEqual(adapted.observed_state, ObservedState.UNKNOWN)

    def test_support_context_uses_cutoff_valid_direct_identifier_link(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        subject_email = "requester@example.test"
        subject = ResolvedSubject(
            ResolutionStatus.UNIQUE,
            "user_fixture",
            current_identifiers=(IdentityIdentifier("email", subject_email),),
        )
        fields = {
            "resource_id": "support_linked",
            "record_json_parsed": {
                "requester_email": subject_email,
                "requester_name": None,
                "requester_phone": None,
                "customer_reference": None,
                "message_excerpt": "Customer asked about an order update.",
            },
        }
        record = EvidenceRecord(
            evidence_id="support_linked_evidence",
            relative_path="evidence/support_linked.json",
            origin="participant snapshot",
            captured_at=audit_at,
            record_timestamp=audit_at,
            format="json",
            locator="json:$.records[0]",
            extracted_content="",
            structured_fields={"records": [{"locator": "json:$.records[0]", "record_timestamp": audit_at, "fields": fields}]},
        )
        observation = ResourceObservation(
            system_id="support_platform",
            resource_id="support_linked",
            data_category="UNKNOWN",
            observed_state=ObservedState.PRESENT,
            identifiers=(IdentityIdentifier("email", subject_email),),
            observation_timestamp=audit_at,
            evidence_references=(record.evidence_id,),
        )

        adapted = _adapt_evidence_to_policy(
            [observation], EvidenceIndex(records=(record,)), audit_at, subject,
        )[0]

        fact = next(
            relation for relation in adapted.relationships
            if relation.relationship == "policy_fact:shared_context=true"
        )
        proof = json.loads(fact.details)
        self.assertEqual(proof["evidence_id"], record.evidence_id)
        self.assertEqual(proof["locator"], "json:$.records[0]")
        self.assertEqual(
            proof["source_fields"]["record_json_parsed.requester_email"],
            subject_email,
        )

        rules = read_deletion_rules(Path(__file__).resolve().parents[1] / "dataset")
        decision = importlib.import_module("code.policy_engine").evaluate([adapted], rules)
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(any(step.operation.value == "REDACT_RECORD" for step in decision.steps))

    def test_verify_only_can_complete_from_directly_cited_current_state(self):
        audit_at = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        observation = ResourceObservation(
            system_id="account_service",
            resource_id="account_fixture",
            data_category="USER_PROFILE",
            observed_state=ObservedState.ABSENT,
            identifiers=(IdentityIdentifier("user_id", "user_fixture"),),
            observation_timestamp=audit_at,
            evidence_references=("fixture_evidence",),
        )
        request, _, modules, rules = self._verify_only_pipeline_fixture(
            [observation], ["fixture_evidence"]
        )

        rows = build_rows([request], [], [], [], rules, Path("unused-fixture-root"), modules)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].deletion_status, DeletionStatus.COMPLETE)
        steps = json.loads(rows[0].steps_json)
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["phase"], "VERIFICATION")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(steps[0]["evidence_id"], "fixture_evidence")

    def test_verify_only_without_state_evidence_fails_closed(self):
        observation = ResourceObservation(
            system_id="account_service",
            resource_id="account_fixture",
            data_category="USER_PROFILE",
            observed_state=ObservedState.ABSENT,
        )
        request, _, modules, rules = self._verify_only_pipeline_fixture([observation], [])

        with self.assertRaisesRegex(
            PipelineBlockedError,
            "verification-only audit could not establish a compliant state",
        ):
            build_rows([request], [], [], [], rules, Path("unused-fixture-root"), modules)

    def test_case26_has_no_cutoff_valid_indirect_link_to_account_or_analytics(self):
        identity_module = importlib.import_module("code.identity_resolution")
        evidence_module = importlib.import_module("code.evidence_processing")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_26"
        )
        subject = identity_module.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(read_identities(dataset_root)),
            _identity_audit_rows_for_resolver(read_identity_audit(dataset_root)),
        )
        self.assertEqual(subject.resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(subject.user_id, "user_26")
        self.assertFalse(any(item.user_id == subject.user_id for item in read_identity_audit(dataset_root)))
        index = evidence_module.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        observations = evidence_module.search_subject(subject, request.audit_at, index, read_activity(dataset_root))
        observed_resource_ids = {item.resource_id for item in observations}
        self.assertNotIn("account_5684", observed_resource_ids)
        self.assertNotIn("analytics_4566", observed_resource_ids)
        target_ids = {"account_5684", "analytics_4566"}
        for observation in observations:
            for relationship in observation.relationships:
                self.assertNotIn(relationship.resource_id, target_ids)
                self.assertFalse(any(target in relationship.details for target in target_ids))

        record = index.records_by_id["evidence_92"]
        segments = [
            segment for segment in record.structured_fields.get("records", ())
            if isinstance(segment, dict) and isinstance(segment.get("fields"), dict)
        ]

        def scalar_pairs(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from scalar_pairs(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    yield from scalar_pairs(child)
            elif value is not None:
                yield str(value)

        def trace_ids(value):
            found = set()
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.casefold() in {"trace_id", "traceid"} and child:
                        found.add(str(child))
                    found.update(trace_ids(child))
            elif isinstance(value, (list, tuple)):
                for child in value:
                    found.update(trace_ids(child))
            return found

        subject_values = {
            subject.user_id.casefold(),
            *(
                identifier.value.casefold()
                for identifier in (*subject.current_identifiers, *subject.historical_identifiers)
            ),
        }
        target_segments = {
            resource_id: next(
                segment for segment in segments
                if segment["fields"].get("resource_id") == resource_id
            )
            for resource_id in ("account_5684", "analytics_4566")
        }
        for resource_id in target_segments:
            resource_records = evidence_module.search_resource_id(index, resource_id)
            self.assertEqual(
                {item.evidence_id for item in resource_records},
                {"evidence_02", "evidence_92"},
                resource_id,
            )
            cutoff_records = [item for item in resource_records if item.captured_at <= request.audit_at]
            self.assertEqual([item.evidence_id for item in cutoff_records], ["evidence_92"], resource_id)
        subject_segments = [
            segment for segment in segments
            if subject.user_id.casefold() in {value.casefold() for value in scalar_pairs(segment["fields"])}
        ]
        self.assertTrue(subject_segments, "the export contains other resources directly linked to user_26")
        for resource_id, segment in target_segments.items():
            values = {value.casefold() for value in scalar_pairs(segment["fields"])}
            self.assertFalse(values & subject_values, resource_id)
            target_traces = trace_ids(segment["fields"])
            self.assertFalse(target_traces, resource_id)
            linked_traces = set().union(*(trace_ids(item["fields"]) for item in subject_segments))
            self.assertFalse(target_traces & linked_traces, resource_id)

        # Activity only names these resources and reports workflow results;
        # it contains no subject key or cross-resource edge to bridge the gap.
        subject_names = subject_values
        for event in read_activity(dataset_root):
            if event.resource_id not in target_segments:
                continue
            details = {value.casefold() for value in scalar_pairs(event.details)}
            self.assertFalse(details & subject_names, event.activity_id)

    def test_case26_post_cutoff_snapshot_cannot_supply_the_missing_subject_link(self):
        evidence_module = importlib.import_module("code.evidence_processing")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_26"
        )
        subject = importlib.import_module("code.identity_resolution").resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(read_identities(dataset_root)),
            _identity_audit_rows_for_resolver(read_identity_audit(dataset_root)),
        )
        index = evidence_module.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        later_snapshot = index.records_by_id["evidence_02"]
        self.assertGreater(later_snapshot.captured_at, request.audit_at)
        later_fields = [
            segment.get("fields", {})
            for segment in later_snapshot.structured_fields.get("records", ())
            if isinstance(segment, dict)
        ]
        later_account = [fields for fields in later_fields if fields.get("resource_id") == "account_5684"]
        later_analytics = [fields for fields in later_fields if fields.get("resource_id") == "analytics_4566"]
        self.assertTrue(later_account)
        self.assertTrue(any(
            subject.user_id in {str(value) for value in fields.values() if value is not None}
            for fields in later_account
        ))
        self.assertTrue(later_analytics)
        self.assertFalse(any(
            subject.user_id in {str(value) for value in fields.values() if value is not None}
            for fields in later_analytics
        ))

        observations = evidence_module.search_subject(
            subject, request.audit_at, index, read_activity(dataset_root)
        )
        self.assertNotIn("account_5684", {item.resource_id for item in observations})
        self.assertNotIn("analytics_4566", {item.resource_id for item in observations})

    def test_case01_timed_activity_and_empty_snapshot_do_not_identify_the_subject(self):
        identity_module = importlib.import_module("code.identity_resolution")
        evidence_module = importlib.import_module("code.evidence_processing")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        requests = read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
        request = next(item for item in requests if item.case_id == "case_01")
        subject = identity_module.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(read_identities(dataset_root)),
            _identity_audit_rows_for_resolver(read_identity_audit(dataset_root)),
        )
        index = evidence_module.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        observations = evidence_module.search_subject(subject, request.audit_at, index, read_activity(dataset_root))
        self.assertEqual(observations, [])

        event = next(item for item in read_activity(dataset_root) if item.activity_id == "activity_3342")
        self.assertEqual(event.resource_id, "account_001")
        self.assertLessEqual(abs((request.reported_at - event.event_time).total_seconds()), 60)
        self.assertNotIn(subject.user_id, str(event.details))
        self.assertNotIn(request.email, str(event.details))
        self.assertEqual(evidence_module.search_resource_id(index, "account_001"), [])
        snapshot = index.records_by_id["evidence_54"]
        self.assertLessEqual(snapshot.captured_at, request.audit_at)
        self.assertFalse(any(
            segment.get("fields", {}).get("resource_id") == "account_001"
            for segment in snapshot.structured_fields.get("records", ())
            if isinstance(segment, dict)
        ))

        requests_by_id = {item.case_id: item for item in requests}
        self.assertEqual(
            requests_by_id["case_16"].reported_at,
            requests_by_id["case_22"].reported_at,
        )
        self.assertEqual(requests_by_id["case_16"].reported_at.isoformat(), "2026-09-01T10:00:00+00:00")
        collision_event = next(item for item in read_activity(dataset_root) if item.activity_id == "activity_3575")
        self.assertLessEqual(abs((requests_by_id["case_16"].reported_at - collision_event.event_time).total_seconds()), 5)
        self.assertLessEqual(abs((requests_by_id["case_22"].reported_at - collision_event.event_time).total_seconds()), 5)

        with self.assertRaises(PipelineBlockedError):
            build_rows(
                [request],
                read_identities(dataset_root),
                read_identity_audit(dataset_root),
                read_activity(dataset_root),
                read_deletion_rules(dataset_root),
                dataset_root,
                load_feature_modules(),
            )

    def test_case_15_trace_correlates_subject_to_active_flow_for_policy(self):
        identity_module = importlib.import_module("code.identity_resolution")
        evidence_module = importlib.import_module("code.evidence_processing")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_15"
        )
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        subject = identity_module.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(identities),
            _identity_audit_rows_for_resolver(audit_log),
        )
        evidence_index = evidence_module.load_evidence(dataset_root / "evidence_files.csv", dataset_root)
        observations = evidence_module.search_subject(
            subject, request.audit_at, evidence_index, read_activity(dataset_root)
        )
        observations = _adapt_trace_linked_active_flows(observations, request.audit_at)
        flow = next((item for item in observations if item.resource_id == "data_flow_9846"), None)

        self.assertIsNotNone(flow, "trace-correlated connector heartbeat should be joined to the subject key")
        self.assertEqual(flow.observed_state, ObservedState.ACTIVE)
        self.assertTrue(
            {relationship.relationship.casefold() for relationship in flow.relationships}
            & {"sync_flow", "import_flow", "data_flow", "active_sync", "active_import"},
            "policy engine requires an explicit active-flow relationship marker",
        )
        trace_link = next(item for item in flow.relationships if item.relationship == "TRACE_CORRELATED_EVIDENCE")
        trace_details = json.loads(trace_link.details)
        self.assertEqual(trace_details["trace_id"], "tr-9750867")
        self.assertEqual(trace_details["evidence_id"], "evidence_01")
        self.assertEqual(trace_details["identifier_locator"], "line:85")
        self.assertEqual(trace_details["resource_locator"], "line:88")
        decision = importlib.import_module("code.policy_engine").evaluate(
            [flow], read_deletion_rules(dataset_root)
        )
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        active_flow_finding = next(
            step for step in decision.steps if step.operation.value == "REPORT_ACTIVE_DATA_FLOW"
        )
        self.assertEqual(active_flow_finding.evidence_id, "evidence_01")

        pipeline_rows = build_rows(
            [request],
            identities,
            audit_log,
            read_activity(dataset_root),
            read_deletion_rules(dataset_root),
            dataset_root,
            load_feature_modules(),
        )
        self.assertEqual(len(pipeline_rows), 1)
        self.assertEqual(pipeline_rows[0].deletion_status, DeletionStatus.INCOMPLETE)
        serialized_steps = json.loads(pipeline_rows[0].steps_json)
        self.assertTrue(any(
            step["operation"] == "REPORT_ACTIVE_DATA_FLOW"
            and step["resource_id"] == "data_flow_9846"
            and step["evidence_id"] == "evidence_01"
            for step in serialized_steps
        ))

    def test_unverified_trace_relationship_does_not_become_active_flow_marker(self):
        from datetime import datetime, timezone

        observation = ResourceObservation(
            system_id="integration_service",
            resource_id="data_flow_unverified",
            data_category="DATA_FLOW",
            observed_state=ObservedState.ACTIVE,
            observation_timestamp=datetime(2026, 9, 15, 11, 0, tzinfo=timezone.utc),
            evidence_references=("evidence_01",),
            relationships=(ResourceRelationship(
                relationship="TRACE_CORRELATED_EVIDENCE",
                system_id="integration_service",
                resource_id="data_flow_unverified",
                details=json.dumps({
                    "correlation": "same_file_trace_id",
                    "trace_id": "trace-present",
                    "evidence_id": "evidence_01",
                    "identifier_locator": "line:1",
                    "resource_locator": "line:2",
                    "supported_state": "UNKNOWN",
                    "supported_fields": {"enabled": "true", "scheduler_registered": "false"},
                    "identifier_record_timestamp": "2026-09-15T10:00:00Z",
                    "resource_record_timestamp": "2026-09-15T10:01:00Z",
                }),
            ),),
        )

        adapted = _adapt_trace_linked_active_flows(
            [observation], datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        )

        self.assertEqual(adapted[0], observation)
        self.assertFalse(any(
            item.relationship.casefold() == "data_flow"
            for item in adapted[0].relationships
        ))

    def test_unproven_support_context_is_not_promoted_to_policy_fact(self):
        policy_module = importlib.import_module("code.policy_engine")
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        request = next(
            item for item in read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
            if item.case_id == "case_11"
        )
        evidence_path = dataset_root / "evidence/records/customer_account_handover_20261001.txt"
        matching_lines = [
            line for line in evidence_path.read_text(encoding="utf-8").splitlines()
            if "support_864" in line
        ]
        self.assertEqual(len(matching_lines), 1)
        self.assertIn("IDENTIFIABLE", matching_lines[0])
        self.assertFalse(any(term in matching_lines[0].casefold() for term in ("shared_context", "order_id", "agent_id")))

        observation = ResourceObservation(
            system_id="support_platform",
            resource_id="support_864",
            data_category="SUPPORT_MESSAGE",
            observed_state=ObservedState.PRESENT,
            identifiers=(IdentityIdentifier("email", request.email),),
            evidence_references=("evidence_03",),
        )
        rules = read_deletion_rules(dataset_root)
        with self.assertRaises(policy_module.PolicyConditionError):
            policy_module.evaluate([observation], rules)

    def test_real_sample_fixtures_cover_requested_scenarios(self):
        dataset_root = Path(__file__).resolve().parents[1] / "dataset"
        sample_requests = read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
        request_by_id = {request.case_id: request for request in sample_requests}
        with (dataset_root / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
            output_by_id = {row["case_id"]: row for row in csv.DictReader(handle)}
        self.assertEqual(len(output_by_id), 32)

        audit_log = read_identity_audit(dataset_root)
        historical = request_by_id["case_10"]
        self.assertTrue(any(
            event.field_name == "email" and event.old_value == historical.email
            for event in audit_log
        ))
        self.assertEqual(output_by_id["case_01"]["deletion_status"], "COMPLETE")
        steps = {case_id: json.loads(row["steps_json"]) for case_id, row in output_by_id.items()}
        self.assertGreaterEqual(
            len({step["system_id"] for step in steps["case_13"] if step["operation"] == "REPORT_REMAINING_RECORD"}),
            2,
        )
        operations = {case_id: {step["operation"] for step in case_steps} for case_id, case_steps in steps.items()}
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", operations["case_11"])
        self.assertIn("REPORT_RESTORE_RISK", operations["case_09"])
        self.assertIn("REDACT_RECORD", operations["case_11"])
        self.assertIn("ANONYMIZE_RECORD", operations["case_11"])
        self.assertIn("VERIFY_RECORD_PRESENT", operations["case_11"])

    def test_sample_dataset_identity_and_policy_scenarios(self):
        modules = self._member_modules_or_skip()
        repository_root = Path(__file__).resolve().parents[1]
        dataset_root = repository_root / "dataset"
        sample_requests = read_requests_file(dataset_root / "sample_deletion_requests.csv", expected_count=32)
        identities = read_identities(dataset_root)
        audit_log = read_identity_audit(dataset_root)
        activity = read_activity(dataset_root)
        rules = read_deletion_rules(dataset_root)

        actual_rows = build_rows(sample_requests, identities, audit_log, activity, rules, dataset_root, modules)
        actual_by_id = {row.case_id: row for row in actual_rows}
        with (dataset_root / "sample_output.csv").open(newline="", encoding="utf-8-sig") as handle:
            expected_rows = {row["case_id"]: row for row in csv.DictReader(handle)}
        self.assertEqual(set(actual_by_id), set(expected_rows))
        for case_id, expected in expected_rows.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(actual_by_id[case_id].deletion_status.value, expected["deletion_status"])
                self.assertEqual(json.loads(actual_by_id[case_id].steps_json), json.loads(expected["steps_json"]))

        sample_operations = {
            case_id: [step["operation"] for step in json.loads(row["steps_json"])]
            for case_id, row in expected_rows.items()
        }
        self.assertEqual(actual_by_id["case_01"].deletion_status.value, "COMPLETE")
        self.assertGreaterEqual(sample_operations["case_13"].count("REPORT_REMAINING_RECORD"), 2)
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", sample_operations["case_11"])
        self.assertIn("REPORT_RESTORE_RISK", sample_operations["case_09"])
        self.assertIn("REDACT_RECORD", sample_operations["case_11"])
        self.assertIn("ANONYMIZE_RECORD", sample_operations["case_11"])
        self.assertIn("VERIFY_RECORD_PRESENT", sample_operations["case_11"])

    def _check_module(self, module_name: str, expected: dict[str, tuple[list[str], Any]]) -> None:
        qualified_name = f"code.{module_name}"
        if importlib.util.find_spec(qualified_name) is None:
            self.skipTest(f"{qualified_name} is not available yet")
        module = importlib.import_module(qualified_name)
        for function_name, (parameter_names, expected_return) in expected.items():
            with self.subTest(module=qualified_name, function=function_name):
                function = getattr(module, function_name, None)
                self.assertTrue(callable(function), f"{qualified_name}.{function_name} must be callable")
                signature = inspect.signature(function)
                self.assertEqual(
                    list(signature.parameters),
                    parameter_names,
                    f"{qualified_name}.{function_name} parameter names/order do not match the shared interface",
                )
                hints = get_type_hints(function)
                self.assertEqual(
                    hints.get("return"),
                    expected_return,
                    f"{qualified_name}.{function_name} return annotation must be {expected_return!r}",
                )

    def test_ambiguous_identity_stops_without_asserting_a_deletion_status(self):
        subject = contracts.ResolvedSubject(contracts.ResolutionStatus.AMBIGUOUS, None)
        with self.assertRaises(PipelineBlockedError):
            _require_unique_subject("unit-case", subject)

    def test_identity_resolution_interface(self):
        self.assertTrue(hasattr(contracts, "ResolvedSubject"))
        self._check_module(
            "identity_resolution",
            {
                "classify_deletion_request": (["request_text"], contracts.IntentDecision),
                "resolve_identity": (
                    ["request_email", "requested_at", "audit_at", "identities", "audit_log"],
                    contracts.ResolvedSubject,
                ),
            },
        )

    def test_evidence_processing_interface(self):
        self.assertTrue(hasattr(contracts, "EvidenceIndex"))
        self._check_module(
            "evidence_processing",
            {
                "load_evidence": (["manifest_path", "dataset_root"], contracts.EvidenceIndex),
                "search_subject": (
                    ["resolved_subject", "audit_at", "evidence_index", "activity"],
                    list[contracts.ResourceObservation],
                ),
            },
        )

    def test_policy_engine_interface(self):
        self.assertTrue(hasattr(contracts, "AuditDecision"))
        self._check_module(
            "policy_engine",
            {"evaluate": (["observations", "rules"], contracts.AuditDecision)},
        )

    def test_independent_replay_continues_after_one_case_blocks(self):
        requests = [SimpleNamespace(case_id=f"case_{index:02d}") for index in range(1, 4)]
        processed: list[str] = []

        def build_one(request):
            processed.append(request.case_id)
            if request.case_id == "case_02":
                raise PipelineBlockedError("identity resolution is ambiguous")
            return _not_applicable_row(request.case_id)

        rows, unresolved = collect_independent_rows(
            requests,
            build_one,
            lambda row, request: OutputRow(row.case_id, row.deletion_status, row.steps_json),
        )

        self.assertEqual(processed, ["case_01", "case_02", "case_03"])
        self.assertEqual([row.case_id for row in rows], ["case_01", "case_03"])
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["case_id"], "case_02")
        self.assertEqual(unresolved[0]["stage"], "identity_resolution")
        self.assertEqual(unresolved[0]["blocker_reason"], "identity resolution is ambiguous")

    def test_independent_replay_records_row_validation_failure_and_continues(self):
        requests = [SimpleNamespace(case_id=f"case_{index:02d}") for index in range(1, 4)]

        def build_one(request):
            return _not_applicable_row(request.case_id)

        def validate_one(row, request):
            OutputRow(row.case_id, row.deletion_status, row.steps_json)
            if request.case_id == "case_02":
                raise ValueError("unknown evidence reference: absent-id")

        rows, unresolved = collect_independent_rows(requests, build_one, validate_one)

        self.assertEqual([row.case_id for row in rows], ["case_01", "case_03"])
        self.assertEqual([item["case_id"] for item in unresolved], ["case_02"])
        self.assertEqual(unresolved[0]["stage"], "evidence_discovery")
        self.assertEqual(unresolved[0]["blocker_reason"], "unknown evidence reference: absent-id")

    def test_diagnostic_stage_distinguishes_policy_blockers_from_evidence_discovery(self):
        self.assertEqual(
            _diagnostic_stage(
                "case case_x: policy evaluation failed: Insufficient evidence to decide policy applicability"
            ),
            "policy_evaluation",
        )
        self.assertEqual(
            _diagnostic_stage(
                "case case_x: no cutoff-valid evidence links the resolved subject to a resource"
            ),
            "evidence_discovery",
        )


if __name__ == "__main__":
    unittest.main()
