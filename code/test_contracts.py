"""Focused tests for the shared pipeline contracts."""

import json
import unittest
from datetime import datetime, timezone

from code.contracts import (
    ALLOWED_OPERATION_STATES,
    OPERATION_ORDER,
    ActivityEvent,
    AuditDecision,
    AuditStep,
    DeletionRequest,
    DeletionStatus,
    EvidenceIndex,
    EvidenceManifestEntry,
    EvidenceParserStatus,
    EvidenceRecord,
    IdentityAuditEvent,
    IdentityIdentifier,
    IdentityProvenance,
    IdentityRecord,
    Intent,
    IntentDecision,
    ObservedState,
    Operation,
    OutputRow,
    Phase,
    ReportedStatus,
    ResolutionStatus,
    ResolvedSubject,
    ResourceObservation,
    StepState,
    steps_to_json,
    validate_evidence_references,
)


NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


class ContractsTests(unittest.TestCase):
    def test_request_and_decision_construction(self):
        request = DeletionRequest("case_1", "old@example.test", NOW, "COMPLETE", None, NOW, "delete my data")
        self.assertEqual(request.reported_status, ReportedStatus.COMPLETE)
        self.assertEqual(IntentDecision("DELETE", "explicit request").intent, Intent.DELETE)

    def test_identity_status_and_optional_user_id(self):
        unique = ResolvedSubject("UNIQUE", "user-1", resolution_explanation="matched email")
        unresolved = ResolvedSubject(ResolutionStatus.UNRESOLVED, None)
        self.assertEqual(unique.user_id, "user-1")
        self.assertIsNone(unresolved.user_id)
        with self.assertRaises(ValueError):
            ResolvedSubject("UNIQUE", None)

    def test_evidence_optional_fields_and_index(self):
        entry = EvidenceManifestEntry("file-1", "evidence/a.json", "archive", NOW)
        record = EvidenceRecord(
            "file-1", entry.file_path, entry.origin, NOW, None, "json", "$.items[0]", "",
            parser_status=EvidenceParserStatus.PARTIAL, confidence=None,
        )
        index = EvidenceIndex((record,), by_identifier={"user-1": ("file-1",)})
        self.assertIsNone(record.record_timestamp)
        self.assertIsNone(record.confidence)
        self.assertEqual(index.records_by_id["file-1"], record)
        self.assertIsNone(ActivityEvent("a1", NOW, "SYNC", "source", "target", "r1", None).reported_result)
        self.assertEqual(ResourceObservation("s", "r", "PROFILE", ObservedState.UNKNOWN).observed_state, ObservedState.UNKNOWN)
        self.assertEqual(IdentityIdentifier("email", "old@example.test").valid_to, None)
        self.assertIsNone(IdentityProvenance("audit_log").audit_id)
        current_identity = IdentityRecord("user-1", (IdentityIdentifier("email", "e@example.test"),), NOW)
        self.assertEqual(current_identity.identifiers[0].value, "e@example.test")
        audit_event = IdentityAuditEvent("audit-1", "user-1", NOW, "email", "old@example.test", "e@example.test")
        self.assertEqual(audit_event.audit_id, "audit-1")

    def test_operation_state_table_is_complete_and_enforced(self):
        self.assertEqual(len(ALLOWED_OPERATION_STATES), 15)
        step = AuditStep(1, "FINDING", "account_service", "account_1", "REPORT_REMAINING_RECORD", "PRESENT", "file-1")
        self.assertEqual(step.state, StepState.PRESENT)
        with self.assertRaises(ValueError):
            AuditStep(1, Phase.FINDING, "s", "r", Operation.REPORT_REMAINING_RECORD, StepState.ACTIVE, "file-1")
        with self.assertRaises(ValueError):
            AuditStep(1, Phase.FINDING, "s", "r", Operation.DELETE_RECORD, StepState.ABSENT, "file-1")

    def test_invalid_status_and_operation_names_are_rejected(self):
        with self.assertRaises(ValueError):
            AuditDecision("UNKNOWN", ())
        with self.assertRaises(ValueError):
            EvidenceRecord("f", "p", "o", NOW, None, "json", "loc", "", confidence="high")
        with self.assertRaises(ValueError):
            AuditStep(1, "FINDING", "s", "r", "DELETE_USER", "ABSENT", "file-1")
        with self.assertRaises(ValueError):
            DeletionRequest("case_1", "e", NOW, "DONE", None, NOW, "delete")
        with self.assertRaises(ValueError):
            DeletionRequest("case_1", "e", datetime(2026, 11, 4), "COMPLETE", None, NOW, "delete")

    def test_decision_enforces_status_evidence_and_empty_nonapplicable(self):
        finding = AuditStep(1, Phase.FINDING, "s", "r", Operation.REPORT_REMAINING_RECORD, StepState.PRESENT, "e1")
        remediation = AuditStep(2, Phase.REMEDIATION, "s", "r", Operation.DELETE_RECORD, StepState.ABSENT, "")
        future_verification = AuditStep(3, Phase.VERIFICATION, "s", "r", Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, "")
        incomplete = AuditDecision(DeletionStatus.INCOMPLETE, (finding, remediation, future_verification))
        self.assertEqual(incomplete.deletion_status, DeletionStatus.INCOMPLETE)
        complete_step = AuditStep(1, Phase.VERIFICATION, "s", "r", Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, "e2")
        AuditDecision(DeletionStatus.COMPLETE, (complete_step,))
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.NOT_APPLICABLE, (complete_step,))
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.COMPLETE, (future_verification,))
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.INCOMPLETE, (complete_step,))
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.COMPLETE, ())
        with self.assertRaises(ValueError):
            validate_evidence_references((complete_step,), set())
        validate_evidence_references((complete_step,), {"e2"})

    def test_json_serialization_and_exact_output_schema(self):
        steps = (AuditStep(1, "VERIFICATION", "s", "r", "VERIFY_RECORD_ABSENT", "ABSENT", "e1"),)
        encoded = steps_to_json(steps)
        parsed = json.loads(encoded)
        self.assertEqual(set(parsed[0]), {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"})
        row = OutputRow.from_decision("case_1", AuditDecision("COMPLETE", steps))
        self.assertEqual(row.to_dict()["deletion_status"], "COMPLETE")
        not_applicable = OutputRow.from_decision("unit-case", AuditDecision("NOT_APPLICABLE", ()))
        self.assertEqual(not_applicable.steps_json, "[]")
        with self.assertRaises(ValueError):
            OutputRow("case_3", "NOT_APPLICABLE", "{}")
        with self.assertRaises(ValueError):
            OutputRow("case_4", "NOT_APPLICABLE", '[{"step_no":1}]')

    def test_step_numbers_and_phase_order(self):
        remediation = AuditStep(1, Phase.REMEDIATION, "s", "r", Operation.DELETE_RECORD, StepState.ABSENT, "")
        finding = AuditStep(2, Phase.FINDING, "s", "r", Operation.REPORT_REMAINING_RECORD, StepState.PRESENT, "e1")
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.INCOMPLETE, (remediation, finding))
        with self.assertRaises(ValueError):
            steps_to_json((AuditStep(2, Phase.VERIFICATION, "s", "r", Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, "e"),))
        later_op = AuditStep(1, Phase.FINDING, "a", "a", Operation.REPORT_ACTIVE_DATA_FLOW, StepState.ACTIVE, "e1")
        earlier_op = AuditStep(2, Phase.FINDING, "z", "z", Operation.REPORT_REMAINING_RECORD, StepState.PRESENT, "e2")
        ordered_remediation = AuditStep(3, Phase.REMEDIATION, "s", "r", Operation.DELETE_RECORD, StepState.ABSENT, "")
        ordered_verification = AuditStep(4, Phase.VERIFICATION, "s", "r", Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, "")
        with self.assertRaises(ValueError):
            AuditDecision(DeletionStatus.INCOMPLETE, (later_op, earlier_op, ordered_remediation, ordered_verification))
        self.assertEqual(len(OPERATION_ORDER[Phase.FINDING]), 4)


if __name__ == "__main__":
    unittest.main()
