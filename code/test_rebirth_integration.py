"""Adapter regressions using typed fixtures, separate from live case data."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from code.contracts import (
    AuditDecision,
    AuditStep,
    DeletionStatus,
    EvidenceIndex,
    EvidenceRecord,
    IdentityIdentifier,
    ObservedState,
    Operation,
    Phase,
    ResolutionStatus,
    ResolvedSubject,
    ResourceObservation,
    StepState,
)
from code.rebirth_integration import build_rebirth_frontend_payload


T = datetime(2026, 1, 1, tzinfo=timezone.utc)
IDS = (IdentityIdentifier("email", "person@example.test"),)


def evidence(evidence_id: str, at: datetime = T, content: str = "indexed") -> EvidenceRecord:
    return EvidenceRecord(evidence_id, "fixture.json", "fixture", at, at, "json", "line:1", content)


class RebirthPipelineAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subject = ResolvedSubject(ResolutionStatus.UNIQUE, "user-1")

    def test_partial_live_inputs_are_indeterminate_not_no_reappearance(self) -> None:
        index = EvidenceIndex((evidence("later", T + timedelta(days=4)),))
        later = ResourceObservation(
            "profile_service", "profile-1", "USER_PROFILE", ObservedState.PRESENT,
            IDS, T + timedelta(days=4), ("later",),
        )
        payload = build_rebirth_frontend_payload(
            self.subject, T + timedelta(days=1), (later,), index, T + timedelta(days=5),
        )
        finding = payload["findings"][0]
        self.assertEqual(finding["status"], "INDETERMINATE")
        self.assertEqual(payload["input_summary"]["complete_snapshots"], 0)
        self.assertFalse(payload["input_summary"]["scope_established"])

    def test_confirmed_reappearance_uses_actual_indexed_absence_observation(self) -> None:
        index = EvidenceIndex(tuple(evidence(name, T + timedelta(days=day)) for name, day in (
            ("baseline", 0), ("deleted", 2), ("later", 4),
        )))
        baseline = ResourceObservation(
            "primary_db", "profile-1", "USER_PROFILE", ObservedState.PRESENT,
            IDS, T, ("baseline",),
        )
        verification = ResourceObservation(
            "primary_db", "profile-1", "USER_PROFILE", ObservedState.ABSENT,
            IDS, T + timedelta(days=2), ("deleted",),
        )
        later = ResourceObservation(
            "search_service", "profile-2", "USER_PROFILE", ObservedState.PRESENT,
            IDS, T + timedelta(days=4), ("later",),
        )
        decision = AuditDecision(DeletionStatus.INCOMPLETE, (
            AuditStep(1, Phase.FINDING, "search_service", "profile-2",
                      Operation.REPORT_REMAINING_RECORD, StepState.PRESENT, "later"),
            AuditStep(2, Phase.REMEDIATION, "search_service", "profile-2",
                      Operation.DELETE_RECORD, StepState.ABSENT, ""),
            AuditStep(3, Phase.VERIFICATION, "search_service", "profile-2",
                      Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, ""),
        ))
        payload = build_rebirth_frontend_payload(
            self.subject,
            T + timedelta(days=1),
            (baseline, verification, later),
            index,
            T + timedelta(days=5),
            decision,
        )
        finding = payload["findings"][0]
        self.assertEqual(finding["status"], "CONFIRMED_REAPPEARANCE")
        self.assertEqual(finding["deletion_evidence_ids"], ["deleted"])
        self.assertEqual([item["kind"] for item in finding["trail"]], [
            "ORIGINAL", "DELETION_VERIFIED", "REAPPEARED",
        ])

    def test_future_or_uncited_verification_step_is_not_used(self) -> None:
        index = EvidenceIndex((evidence("baseline"), evidence("later", T + timedelta(days=4))))
        baseline = ResourceObservation(
            "profile_service", "profile-1", "USER_PROFILE", ObservedState.PRESENT,
            IDS, T, ("baseline",),
        )
        later = ResourceObservation(
            "profile_service", "profile-1", "USER_PROFILE", ObservedState.PRESENT,
            IDS, T + timedelta(days=4), ("later",),
        )
        decision = AuditDecision(DeletionStatus.INCOMPLETE, (
            AuditStep(1, Phase.FINDING, "profile_service", "profile-1",
                      Operation.REPORT_REMAINING_RECORD, StepState.PRESENT, "later"),
            AuditStep(2, Phase.REMEDIATION, "profile_service", "profile-1",
                      Operation.DELETE_RECORD, StepState.ABSENT, ""),
            AuditStep(3, Phase.VERIFICATION, "profile_service", "profile-1",
                      Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT, ""),
        ))
        payload = build_rebirth_frontend_payload(
            self.subject, T + timedelta(days=1), (baseline, later), index,
            T + timedelta(days=5), decision,
        )
        self.assertEqual(payload["findings"][0]["status"], "POSSIBLE_REAPPEARANCE")
        self.assertEqual(payload["findings"][0]["deletion_evidence_ids"], [])


if __name__ == "__main__":
    unittest.main()
