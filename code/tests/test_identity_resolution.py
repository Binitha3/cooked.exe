"""Focused unit tests for identity resolution and request intent."""

from __future__ import annotations

import unittest

from code.contracts import (
    IdentityIdentifier,
    IdentityProvenance,
    Intent,
    IntentDecision,
    ResolutionStatus,
    ResolvedSubject,
)
from code.identity_resolution import (
    classify_deletion_request,
    resolve_identity,
)


def snapshot(
    *,
    user_id: str = "user_01",
    email: str = "person@example.test",
    updated_at: str = "2025-01-01T00:00:00Z",
    phone: str = "+15550100000",
    email_hash: str = "a" * 64,
) -> dict[str, str]:
    return {
        "user_id": user_id,
        "name": "Example Person",
        "email": email,
        "phone": phone,
        "email_hash": email_hash,
        "updated_at": updated_at,
    }


def audit(
    *,
    audit_id: str = "audit_01",
    user_id: str = "user_01",
    event_time: str = "2024-12-01T00:00:00Z",
    field_name: str = "email",
    old_value: str = "former@example.test",
    new_value: str = "person@example.test",
) -> dict[str, str]:
    return {
        "audit_id": audit_id,
        "user_id": user_id,
        "event_time": event_time,
        "field_name": field_name,
        "old_value": old_value,
        "new_value": new_value,
    }


def resolve(email: str, identities, audit_log, *, requested_at="2025-01-10T00:00:00Z", audit_at="2025-02-01T00:00:00Z") -> ResolvedSubject:
    return resolve_identity(email, requested_at, audit_at, identities, audit_log)


def identifier_values(identifiers: tuple[IdentityIdentifier, ...]) -> dict[str, str]:
    return {identifier.identifier_type: identifier.value for identifier in identifiers}


class IdentityResolutionTests(unittest.TestCase):
    def test_current_email_matches_and_preserves_string_identifiers(self):
        result = resolve("person@example.test", [snapshot(user_id="user_001")], [])

        self.assertIs(result.resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(result.user_id, "user_001")
        self.assertEqual(identifier_values(result.current_identifiers)["email"], "person@example.test")
        self.assertEqual(identifier_values(result.current_identifiers)["phone"], "+15550100000")
        self.assertEqual(result.historical_identifiers, ())
        self.assertTrue(any(p.source == "user_identities.csv:matched_email" for p in result.identity_provenance))

    def test_historical_email_matches_with_audit_provenance(self):
        result = resolve("former@example.test", [snapshot()], [audit(audit_id="audit_077")])

        self.assertIs(result.resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(result.user_id, "user_01")
        self.assertEqual(identifier_values(result.current_identifiers)["email"], "person@example.test")
        self.assertIn("former@example.test", [item.value for item in result.historical_identifiers])
        self.assertTrue(any(p.audit_id == "audit_077" for p in result.identity_provenance))
        self.assertTrue(any(p.source == "user_audit_log.csv:matched_old_email" for p in result.identity_provenance))

    def test_post_snapshot_audit_reconstructs_current_and_historical_values(self):
        base = snapshot(email="before@example.test", updated_at="2025-01-01T00:00:00Z")
        change = audit(
            audit_id="audit_090",
            event_time="2025-01-05T00:00:00Z",
            old_value="before@example.test",
            new_value="after@example.test",
        )

        result = resolve("after@example.test", [base], [change])

        self.assertIs(result.resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(identifier_values(result.current_identifiers)["email"], "after@example.test")
        self.assertIn("before@example.test", [item.value for item in result.historical_identifiers])
        self.assertTrue(any(p.audit_id == "audit_090" for p in result.identity_provenance))

    def test_case_insensitive_email_match_does_not_strip_alias_parts(self):
        result = resolve("PERSON@EXAMPLE.TEST", [snapshot()], [])
        plus_tag = resolve("person+tag@example.test", [snapshot()], [])
        dotted_local = resolve("per.son@example.test", [snapshot()], [])

        self.assertIs(result.resolution_status, ResolutionStatus.UNIQUE)
        self.assertIs(plus_tag.resolution_status, ResolutionStatus.UNRESOLVED)
        self.assertIs(dotted_local.resolution_status, ResolutionStatus.UNRESOLVED)

    def test_audit_at_excludes_future_snapshot_and_audit_rows(self):
        future_snapshot = snapshot(email="future@example.test", updated_at="2025-03-01T00:00:00Z")
        future_event = audit(
            event_time="2025-03-01T00:00:00Z",
            old_value="earlier@example.test",
            new_value="future@example.test",
        )
        result = resolve(
            "future@example.test",
            [future_snapshot],
            [future_event],
            audit_at="2025-02-01T00:00:00Z",
        )

        self.assertIs(result.resolution_status, ResolutionStatus.UNRESOLVED)

    def test_post_cutoff_event_does_not_replace_current_snapshot_value(self):
        future_event = audit(
            event_time="2025-03-01T00:00:00Z",
            old_value="person@example.test",
            new_value="later@example.test",
        )
        result = resolve("person@example.test", [snapshot()], [future_event])

        self.assertIs(result.resolution_status, ResolutionStatus.UNIQUE)
        self.assertEqual(identifier_values(result.current_identifiers)["email"], "person@example.test")
        self.assertEqual(result.historical_identifiers, ())
        self.assertFalse(any(p.audit_id for p in result.identity_provenance))

    def test_conflicting_email_mapping_is_ambiguous(self):
        identities = [snapshot(user_id="user_01"), snapshot(user_id="user_02")]

        result = resolve("person@example.test", identities, [])

        self.assertIs(result.resolution_status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)

    def test_historical_email_collision_is_ambiguous(self):
        identities = [
            snapshot(user_id="user_01", email="first@example.test"),
            snapshot(user_id="user_02", email="second@example.test"),
        ]
        events = [
            audit(audit_id="audit_01", user_id="user_01", old_value="shared@example.test", new_value="first@example.test"),
            audit(audit_id="audit_02", user_id="user_02", old_value="shared@example.test", new_value="second@example.test"),
        ]

        result = resolve("shared@example.test", identities, events)

        self.assertIs(result.resolution_status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(result.user_id)
        self.assertEqual({p.audit_id for p in result.identity_provenance if p.audit_id}, {"audit_01", "audit_02"})

    def test_broken_audit_chain_is_ambiguous(self):
        events = [
            audit(audit_id="audit_01", old_value="old@example.test", new_value="middle@example.test"),
            audit(
                audit_id="audit_02",
                event_time="2025-01-05T00:00:00Z",
                old_value="unlinked@example.test",
                new_value="person@example.test",
            ),
        ]

        result = resolve("old@example.test", [snapshot()], events)

        self.assertIs(result.resolution_status, ResolutionStatus.AMBIGUOUS)
        self.assertIn("broken", result.resolution_explanation)

    def test_inconsistent_snapshot_and_latest_audit_value_is_ambiguous(self):
        result = resolve("former@example.test", [snapshot(email="different@example.test")], [audit()])

        self.assertIs(result.resolution_status, ResolutionStatus.AMBIGUOUS)
        self.assertIn("conflicts", result.resolution_explanation)

    def test_malformed_email_and_timestamps_fail_closed(self):
        self.assertIs(resolve("not-an-email", [snapshot()], []).resolution_status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(
            resolve_identity("person@example.test", "not-a-time", "2025-02-01T00:00:00Z", [snapshot()], []).resolution_status,
            ResolutionStatus.UNRESOLVED,
        )
        self.assertEqual(
            resolve_identity("person@example.test", "2025-01-01T00:00:00", "2025-02-01T00:00:00Z", [snapshot()], []).resolution_status,
            ResolutionStatus.UNRESOLVED,
        )
        malformed_snapshot = snapshot(updated_at="not-a-time")
        self.assertIs(resolve("person@example.test", [malformed_snapshot], []).resolution_status, ResolutionStatus.AMBIGUOUS)
        malformed_event = audit(event_time="not-a-time")
        self.assertIs(resolve("former@example.test", [], [malformed_event]).resolution_status, ResolutionStatus.AMBIGUOUS)

    def test_missing_snapshot_fields_mark_matched_identity_ambiguous(self):
        malformed = snapshot()
        malformed["phone"] = ""

        result = resolve("person@example.test", [malformed], [])

        self.assertIs(result.resolution_status, ResolutionStatus.AMBIGUOUS)


class RequestClassificationTests(unittest.TestCase):
    def test_explicit_english_deletion_request(self):
        decision = classify_deletion_request("Please erase my account and personal data.")
        self.assertEqual(decision.intent, "DELETE")

    def test_non_deletion_access_export_and_marketing_requests(self):
        for text in (
            "Please send me a copy of my data.",
            "I request access to the information stored about me.",
            "Unsubscribe me from marketing messages.",
            "Please remove me from the mailing list.",
        ):
            with self.subTest(text=text):
                self.assertEqual(classify_deletion_request(text).intent, "NOT_DELETE")

    def test_english_negation_is_not_deletion(self):
        self.assertEqual(
            classify_deletion_request("Please do not delete my account.").intent,
            "NOT_DELETE",
        )
        self.assertEqual(
            classify_deletion_request("I did not request deletion of my data.").intent,
            "NOT_DELETE",
        )

    def test_mixed_positive_and_negated_deletion_is_ambiguous(self):
        decision = classify_deletion_request(
            "Do not delete my profile, but erase my archived personal data."
        )
        self.assertEqual(decision.intent, "AMBIGUOUS")

    def test_japanese_and_korean_deletion_requests(self):
        for text in (
            "このアカウントの完全な削除をお願いします。",
            "내 계정과 개인정보의 영구 삭제를 요청합니다.",
        ):
            with self.subTest(text=text):
                self.assertEqual(classify_deletion_request(text).intent, "DELETE")

    def test_japanese_and_korean_negation_is_not_deletion(self):
        for text in (
            "アカウントを削除しないでください。",
            "계정을 삭제하지 마세요.",
        ):
            with self.subTest(text=text):
                self.assertEqual(classify_deletion_request(text).intent, "NOT_DELETE")

    def test_portuguese_spanish_and_french_requests_and_negations(self):
        deletion_requests = (
            "Solicito a exclusão permanente da minha conta.",
            "Solicito la eliminación permanente de mi cuenta.",
            "Je demande la suppression définitive de mon compte.",
        )
        non_deletion_requests = (
            "Não solicito a exclusão da minha conta.",
            "No solicito la eliminación de mi cuenta.",
            "Je ne demande pas la suppression de mon compte.",
        )
        for text in deletion_requests:
            with self.subTest(text=text):
                self.assertEqual(classify_deletion_request(text).intent, "DELETE")
        for text in non_deletion_requests:
            with self.subTest(text=text):
                self.assertEqual(classify_deletion_request(text).intent, "NOT_DELETE")

    def test_non_english_non_deletion_and_ambiguous_text(self):
        self.assertEqual(
            classify_deletion_request("私のデータをダウンロードしてください。").intent,
            "NOT_DELETE",
        )
        self.assertEqual(classify_deletion_request("Deletion is discussed in this notice.").intent, "AMBIGUOUS")
        self.assertEqual(classify_deletion_request("").intent, "AMBIGUOUS")
        self.assertEqual(classify_deletion_request(None).intent, "AMBIGUOUS")  # type: ignore[arg-type]


class SharedContractIntegrationTests(unittest.TestCase):
    def test_return_values_are_shared_contract_instances(self):
        decision = classify_deletion_request("Please erase my account and personal data.")
        subject = resolve("former@example.test", [snapshot()], [audit(audit_id="audit_123")])

        self.assertIsInstance(decision, IntentDecision)
        self.assertIs(decision.intent, Intent.DELETE)
        self.assertIsInstance(subject, ResolvedSubject)
        self.assertIs(subject.resolution_status, ResolutionStatus.UNIQUE)
        self.assertTrue(all(isinstance(item, IdentityIdentifier) for item in subject.current_identifiers))
        self.assertTrue(all(isinstance(item, IdentityIdentifier) for item in subject.historical_identifiers))
        self.assertTrue(all(isinstance(item, IdentityProvenance) for item in subject.identity_provenance))
        self.assertTrue(any(item.audit_id == "audit_123" for item in subject.identity_provenance))

    def test_non_unique_results_conform_to_contract_without_asserting_user(self):
        ambiguous = resolve(
            "person@example.test",
            [snapshot(user_id="user_01"), snapshot(user_id="user_02")],
            [],
        )
        unresolved = resolve("unknown@example.test", [snapshot()], [])

        self.assertIsInstance(ambiguous, ResolvedSubject)
        self.assertIs(ambiguous.resolution_status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(ambiguous.user_id)
        self.assertIs(unresolved.resolution_status, ResolutionStatus.UNRESOLVED)
        self.assertIsNone(unresolved.user_id)


if __name__ == "__main__":
    unittest.main()
