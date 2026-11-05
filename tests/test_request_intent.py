"""Tests for integration-level deletion versus verification authorization."""

import unittest

from code.contracts import Intent
from code.request_intent import classify_request_intent


class RequestIntentTests(unittest.TestCase):
    def test_explicit_new_deletion_request_remains_delete(self):
        decision = classify_request_intent("Please permanently delete all my personal data.")
        self.assertIs(decision.intent, Intent.DELETE)

    def test_prior_deletion_verification_is_verify_only(self):
        decision = classify_request_intent(
            "I submitted a deletion request earlier. Please verify it completed and confirm my profile is gone."
        )
        self.assertIs(decision.intent, Intent.VERIFY_ONLY)

    def test_general_data_question_does_not_authorize_deletion_or_verification(self):
        decision = classify_request_intent("What personal data do you currently have about me?")
        self.assertIs(decision.intent, Intent.AMBIGUOUS)

    def test_unclear_old_report_without_verification_action_remains_ambiguous(self):
        decision = classify_request_intent(
            "I found an old report about my account, but I am not sure what happened."
        )
        self.assertIs(decision.intent, Intent.AMBIGUOUS)

    def test_new_destructive_directive_is_not_downgraded_to_verification_only(self):
        decision = classify_request_intent(
            "I found an old report. Please delete my account now and confirm it is gone."
        )
        self.assertIs(decision.intent, Intent.DELETE)


if __name__ == "__main__":
    unittest.main()
