"""Contract/interface smoke tests for feature modules as they arrive."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import unittest
from typing import Any, get_type_hints

from code import contracts
from code.contracts import AuditDecision, DeletionStatus, OutputRow
from code.output import EXPECTED_REQUEST_COUNT


class FeatureInterfaceTests(unittest.TestCase):
    def test_output_contract_for_not_applicable_and_dataset_size(self):
        row = OutputRow.from_decision(
            "unit-case",
            AuditDecision(DeletionStatus.NOT_APPLICABLE, ()),
        )
        self.assertEqual(row.steps_json, "[]")
        self.assertEqual(EXPECTED_REQUEST_COUNT, 518)

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


if __name__ == "__main__":
    unittest.main()
