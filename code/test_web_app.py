"""End-to-end smoke tests for the local DEADBYTE API and audit journey."""

from __future__ import annotations

import json
import threading
import unittest
from urllib.request import Request, urlopen

from code.web_app import AuditHTTPServer, analyze_case, load_context


class DeadbyteWebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.context = load_context()

    def test_case_catalog_uses_real_request_rows(self) -> None:
        from code.web_app import case_catalog

        catalog = case_catalog(self.context)
        self.assertEqual(len(catalog), 550)
        self.assertEqual([item["case_id"] for item in catalog], sorted(self.context.requests))
        self.assertIn("request_text", catalog[0])
        self.assertIn("audit_at", catalog[0])
        sample = next(item for item in catalog if item["case_id"] == "case_16")
        self.assertEqual(sample["dataset_group"], "PUBLIC SAMPLE")

    def test_frontend_has_visible_navigation_to_integrated_features(self) -> None:
        from pathlib import Path

        html = (Path(__file__).parent / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('<nav class="feature-nav" aria-label="Investigation feature navigation">', html)
        for target in ("ghost-map-panel", "timeline-panel", "explainability-panel", "rebirth-panel"):
            self.assertIn(f'href="#{target}"', html)
        self.assertIn("Risks &amp; What-If", html)

    def test_case16_returns_real_findings_and_policy_plan_in_memory(self) -> None:
        result = analyze_case(self.context, "case_16")

        self.assertEqual(result["intent"], "DELETE")
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertEqual(result["pipeline_state"], "COMPLETE")
        self.assertFalse(result["deletion_executed"])
        graph = json.loads(result["ghost_data_map_json"])
        self.assertEqual(graph["schema_version"], "ghost-data-map.v1")
        self.assertTrue(any(node["node_type"] == "RESOURCE" for node in graph["nodes"]))
        node_ids = {node["node_id"] for node in graph["nodes"]}
        self.assertTrue(all(
            edge["source_node_id"] in node_ids and edge["destination_node_id"] in node_ids
            for edge in graph["edges"]
        ))
        findings = [step for step in result["steps"] if step["phase"] == "FINDING"]
        self.assertTrue(findings)
        self.assertTrue(all(step["evidence_id"] for step in findings))
        for observation in result["observations"]:
            for evidence_id in observation["evidence_references"]:
                self.assertIn(evidence_id, result["evidence"])
        self.assertEqual(result["explainability"]["investigation"]["deletion_status"], "INCOMPLETE")
        self.assertTrue(result["explainability"]["investigation"]["risk_cards"])
        self.assertEqual(result["rebirth"]["findings"][0]["status"], "INDETERMINATE")
        self.assertFalse(result["rebirth"]["input_summary"]["scope_established"])

    def test_case15_rebirth_is_uncertain_without_verified_deletion_and_coverage(self) -> None:
        result = analyze_case(self.context, "case_15")

        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertEqual(result["rebirth"]["findings"][0]["status"], "INDETERMINATE")
        self.assertEqual(result["rebirth"]["input_summary"]["deletion_verifications"], 0)
        self.assertEqual(result["rebirth"]["input_summary"]["complete_snapshots"], 0)
        self.assertEqual(result["explainability"]["investigation"]["deletion_status"], "INCOMPLETE")
        self.assertTrue(any(card["category"] == "Active data flow" for card in result["explainability"]["investigation"]["risk_cards"]))

    def test_case26_verification_only_searches_but_never_returns_remediation(self) -> None:
        result = analyze_case(self.context, "case_26")

        self.assertEqual(result["intent"], "VERIFY_ONLY")
        self.assertEqual(result["pipeline_state"], "POLICY_UNRESOLVED")
        self.assertIsNone(result["deletion_status"])
        self.assertTrue(result["observations"], "verification-only authorization should permit evidence discovery")
        self.assertEqual(result["steps"], [])
        self.assertFalse(result["deletion_executed"])
        self.assertIn("no new remediation is authorized", result["message"].casefold())

    def test_activity_references_keep_source_event_provenance(self) -> None:
        result = analyze_case(self.context, "case_33")

        activity_refs = {
            evidence_id: item
            for evidence_id, item in result["evidence"].items()
            if item["source_type"] == "ACTIVITY_EVENT"
        }
        self.assertTrue(activity_refs)
        for evidence_id, item in activity_refs.items():
            self.assertEqual(item["activity_id"], evidence_id)
            self.assertTrue(item["record_timestamp"])
            self.assertTrue(item["event_type"])
            self.assertTrue(item["resource_id"])

    def test_http_case_select_verify_and_evidence_drawer_payload(self) -> None:
        server = AuditHTTPServer(("127.0.0.1", 0), self.context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(f"{base_url}/api/cases") as response:
                cases = json.loads(response.read())
            self.assertEqual(len(cases["cases"]), 550)

            body = json.dumps({"case_id": "case_15"}).encode("utf-8")
            request = Request(
                f"{base_url}/api/verify",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request) as response:
                result = json.loads(response.read())
            self.assertEqual(result["deletion_status"], "INCOMPLETE")
            graph = json.loads(result["ghost_data_map_json"])
            self.assertEqual(graph["schema_version"], "ghost-data-map.v1")
            self.assertEqual(graph["audit_at"], result["case"]["audit_at"])
            flow_node = next(
                node for node in graph["nodes"]
                if node["resource_id"] == "data_flow_9846"
            )
            self.assertEqual(flow_node["observed_state"], "ACTIVE")
            self.assertEqual(flow_node["evidence_ids"], ["evidence_01"])
            flow_provenance = flow_node["provenance"][0]
            self.assertIn("tr-9750867", flow_provenance["trace_ids"])
            self.assertEqual(set(flow_provenance["source_locators"]), {"line:85", "line:88"})
            # The participant evidence correlates the subject and flow but does
            # not identify both endpoints, so no propagation edge is invented.
            self.assertFalse(any(edge["edge_type"] == "ACTIVE_DATA_FLOW" for edge in graph["edges"]))
            node_ids = {node["node_id"] for node in graph["nodes"]}
            self.assertTrue(all(
                edge["source_node_id"] in node_ids and edge["destination_node_id"] in node_ids
                for edge in graph["edges"]
            ))
            self.assertTrue(any(
                step["operation"] == "REPORT_ACTIVE_DATA_FLOW"
                and step["resource_id"] == "data_flow_9846"
                and step["evidence_id"] == "evidence_01"
                for step in result["steps"]
            ))
            trace = next(link for link in result["trace_links"] if link["resource_id"] == "data_flow_9846")
            self.assertEqual(trace["trace_id"], "tr-9750867")
            self.assertEqual(trace["identifier_locator"], "line:85")
            self.assertEqual(trace["resource_locator"], "line:88")

            risk = result["explainability"]["investigation"]["risk_cards"][0]
            what_if_request = Request(
                f"{base_url}/api/what-if",
                data=json.dumps({
                    "case_id": "case_15",
                    "risk_id": risk["risk_id"],
                    "proposed_action": risk["recommended_action"],
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(what_if_request) as response:
                preview = json.loads(response.read())
            self.assertTrue(preview["simulation_only"])
            self.assertEqual(preview["decision_status_after_preview"], "INCOMPLETE")
            self.assertFalse(result["deletion_executed"])
            after_preview = analyze_case(self.context, "case_15")
            self.assertEqual(after_preview["deletion_status"], "INCOMPLETE")
            self.assertFalse(after_preview["deletion_executed"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
