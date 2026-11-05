"""Pipeline integration tests using actual policy-engine and shared objects."""
import json
import unittest
from datetime import datetime, timezone

from code.contracts import (
    DeletionRule, EvidenceIndex, EvidenceRecord, IdentityIdentifier, ObservedState,
    Operation, ResourceObservation, ResourceRelationship,
)
from code.explainability_adapter import build_frontend_payload, preview_frontend_action
from code.policy_engine import evaluate

NOW=datetime(2026,11,4,12,tzinfo=timezone.utc)

def ev():
    return EvidenceIndex((EvidenceRecord("e1","dataset/evidence/fixture.json","test",NOW,None,"json","$.resource","evidence",confidence=.9),))

class ExplainabilityAdapterTests(unittest.TestCase):
    def test_actual_policy_decisions_cover_delete_redact_anonymize_and_retain(self):
        cases=(
            (ResourceObservation("s","r1","USER_PROFILE",ObservedState.PRESENT,evidence_references=("e1",)),
             DeletionRule("del","USER_PROFILE","Always","DELETE"),Operation.DELETE_RECORD,"Residual personal data"),
            (ResourceObservation("s","r2","SUPPORT_MESSAGE",ObservedState.PRESENT,(IdentityIdentifier("email","x"),),evidence_references=("e1",),relationships=(ResourceRelationship("policy_fact:shared_context=true","policy","r2"),)),
             DeletionRule("red","SUPPORT_MESSAGE","Conversation contains shared customer, agent, or order context that must be retained","REDACT"),Operation.REDACT_RECORD,"Exposed PII"),
            (ResourceObservation("s","r3","ANALYTICS_PROFILE",ObservedState.PRESENT,(IdentityIdentifier("user_id","u"),),evidence_references=("e1",),relationships=(ResourceRelationship("policy_fact:attributable=true","policy","r3"),)),
             DeletionRule("anon","ANALYTICS_PROFILE","Record is still attributable to a user","ANONYMIZE"),Operation.ANONYMIZE_RECORD,"Exposed PII"),
        )
        for observation,rule,action,category in cases:
            decision=evaluate([observation],[rule])
            handoff=build_frontend_payload(decision,[observation],[rule],ev())
            payload=handoff.to_dict()
            self.assertEqual(payload["schema_version"],"1.0")
            self.assertTrue(any(s.operation is action for s in decision.steps))
            self.assertEqual(payload["investigation"]["risk_cards"][0]["category"],category)
            json.dumps(payload)
            risk_id=payload["investigation"]["risk_cards"][0]["risk_id"]
            preview=preview_frontend_action(handoff,risk_id,action,[observation],decision)
            self.assertTrue(preview["action_addresses_finding"])
            self.assertTrue(preview["verification_requirements"])
            self.assertEqual(preview["decision_status_after_preview"],"INCOMPLETE")
        retained=ResourceObservation("s","r4","SECURITY_AUDIT_LOG",ObservedState.PRESENT,evidence_references=("e1",),relationships=(ResourceRelationship("policy_fact:within_retention_period=true","policy","r4"),))
        retention_rule=DeletionRule("retain","SECURITY_AUDIT_LOG","Record is within the supplied retention period","RETAIN")
        report=build_frontend_payload(evaluate([retained],[retention_rule]),[retained],[retention_rule],ev()).to_dict()["investigation"]
        card=report["risk_cards"][0]
        self.assertEqual(card["category"],"Retention or legal-hold condition")
        self.assertFalse(card["is_policy_violation"])

    def test_actual_active_flow_and_restore_actions_preview_without_mutation(self):
        for category, marker, expected in (("SYNC_FLOW","sync_flow",Operation.DISABLE_DATA_FLOW),("RESTORE_FLOW","restore_path",Operation.BLOCK_RESTORE)):
            obs=ResourceObservation("integration",category.lower(),category,ObservedState.ACTIVE,evidence_references=("e1",),relationships=(ResourceRelationship(marker,"backup_service","backup"),))
            decision=evaluate([obs],[])
            handoff=build_frontend_payload(decision,[obs],[],ev())
            risk=handoff.to_dict()["investigation"]["risk_cards"][0]["risk_id"]
            before=(decision,obs)
            preview=preview_frontend_action(handoff,risk,expected,[obs],decision)
            self.assertTrue(preview["simulation_only"])
            self.assertTrue(preview["action_addresses_finding"])
            self.assertEqual(preview["decision_status_after_preview"],"INCOMPLETE")
            self.assertTrue(preview["expected_risk_reduction"])
            self.assertTrue(preview["verification_requirements"])
            self.assertEqual((decision,obs),before)

    def test_missing_indexed_evidence_is_visible_not_compliant(self):
        obs=ResourceObservation("s","r","USER_PROFILE",ObservedState.PRESENT,evidence_references=("e1",))
        decision=evaluate([obs],[DeletionRule("d","USER_PROFILE","Always","DELETE")])
        handoff=build_frontend_payload(decision,[obs],[DeletionRule("d","USER_PROFILE","Always","DELETE")],EvidenceIndex())
        card=handoff.to_dict()["investigation"]["risk_cards"][0]
        self.assertEqual(decision.deletion_status.value,"INCOMPLETE")
        self.assertIsNone(card["evidence"][0]["source_file"])
        self.assertTrue(card["uncertainty"])

if __name__=="__main__": unittest.main()
