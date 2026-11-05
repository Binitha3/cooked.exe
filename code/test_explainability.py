"""Explainability and preview-only simulator tests against shared contracts."""
import unittest
from datetime import datetime, timezone

from code.contracts import (
    ActivityEvent, AuditDecision, AuditStep, DeletionRule, DeletionStatus, EvidenceIndex,
    EvidenceRecord, IdentityAuditEvent, IdentityIdentifier, ObservedState, Operation, Phase,
    ResourceObservation, ResourceRelationship, StepState,
)
from code.explainability import (
    RiskCategory, Severity, explain_decision, simulate_what_if,
)
from code.policy_engine import evaluate

NOW=datetime(2026,11,4,12,tzinfo=timezone.utc)

def evidence(eid="ev1", status="PARSED"):
    return EvidenceRecord(eid,"dataset/evidence/records/source.json","unit",NOW,None,"json","$.records[0]",
                          "source evidence",parser_status=status,confidence=.95)

def incomplete(op=Operation.REPORT_REMAINING_RECORD, sys="account_service", rid="profile", eid="ev1", verify=Operation.VERIFY_RECORD_ABSENT):
    finding=AuditStep(1,Phase.FINDING,sys,rid,op,StepState.ACTIVE if op in (Operation.REPORT_ACTIVE_DATA_FLOW,Operation.REPORT_RESTORE_RISK) else StepState.PRESENT,eid)
    remap={Operation.REPORT_REMAINING_RECORD:(Operation.DELETE_RECORD,StepState.ABSENT),Operation.REPORT_EXPOSED_PII:(Operation.REDACT_RECORD,StepState.REDACTED),Operation.REPORT_ACTIVE_DATA_FLOW:(Operation.DISABLE_DATA_FLOW,StepState.DISABLED),Operation.REPORT_RESTORE_RISK:(Operation.BLOCK_RESTORE,StepState.BLOCKED)}
    rop,rstate=remap[op]
    vstate={Operation.VERIFY_RECORD_ABSENT:StepState.ABSENT,Operation.VERIFY_RECORD_REDACTED:StepState.REDACTED,Operation.VERIFY_RECORD_ANONYMIZED:StepState.ANONYMIZED,Operation.VERIFY_DATA_FLOW_DISABLED:StepState.DISABLED,Operation.VERIFY_RESTORE_BLOCKED:StepState.BLOCKED}[verify]
    return AuditDecision(DeletionStatus.INCOMPLETE,(finding,AuditStep(2,Phase.REMEDIATION,sys,rid,rop,rstate,""),AuditStep(3,Phase.VERIFICATION,sys,rid,verify,vstate,"")))

class ExplainabilityTests(unittest.TestCase):
    def test_residual_record_explains_policy_evidence_and_action(self):
        obs=ResourceObservation("account_service","profile","USER_PROFILE",ObservedState.PRESENT,evidence_references=("ev1",))
        rule=DeletionRule("rule1","USER_PROFILE","Always","DELETE")
        report=explain_decision(incomplete(),[obs],[rule],EvidenceIndex((evidence(),)))
        card=report.risk_cards[0]
        self.assertEqual(card.category,RiskCategory.RESIDUAL_PERSONAL_DATA)
        self.assertEqual(card.severity,Severity.HIGH)
        self.assertIn("requires deletion",card.what_was_discovered)
        self.assertEqual(card.applicable_policy[0]["rule_id"],"rule1")
        self.assertEqual(card.recommended_action,"DELETE_RECORD")
        self.assertEqual(card.evidence[0].source_file,"dataset/evidence/records/source.json")
        self.assertEqual(card.evidence[0].locator,"$.records[0]")
        self.assertTrue(card.verification_requirements)

    def test_severity_rules_for_flow_and_restore(self):
        for op,category,severity in ((Operation.REPORT_ACTIVE_DATA_FLOW,RiskCategory.ACTIVE_DATA_FLOW,Severity.HIGH),(Operation.REPORT_RESTORE_RISK,RiskCategory.RESTORE_RISK,Severity.CRITICAL)):
            decision=incomplete(op,rid="flow",verify=Operation.VERIFY_DATA_FLOW_DISABLED if op is Operation.REPORT_ACTIVE_DATA_FLOW else Operation.VERIFY_RESTORE_BLOCKED)
            obs=ResourceObservation("account_service","flow","SYNC_FLOW",ObservedState.ACTIVE,evidence_references=("ev1",))
            card=explain_decision(decision,[obs],[],EvidenceIndex((evidence(),))).risk_cards[0]
            self.assertEqual((card.category,card.severity),(category,severity))

    def test_missing_evidence_source_is_explicit_uncertainty(self):
        obs=ResourceObservation("account_service","profile","USER_PROFILE",ObservedState.PRESENT,evidence_references=("ev1",))
        report=explain_decision(incomplete(),[obs],[DeletionRule("r","USER_PROFILE","Always","DELETE")],EvidenceIndex())
        self.assertIsNone(report.risk_cards[0].evidence[0].source_file)
        self.assertTrue(any("absent from the supplied evidence index" in s for s in report.risk_cards[0].uncertainty))

    def test_complete_verification_requires_indexed_evidence(self):
        step=AuditStep(1,Phase.VERIFICATION,"account_service","profile",Operation.VERIFY_RECORD_ABSENT,StepState.ABSENT,"missing")
        decision=AuditDecision(DeletionStatus.COMPLETE,(step,))
        with self.assertRaisesRegex(ValueError,"absent from supplied catalogs"):
            explain_decision(decision,[],[],EvidenceIndex())

    def test_complete_verification_rejects_activity_or_audit_only_citations(self):
        activity=ActivityEvent("act1",NOW,"DELETE","account_service","account_service","profile","success")
        audit=IdentityAuditEvent("audit1","user1",NOW,"email","old@example.invalid",None)
        for evidence_id,activity_events,audit_events,error in (
            ("act1",(activity,),(),"activity-only claim"),
            ("audit1",(),(audit,),"identity-audit history alone"),
        ):
            with self.subTest(evidence_id=evidence_id):
                step=AuditStep(1,Phase.VERIFICATION,"account_service","profile",Operation.VERIFY_RECORD_ABSENT,StepState.ABSENT,evidence_id)
                decision=AuditDecision(DeletionStatus.COMPLETE,(step,))
                with self.assertRaisesRegex(ValueError,error):
                    explain_decision(decision,[],[],EvidenceIndex(),activity_events,audit_events)

    def test_complete_verification_payload_carries_source_locator_and_timestamp(self):
        step=AuditStep(1,Phase.VERIFICATION,"account_service","profile",Operation.VERIFY_RECORD_ABSENT,StepState.ABSENT,"ev1")
        decision=AuditDecision(DeletionStatus.COMPLETE,(step,))
        obs=ResourceObservation("account_service","profile","USER_PROFILE",ObservedState.ABSENT,evidence_references=("ev1",))
        report=explain_decision(decision,[obs],[DeletionRule("d","USER_PROFILE","Always","DELETE")],EvidenceIndex((evidence(),)))
        check=report.verification_requirements[0]
        self.assertEqual(check.evidence[0].evidence_id,"ev1")
        self.assertEqual(check.evidence[0].source_file,"dataset/evidence/records/source.json")
        self.assertEqual(check.evidence[0].locator,"$.records[0]")
        self.assertEqual(check.evidence[0].captured_at,NOW.isoformat())
        self.assertIn("absent",check.evidence_that_would_verify[0])

    def test_retained_record_gets_non_violation_explanation(self):
        step=AuditStep(1,Phase.VERIFICATION,"security_service","audit",Operation.VERIFY_RECORD_PRESENT,StepState.PRESENT,"ev1")
        decision=AuditDecision(DeletionStatus.COMPLETE,(step,))
        obs=ResourceObservation("security_service","audit","SECURITY_AUDIT_LOG",ObservedState.PRESENT,evidence_references=("ev1",))
        rule=DeletionRule("ret","SECURITY_AUDIT_LOG","retention applies","RETAIN")
        card=explain_decision(decision,[obs],[rule],EvidenceIndex((evidence(),))).risk_cards[0]
        self.assertEqual(card.category,RiskCategory.RETENTION_CONDITION)
        self.assertFalse(card.is_policy_violation)
        self.assertEqual(card.recommended_action,"RETAIN")

    def test_redact_and_anonymize_findings_recommend_policy_action(self):
        cases=(
            ("SUPPORT_MESSAGE","shared_context","Conversation contains shared customer, agent, or order context that must be retained","REDACT",IdentityIdentifier("email","subject"),Operation.REDACT_RECORD),
            ("ANALYTICS_PROFILE","attributable","Record is still attributable to a user","ANONYMIZE",IdentityIdentifier("user_id","subject"),Operation.ANONYMIZE_RECORD),
        )
        for category,fact,condition,action,identifier,expected in cases:
            obs=ResourceObservation("s","r",category,ObservedState.PRESENT,(identifier,),evidence_references=("ev1",),
                relationships=(ResourceRelationship(f"policy_fact:{fact}=true","policy","r"),))
            rules=(DeletionRule("rule",category,condition,action),)
            decision=evaluate([obs],rules)
            report=explain_decision(decision,[obs],rules,EvidenceIndex((evidence(),)))
            self.assertEqual(report.risk_cards[0].recommended_action,expected.value)

    def test_what_if_is_preview_only_and_lists_remaining_downstream(self):
        decision=incomplete()
        profile=ResourceObservation("account_service","profile","USER_PROFILE",ObservedState.PRESENT,evidence_references=("ev1",))
        downstream=ResourceObservation("search_service","search","SEARCH_INDEX_ENTRY",ObservedState.PRESENT,
             relationships=(ResourceRelationship("downstream_of","account_service","profile"),))
        report=explain_decision(decision,[profile,downstream],[DeletionRule("r","USER_PROFILE","Always","DELETE")],EvidenceIndex((evidence(),)))
        preview=simulate_what_if(report,report.risk_cards[0].risk_id,Operation.DELETE_RECORD,[profile,downstream],decision)
        self.assertTrue(preview.simulation_only)
        self.assertTrue(preview.action_addresses_finding)
        self.assertEqual(preview.decision_status_after_preview,"INCOMPLETE")
        self.assertEqual(preview.expected_risk_reduction,(RiskCategory.RESIDUAL_PERSONAL_DATA.value,))
        self.assertEqual(preview.downstream_resources_remaining[0]["resource_id"],"search")
        self.assertTrue(preview.verification_requirements)
        self.assertTrue(preview.verification_requirements[0].evidence_that_would_verify)
        mismatch=simulate_what_if(report,report.risk_cards[0].risk_id,Operation.REDACT_RECORD,[profile],decision)
        self.assertFalse(mismatch.action_addresses_finding)
        self.assertFalse(mismatch.expected_risk_reduction)

if __name__=="__main__": unittest.main()
