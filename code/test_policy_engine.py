"""Policy engine tests using the shared contracts."""
import unittest
from pathlib import Path

from code.contracts import (
    AuditDecision, DeletionRule, DeletionStatus, IdentityIdentifier, ObservedState,
    Operation, Phase, ResourceObservation, ResourceRelationship, StepState,
)
from code.policy_engine import PolicyConditionError, evaluate, load_policy

ROOT = Path(__file__).resolve().parents[1]

def obs(category, resource="r", state=ObservedState.PRESENT, facts=(), ids=(), refs=("ev",), rels=()):
    fact_rels=tuple(ResourceRelationship(f"policy_fact:{k}={'true' if v else 'false'}", "policy", resource) for k,v in facts)
    return ResourceObservation("sys", resource, category, state, tuple(ids), evidence_references=tuple(refs), relationships=fact_rels+tuple(rels))

class PolicyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.rules=load_policy(ROOT/"dataset"/"deletion_rules.csv")

    def test_policy_loads_exact_actions(self):
        self.assertEqual({r.required_action for r in self.rules},{"DELETE","REDACT","ANONYMIZE","RETAIN"})
        self.assertTrue(all(isinstance(r,DeletionRule) for r in self.rules))

    def test_all_actions_and_contract_object_types(self):
        observations=[
            obs("USER_PROFILE",resource="profile",state=ObservedState.PRESENT),
            obs("SUPPORT_MESSAGE",resource="message",facts=(("shared_context",True),),ids=(IdentityIdentifier("email","x"),)),
            obs("ANALYTICS_PROFILE",resource="analytics",facts=(("attributable",True),),state=ObservedState.PRESENT,ids=(IdentityIdentifier("user_id","u"),)),
            obs("SECURITY_AUDIT_LOG",resource="audit",facts=(("within_retention_period",True),)),
        ]
        decision=evaluate(observations,self.rules)
        self.assertIsInstance(decision,AuditDecision)
        self.assertEqual(decision.deletion_status,DeletionStatus.INCOMPLETE)
        self.assertTrue(all(isinstance(s, __import__('code.contracts',fromlist=['AuditStep']).AuditStep) for s in decision.steps))
        self.assertIn(Operation.DELETE_RECORD,[s.operation for s in decision.steps])
        self.assertIn(Operation.REDACT_RECORD,[s.operation for s in decision.steps])
        self.assertIn(Operation.ANONYMIZE_RECORD,[s.operation for s in decision.steps])
        self.assertIn(Operation.VERIFY_RECORD_PRESENT,[s.operation for s in decision.steps])

    def test_conditional_rule_requires_explicit_true_or_false_fact(self):
        with self.assertRaises(PolicyConditionError): evaluate([obs("SUPPORT_ATTACHMENT")],self.rules)
        # Explicit false means no policy rule applies; without positive proof of
        # any final required state the engine must not invent COMPLETE.
        with self.assertRaises(ValueError): evaluate([obs("SUPPORT_ATTACHMENT",facts=(("subject_only_attachment",False),))],self.rules)

    def test_tombstone_requires_stable_user_id_and_no_direct_identifiers(self):
        bad=obs("ACCOUNT_TOMBSTONE",facts=(("tombstone_stable_reference_required",True),),ids=(IdentityIdentifier("user_id","u"),IdentityIdentifier("email","x")),state=ObservedState.REDACTED)
        decision=evaluate([bad],self.rules)
        self.assertEqual(decision.deletion_status,DeletionStatus.INCOMPLETE)
        self.assertIn(Operation.REDACT_RECORD,[s.operation for s in decision.steps])
        good=obs("ACCOUNT_TOMBSTONE",facts=(("tombstone_stable_reference_required",True),),ids=(IdentityIdentifier("user_id","u"),),state=ObservedState.REDACTED)
        self.assertEqual(evaluate([good],self.rules).deletion_status,DeletionStatus.COMPLETE)

    def test_backup_retention_and_restore_block(self):
        backup=obs("BACKUP_ARCHIVE",resource="backup",facts=(("restore_blockable",True),),state=ObservedState.PRESENT)
        restore=obs("RESTORE_FLOW",resource="restore",state=ObservedState.ACTIVE,rels=(ResourceRelationship("restore_path","backup_service","backup"),))
        decision=evaluate([backup,restore],self.rules)
        self.assertEqual(decision.deletion_status,DeletionStatus.INCOMPLETE)
        self.assertIn(Operation.VERIFY_RECORD_PRESENT,[s.operation for s in decision.steps])
        self.assertIn(Operation.BLOCK_RESTORE,[s.operation for s in decision.steps])
        self.assertIn(Operation.VERIFY_RESTORE_BLOCKED,[s.operation for s in decision.steps])

    def test_dependency_relationship_orders_downstream_copy_before_source(self):
        source=obs("USER_PROFILE",resource="z-source")
        copy=obs("SEARCH_INDEX_ENTRY",resource="a-copy",rels=(ResourceRelationship("downstream_of","sys","z-source"),))
        decision=evaluate([source,copy],self.rules)
        edits=[s for s in decision.steps if s.phase is Phase.REMEDIATION]
        self.assertEqual([s.resource_id for s in edits],["a-copy","z-source"])

    def test_findings_keep_evidence_future_steps_empty_and_sequence_valid(self):
        decision=evaluate([obs("USER_PROFILE")],self.rules)
        self.assertEqual([s.step_no for s in decision.steps],list(range(1,len(decision.steps)+1)))
        findings=[s for s in decision.steps if s.phase is Phase.FINDING]
        proposed=[s for s in decision.steps if s.phase in (Phase.REMEDIATION,Phase.VERIFICATION)]
        self.assertTrue(all(s.evidence_id=="ev" for s in findings))
        self.assertTrue(all(s.evidence_id=="" for s in proposed))
        self.assertTrue(all((s.phase,s.operation) in __import__('code.contracts',fromlist=['ALLOWED_OPERATION_STATES']).ALLOWED_OPERATION_STATES and __import__('code.contracts',fromlist=['ALLOWED_OPERATION_STATES']).ALLOWED_OPERATION_STATES[(s.phase,s.operation)] is s.state for s in decision.steps))

    def test_active_flow_is_only_found_with_explicit_marker(self):
        unsupported=obs("UNCLASSIFIED",state=ObservedState.ACTIVE)
        with self.assertRaises(ValueError): evaluate([unsupported],self.rules)
        supported=obs("SYNC_FLOW",resource="flow",state=ObservedState.ACTIVE,rels=(ResourceRelationship("sync_flow","integration","dst"),))
        d=evaluate([supported],self.rules)
        self.assertEqual(d.deletion_status,DeletionStatus.INCOMPLETE)
        self.assertIn(Operation.DISABLE_DATA_FLOW,[s.operation for s in d.steps])

if __name__=="__main__": unittest.main()
