import unittest
from datetime import datetime, timezone, timedelta
from code.contracts import EvidenceIndex, EvidenceRecord, IdentityIdentifier, ResolvedSubject
from code.rebirth_detection import *
T=datetime(2026,1,1,tzinfo=timezone.utc)
def ev(i,dt=T): return EvidenceRecord(i,'fixture.json','fixture',dt,None,'json','$','fixture')
def fixture(later=True, verified=True, exact=True, future=False):
    es=EvidenceIndex(tuple(ev(i,T+timedelta(days=10) if future and i=='later' else T) for i in ('base','delete','later','coverage')))
    sub=ResolvedSubject('UNIQUE','u1')
    ids=(IdentityIdentifier('email','a@x.test'),IdentityIdentifier('phone','111'))
    old=RecordEvidence('db','r1',T,ids,('base',))
    new=RecordEvidence('db2','r2',T+timedelta(days=2),ids if exact else ids[:1],('later',))
    dels=(DeletionVerification('db','r1',T+timedelta(days=1),('delete',),'ABSENT'),) if verified else ()
    cov=(SnapshotCoverage('db2',T+timedelta(days=3),('r2',),('coverage',),True),)
    return sub,[old],dels,[new] if later else [],es,cov
class RebirthTests(unittest.TestCase):
 def test_exact_confirmed(self):
  s,b,d,l,e,c=fixture(); self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.CONFIRMED_REAPPEARANCE)
 def test_partial_possible(self):
  s,b,d,l,e,c=fixture(exact=False); self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.POSSIBLE_REAPPEARANCE)
 def test_no_reappearance_requires_full_declared_coverage(self):
  s,b,d,l,e,c=fixture(later=False); x=detect_rebirth(s,b,d,l,e,T+timedelta(days=4),coverage=c,expected_systems=('db2',))[0]; self.assertEqual(x.status,RebirthStatus.NO_REAPPEARANCE)
 def test_missing_coverage_indeterminate(self):
  s,b,d,l,e,c=fixture(later=False); self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.INDETERMINATE)
 def test_missing_verification_not_confirmed(self):
  s,b,d,l,e,c=fixture(verified=False); self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.POSSIBLE_REAPPEARANCE)
 def test_unrelated_does_not_match(self):
  s,b,d,l,e,c=fixture(); l=[RecordEvidence('db2','other',T+timedelta(days=2),(IdentityIdentifier('email','z@x.test'),),('later',))]; self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.INDETERMINATE)
 def test_future_evidence_excluded(self):
  s,b,d,l,e,c=fixture(future=True); self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4))[0].status,RebirthStatus.INDETERMINATE)

 def test_supported_causes_require_event_text_and_resource_link(self):
  for cause, phrase in (("BACKUP_RESTORATION","restore event"),("SYNCHRONIZATION","synchronization trace"),("ACCIDENTAL_REIMPORT","re-import event")):
   with self.subTest(cause=cause):
    sub,b,d,l,e,c=fixture()
    cause_record=EvidenceRecord("cause","fixture.json","fixture",T,None,"json","$",f"{phrase}: source r1 to target r2")
    e=EvidenceIndex(e.records+(cause_record,))
    finding=detect_rebirth(sub,b,d,l,e,T+timedelta(days=4),causes=(CauseEvidence(cause,"db2","r2",T+timedelta(days=1, hours=12),("cause",)),))[0]
    self.assertEqual(finding.cause,cause)
 def test_irrelevant_content_and_missing_cause_evidence_are_unconfirmed(self):
  s,b,d,l,e,c=fixture(); c1=CauseEvidence("BACKUP_RESTORATION","db2","r2",T+timedelta(days=1,hours=12),("later",))
  self.assertIsNone(detect_rebirth(s,b,d,l,e,T+timedelta(days=4),causes=(c1,))[0].cause)
  c2=CauseEvidence("SYNCHRONIZATION","db2","r2",T+timedelta(days=1,hours=12),("absent",))
  self.assertIsNone(detect_rebirth(s,b,d,l,e,T+timedelta(days=4),causes=(c2,))[0].cause)
 def test_incomplete_or_future_coverage_is_indeterminate(self):
  s,b,d,l,e,c=fixture(later=False); c=(SnapshotCoverage("db2",T+timedelta(days=5),("r2",),("coverage",),False),)
  self.assertEqual(detect_rebirth(s,b,d,l,e,T+timedelta(days=4),coverage=c,expected_systems=("db2",))[0].status,RebirthStatus.INDETERMINATE)
 def test_duplicate_records_are_deterministically_reported(self):
  s,b,d,l,e,c=fixture(); found=detect_rebirth(s,b,d,l+[l[0]],e,T+timedelta(days=4)); self.assertEqual(len(found),2)


 def test_cause_requires_both_resource_ids_and_cutoff_evidence(self):
  s,b,d,l,e,c=fixture()
  for text,stamp in (("restore event source r1",T),("restore event source r1 target r2",T+timedelta(days=10))):
   with self.subTest(text=text):
    ex=EvidenceRecord("cause","f","f",stamp,None,"txt","$",text); exi=EvidenceIndex(e.records+(ex,))
    cause=CauseEvidence("BACKUP_RESTORATION","db2","r2",T+timedelta(days=1,hours=12),("cause",))
    self.assertIsNone(detect_rebirth(s,b,d,l,exi,T+timedelta(days=4),causes=(cause,))[0].cause)
 def test_conflicting_supported_causes_remain_unconfirmed(self):
  s,b,d,l,e,c=fixture(); evid=[]; causes=[]
  for name,verb,cause in (("c1","restore event","BACKUP_RESTORATION"),("c2","synchronization trace","SYNCHRONIZATION")):
   evid.append(EvidenceRecord(name,"f","f",T,None,"txt","$",f"{verb} source r1 target r2"))
   causes.append(CauseEvidence(cause,"db2","r2",T+timedelta(days=1,hours=12),(name,)))
  ex=EvidenceIndex(e.records+tuple(evid))
  self.assertIsNone(detect_rebirth(s,b,d,l,ex,T+timedelta(days=4),causes=causes)[0].cause)

if __name__=='__main__': unittest.main()

