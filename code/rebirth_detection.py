"""Evidence-backed detection of deleted data reappearing in later systems.

Inputs are explicit observations produced by an evidence parser/caller. This
module does not inspect files or execute mutations. All timestamps are
timezone-aware and evidence captured after ``audit_at`` is excluded.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Iterable

from .contracts import EvidenceIndex, IdentityIdentifier, ResolvedSubject


class RebirthStatus(str, Enum):
    CONFIRMED_REAPPEARANCE = "CONFIRMED_REAPPEARANCE"
    POSSIBLE_REAPPEARANCE = "POSSIBLE_REAPPEARANCE"
    NO_REAPPEARANCE = "NO_REAPPEARANCE"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class RecordEvidence:
    system_id: str
    resource_id: str
    observed_at: datetime
    identifiers: tuple[IdentityIdentifier, ...]
    evidence_ids: tuple[str, ...]
    data_category: str = ""
    legitimate_retention: bool = False


@dataclass(frozen=True)
class DeletionVerification:
    system_id: str
    resource_id: str
    verified_at: datetime
    evidence_ids: tuple[str, ...]
    verified_state: str


@dataclass(frozen=True)
class SnapshotCoverage:
    """Explicit parser assertion that a system snapshot was completely examined."""
    system_id: str
    snapshot_at: datetime
    examined_resources: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    complete: bool


@dataclass(frozen=True)
class CauseEvidence:
    cause: str  # BACKUP_RESTORATION, SYNCHRONIZATION, ACCIDENTAL_REIMPORT
    system_id: str
    resource_id: str
    occurred_at: datetime
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class TrailEvent:
    kind: str
    timestamp: datetime
    system_id: str
    resource_id: str
    evidence_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class RebirthFinding:
    finding_id: str
    status: RebirthStatus
    original_system_id: str | None
    original_resource_id: str | None
    reappeared_system_id: str | None
    reappeared_resource_id: str | None
    baseline_evidence_ids: tuple[str, ...]
    deletion_evidence_ids: tuple[str, ...]
    later_evidence_ids: tuple[str, ...]
    match_explanation: str
    confidence: float
    cause: str | None
    cause_evidence_ids: tuple[str, ...]
    affected_system_id: str | None
    recommended_action: str
    follow_up_verification: str
    trail: tuple[TrailEvent, ...]


def _ids(records: Iterable[RecordEvidence], index: EvidenceIndex, cutoff: datetime) -> tuple[str, ...]:
    known = index.records_by_id
    return tuple(sorted({eid for r in records for eid in r.evidence_ids
                         if eid in known and known[eid].captured_at <= cutoff}))


def _cause_is_supported(cause: CauseEvidence, old: RecordEvidence, new: RecordEvidence,
                        evidence: EvidenceIndex, cutoff: datetime) -> bool:
    """Require event language and both resource references in evidence content."""
    if not cause.evidence_ids:
        return False
    records = evidence.records_by_id
    if any(eid not in records or records[eid].captured_at > cutoff for eid in cause.evidence_ids):
        return False
    patterns = {
        "BACKUP_RESTORATION": r"\b(?:restore|restored|restoration|restore event)\b",
        "SYNCHRONIZATION": r"\b(?:sync|synced|synchroniz(?:e|ed|ation)|replicat(?:e|ed|ion))\b",
        "ACCIDENTAL_REIMPORT": r"\b(?:import|imported|re-import|reimport|ingest(?:ed|ion))\b",
    }
    pattern = patterns.get(cause.cause)
    if pattern is None:
        return False
    text = " ".join(records[eid].extracted_content.casefold() for eid in cause.evidence_ids)
    required_refs = (old.resource_id, new.resource_id)
    return bool(re.search(pattern, text, re.I) and all(ref.casefold() in text for ref in required_refs))


def detect_rebirth(subject: ResolvedSubject, baseline: Iterable[RecordEvidence],
                   deletion_verifications: Iterable[DeletionVerification],
                   later_observations: Iterable[RecordEvidence], evidence: EvidenceIndex,
                   audit_at: datetime, causes: Iterable[CauseEvidence] = (),
                   coverage: Iterable[SnapshotCoverage] = (), expected_systems: Iterable[str] = ()) -> tuple[RebirthFinding, ...]:
    """Compare caller-supplied pre-deletion/later records for one resolved subject.

    Confirmation requires a matching baseline, an explicit successful deletion
    verification for that resource, and a later observed record with evidence.
    Exact identifier equality is confirmed; partial overlap is only possible.
    Cause is attributed only for an explicit resource-linked CauseEvidence with
    supporting indexed evidence. Missing/invalid inputs fail closed.
    """
    if audit_at.tzinfo is None or subject.user_id is None or subject.resolution_status.value != "UNIQUE":
        return ()
    base = [r for r in baseline if r.observed_at <= audit_at and _ids([r], evidence, audit_at)]
    dels = [d for d in deletion_verifications if d.verified_at <= audit_at and d.verified_state in {"ABSENT", "REDACTED", "ANONYMIZED"} and _ids([RecordEvidence(d.system_id,d.resource_id,d.verified_at,(),d.evidence_ids)],evidence,audit_at)]
    later = [r for r in later_observations if r.observed_at <= audit_at and _ids([r], evidence, audit_at)]
    findings=[]
    for old in base:
        oldmap={(i.identifier_type,i.value.casefold()) for i in old.identifiers}
        for new in later:
            newmap={(i.identifier_type,i.value.casefold()) for i in new.identifiers}
            overlap=oldmap & newmap
            if not overlap or new.legitimate_retention: continue
            verified=next((d for d in dels if d.system_id==old.system_id and d.resource_id==old.resource_id and d.verified_at<=new.observed_at),None)
            exact=oldmap==newmap
            status=RebirthStatus.CONFIRMED_REAPPEARANCE if verified and exact else RebirthStatus.POSSIBLE_REAPPEARANCE
            supported = [c for c in causes if c.system_id == new.system_id and c.resource_id == new.resource_id
                         and old.observed_at < c.occurred_at <= new.observed_at and c.occurred_at <= audit_at
                         and _cause_is_supported(c, old, new, evidence, audit_at)]
            # Conflicting supported explanations are not arbitrarily selected.
            cause = supported[0] if len({c.cause for c in supported}) == 1 and supported else None
            ids=tuple(sorted(set(old.evidence_ids+new.evidence_ids+(verified.evidence_ids if verified else ()))))
            trail=[TrailEvent("ORIGINAL",old.observed_at,old.system_id,old.resource_id,old.evidence_ids,"Pre-deletion record observed")]
            if verified: trail.append(TrailEvent("DELETION_VERIFIED",verified.verified_at,verified.system_id,verified.resource_id,verified.evidence_ids,"Deletion state explicitly verified"))
            trail.append(TrailEvent("REAPPEARED",new.observed_at,new.system_id,new.resource_id,new.evidence_ids,"Matching later record observed"))
            findings.append(RebirthFinding(f"rebirth:{old.resource_id}:{new.resource_id}",status,old.system_id,old.resource_id,new.system_id,new.resource_id,old.evidence_ids,verified.evidence_ids if verified else (),new.evidence_ids,"Exact identifier set match" if exact else f"Partial identifier overlap: {len(overlap)}",0.98 if exact and verified else 0.6,cause.cause if cause else None,cause.evidence_ids if cause else (),new.system_id,"Investigate and remove or redact according to policy","Capture a later snapshot and verify required state",tuple(sorted(trail,key=lambda e:e.timestamp))) )
    if findings: return tuple(findings)
    required = set(expected_systems)
    eligible_coverage = [c for c in coverage if c.complete and c.snapshot_at <= audit_at
                         and c.snapshot_at.tzinfo is not None
                         and _ids([RecordEvidence(c.system_id, "coverage", c.snapshot_at, (), c.evidence_ids)], evidence, audit_at)]
    covered = {c.system_id for c in eligible_coverage}
    # Empty/undeclared scope is never sufficient to prove global absence.
    enough = bool(base and dels and required and required.issubset(covered)
                  and all(c.examined_resources for c in eligible_coverage if c.system_id in required))
    status=RebirthStatus.NO_REAPPEARANCE if enough else RebirthStatus.INDETERMINATE
    return (RebirthFinding("rebirth:none",status,None,None,None,None,(),tuple(e for d in dels for e in d.evidence_ids),(),"No eligible matching observation" if enough else "Insufficient cutoff-eligible baseline, verification, or snapshot evidence",1.0 if enough else 0.0,None,(),None,"None" if enough else "Collect missing baseline/snapshot/verification evidence","Repeat comparison after evidence is available",()),)
