"""Explainable risk cards and preview-only remediation simulation.

The module only interprets an existing policy-engine decision. It never changes
records or upgrades an unresolved decision to COMPLETE. Severity is assigned by
the documented operation/action rubric below, not by free-form inference.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .contracts import (
    ActivityEvent,
    AuditDecision,
    AuditStep,
    DeletionRule,
    DeletionStatus,
    EvidenceIndex,
    EvidenceRecord,
    IdentityAuditEvent,
    Operation,
    Phase,
    ResourceObservation,
)


class RiskCategory(str, Enum):
    RESIDUAL_PERSONAL_DATA = "Residual personal data"
    EXPOSED_PII = "Exposed PII"
    ACTIVE_DATA_FLOW = "Active data flow"
    RESTORE_RISK = "Restore risk"
    RETENTION_CONDITION = "Retention or legal-hold condition"
    OTHER_POLICY_VIOLATION = "Other supported policy violations"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


SEVERITY_RULES: Mapping[str, str] = {
    "Critical": "A cited active restore path can recreate prohibited personal data.",
    "High": "A cited active data flow can propagate data, or a cited record violates DELETE/REDACT policy.",
    "Medium": "A cited record remains attributable where policy requires anonymization, or another supported policy violation is present.",
    "Low": "A policy-required retained record is present; this is disclosed as a compliant retention condition, not a deletion violation.",
}


@dataclass(frozen=True)
class EvidenceExplanation:
    evidence_id: str
    source_file: str | None
    locator: str | None
    captured_at: str | None
    record_timestamp: str | None
    supporting_observation: Mapping[str, Any]
    uncertainty: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationRequirement:
    system_id: str
    resource_id: str
    operation: str
    expected_state: str
    evidence_that_would_verify: tuple[str, ...]
    evidence: tuple[EvidenceExplanation, ...] = ()
    unresolved: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskCard:
    risk_id: str
    category: RiskCategory
    severity: Severity
    title: str
    what_was_discovered: str
    why_it_matters: str
    applicable_policy: tuple[Mapping[str, str], ...]
    potential_consequence: str
    evidence: tuple[EvidenceExplanation, ...]
    recommended_action: str
    verification_requirements: tuple[VerificationRequirement, ...]
    uncertainty: tuple[str, ...]
    is_policy_violation: bool = True


@dataclass(frozen=True)
class ExplainableAudit:
    deletion_status: DeletionStatus
    risk_cards: tuple[RiskCard, ...]
    verification_requirements: tuple[VerificationRequirement, ...]
    unresolved: tuple[str, ...]
    severity_rules: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "deletion_status": self.deletion_status.value,
            "risk_cards": [_jsonable(card) for card in self.risk_cards],
            "verification_requirements": [_jsonable(req) for req in self.verification_requirements],
            "unresolved": list(self.unresolved),
            "severity_rules": dict(self.severity_rules),
        }


@dataclass(frozen=True)
class WhatIfPreview:
    simulation_only: bool
    decision_status_after_preview: str
    finding_id: str
    proposed_action: str
    action_addresses_finding: bool
    expected_risk_reduction: tuple[str, ...]
    risk_reduction_scope: str
    dependencies_remaining: tuple[Mapping[str, str], ...]
    downstream_resources_remaining: tuple[Mapping[str, str], ...]
    verification_requirements: tuple[VerificationRequirement, ...]
    unresolved: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return _jsonable(self)


_FINDING_CATEGORY = {
    Operation.REPORT_REMAINING_RECORD: RiskCategory.RESIDUAL_PERSONAL_DATA,
    Operation.REPORT_EXPOSED_PII: RiskCategory.EXPOSED_PII,
    Operation.REPORT_ACTIVE_DATA_FLOW: RiskCategory.ACTIVE_DATA_FLOW,
    Operation.REPORT_RESTORE_RISK: RiskCategory.RESTORE_RISK,
}
_RECOMMENDED_ACTION = {
    Operation.REPORT_REMAINING_RECORD: Operation.DELETE_RECORD,
    Operation.REPORT_ACTIVE_DATA_FLOW: Operation.DISABLE_DATA_FLOW,
    Operation.REPORT_RESTORE_RISK: Operation.BLOCK_RESTORE,
}
_ACTION_TO_VERIFY = {
    Operation.DELETE_RECORD: Operation.VERIFY_RECORD_ABSENT,
    Operation.REDACT_RECORD: Operation.VERIFY_RECORD_REDACTED,
    Operation.ANONYMIZE_RECORD: Operation.VERIFY_RECORD_ANONYMIZED,
    Operation.DISABLE_DATA_FLOW: Operation.VERIFY_DATA_FLOW_DISABLED,
    Operation.BLOCK_RESTORE: Operation.VERIFY_RESTORE_BLOCKED,
}
_VERIFY_STATE = {
    Operation.VERIFY_RECORD_ABSENT: "ABSENT",
    Operation.VERIFY_RECORD_PRESENT: "PRESENT",
    Operation.VERIFY_RECORD_REDACTED: "REDACTED",
    Operation.VERIFY_RECORD_ANONYMIZED: "ANONYMIZED",
    Operation.VERIFY_DATA_FLOW_DISABLED: "DISABLED",
    Operation.VERIFY_RESTORE_BLOCKED: "BLOCKED",
}
_DIRECT_ID_TYPES = {"name", "full_name", "email", "phone", "email_hash"}
_DEP_LINKS = {"downstream_of", "replica_of", "copy_of", "depends_on"}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return {k: _jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value]
    return value


def _find_rule(obs: ResourceObservation | None, step: AuditStep, rules: Sequence[DeletionRule]) -> tuple[Mapping[str, str], ...]:
    if obs is None:
        return ()
    action = {
        Operation.REPORT_REMAINING_RECORD: "DELETE",
        Operation.REPORT_EXPOSED_PII: None,
    }.get(step.operation)
    candidates = [r for r in rules if r.data_category.casefold() == obs.data_category.casefold()]
    if action is not None:
        candidates = [r for r in candidates if r.required_action.upper() == action]
    elif step.operation is Operation.REPORT_EXPOSED_PII:
        candidates = [r for r in candidates if r.required_action.upper() in {"REDACT", "ANONYMIZE"}]
    return tuple({"rule_id": r.rule_id, "data_category": r.data_category,
                  "condition": r.condition, "required_action": r.required_action.upper()} for r in candidates)


def _evidence_detail(evidence_id: str, observation: ResourceObservation | None,
                    evidence_index: EvidenceIndex, activity: Mapping[str, ActivityEvent],
                    audits: Mapping[str, IdentityAuditEvent]) -> EvidenceExplanation:
    uncertainty: list[str] = []
    support: dict[str, Any] = {}
    if observation is not None:
        support = {
            "system_id": observation.system_id,
            "resource_id": observation.resource_id,
            "data_category": observation.data_category,
            "observed_state": observation.observed_state.value,
            "identifier_types": sorted({i.identifier_type for i in observation.identifiers}),
            "observation_timestamp": _iso(observation.observation_timestamp),
        }
    record = evidence_index.records_by_id.get(evidence_id)
    if record is not None:
        if record.parser_status.value != "PARSED":
            uncertainty.append(f"Evidence parser status is {record.parser_status.value}.")
        if record.confidence is None:
            uncertainty.append("Evidence confidence was not supplied.")
        return EvidenceExplanation(evidence_id, record.relative_path, record.locator,
                                   _iso(record.captured_at), _iso(record.record_timestamp), support,
                                   tuple(uncertainty))
    event = activity.get(evidence_id)
    if event is not None:
        support["activity_type"] = event.event_type
        support["reported_result_is_claim"] = event.reported_result
        uncertainty.append("Activity event is contextual evidence; reported_result alone does not prove resource state.")
        return EvidenceExplanation(evidence_id, "dataset/system_activity.csv", f"activity_id={event.activity_id}",
                                   _iso(event.event_time), None, support, tuple(uncertainty))
    audit = audits.get(evidence_id)
    if audit is not None:
        support.update({"field_name": audit.field_name, "user_id": audit.user_id})
        return EvidenceExplanation(evidence_id, "dataset/user_audit_log.csv", f"audit_id={audit.audit_id}",
                                   _iso(audit.event_time), _iso(audit.event_time), support, tuple(uncertainty))
    uncertainty.append("Evidence reference is absent from the supplied evidence index and event catalogs.")
    return EvidenceExplanation(evidence_id, None, None, None, None, support, tuple(uncertainty))


def _risk_severity(step: AuditStep, rule_rows: Sequence[Mapping[str, str]]) -> Severity:
    if step.operation is Operation.REPORT_RESTORE_RISK:
        return Severity.CRITICAL
    if step.operation is Operation.REPORT_ACTIVE_DATA_FLOW:
        return Severity.HIGH
    actions = {r["required_action"] for r in rule_rows}
    if "ANONYMIZE" in actions and "DELETE" not in actions and "REDACT" not in actions:
        return Severity.MEDIUM
    if actions & {"DELETE", "REDACT"}:
        return Severity.HIGH
    return Severity.MEDIUM


def _explanation(category: RiskCategory, obs: ResourceObservation | None, step: AuditStep,
                 rules: Sequence[Mapping[str, str]]) -> tuple[str, str, str]:
    resource = f"{step.system_id}/{step.resource_id}"
    data_category = obs.data_category if obs else "unclassified resource"
    policy_text = "; ".join(f"{r['data_category']} condition: {r['condition']} requires {r['required_action']}" for r in rules)
    policy_text = policy_text or "No matching policy rule was resolved from the supplied observations."
    if category is RiskCategory.RESIDUAL_PERSONAL_DATA:
        return (f"{data_category} resource {resource} is reported present although policy requires deletion.",
                "The remaining copy may continue to identify or be used to identify the subject.",
                "If retained, the copy may continue exposing personal data or be reintroduced into downstream systems.")
    if category is RiskCategory.EXPOSED_PII:
        id_types = ", ".join(sorted({i.identifier_type for i in obs.identifiers if i.identifier_type.casefold() in _DIRECT_ID_TYPES})) if obs else "identifier details unavailable"
        return (f"{data_category} resource {resource} is reported with identifiers requiring redaction or anonymization ({id_types}).",
                "Direct identifiers or a subject link remain where policy requires their removal.",
                "If left unresolved, the retained record may continue to identify the subject.")
    if category is RiskCategory.ACTIVE_DATA_FLOW:
        return (f"An explicitly marked active data flow remains at {resource}.",
                "It can copy or recreate prohibited data after record-level cleanup.",
                "If left active, deletion work may be undone by later synchronization or import.")
    if category is RiskCategory.RESTORE_RISK:
        return (f"An explicitly marked active restore path remains at {resource}.",
                "Restoring the affected backup could reintroduce deleted data.",
                "If restore access remains available, previously removed records may return.")
    return (f"A supported policy condition applies to {resource}.",
            "The record must follow the applicable retention or legal-hold requirement.",
            "Changing or removing a required record could violate the supplied retention condition.")


_VERIFICATION_EVIDENCE = {
    Operation.VERIFY_RECORD_ABSENT: "A timestamped query or snapshot showing the resource is absent in every relevant store or replica.",
    Operation.VERIFY_RECORD_PRESENT: "A timestamped snapshot showing the policy-required retained record remains available.",
    Operation.VERIFY_RECORD_REDACTED: "A timestamped record view showing prohibited identifiers are removed; for tombstones, the stable user_id remains.",
    Operation.VERIFY_RECORD_ANONYMIZED: "A timestamped record view plus linkage check showing the record can no longer be attributed to the subject.",
    Operation.VERIFY_DATA_FLOW_DISABLED: "A timestamped integration/job configuration and run-state view showing the flow is disabled.",
    Operation.VERIFY_RESTORE_BLOCKED: "A timestamped backup access-control or restore test showing the affected data cannot be restored.",
}


def _verification_requirements(decision: AuditDecision, card_step: AuditStep | None = None,
                               uncertainty: Sequence[str] = (),
                               observations: Mapping[tuple[str, str], ResourceObservation] | None = None,
                               evidence_index: EvidenceIndex | None = None,
                               activity: Mapping[str, ActivityEvent] | None = None,
                               audits: Mapping[str, IdentityAuditEvent] | None = None) -> tuple[VerificationRequirement, ...]:
    return tuple(
        VerificationRequirement(s.system_id, s.resource_id, s.operation.value,
                                _VERIFY_STATE[s.operation],
                                (_VERIFICATION_EVIDENCE[s.operation],),
                                tuple(_evidence_detail(s.evidence_id,
                                    (observations or {}).get((s.system_id, s.resource_id)),
                                    evidence_index or EvidenceIndex(), activity or {}, audits or {})
                                      for _ in (0,) if s.evidence_id),
                                tuple(uncertainty))
        for s in decision.steps
        if s.phase is Phase.VERIFICATION and
        (card_step is None or (s.system_id, s.resource_id) == (card_step.system_id, card_step.resource_id))
    )


def explain_decision(
    decision: AuditDecision,
    observations: Sequence[ResourceObservation],
    rules: Sequence[DeletionRule],
    evidence_index: EvidenceIndex,
    activity: Sequence[ActivityEvent] = (),
    audit_events: Sequence[IdentityAuditEvent] = (),
) -> ExplainableAudit:
    """Create stable frontend-ready explanations without changing the decision."""
    obs_by_key = {(o.system_id, o.resource_id): o for o in observations}
    activity_by_id = {a.activity_id: a for a in activity}
    audits_by_id = {a.audit_id: a for a in audit_events}
    cards: list[RiskCard] = []
    unresolved: list[str] = []
    for step in decision.steps:
        if step.phase is not Phase.FINDING:
            continue
        category = _FINDING_CATEGORY[step.operation]
        obs = obs_by_key.get((step.system_id, step.resource_id))
        rule_rows = _find_rule(obs, step, rules)
        evidence = (_evidence_detail(step.evidence_id, obs, evidence_index, activity_by_id, audits_by_id),)
        uncertainties = [u for item in evidence for u in item.uncertainty]
        if obs is None:
            uncertainties.append("No matching ResourceObservation was supplied for this finding.")
        if not rule_rows:
            uncertainties.append("Applicable policy rule could not be uniquely linked to this finding.")
        elif len(rule_rows) > 1:
            uncertainties.append("Multiple policy rules match this finding; condition-level selection is unresolved.")
        title = f"{category.value}: {step.system_id}/{step.resource_id}"
        what, why, consequence = _explanation(category, obs, step, rule_rows)
        action = _RECOMMENDED_ACTION.get(step.operation)
        if step.operation is Operation.REPORT_EXPOSED_PII:
            required = {r["required_action"] for r in rule_rows}
            action = (Operation.REDACT_RECORD if required == {"REDACT"} else
                      Operation.ANONYMIZE_RECORD if required == {"ANONYMIZE"} else None)
        recommended = action.value if action else "ADDITIONAL_VERIFICATION"
        stable = "|".join((step.system_id, step.resource_id, step.operation.value, step.evidence_id))
        risk_id = "risk_" + sha256(stable.encode("utf-8")).hexdigest()[:16]
        cards.append(RiskCard(risk_id, category, _risk_severity(step, rule_rows), title, what, why,
                              rule_rows, consequence, evidence, recommended,
                              _verification_requirements(decision, step, uncertainties, obs_by_key,
                                                         evidence_index, activity_by_id, audits_by_id), tuple(uncertainties)))
        unresolved.extend(uncertainties)
    # Required retained records are disclosed as compliant conditions, not risks.
    for step in decision.steps:
        if step.phase is not Phase.VERIFICATION or step.operation is not Operation.VERIFY_RECORD_PRESENT:
            continue
        obs = obs_by_key.get((step.system_id, step.resource_id))
        if not obs:
            continue
        matched = [r for r in rules if r.data_category.casefold() == obs.data_category.casefold()
                   and r.required_action.upper() == "RETAIN"]
        if not matched:
            continue
        evs = tuple(_evidence_detail(ref, obs, evidence_index, activity_by_id, audits_by_id)
                    for ref in obs.evidence_references)
        uncertainty = tuple(u for e in evs for u in e.uncertainty)
        title = f"Required retention: {step.system_id}/{step.resource_id}"
        stable = f"retain|{step.system_id}|{step.resource_id}|{step.evidence_id}"
        cards.append(RiskCard("risk_" + sha256(stable.encode()).hexdigest()[:16],
                              RiskCategory.RETENTION_CONDITION, Severity.LOW, title,
                              f"A {obs.data_category} record is present under a RETAIN policy.",
                              "This record is retained to satisfy the supplied policy condition and should not be deleted.",
                              tuple({"rule_id":r.rule_id,"data_category":r.data_category,"condition":r.condition,"required_action":r.required_action.upper()} for r in matched),
                              "Removing a required record could violate the stated retention or legal-hold requirement.",
                              evs, "RETAIN", _verification_requirements(decision, step, uncertainty, obs_by_key,
                                                                         evidence_index, activity_by_id, audits_by_id), uncertainty,
                              is_policy_violation=False))
    verifications = _verification_requirements(decision, observations=obs_by_key,
                                               evidence_index=evidence_index,
                                               activity=activity_by_id, audits=audits_by_id)
    if decision.deletion_status is DeletionStatus.COMPLETE:
        for step in decision.steps:
            if step.phase is Phase.VERIFICATION and step.evidence_id not in evidence_index.records_by_id:
                if step.evidence_id in activity_by_id:
                    raise ValueError(
                        f"COMPLETE verification cannot rely on activity-only claim: {step.evidence_id}"
                    )
                if step.evidence_id in audits_by_id:
                    raise ValueError(
                        f"COMPLETE verification cannot rely on identity-audit history alone: {step.evidence_id}"
                    )
            if step.evidence_id not in evidence_index.records_by_id and step.evidence_id not in activity_by_id and step.evidence_id not in audits_by_id:
                raise ValueError(f"COMPLETE verification cites evidence absent from supplied catalogs: {step.evidence_id}")
    return ExplainableAudit(decision.deletion_status, tuple(cards), verifications,
                            tuple(dict.fromkeys(unresolved)), dict(SEVERITY_RULES))


def simulate_what_if(report: ExplainableAudit, risk_id: str, proposed_action: str | Operation,
                     observations: Sequence[ResourceObservation], decision: AuditDecision) -> WhatIfPreview:
    """Preview a remediation action; this function never mutates observations."""
    card = next((c for c in report.risk_cards if c.risk_id == risk_id), None)
    if card is None:
        raise KeyError(f"Unknown finding id: {risk_id}")
    action = proposed_action if isinstance(proposed_action, Operation) else Operation(proposed_action)
    matched = action.value == card.recommended_action
    obs = next((o for o in observations if any(e.supporting_observation.get("resource_id") == o.resource_id and e.supporting_observation.get("system_id") == o.system_id for e in card.evidence)), None)
    dependencies: list[Mapping[str, str]] = []
    downstream: list[Mapping[str, str]] = []
    if obs:
        for rel in obs.relationships:
            if rel.relationship.casefold().strip() in _DEP_LINKS:
                dependencies.append({"system_id": rel.system_id, "resource_id": rel.resource_id, "relationship": rel.relationship})
        for candidate in observations:
            for rel in candidate.relationships:
                if rel.relationship.casefold().strip() in _DEP_LINKS and (rel.system_id, rel.resource_id) == (obs.system_id, obs.resource_id):
                    downstream.append({"system_id": candidate.system_id, "resource_id": candidate.resource_id, "relationship": rel.relationship})
    checks = tuple(v for v in report.verification_requirements
                   if (v.system_id, v.resource_id) == (card.evidence[0].supporting_observation.get("system_id"), card.evidence[0].supporting_observation.get("resource_id"))) if card.evidence else ()
    unresolved = list(card.uncertainty)
    if not matched:
        unresolved.append("Proposed action does not match the policy-derived recommended action; no risk reduction is credited.")
    if not checks:
        unresolved.append("No matching verification requirement is present; post-action evidence is still required.")
    reduction_scope = ("Resource-local preview only; related or downstream resources listed below remain unchanged."
                       if dependencies or downstream else
                       "This preview concerns the identified resource only; no record or process is changed.")
    return WhatIfPreview(True, decision.deletion_status.value, card.risk_id, action.value, matched,
                          (card.category.value,) if matched else (), reduction_scope,
                          tuple(dependencies), tuple(downstream),
                          checks, tuple(dict.fromkeys(unresolved)))


__all__ = ["EvidenceExplanation", "ExplainableAudit", "RiskCard", "RiskCategory", "SEVERITY_RULES",
           "Severity", "VerificationRequirement", "WhatIfPreview", "explain_decision", "simulate_what_if"]
