"""Deletion policy evaluation using the shared pipeline contracts.

Condition facts are carried by ResourceRelationship.relationship using the
explicit ``policy_fact:<name>=true|false`` convention. Missing facts fail with
PolicyConditionError; they are never treated as satisfied or inapplicable.
Resource relationships may also express dependency edges with
``downstream_of``/``replica_of``/``copy_of``/``depends_on`` in the downstream
observation's relationships.
"""
from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Iterable, Sequence

from .contracts import (
    ALLOWED_OPERATION_STATES,
    OPERATION_ORDER,
    AuditDecision,
    AuditStep,
    DeletionRule,
    DeletionStatus,
    ObservedState,
    Operation,
    Phase,
    ResourceObservation,
    StepState,
)


class PolicyConditionError(ValueError):
    """Raised when evidence does not resolve a policy condition."""


_ACTIONS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}
_CONDITION_FACTS = {
    "conversation contains shared customer, agent, or order context that must be retained": "shared_context",
    "attachment belongs only to the deletion subject": "subject_only_attachment",
    "record is still attributable to a user": "attributable",
    "log contains a user email address": "contains_user_email",
    "record is within the supplied retention period": "within_retention_period",
    "a supplied legal hold is active": "legal_hold_active",
    "restore access can be blocked": "restore_blockable",
    "account is deleted and only a stable internal user_id is needed to preserve references to retained records": "tombstone_stable_reference_required",
}
_DIRECT_ID_TYPES = {"name", "email", "phone", "email_hash", "full_name"}
_FLOW_MARKERS = {"sync_flow", "import_flow", "data_flow", "active_sync", "active_import"}
_RESTORE_MARKERS = {"restore_path", "backup_restore", "restore_flow"}
_DEPENDENCY_RELATIONS = {"downstream_of", "replica_of", "copy_of", "depends_on"}


def load_policy(path: str | Path) -> list[DeletionRule]:
    """Load deletion_rules.csv using its exact shared contract schema."""
    expected = ["rule_id", "data_category", "condition", "required_action"]
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected:
            raise ValueError(f"Expected policy columns {expected!r}, got {reader.fieldnames!r}")
        result: list[DeletionRule] = []
        seen: set[str] = set()
        for line, row in enumerate(reader, 2):
            if any(not (row.get(k) or "").strip() for k in expected):
                raise ValueError(f"Empty policy field at CSV line {line}")
            rule = DeletionRule(row["rule_id"].strip(), row["data_category"].strip(),
                                row["condition"].strip(), row["required_action"].strip().upper())
            if rule.rule_id in seen:
                raise ValueError(f"Duplicate rule_id {rule.rule_id!r}")
            seen.add(rule.rule_id)
            if rule.required_action not in _ACTIONS:
                raise ValueError(f"Unsupported policy action {rule.required_action!r} at line {line}")
            result.append(rule)
    return result


def _facts(observation: ResourceObservation) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for relationship in observation.relationships:
        marker = relationship.relationship.strip().casefold()
        match = re.fullmatch(r"policy_fact:([a-z0-9_]+)=(true|false)", marker)
        if match:
            key, value = match.groups()
            parsed = value == "true"
            if key in result and result[key] != parsed:
                raise PolicyConditionError(f"Conflicting policy fact {key!r} for {observation.resource_id}")
            result[key] = parsed
    return result


def _condition_fact(condition: str) -> str:
    normalized = " ".join(condition.casefold().split())
    if normalized == "always":
        return ""
    fact = _CONDITION_FACTS.get(normalized)
    if fact is None:
        raise PolicyConditionError(f"Unsupported policy condition: {condition!r}")
    return fact


def _rule_for(observation: ResourceObservation, rules: Sequence[DeletionRule]) -> DeletionRule | None:
    category_rules = [r for r in rules if r.data_category.casefold() == observation.data_category.casefold()]
    applicable: list[DeletionRule] = []
    facts = _facts(observation)
    for rule in category_rules:
        fact = _condition_fact(rule.condition)
        if not fact:
            applicable.append(rule)
            continue
        if fact not in facts:
            raise PolicyConditionError(
                f"Missing policy fact {fact!r} for {observation.system_id}/{observation.resource_id}"
            )
        if facts[fact]:
            applicable.append(rule)
    if len(applicable) > 1:
        raise PolicyConditionError(f"Multiple applicable rules for {observation.data_category}")
    return applicable[0] if applicable else None


def _has_direct_identifiers(observation: ResourceObservation) -> bool:
    return any(identifier.identifier_type.casefold() in _DIRECT_ID_TYPES for identifier in observation.identifiers)


def _treatment_ok(observation: ResourceObservation, action: str) -> tuple[bool, Operation, StepState]:
    state = observation.observed_state
    if action == "DELETE":
        return state is ObservedState.ABSENT, Operation.VERIFY_RECORD_ABSENT, StepState.ABSENT
    if action == "REDACT":
        is_tombstone = observation.data_category.casefold() == "account_tombstone"
        stable_ref = any(i.identifier_type.casefold() == "user_id" for i in observation.identifiers)
        ok = state is ObservedState.REDACTED and not _has_direct_identifiers(observation)
        if is_tombstone:
            ok = ok and stable_ref
        return ok, Operation.VERIFY_RECORD_REDACTED, StepState.REDACTED
    if action == "ANONYMIZE":
        return state is ObservedState.ANONYMIZED and not observation.identifiers, Operation.VERIFY_RECORD_ANONYMIZED, StepState.ANONYMIZED
    if action == "RETAIN":
        return state is ObservedState.PRESENT, Operation.VERIFY_RECORD_PRESENT, StepState.PRESENT
    raise ValueError(f"Unsupported policy action: {action}")


def _step(phase: Phase, system_id: str, resource_id: str, operation: Operation,
          state: StepState, evidence_id: str) -> AuditStep:
    expected = ALLOWED_OPERATION_STATES.get((phase, operation))
    if expected is not state:
        raise ValueError(f"Invalid {phase.value}/{operation.value}/{state.value} combination")
    return AuditStep(1, phase, system_id, resource_id, operation, state, evidence_id)


def _flow_type(observation: ResourceObservation) -> str | None:
    if observation.observed_state is not ObservedState.ACTIVE:
        return None
    names = {r.relationship.casefold().strip() for r in observation.relationships}
    if observation.data_category.casefold() == "backup_archive" or names & _RESTORE_MARKERS:
        return "restore"
    if names & _FLOW_MARKERS:
        return "flow"
    return None


def _verified_control_state(observation: ResourceObservation) -> tuple[Operation, StepState] | None:
    """Return a verification operation only for directly marked terminal controls."""
    markers = {
        relationship.relationship.casefold().strip()
        for relationship in observation.relationships
        if relationship.system_id == observation.system_id
        and relationship.resource_id == observation.resource_id
    }
    if (
        observation.data_category.casefold() == "data_flow"
        and observation.observed_state is ObservedState.DISABLED
        and markers & _FLOW_MARKERS
    ):
        return Operation.VERIFY_DATA_FLOW_DISABLED, StepState.DISABLED
    if (
        observation.data_category.casefold() == "restore_flow"
        and observation.observed_state is ObservedState.BLOCKED
        and markers & _RESTORE_MARKERS
    ):
        return Operation.VERIFY_RESTORE_BLOCKED, StepState.BLOCKED
    return None


def _dependency_order(edits: list[AuditStep], observations: Sequence[ResourceObservation]) -> list[AuditStep]:
    """Stable topo sort; for downstream relation, remediate copy before source."""
    keys: dict[tuple[str, str], AuditStep] = {}
    for step in edits:
        key = (step.system_id, step.resource_id)
        existing = keys.get(key)
        if existing is None:
            keys[key] = step
        elif (existing.operation, existing.state) != (step.operation, step.state):
            raise ValueError(
                "Conflicting remediation actions for the same resource: "
                f"{step.system_id}/{step.resource_id}"
            )
        # Repeated observations can independently establish the same required
        # action for one resource. Keep one remediation step for that resource;
        # exact duplicate citations are collapsed later by _ordered().
    by_resource: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for key in keys:
        by_resource.setdefault(key, []).append(key)
    edges: dict[tuple[str, str], set[tuple[str, str]]] = {k: set() for k in keys}
    indegree = {k: 0 for k in keys}
    for obs in observations:
        child = (obs.system_id, obs.resource_id)
        if child not in keys:
            continue
        for rel in obs.relationships:
            if rel.relationship.casefold().strip() not in _DEPENDENCY_RELATIONS:
                continue
            for parent in by_resource.get((rel.system_id, rel.resource_id), ()):
                if parent != child and parent not in edges[child]:
                    edges[child].add(parent)
                    indegree[parent] += 1
    op_order = {op: n for n, op in enumerate(OPERATION_ORDER[Phase.REMEDIATION])}
    sortkey = lambda k: (op_order[keys[k].operation], keys[k].system_id, keys[k].resource_id)
    ready = sorted((k for k, degree in indegree.items() if degree == 0), key=sortkey)
    ordered: list[AuditStep] = []
    while ready:
        current = ready.pop(0)
        ordered.append(keys[current])
        for nxt in sorted(edges[current], key=sortkey):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                ready.append(nxt)
                ready.sort(key=sortkey)
    if len(ordered) != len(keys):
        raise ValueError("Cyclic resource dependency relationships")
    return ordered


def _ordered(steps: Iterable[AuditStep]) -> tuple[AuditStep, ...]:
    phase_rank = {Phase.FINDING: 0, Phase.REMEDIATION: 1, Phase.VERIFICATION: 2}
    operation_rank = {phase: {op: i for i, op in enumerate(ops)} for phase, ops in OPERATION_ORDER.items()}
    unique: dict[tuple[Phase, str, str, Operation, StepState, str], AuditStep] = {}
    for step in steps:
        key = (step.phase, step.system_id, step.resource_id, step.operation, step.state, step.evidence_id)
        unique.setdefault(key, step)
    return tuple(sorted(unique.values(), key=lambda s: (phase_rank[s.phase], operation_rank[s.phase][s.operation], s.system_id, s.resource_id, s.evidence_id)))


def evaluate(observations: Sequence[ResourceObservation], rules: Sequence[DeletionRule]) -> AuditDecision:
    """Evaluate observations under rules and return a validated shared decision.

    Caller must supply observations filtered to the request subject and audit_at.
    Active flows/restore paths are recognized only from ACTIVE observations with
    explicit relationship markers (``sync_flow``, ``import_flow``,
    ``data_flow``, ``restore_path``, ``backup_restore``, ``restore_flow``).
    Conditional facts use ``policy_fact:<name>=true|false`` relationships.
    """
    findings: list[AuditStep] = []
    violations: list[tuple[ResourceObservation, Operation, StepState]] = []
    complete_checks: list[AuditStep] = []
    flow_actions: list[AuditStep] = []
    flow_checks: list[AuditStep] = []
    unresolved: list[str] = []
    for observation in observations:
        flow = _flow_type(observation)
        refs = sorted(set(observation.evidence_references))
        verified_control = _verified_control_state(observation)
        if verified_control is not None:
            if not refs:
                unresolved.append(
                    f"completed control state lacks citation: {observation.system_id}/{observation.resource_id}"
                )
                continue
            operation, state = verified_control
            complete_checks.extend(
                _step(Phase.VERIFICATION, observation.system_id, observation.resource_id, operation, state, ref)
                for ref in refs
            )
            # These are separate control observations, not records governed by
            # a retention/deletion rule. Their source observation remains in
            # the companion resource record when one exists.
            continue
        if flow:
            if not refs:
                unresolved.append(f"active recreation risk lacks citation: {observation.system_id}/{observation.resource_id}")
                flow = None
            else:
                restore = flow == "restore"
                fop = Operation.REPORT_RESTORE_RISK if restore else Operation.REPORT_ACTIVE_DATA_FLOW
                findings.extend(_step(Phase.FINDING, observation.system_id, observation.resource_id, fop, StepState.ACTIVE, ref) for ref in refs)
                mop = Operation.BLOCK_RESTORE if restore else Operation.DISABLE_DATA_FLOW
                mstate = StepState.BLOCKED if restore else StepState.DISABLED
                vop = Operation.VERIFY_RESTORE_BLOCKED if restore else Operation.VERIFY_DATA_FLOW_DISABLED
                flow_actions.append(_step(Phase.REMEDIATION, observation.system_id, observation.resource_id, mop, mstate, ""))
                flow_checks.append(_step(Phase.VERIFICATION, observation.system_id, observation.resource_id, vop, mstate, ""))
        try:
            rule = _rule_for(observation, rules)
        except PolicyConditionError as exc:
            unresolved.append(str(exc))
            continue
        if rule is None:
            continue
        if rule.required_action not in _ACTIONS:
            raise ValueError(f"Unsupported policy action {rule.required_action!r}")
        ok, verify_op, verify_state = _treatment_ok(observation, rule.required_action)
        if ok:
            if not refs:
                raise ValueError(f"Compliant observation lacks evidence: {observation.resource_id}")
            if not flow:
                complete_checks.extend(_step(Phase.VERIFICATION, observation.system_id, observation.resource_id,
                                             verify_op, verify_state, ref) for ref in refs)
            continue
        if observation.observed_state is ObservedState.UNKNOWN:
            unresolved.append(f"Unknown resource state for applicable policy: {observation.resource_id}")
            continue
        if not refs:
            raise ValueError(f"Policy violation lacks evidence: {observation.resource_id}")
        if rule.required_action == "DELETE":
            fop = Operation.REPORT_REMAINING_RECORD
            mop, mstate = Operation.DELETE_RECORD, StepState.ABSENT
        elif rule.required_action in {"REDACT", "ANONYMIZE"}:
            fop = Operation.REPORT_EXPOSED_PII
            mop, mstate = ((Operation.REDACT_RECORD, StepState.REDACTED) if rule.required_action == "REDACT"
                           else (Operation.ANONYMIZE_RECORD, StepState.ANONYMIZED))
        else:
            # A required retained record is absent: it cannot be repaired by the
            # allowed deletion-operation vocabulary, so surface a clear blocker.
            raise ValueError(f"Required RETAIN record is absent and cannot be remediated safely: {observation.resource_id}")
        findings.extend(_step(Phase.FINDING, observation.system_id, observation.resource_id, fop, StepState.PRESENT, ref) for ref in refs)
        violations.append((observation, mop, mstate))
    if not violations and not flow_actions and unresolved:
        raise PolicyConditionError("Insufficient evidence to decide policy applicability or state: " + "; ".join(unresolved))
    if not violations and not flow_actions:
        steps = _ordered(complete_checks)
        if not steps:
            raise ValueError("Cannot establish COMPLETE without evidence-backed verification")
        steps = tuple(AuditStep(i, s.phase, s.system_id, s.resource_id, s.operation, s.state, s.evidence_id) for i, s in enumerate(steps, 1))
        return AuditDecision(DeletionStatus.COMPLETE, steps)
    edits = [_step(Phase.REMEDIATION, obs.system_id, obs.resource_id, op, state, "") for obs, op, state in violations]
    edits = flow_actions + _dependency_order(edits, observations)
    retained_checks = [_step(Phase.VERIFICATION, step.system_id, step.resource_id,
                             step.operation, step.state, "") for step in complete_checks]
    future_checks = flow_checks + retained_checks + [_step(Phase.VERIFICATION, obs.system_id, obs.resource_id,
                                        _verification_for_action(op), _verification_state_for_action(op), "")
                                   for obs, op, _ in violations]
    # Operation order from the shared contract takes precedence; dependency
    # edges order like-treatment dependent copies, where the contract permits.
    steps = _ordered([*findings, *edits, *future_checks])
    steps = tuple(AuditStep(i, s.phase, s.system_id, s.resource_id, s.operation, s.state, s.evidence_id) for i, s in enumerate(steps, 1))
    return AuditDecision(DeletionStatus.INCOMPLETE, steps)


def _verification_for_action(operation: Operation) -> Operation:
    return {Operation.DELETE_RECORD: Operation.VERIFY_RECORD_ABSENT,
            Operation.REDACT_RECORD: Operation.VERIFY_RECORD_REDACTED,
            Operation.ANONYMIZE_RECORD: Operation.VERIFY_RECORD_ANONYMIZED}[operation]


def _verification_state_for_action(operation: Operation) -> StepState:
    return {Operation.DELETE_RECORD: StepState.ABSENT,
            Operation.REDACT_RECORD: StepState.REDACTED,
            Operation.ANONYMIZE_RECORD: StepState.ANONYMIZED}[operation]


__all__ = ["PolicyConditionError", "evaluate", "load_policy"]
