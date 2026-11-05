"""Frontend adapter for the investigation pipeline's shared contract objects.

Member 4 can call :func:`build_frontend_payload` immediately after policy
evaluation and :func:`preview_frontend_action` from a risk-card action. Both
functions are pure transformations; the preview has no persistence or mutation
path. See ``EXPLAINABILITY_INTEGRATION.md`` for the stable JSON schema.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .contracts import (
    ActivityEvent,
    AuditDecision,
    DeletionRule,
    EvidenceIndex,
    IdentityAuditEvent,
    Operation,
    ResourceObservation,
)
from .explainability import ExplainableAudit, explain_decision, simulate_what_if


SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class FrontendHandoff:
    """In-memory report plus an explicit JSON serialization boundary."""

    report: ExplainableAudit

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "investigation": self.report.to_dict(),
            "simulator": {
                "mode": "preview_only",
                "allowed_actions": [
                    Operation.DELETE_RECORD.value,
                    Operation.REDACT_RECORD.value,
                    Operation.ANONYMIZE_RECORD.value,
                    Operation.DISABLE_DATA_FLOW.value,
                    Operation.BLOCK_RESTORE.value,
                ],
                "invocation": "preview_frontend_action(handoff, risk_id, proposed_action, observations, decision)",
            },
        }


def build_frontend_payload(
    decision: AuditDecision,
    observations: Sequence[ResourceObservation],
    rules: Sequence[DeletionRule],
    evidence_index: EvidenceIndex,
    activity: Sequence[ActivityEvent] = (),
    audit_events: Sequence[IdentityAuditEvent] = (),
) -> FrontendHandoff:
    """Adapt actual pipeline objects to a versioned frontend handoff."""
    report: ExplainableAudit = explain_decision(
        decision, observations, rules, evidence_index, activity, audit_events
    )
    return FrontendHandoff(report)


def preview_frontend_action(
    handoff: FrontendHandoff,
    risk_id: str,
    proposed_action: str | Operation,
    observations: Sequence[ResourceObservation],
    decision: AuditDecision,
) -> dict:
    """Return a serializable preview without applying the proposed operation."""
    if not isinstance(handoff, FrontendHandoff):
        raise TypeError("handoff must be the in-memory FrontendHandoff; JSON payloads are display-only")
    return simulate_what_if(handoff.report, risk_id, proposed_action, observations, decision).to_dict()


__all__ = ["FrontendHandoff", "SCHEMA_VERSION", "build_frontend_payload", "preview_frontend_action"]
