# Explainability handoff for Member 4

This module consumes existing shared contracts and policy decisions. It does not perform evidence extraction, policy evaluation, deletion, or status changes.

## Pipeline placement

Call the adapter after the investigation pipeline has produced the subject-filtered `ResourceObservation` list, `DeletionRule` list, `EvidenceIndex`, and `AuditDecision`:

```python
from code.explainability_adapter import build_frontend_payload

handoff = build_frontend_payload(
    decision=audit_decision,       # code.contracts.AuditDecision
    observations=observations,    # Sequence[ResourceObservation]
    rules=rules,                   # Sequence[DeletionRule]
    evidence_index=evidence_index, # EvidenceIndex
    activity=activity_events,      # optional Sequence[ActivityEvent]
    audit_events=audit_events,      # optional Sequence[IdentityAuditEvent]
)
frontend_json = handoff.to_dict()
```

`frontend_json` has this stable top-level shape:

```json
{
  "schema_version": "1.0",
  "investigation": {
    "deletion_status": "INCOMPLETE",
    "risk_cards": [],
    "verification_requirements": [],
    "unresolved": [],
    "severity_rules": {}
  },
  "simulator": {
    "mode": "preview_only",
    "allowed_actions": ["DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"],
    "invocation": "preview_frontend_action(handoff, risk_id, proposed_action, observations, decision)"
  }
}
```

Each risk card includes a stable `risk_id`, category, rubric-derived severity, discovery explanation, why it matters, matched policy rows, possible consequence, evidence references, recommended action, verification requirements, uncertainty, and `is_policy_violation`. Evidence cards use `EvidenceRecord.relative_path`, `locator`, `captured_at`, and `record_timestamp`; activity and audit references use their participant-facing CSV path and ID locator. Identifier values are not copied into the frontend payload; only identifier types are included.

## What-If preview

Keep the in-memory `FrontendHandoff` associated with the displayed investigation. When the user previews an action, call:

```python
from code.explainability_adapter import preview_frontend_action

preview_json = preview_frontend_action(
    handoff,
    risk_id=selected_risk_id,
    proposed_action="DELETE_RECORD",
    observations=observations,
    decision=audit_decision,
)
```

The result has `simulation_only: true`, the unchanged decision status, whether the action matches the recommendation, expected risk reduction, remaining dependencies/downstream resources, required verification, and uncertainty. JSON card data from the browser is display-only; pass the original in-memory handoff and actual pipeline objects to the adapter. No action is executed.

## Severity rubric

- **Critical:** an evidence-cited active restore path may reintroduce prohibited data.
- **High:** an evidence-cited active data flow can propagate data, or a record violates DELETE/REDACT policy.
- **Medium:** a record remains attributable where ANONYMIZE applies, or another supported policy violation exists.
- **Low:** a policy-required retained record is disclosed. Such a card has `is_policy_violation: false` and recommends `RETAIN`.

## Evidence and unresolved data

The adapter never supplies missing references or converts missing evidence to compliance. A missing index entry is surfaced as an uncertainty on the evidence explanation. A COMPLETE decision referencing an ID absent from all supplied evidence/event catalogs raises `ValueError`. Activity `reported_result` is explicitly labelled a claim and is not represented as proof of resource state. Evidence-processing must supply correctly subject-matched observations and catalog records before this adapter is called.

## Integrated application behavior

The local application calls `build_frontend_payload()` from `code/web_app.py` after identity resolution, evidence search, and policy evaluation. It passes the actual `AuditDecision`, cutoff-filtered observations and rules, the loaded `EvidenceIndex`, global activity, and identity audit events. The resulting versioned payload is displayed alongside the Ghost Data Map and the evidence timeline.

The web application retains the original in-memory `FrontendHandoff`, decision, and observations per case. `POST /api/what-if` accepts the case ID, risk ID, and proposed action, then calls `preview_frontend_action()` using those retained objects. Browser-supplied report JSON is never used as a decision input, and this endpoint performs no remediation.

Live Rebirth analysis is adapted by `code/rebirth_integration.py`. The current evidence parser does not establish complete snapshot coverage, so live negative findings remain `INDETERMINATE` unless complete, cutoff-valid coverage is supplied explicitly. See the evaluation report for the current case 26 and case 33 blockers.
