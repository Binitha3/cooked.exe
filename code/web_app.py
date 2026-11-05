"""Local web interface for the existing deletion-audit pipeline.

Run with ``python3 -m code.web_app`` from the repository root. The server binds
to localhost, serves the static DEADBYTE UI, and evaluates one selected request
in memory. It never writes or updates output.csv.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from code.contracts import (
    AuditDecision,
    DeletionStatus,
    Intent,
    OutputRow,
    ResolutionStatus,
)
from code.ghost_data_map import build_ghost_data_map_payload
from code.explainability_adapter import (
    build_frontend_payload,
    preview_frontend_action,
)
from code.main import (
    PipelineBlockedError,
    _adapt_trace_linked_active_flows,
    _identity_audit_rows_for_resolver,
    _identity_rows_for_resolver,
    _require_unique_subject,
    load_feature_modules,
    read_activity,
    read_deletion_rules,
    read_identities,
    read_identity_audit,
    read_requests,
    read_requests_file,
)
from code.rebirth_integration import build_rebirth_frontend_payload
from code.request_intent import classify_request_intent


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPOSITORY_ROOT / "dataset"
STATIC_ROOT = Path(__file__).resolve().parent / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


@dataclass
class AuditContext:
    repository_root: Path
    dataset_root: Path
    requests: dict[str, Any]
    request_sources: dict[str, str]
    identities: list[Any]
    identity_audit: list[Any]
    activity: list[Any]
    rules: list[Any]
    modules: Any
    demo_mode: bool = False
    evidence_index: Any = None
    analysis_state_by_case: dict[str, dict[str, Any]] = field(default_factory=dict)


def load_context(repository_root: Path = REPOSITORY_ROOT) -> AuditContext:
    dataset_root = repository_root / "dataset"
    demo_mode = os.environ.get("DEADBYTE_DEMO_MODE", "").strip().casefold() in {
        "1", "true", "yes", "on"
    }
    sample_requests = read_requests_file(
        dataset_root / "sample_deletion_requests.csv",
        expected_count=32,
    )
    evaluation_requests = [] if demo_mode else read_requests(dataset_root)
    all_requests = [*sample_requests, *evaluation_requests]
    return AuditContext(
        repository_root=repository_root,
        dataset_root=dataset_root,
        requests={request.case_id: request for request in all_requests},
        request_sources={
            **{request.case_id: "PUBLIC SAMPLE" for request in sample_requests},
            **{request.case_id: "EVALUATION" for request in evaluation_requests},
        },
        identities=read_identities(dataset_root),
        identity_audit=read_identity_audit(dataset_root),
        activity=read_activity(dataset_root),
        rules=read_deletion_rules(dataset_root),
        modules=load_feature_modules(),
        demo_mode=demo_mode,
    )


def case_catalog(context: AuditContext) -> list[dict[str, str]]:
    """Return request metadata only; case results are computed on demand."""
    return [
        {
            "case_id": request.case_id,
            "dataset_group": context.request_sources[request.case_id],
            "email": _mask_email(request.email),
            "requested_at": request.requested_at.isoformat(),
            "audit_at": request.audit_at.isoformat(),
            "reported_status": request.reported_status.value,
            "request_text": request.request_text,
        }
        for request in sorted(context.requests.values(), key=lambda item: item.case_id)
    ]


def analyze_case(context: AuditContext, case_id: str) -> dict[str, Any]:
    """Run the real single-request pipeline without writing submission output."""
    request = context.requests.get(case_id)
    if request is None:
        raise KeyError(f"Unknown case_id: {case_id}")

    base: dict[str, Any] = {
        "case": case_catalog_item(context, case_id),
        "intent": None,
        "resolution_status": None,
        "user_id": None,
        "deletion_status": None,
        "pipeline_state": "NOT_RUN",
        "steps": [],
        "observations": [],
        "trace_links": [],
        "ghost_data_map_json": None,
        "ghost_data_map_error": None,
        "explainability": None,
        "explainability_error": None,
        "rebirth": None,
        "evidence": {},
        "residual_count": None,
        "message": "Run evidence verification to evaluate this request.",
        "deletion_executed": False,
    }

    try:
        intent_decision = classify_request_intent(
            request.request_text,
            context.modules.identity_resolution.classify_deletion_request,
        )
    except Exception as exc:
        return _blocked(base, "INTENT_UNRESOLVED", f"Intent classification failed: {exc}")
    base["intent"] = intent_decision.intent.value

    if intent_decision.intent is Intent.AMBIGUOUS:
        return _blocked(
            base,
            "INTENT_AMBIGUOUS",
            "The request does not clearly authorize deletion. No identity or evidence search was run.",
        )

    if intent_decision.intent is Intent.NOT_DELETE:
        row = OutputRow.from_decision(
            request.case_id,
            AuditDecision(DeletionStatus.NOT_APPLICABLE, ()),
        )
        return _result_from_row(base, row)

    try:
        subject = context.modules.identity_resolution.resolve_identity(
            request.email,
            request.requested_at,
            request.audit_at,
            _identity_rows_for_resolver(context.identities),
            _identity_audit_rows_for_resolver(context.identity_audit),
        )
        base["resolution_status"] = subject.resolution_status.value
        if subject.resolution_status is not ResolutionStatus.UNIQUE or subject.user_id is None:
            return _blocked(
                base,
                "IDENTITY_UNRESOLVED",
                f"Identity resolution is {subject.resolution_status.value}; no deletion decision was made.",
            )
        subject = _require_unique_subject(request.case_id, subject)
        base["user_id"] = subject.user_id

        if context.evidence_index is None:
            context.evidence_index = context.modules.evidence_processing.load_evidence(
                context.dataset_root / "evidence_files.csv",
                context.dataset_root,
            )
        observations = context.modules.evidence_processing.search_subject(
            subject,
            request.audit_at,
            context.evidence_index,
            context.activity,
        )
        observations = _adapt_trace_linked_active_flows(observations, request.audit_at)
        try:
            base["rebirth"] = build_rebirth_frontend_payload(
                subject,
                request.requested_at,
                observations,
                context.evidence_index,
                request.audit_at,
            )
        except Exception as exc:
            # Rebirth is an independent analysis view and must not mask the
            # policy decision if one case has malformed optional inputs.
            base["rebirth"] = {
                "schema_version": "1.0",
                "analysis_status": "UNAVAILABLE",
                "findings": [],
                "message": f"Rebirth analysis unavailable: {exc}",
            }
        base["observations"] = [_observation_to_dict(item) for item in observations]
        base["trace_links"] = _trace_links_to_dict(observations)
        base["evidence"] = _evidence_to_dict(
            context.evidence_index, observations, context.activity, context.identity_audit, []
        )
        try:
            base["ghost_data_map_json"] = build_ghost_data_map_payload(
                observations,
                context.evidence_index,
                request.audit_at,
                context.activity,
            )
        except Exception as exc:
            # Graph rendering is an independent presentation layer. Preserve
            # the actual audit decision if graph serialization encounters a
            # data-specific issue, and expose the failure to the frontend.
            base["ghost_data_map_error"] = str(exc)
        try:
            decision = context.modules.policy_engine.evaluate(observations, context.rules)
        except Exception as exc:
            if intent_decision.intent is Intent.VERIFY_ONLY:
                raise ValueError(
                    "Verification-only audit could not establish a compliant state; "
                    f"no new remediation is authorized: {exc}"
                ) from exc
            raise
        if intent_decision.intent is Intent.VERIFY_ONLY and decision.deletion_status is not DeletionStatus.COMPLETE:
            raise ValueError(
                "Verification-only audit did not prove COMPLETE; no new remediation is authorized."
            )
        row = OutputRow.from_decision(request.case_id, decision)
        try:
            handoff = build_frontend_payload(
                decision=decision,
                observations=observations,
                rules=context.rules,
                evidence_index=context.evidence_index,
                activity=context.activity,
                audit_events=context.identity_audit,
            )
            base["explainability"] = handoff.to_dict()
            context.analysis_state_by_case[case_id] = {
                "handoff": handoff,
                "decision": decision,
                "observations": tuple(observations),
            }
        except Exception as exc:
            base["explainability_error"] = f"Explainability is unavailable: {exc}"
        base["evidence"] = _evidence_to_dict(
            context.evidence_index,
            observations,
            context.activity,
            context.identity_audit,
            [step["evidence_id"] for step in json.loads(row.steps_json)],
        )
    except Exception as exc:
        return _blocked(
            base,
            "POLICY_UNRESOLVED" if base["observations"] else "PIPELINE_ERROR",
            f"The pipeline could not establish a decision: {exc}",
        )
    return _result_from_row(base, row)


def case_catalog_item(context: AuditContext, case_id: str) -> dict[str, str]:
    request = context.requests[case_id]
    return {
        "case_id": request.case_id,
        "dataset_group": context.request_sources[request.case_id],
        "email": _mask_email(request.email),
        "requested_at": request.requested_at.isoformat(),
        "audit_at": request.audit_at.isoformat(),
        "reported_status": request.reported_status.value,
        "request_text": request.request_text,
    }


def _blocked(result: dict[str, Any], state: str, message: str) -> dict[str, Any]:
    result.update({"pipeline_state": state, "message": message, "deletion_executed": False})
    return result


def _result_from_row(result: dict[str, Any], row: OutputRow) -> dict[str, Any]:
    steps = json.loads(row.steps_json)
    finding_ops = {
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    }
    result.update({
        "deletion_status": row.deletion_status.value,
        "pipeline_state": "COMPLETE",
        "steps": steps,
        "residual_count": len({
            (step["system_id"], step["resource_id"])
            for step in steps
            if step["phase"] == "FINDING" and step["operation"] in finding_ops
        }),
        "message": "Evidence review complete. Remediation steps, if listed, are recommendations only; no deletion was executed.",
        "deletion_executed": False,
    })
    return result


def _observation_to_dict(observation: Any) -> dict[str, Any]:
    return {
        "system_id": observation.system_id,
        "resource_id": observation.resource_id,
        "data_category": observation.data_category,
        "observed_state": observation.observed_state.value,
        "identifiers": [
            {"type": item.identifier_type, "value": _mask_identifier(item.identifier_type, item.value)}
            for item in observation.identifiers
        ],
        "observation_timestamp": (
            observation.observation_timestamp.isoformat()
            if observation.observation_timestamp is not None else None
        ),
        "evidence_references": list(observation.evidence_references),
        "relationships": [_relationship_to_dict(item) for item in observation.relationships],
    }


def _relationship_to_dict(relationship: Any) -> dict[str, Any]:
    try:
        details: Any = json.loads(relationship.details)
    except (TypeError, json.JSONDecodeError):
        details = relationship.details
    return {
        "relationship": relationship.relationship,
        "system_id": relationship.system_id,
        "resource_id": relationship.resource_id,
        "details": details,
    }


def _trace_links_to_dict(observations: list[Any]) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for observation in observations:
        for relationship in observation.relationships:
            if relationship.relationship.casefold() != "trace_correlated_evidence":
                continue
            details = _relationship_to_dict(relationship)["details"]
            if not isinstance(details, dict) or details.get("correlation") != "same_file_trace_id":
                continue
            links.append({
                "system_id": relationship.system_id,
                "resource_id": relationship.resource_id,
                "evidence_id": details.get("evidence_id"),
                "trace_id": details.get("trace_id"),
                "identifier_locator": details.get("identifier_locator"),
                "resource_locator": details.get("resource_locator"),
                "identifier_record_timestamp": details.get("identifier_record_timestamp"),
                "resource_record_timestamp": details.get("resource_record_timestamp"),
                "supported_state": details.get("supported_state"),
                "supported_fields": details.get("supported_fields", {}),
            })
    return links


def _evidence_to_dict(
    evidence_index: Any,
    observations: list[Any],
    activity: list[Any],
    identity_audit: list[Any],
    step_evidence_ids: list[str],
) -> dict[str, dict[str, Any]]:
    evidence_ids = sorted({
        evidence_id
        for observation in observations
        for evidence_id in observation.evidence_references
    } | {evidence_id for evidence_id in step_evidence_ids if evidence_id})
    records = evidence_index.records_by_id
    activity_by_id = {event.activity_id: event for event in activity}
    audit_by_id = {event.audit_id: event for event in identity_audit}
    evidence: dict[str, dict[str, Any]] = {}
    for evidence_id in evidence_ids:
        record = records.get(evidence_id)
        if record is not None:
            evidence[evidence_id] = {
                "source_type": "EVIDENCE_FILE",
                "file_id": record.file_id,
                "relative_path": record.relative_path,
                "origin": record.origin,
                "captured_at": record.captured_at.isoformat(),
                "record_timestamp": (
                    record.record_timestamp.isoformat() if record.record_timestamp else None
                ),
                "format": record.format,
                "locator": record.locator,
                "parser_status": record.parser_status.value,
                "confidence": record.confidence,
            }
            continue
        event = activity_by_id.get(evidence_id)
        if event is not None:
            evidence[evidence_id] = {
                "source_type": "ACTIVITY_EVENT",
                "activity_id": event.activity_id,
                "record_timestamp": event.event_time.isoformat(),
                "event_type": event.event_type,
                "source_system": event.source_system,
                "target_system": event.target_system,
                "resource_id": event.resource_id,
                "reported_result": event.reported_result,
                "details": dict(event.details),
            }
            continue
        audit_event = audit_by_id.get(evidence_id)
        if audit_event is not None:
            evidence[evidence_id] = {
                "source_type": "IDENTITY_AUDIT",
                "audit_id": audit_event.audit_id,
                "record_timestamp": audit_event.event_time.isoformat(),
                "field_name": audit_event.field_name,
                "user_id": audit_event.user_id,
            }
    return evidence


def _mask_email(value: str) -> str:
    local, separator, domain = value.partition("@")
    if not separator:
        return "•••"
    visible = local[:1] if local else "•"
    return f"{visible}•••@{domain}"


def _mask_identifier(kind: str, value: str) -> str:
    if kind.casefold() == "email":
        return _mask_email(value)
    if kind.casefold() in {"phone", "phone_number"}:
        digits = re.sub(r"\D", "", value)
        return f"••••{digits[-2:]}" if digits else "•••"
    return value


class AuditRequestHandler(BaseHTTPRequestHandler):
    server_version = "DEADBYTE/1.0"

    @property
    def context(self) -> AuditContext:
        return self.server.audit_context  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlparse(self.path).path
        if path == "/api/health":
            self._send_json({"status": "ok"})
            return
        if path == "/api/cases":
            self._send_json({"cases": case_catalog(self.context)})
            return
        static = STATIC_FILES.get(path)
        if static is None:
            self._send_json({"error": "not found"}, status=404)
            return
        filename, content_type = static
        file_path = STATIC_ROOT / filename
        try:
            body = file_path.read_bytes()
        except OSError:
            self._send_json({"error": "frontend asset unavailable"}, status=500)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlparse(self.path).path
        if path not in {"/api/verify", "/api/what-if"}:
            self._send_json({"error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                raise ValueError("request body must be between 1 and 4096 bytes")
            payload = json.loads(self.rfile.read(length))
            case_id = payload.get("case_id") if isinstance(payload, dict) else None
            if not isinstance(case_id, str) or not case_id:
                raise ValueError("case_id is required")
            if path == "/api/verify":
                result = analyze_case(self.context, case_id)
            else:
                state = self.context.analysis_state_by_case.get(case_id)
                if state is None:
                    self._send_json({"error": "Run verification for this case before requesting a What-If preview."}, status=409)
                    return
                risk_id = payload.get("risk_id")
                proposed_action = payload.get("proposed_action")
                if not isinstance(risk_id, str) or not risk_id:
                    raise ValueError("risk_id is required")
                if not isinstance(proposed_action, str) or not proposed_action:
                    raise ValueError("proposed_action is required")
                result = preview_frontend_action(
                    state["handoff"],
                    risk_id,
                    proposed_action,
                    state["observations"],
                    state["decision"],
                )
        except KeyError as exc:
            self._send_json({"error": str(exc)}, status=404)
            return
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        except (TypeError, KeyError) as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        self._send_json(result)

    def _send_json(self, value: Any, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[deadbyte-ui] {self.address_string()} {format % args}")


class AuditHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], context: AuditContext) -> None:
        super().__init__(address, AuditRequestHandler)
        self.audit_context = context


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run the local DEADBYTE deletion verification UI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    context = load_context()
    server = AuditHTTPServer((args.host, args.port), context)
    print(f"DEADBYTE review UI: http://{args.host}:{args.port}/")
    print("Verification invokes the audit pipeline only; remediation is not executed and output.csv is untouched.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping DEADBYTE UI")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
