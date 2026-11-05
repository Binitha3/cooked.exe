"""Evidence loading, format-aware extraction, indexing, and subject discovery.

The shared dataclasses and enums are imported from :mod:`code.contracts`. This
module deliberately does not resolve identities or evaluate deletion policy.
Every manifest entry yields one :class:`EvidenceRecord` (the shared index
requires unique evidence IDs); per-line, row, JSON-node, page, or OCR-box
provenance is retained in ``EvidenceRecord.structured_fields["records"]``.

Optional extraction dependencies: ``pypdf`` reads PDF text; ``PyMuPDF`` renders
PDF pages for OCR fallback; ``Pillow`` plus ``pytesseract`` and the Tesseract
executable perform PNG/PDF OCR. Missing dependencies are recorded as
UNSUPPORTED rather than making the corpus load fail.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
import shlex
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from code.contracts import (
    ActivityEvent,
    EvidenceIndex,
    EvidenceManifestEntry,
    EvidenceParserStatus,
    EvidenceRecord,
    IdentityIdentifier,
    ObservedState,
    ResolvedSubject,
    ResolutionStatus,
    ResourceObservation,
    ResourceRelationship,
)

LOGGER = logging.getLogger(__name__)

MANIFEST_COLUMNS = ("file_id", "file_path", "origin", "captured_at")
ACTIVITY_COLUMNS = (
    "activity_id", "event_time", "event_type", "source_system", "target_system",
    "resource_id", "reported_result", "details",
)

_RECORD_TIME_KEYS = {
    "timestamp", "event_time", "occurred_at", "recorded_at", "observed_at",
    "updated_at", "created_at", "indexed_at", "sent_at", "delivered_at",
    "deleted_at", "restored_at", "requested_at", "completed_at", "processed_at",
    "captured_at",
}
_IDENTIFIER_KEYS = {
    "email", "email_address", "customer_email", "owner_email", "requester_email",
    "phone", "phone_number", "email_hash", "user_id", "customer_reference",
    "subject_reference", "subject_ref", "lookup_key", "match_key", "correlation_key",
    "selector", "subject_selector", "lookup_value",
}
_RESOURCE_KEYS = {"resource_id", "resource", "object_id", "record_id"}
_RESOURCE_ID_FALLBACK_RE = re.compile(
    r"^(?:account|search|analytics|support|export|backup|data_flow|tombstone|"
    r"audit_record|marketing|cache|object|legal)_\d+[a-z0-9_-]*$",
    re.I,
)
_SYSTEM_KEYS = {
    "system", "system_id", "source_system", "target_system", "origin_system",
    "service", "service_id", "function",
}
_FIELD_TIMESTAMP_RE = re.compile(r"(?:time|timestamp)$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+(?![\w@.-])", re.I)
_KV_RE = re.compile(r"(?P<key>[A-Za-z_][\w.-]*)=(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s|]+)")
_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")

_TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_failover_replica",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}
_TABLE_CATEGORY = {
    "customer_profiles": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "connector_subscriptions": "SECONDARY_IDENTIFIER",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
}


def _parse_datetime(value: Any) -> datetime | None:
    """Parse an ISO timestamp without silently assigning a timezone."""
    if isinstance(value, datetime):
        return value if value.tzinfo and value.utcoffset() is not None else None
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    return result if result.tzinfo and result.utcoffset() is not None else None


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")


def _read_csv(path: Path, required_columns: Sequence[str]) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames is None:
            raise ValueError(f"CSV has no header: {path}")
        if tuple(reader.fieldnames) != tuple(required_columns):
            raise ValueError(
                f"Unexpected CSV schema in {path}: expected {tuple(required_columns)!r}, "
                f"got {tuple(reader.fieldnames)!r}"
            )
        rows: list[dict[str, str]] = []
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                LOGGER.warning("Skipping malformed CSV row %s:%d: extra fields", path, line_number)
                continue
            rows.append({key: value or "" for key, value in row.items()})
        return rows


def load_manifest(manifest_path: str | Path) -> list[EvidenceManifestEntry]:
    """Load and validate ``evidence_files.csv`` using the shared manifest type."""
    path = Path(manifest_path)
    rows = _read_csv(path, MANIFEST_COLUMNS)
    entries: list[EvidenceManifestEntry] = []
    seen: set[str] = set()
    for row_number, row in enumerate(rows, start=2):
        captured_at = _parse_datetime(row["captured_at"])
        if not all(row[name] for name in MANIFEST_COLUMNS) or captured_at is None:
            LOGGER.warning("Skipping invalid evidence manifest row %s:%d", path, row_number)
            continue
        if row["file_id"] in seen:
            LOGGER.warning("Skipping duplicate evidence file_id %s at %s:%d", row["file_id"], path, row_number)
            continue
        try:
            entry = EvidenceManifestEntry(
                file_id=row["file_id"],
                file_path=row["file_path"],
                origin=row["origin"],
                captured_at=captured_at,
            )
        except ValueError as exc:
            LOGGER.warning("Skipping invalid evidence manifest row %s:%d: %s", path, row_number, exc)
            continue
        entries.append(entry)
        seen.add(entry.file_id)
    return entries


def load_activity(activity_path: str | Path) -> list[ActivityEvent]:
    """Load activity rows as shared events; ``reported_result`` remains a claim."""
    path = Path(activity_path)
    events: list[ActivityEvent] = []
    for row_number, row in enumerate(_read_csv(path, ACTIVITY_COLUMNS), start=2):
        event_time = _parse_datetime(row["event_time"])
        if event_time is None or not all(row[name] for name in ACTIVITY_COLUMNS[:1] + ACTIVITY_COLUMNS[2:6]):
            LOGGER.warning("Skipping invalid activity row %s:%d", path, row_number)
            continue
        details = _parse_kv_fields(row["details"])
        details["raw_text"] = row["details"]
        try:
            events.append(ActivityEvent(
                activity_id=row["activity_id"],
                event_time=event_time,
                event_type=row["event_type"],
                source_system=row["source_system"],
                target_system=row["target_system"],
                resource_id=row["resource_id"],
                reported_result=row["reported_result"] or None,
                details=details,
            ))
        except ValueError as exc:
            LOGGER.warning("Skipping invalid activity row %s:%d: %s", path, row_number, exc)
    return events


def load_evidence(manifest_path: str | Path, dataset_root: str | Path) -> EvidenceIndex:
    """Extract manifest files into a contract-compliant, file-ID keyed index.

    A malformed or missing evidence file becomes a FAILED/PARTIAL/UNSUPPORTED
    record with an error in ``structured_fields['parser_errors']``. Other files
    continue processing. Source files are read-only and never altered.
    """
    root = Path(dataset_root).resolve()
    records: list[EvidenceRecord] = []
    for entry in load_manifest(manifest_path):
        path = (root / entry.file_path).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            records.append(_failed_record(entry, "manifest path escapes dataset_root", "UNSAFE_PATH"))
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            LOGGER.warning("Unable to read evidence %s (%s): %s", entry.file_id, path, exc)
            records.append(_failed_record(entry, f"read error: {exc}", "READ_ERROR"))
            continue
        try:
            record = _extract_file(entry, path, raw)
        except Exception as exc:  # Isolate unexpected parser failures per file.
            LOGGER.exception("Evidence parser failed for %s", entry.file_id)
            record = _failed_record(entry, f"{type(exc).__name__}: {exc}", "PARSER_EXCEPTION", raw)
        records.append(record)
    return build_evidence_index(records)


def build_evidence_index(records: Iterable[EvidenceRecord]) -> EvidenceIndex:
    """Build contract indexes over structured identifiers, resources, systems, and text."""
    records = tuple(records)
    by_identifier: dict[str, set[str]] = defaultdict(set)
    by_resource: dict[str, set[str]] = defaultdict(set)
    by_system: dict[str, set[str]] = defaultdict(set)
    by_text: dict[str, set[str]] = defaultdict(set)
    for record in records:
        segments = record.structured_fields.get("records", ())
        values = [record.structured_fields]
        if isinstance(segments, list):
            values.extend(segment.get("fields", {}) for segment in segments if isinstance(segment, Mapping))
        for fields in values:
            for key, value, _path in _walk_scalars(fields):
                normalized = str(value).strip().casefold()
                if not normalized:
                    continue
                key_norm = key.casefold().split(".")[-1]
                if key_norm in _IDENTIFIER_KEYS or "email" in key_norm or "phone" in key_norm or "hash" in key_norm:
                    by_identifier[normalized].add(record.evidence_id)
                if key_norm in _RESOURCE_KEYS:
                    by_resource[normalized].add(record.evidence_id)
                if key_norm in _SYSTEM_KEYS:
                    by_system[normalized].add(record.evidence_id)
        for email in _EMAIL_RE.findall(record.extracted_content):
            by_identifier[email.casefold()].add(record.evidence_id)
        text = _searchable_corpus(record).casefold()
        for token in re.findall(r"[\w@.+#-]+", text, flags=re.UNICODE):
            if len(token) >= 2:
                by_text[token].add(record.evidence_id)
    return EvidenceIndex(
        records=records,
        by_identifier=_freeze_index(by_identifier),
        by_resource_id=_freeze_index(by_resource),
        by_system_id=_freeze_index(by_system),
        by_searchable_text=_freeze_index(by_text),
    )


def search_identifier(evidence_index: EvidenceIndex, identifier: str) -> list[EvidenceRecord]:
    return _records_for(evidence_index, evidence_index.by_identifier.get(identifier.strip().casefold(), ()))


def search_resource_id(evidence_index: EvidenceIndex, resource_id: str) -> list[EvidenceRecord]:
    return _records_for(evidence_index, evidence_index.by_resource_id.get(resource_id.strip().casefold(), ()))


def search_system_id(evidence_index: EvidenceIndex, system_id: str) -> list[EvidenceRecord]:
    return _records_for(evidence_index, evidence_index.by_system_id.get(system_id.strip().casefold(), ()))


def search_text(evidence_index: EvidenceIndex, query: str) -> list[EvidenceRecord]:
    """Search case-insensitive text by phrase or by intersecting token sets."""
    normalized = query.strip().casefold()
    if not normalized:
        return []
    records = evidence_index.records_by_id
    if " " not in normalized and normalized in evidence_index.by_searchable_text:
        return _records_for(evidence_index, evidence_index.by_searchable_text[normalized])
    terms = [term for term in re.findall(r"[\w@.+#-]+", normalized) if len(term) >= 2]
    candidates: set[str] | None = None
    for term in terms:
        refs = set(evidence_index.by_searchable_text.get(term, ()))
        candidates = refs if candidates is None else candidates & refs
    if candidates is None:
        candidates = set(records)
    return [records[ref] for ref in sorted(candidates) if normalized in _searchable_corpus(records[ref]).casefold()]


def search_time(
    evidence_index: EvidenceIndex,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[EvidenceRecord]:
    """Search file capture timestamps (internal timestamps remain separate)."""
    if start is not None:
        _require_aware(start, "start")
    if end is not None:
        _require_aware(end, "end")
    return [
        record for record in evidence_index.records
        if (start is None or record.captured_at >= start) and (end is None or record.captured_at <= end)
    ]


def search_record_time(
    evidence_index: EvidenceIndex,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[EvidenceRecord]:
    """Search internal record/event times without conflating capture time."""
    if start is not None:
        _require_aware(start, "start")
    if end is not None:
        _require_aware(end, "end")
    matches = []
    for record in evidence_index.records:
        times: set[datetime] = set()
        if record.record_timestamp is not None:
            times.add(record.record_timestamp)
        for segment in record.structured_fields.get("records", ()):
            if not isinstance(segment, Mapping):
                continue
            for candidate in segment.get("timestamp_candidates", ()):
                if not isinstance(candidate, Mapping):
                    continue
                parsed = _parse_datetime(candidate.get("parsed"))
                if parsed is not None:
                    times.add(parsed)
        if any((start is None or stamp >= start) and (end is None or stamp <= end) for stamp in times):
            matches.append(record)
    return matches


def search_subject(
    resolved_subject: ResolvedSubject,
    audit_at: datetime,
    evidence_index: EvidenceIndex,
    activity: Sequence[ActivityEvent],
) -> list[ResourceObservation]:
    """Discover exact identifier-linked resources and activity relationships.

    Ambiguous and unresolved subjects deliberately produce no attributed
    observations. Activity ``reported_result`` is never used to infer state;
    activity-derived observations are UNKNOWN and carry only relationship data.
    """
    _require_aware(audit_at, "audit_at")
    if resolved_subject.resolution_status is not ResolutionStatus.UNIQUE or not resolved_subject.user_id:
        return []
    identifiers = _subject_identifiers(resolved_subject, audit_at)
    if not identifiers:
        return []
    by_resource: dict[str, list[EvidenceRecord]] = defaultdict(list)
    observations: dict[tuple[Any, ...], ResourceObservation] = {}
    record_map = evidence_index.records_by_id

    for record in evidence_index.records:
        if record.captured_at > audit_at:
            continue
        segments = record.structured_fields.get("records", ())
        if not isinstance(segments, list):
            continue
        available_segments = [
            segment for segment in segments
            if isinstance(segment, Mapping) and _segment_is_available(segment, audit_at)
        ]
        trace_groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        request_groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for candidate in available_segments:
            candidate_fields = candidate.get("fields", {})
            for trace_id in _trace_ids(candidate_fields):
                trace_groups[trace_id].append(candidate)
            for request_id in _request_ids(candidate_fields):
                request_groups[request_id].append(candidate)

        for segment in available_segments:
            fields = segment.get("fields", {})
            content = str(segment.get("extracted_content", ""))
            matches = _matching_identifiers(identifiers, fields, content)
            if not matches:
                continue

            # Logs often put a subject key and its resource on separate lines.
            # Correlate only exact trace/request IDs within this evidence file,
            # and only after each segment independently passes the cutoff.
            trace_ids = _trace_ids(fields)
            targets: list[tuple[Mapping[str, Any], Mapping[str, Any] | None, str | None, str | None]] = [
                (segment, None, None, None)
            ]
            target_locators = {str(segment.get("locator", ""))}
            for trace_id in trace_ids:
                for candidate in trace_groups.get(trace_id, ()):
                    if candidate is segment or not _resource_ids(candidate.get("fields", {})):
                        continue
                    locator = str(candidate.get("locator", ""))
                    if locator not in target_locators:
                        targets.append((candidate, segment, "trace_id", trace_id))
                        target_locators.add(locator)
            for request_id in _request_ids(fields):
                for candidate in request_groups.get(request_id, ()):
                    if candidate is segment or not _resource_ids(candidate.get("fields", {})):
                        continue
                    locator = str(candidate.get("locator", ""))
                    if locator not in target_locators:
                        targets.append((candidate, segment, "request_id", request_id))
                        target_locators.add(locator)

            for target, correlated_from, correlation_kind, correlation_value in targets:
                target_fields = target.get("fields", {})
                resource_ids = _resource_ids(target_fields)
                if not resource_ids:
                    continue
                target_matches = _matching_identifiers(
                    identifiers, target_fields, str(target.get("extracted_content", "")),
                )
                observation_identifiers = tuple(target_matches or matches)
                for resource_id in resource_ids:
                    by_resource[resource_id.casefold()].append(record)
                    related_events = [
                        event for event in activity
                        if event.event_time <= audit_at and event.resource_id.casefold() == resource_id.casefold()
                    ]
                    systems = _system_ids(target_fields)
                    if not systems:
                        systems = _table_system_ids(target)
                    if not systems:
                        systems = _resource_system_ids(resource_id)
                    if not systems:
                        systems = sorted({event.target_system for event in related_events if event.target_system})
                    relationships = list(_activity_relationships(related_events))
                    if correlated_from is not None and correlation_kind == "trace_id":
                        relationships.append(_trace_correlation_relationship(
                            record, correlated_from, target, resource_id,
                        ))
                    elif correlated_from is not None and correlation_kind == "request_id":
                        relationships.append(_request_correlation_relationship(
                            record, correlated_from, target, resource_id, str(correlation_value),
                        ))
                    for system_id in systems:
                        obs = ResourceObservation(
                            system_id=system_id,
                            resource_id=resource_id,
                            data_category=_data_category(target_fields, resource_id),
                            observed_state=_evidence_state(target, record, resource_id),
                            identifiers=observation_identifiers,
                            observation_timestamp=_segment_observation_time(target),
                            evidence_references=(record.evidence_id,),
                            relationships=tuple(relationships),
                        )
                        _merge_observation(observations, obs)

    # Activity may explicitly contain a subject identifier even without a
    # matching snapshot. It remains an UNKNOWN process/resource relationship.
    for event in activity:
        if event.event_time > audit_at:
            continue
        matches = _matching_identifiers(identifiers, event.details, _safe_json(event.details))
        resource_records = by_resource.get(event.resource_id.casefold(), [])
        if not matches and not resource_records:
            continue
        if resource_records:
            # The snapshot observation already carries this event relationship.
            continue
        obs = ResourceObservation(
            system_id=event.target_system,
            resource_id=event.resource_id,
            data_category="UNKNOWN",
            observed_state=ObservedState.UNKNOWN,
            identifiers=tuple(matches),
            observation_timestamp=event.event_time,
            evidence_references=(event.activity_id,),
            relationships=_activity_relationships([event]),
        )
        _merge_observation(observations, obs)
    return sorted(
        observations.values(),
        key=lambda item: (
            item.system_id, item.resource_id, item.data_category,
            item.observation_timestamp or datetime.min.replace(tzinfo=audit_at.tzinfo),
            item.evidence_references,
        ),
    )


def _extract_file(entry: EvidenceManifestEntry, path: Path, raw: bytes) -> EvidenceRecord:
    suffix = path.suffix.lower().lstrip(".") or "unknown"
    errors: list[dict[str, str]] = []
    if suffix == "json":
        segments = _extract_json(raw, errors)
    elif suffix == "sql":
        segments = _extract_sql(raw, errors)
    elif suffix == "log":
        segments = _extract_log(raw, errors)
    elif suffix in {"txt", "text", "md", "csv"}:
        segments = _extract_text(raw, errors)
    elif suffix == "png":
        segments = _extract_image(raw, errors)
    elif suffix == "pdf":
        segments = _extract_pdf(raw, errors)
    else:
        segments = []
        errors.append({"code": "UNSUPPORTED_FORMAT", "message": f"No extractor for .{suffix}"})

    status = _aggregate_status(segments, errors, suffix)
    content = "\n".join(
        str(segment.get("extracted_content", ""))
        for segment in segments if segment.get("extracted_content")
    )
    segment_timestamps = [segment.get("record_timestamp") for segment in segments]
    # A file-level timestamp is exposed only when every extracted item has the
    # same single unambiguous time. Item-level candidates are always retained.
    record_timestamp = (
        segment_timestamps[0]
        if segment_timestamps
        and isinstance(segment_timestamps[0], datetime)
        and all(value == segment_timestamps[0] for value in segment_timestamps)
        else None
    )
    fields: dict[str, Any] = {
        "records": segments,
        "parser_errors": errors,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size_bytes": len(raw),
        "raw_source": _decode_text(raw) if suffix not in {"png", "pdf"} else None,
    }
    return EvidenceRecord(
        evidence_id=entry.file_id,
        relative_path=entry.file_path,
        origin=entry.origin,
        captured_at=entry.captured_at,
        record_timestamp=record_timestamp,
        format=suffix,
        locator="file",
        extracted_content=content,
        structured_fields=fields,
        parser_status=status,
        confidence=_file_confidence(segments),
    )


def _extract_json(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    text = _decode_text(raw)
    try:
        root = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        errors.append({"code": "JSON_PARSE_ERROR", "message": str(exc)})
        return [{
            "locator": "json:$",
            "record_timestamp": None,
            "timestamp_candidates": [],
            "extracted_content": text,
            "fields": {"raw_source": text},
            "parser_status": EvidenceParserStatus.FAILED.value,
            "confidence": None,
        }]
    candidates: list[tuple[str, Mapping[str, Any]]] = []
    context_keys = {"system", "system_id", "origin_system", "source_system", "target_system",
                    "collection", "collection_name", "record_type", "data_category", "source"}

    def visit(
        node: Any,
        pointer: str,
        inside_array: bool = False,
        inherited: Mapping[str, Any] | None = None,
    ) -> None:
        if isinstance(node, Mapping):
            local_context = {
                str(key): value for key, value in node.items()
                if str(key).casefold() in context_keys and isinstance(value, (str, int, float, bool))
            }
            context = {**(inherited or {}), **local_context}
            if inside_array or _looks_like_record(node):
                candidates.append((pointer, {**context, **node}))
            for key, value in node.items():
                visit(value, f"{pointer}.{key}", isinstance(value, list), context)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, f"{pointer}[{index}]", True, inherited)

    visit(root, "$")
    if not candidates:
        candidates = [("$", root if isinstance(root, Mapping) else {"value": root})]
    return [
        _make_segment(
            f"json:{pointer}",
            json.dumps(node, ensure_ascii=False, sort_keys=True, default=str),
            dict(node),
            EvidenceParserStatus.PARSED,
        )
        for pointer, node in candidates
    ]


def _looks_like_record(node: Mapping[str, Any]) -> bool:
    keys = {str(key).casefold() for key in node}
    return bool(keys & (_IDENTIFIER_KEYS | _RESOURCE_KEYS | {
        "record_type", "event", "event_type", "activity_id", "file_id", "system_id",
        "origin_system", "subject", "subject_id", "id",
    }))


def _extract_sql(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    script = _decode_text(raw)
    db = sqlite3.connect(":memory:")

    allowed_actions = {
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_RECURSIVE,
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_REINDEX,
    }

    def authorize(action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None) -> int:
        if action == sqlite3.SQLITE_PRAGMA:
            return sqlite3.SQLITE_OK if arg1 and arg1.casefold() == "foreign_keys" and (arg2 or "").casefold() in {"on", "1", "true"} else sqlite3.SQLITE_DENY
        # SQLite implements CREATE TABLE by updating its in-memory schema
        # catalog. Keep that narrow internal operation available while denying
        # updates to every user table.
        if action == sqlite3.SQLITE_UPDATE and arg1 in {"sqlite_master", "sqlite_schema"}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY

    db.set_authorizer(authorize)
    try:
        db.executescript(script)
        # Snapshot DDL/DML is loaded in memory; inspection is query-only.
        db.set_authorizer(None)
        db.execute("PRAGMA query_only = ON")
        tables = [
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        segments: list[dict[str, Any]] = []
        for table in tables:
            escaped = table.replace('"', '""')
            cursor = db.execute(f'SELECT * FROM "{escaped}"')
            columns = [description[0] for description in cursor.description or ()]
            for row_number, values in enumerate(cursor.fetchall(), start=1):
                row = dict(zip(columns, values))
                if "record_json" in row and isinstance(row["record_json"], str):
                    try:
                        row["record_json_parsed"] = json.loads(row["record_json"])
                    except json.JSONDecodeError:
                        pass
                locator = f"sql:table:{table}:row:{row_number}"
                segments.append(_make_segment(locator, _format_mapping(row), row, EvidenceParserStatus.PARSED))
        if not segments:
            # Empty but valid snapshots still count as parsed evidence.
            segments.append(_make_segment("sql:schema", "SQLite snapshot schema inspected", {"tables": tables}, EvidenceParserStatus.PARSED))
        return segments
    except sqlite3.Error as exc:
        errors.append({"code": "SQL_PARSE_ERROR", "message": str(exc)})
        return [{
            "locator": "sql:file",
            "record_timestamp": None,
            "timestamp_candidates": [],
            "extracted_content": script,
            "fields": {"raw_source": script},
            "parser_status": EvidenceParserStatus.FAILED.value,
            "confidence": None,
        }]
    finally:
        db.close()


def _extract_log(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    text = _decode_text(raw)
    segments: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        fields, timestamp, status = _parse_log_line(line)
        if status is EvidenceParserStatus.PARTIAL:
            errors.append({"code": "LOG_LINE_PARTIAL", "message": f"line {line_number}: preserved raw line; recognized fields may be incomplete"})
        if timestamp is not None:
            fields.setdefault("event_time", timestamp.isoformat())
        fields["raw_line"] = line
        segments.append(_make_segment(f"line:{line_number}", line, fields, status))
    if not segments and text:
        errors.append({"code": "EMPTY_LOG", "message": "no nonblank log lines"})
    return segments


def _parse_log_line(line: str) -> tuple[dict[str, Any], datetime | None, EvidenceParserStatus]:
    timestamp_match = _ISO_RE.search(line)
    timestamp_raw = timestamp_match.group(0) if timestamp_match else None
    timestamp = _parse_datetime(timestamp_raw)
    remainder = line[timestamp_match.end():].strip() if timestamp_match else line.strip()
    fields: dict[str, Any] = {}
    status = EvidenceParserStatus.PARSED if timestamp is not None else EvidenceParserStatus.PARTIAL
    if remainder.startswith("{"):
        try:
            parsed = json.loads(remainder)
            if isinstance(parsed, Mapping):
                fields.update(parsed)
            else:
                fields["json_value"] = parsed
            _expand_nested_message_fields(fields)
            if timestamp_raw:
                fields["line_timestamp_raw"] = timestamp_raw
            return fields, timestamp, status
        except json.JSONDecodeError:
            status = EvidenceParserStatus.PARTIAL
    if " | " in remainder:
        parts = [part.strip() for part in remainder.strip().strip("|").split("|")]
        for key, value in zip(("level", "service", "trace_id", "event"), parts[:4]):
            if value:
                fields[key] = value
        if len(parts) > 4:
            fields.update(_parse_kv_fields(" | ".join(parts[4:])))
        _expand_nested_message_fields(fields)
        if timestamp_raw:
            fields["line_timestamp_raw"] = timestamp_raw
        return fields, timestamp, status
    if re.match(r"^<\d+>\d+\s", remainder):
        syslog = re.match(r"^<(?P<pri>\d+)>(?P<version>\d+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+(?P<structured>\S+)\s*(?P<msg>.*)$", remainder)
        if syslog:
            fields.update({f"syslog_{key}": value for key, value in syslog.groupdict().items() if value})
            fields.update(_parse_kv_fields(syslog.group("msg")))
        else:
            fields.update(_parse_kv_fields(remainder))
        _expand_nested_message_fields(fields)
        if timestamp_raw:
            fields["line_timestamp_raw"] = timestamp_raw
        return fields, timestamp, status
    kv_fields = _parse_kv_fields(remainder)
    if kv_fields:
        fields.update(kv_fields)
        _expand_nested_message_fields(fields)
        # Parse common bracketed level/service/trace/event prefixes.
        brackets = re.findall(r"\[([^\]]+)\]", remainder)
        for key, value in zip(("level", "service", "trace_id", "event"), brackets):
            fields.setdefault(key, value)
        if timestamp_raw:
            fields["line_timestamp_raw"] = timestamp_raw
        return fields, timestamp, status
    # Space-delimited application traces without key=value fields.
    try:
        tokens = shlex.split(remainder, posix=True) if remainder else []
    except ValueError:
        tokens = [remainder] if remainder else []
        status = EvidenceParserStatus.PARTIAL
    if tokens:
        fields["message"] = " ".join(tokens)
        if timestamp_raw:
            fields["line_timestamp_raw"] = timestamp_raw
    return fields, timestamp, EvidenceParserStatus.PARTIAL if not timestamp or not fields else status


def _parse_kv_fields(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for match in _KV_RE.finditer(text):
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("\\'", "'").replace("\\\\", "\\")
        result[match.group("key")] = value
    return result


def _expand_nested_message_fields(fields: dict[str, Any]) -> None:
    """Parse key/value pairs embedded in a quoted log message, preserving raw text.

    Structured log exports sometimes serialize the service payload into a
    quoted ``message`` string. Keep that original string and expose its parsed
    fields under a separate nested mapping so provenance remains inspectable.
    """
    nested: dict[str, Any] = {}
    for key in ("message", "msg", "payload"):
        value = fields.get(key)
        if isinstance(value, str):
            parsed = _parse_kv_fields(value)
            if parsed:
                nested[key] = parsed
    if nested:
        fields["nested_message_fields"] = nested


def _extract_text(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    text = _decode_text(raw)
    segments: list[dict[str, Any]] = []
    for line_number, source_line in enumerate(text.splitlines(), start=1):
        line = source_line.strip()
        if not line:
            continue
        line = re.sub(r"^[-*•]\s*", "", line)
        timestamp_match = _ISO_RE.search(line)
        if " | " in line:
            parts = [part.strip() for part in line.split(" | ")]
            fields: dict[str, Any] = {}
            if parts and _parse_datetime(parts[0]):
                fields["event_time"] = parts[0]
                names = ("system_id", "resource_id", "event")
                for key, value in zip(names, parts[1:]):
                    fields[key] = value
                if len(parts) > 4:
                    fields["details"] = " | ".join(parts[4:])
                status = EvidenceParserStatus.PARSED
            else:
                fields = {f"column_{i+1}": value for i, value in enumerate(parts)}
                status = EvidenceParserStatus.PARTIAL
        elif ":" in line and not timestamp_match:
            key, value = line.split(":", 1)
            fields = {key.strip().casefold().replace(" ", "_"): value.strip()}
            status = EvidenceParserStatus.PARSED
        else:
            fields = {"text": line}
            status = EvidenceParserStatus.PARSED if timestamp_match else EvidenceParserStatus.PARTIAL
        fields["raw_line"] = source_line
        segments.append(_make_segment(f"line:{line_number}", line, fields, status))
    if not segments and text:
        segments.append(_make_segment("text:file", text, {"raw_source": text}, EvidenceParserStatus.PARTIAL))
    return segments


def _extract_image(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    try:
        from PIL import Image
    except ImportError:
        errors.append({"code": "PILLOW_UNAVAILABLE", "message": "Pillow is not installed; PNG OCR skipped"})
        return []
    try:
        import pytesseract
        from pytesseract import Output
    except ImportError:
        errors.append({"code": "OCR_UNAVAILABLE", "message": "pytesseract is not installed; PNG retained without OCR"})
        return []
    from io import BytesIO
    try:
        image = Image.open(BytesIO(raw)).convert("RGB")
        data = pytesseract.image_to_data(image, output_type=Output.DICT)
        words: dict[tuple[int, int, int, int], list[tuple[str, float, int, int, int, int]]] = defaultdict(list)
        for i, text in enumerate(data.get("text", [])):
            value = str(text).strip()
            if not value:
                continue
            try:
                confidence = max(0.0, min(1.0, float(data["conf"][i]) / 100.0))
            except (TypeError, ValueError, KeyError):
                confidence = 0.0
            key = tuple(int(data[k][i]) for k in ("block_num", "par_num", "line_num", "page_num"))
            words[key].append((value, confidence, int(data["left"][i]), int(data["top"][i]), int(data["width"][i]), int(data["height"][i])))
        result = []
        for key, line_words in sorted(words.items()):
            left = min(item[2] for item in line_words)
            top = min(item[3] for item in line_words)
            right = max(item[2] + item[4] for item in line_words)
            bottom = max(item[3] + item[5] for item in line_words)
            text = " ".join(item[0] for item in line_words)
            confidence = sum(item[1] for item in line_words) / len(line_words)
            result.append(_make_segment(
                f"image:bbox:{left},{top},{right},{bottom}", text,
                {"ocr_text": text, "bbox": [left, top, right, bottom], "image_size": list(image.size)},
                EvidenceParserStatus.PARSED, confidence,
            ))
        if not result:
            errors.append({"code": "OCR_NO_TEXT", "message": "OCR completed but found no text"})
        return result
    except Exception as exc:
        errors.append({"code": "IMAGE_OCR_ERROR", "message": f"{type(exc).__name__}: {exc}"})
        return []


def _extract_pdf(raw: bytes, errors: list[dict[str, str]]) -> list[dict[str, Any]]:
    from io import BytesIO
    reader = None
    backend = None
    try:
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(raw), strict=False)
        backend = "pypdf"
    except ImportError:
        try:
            import fitz  # PyMuPDF
            document = fitz.open(stream=raw, filetype="pdf")
            backend = "pymupdf"
        except ImportError:
            errors.append({"code": "PDF_UNAVAILABLE", "message": "Install pypdf or PyMuPDF for PDF text extraction"})
            return []
        except Exception as exc:
            errors.append({"code": "PDF_PARSE_ERROR", "message": f"{type(exc).__name__}: {exc}"})
            return []
    except Exception as exc:
        errors.append({"code": "PDF_PARSE_ERROR", "message": f"{type(exc).__name__}: {exc}"})
        return []

    page_text: list[tuple[int, str]] = []
    try:
        if backend == "pypdf":
            for page_number, page in enumerate(reader.pages, start=1):
                page_text.append((page_number, page.extract_text() or ""))
        else:
            for page_number, page in enumerate(document, start=1):
                page_text.append((page_number, page.get_text("text") or ""))
    except Exception as exc:
        errors.append({"code": "PDF_TEXT_ERROR", "message": f"{type(exc).__name__}: {exc}"})
    segments = []
    for number, text in page_text:
        if not text.strip():
            continue
        # Keep page text unchanged, then expose only explicit labeled values
        # (resource/subject references, record times, and retention dates) as
        # structured fields. No policy outcome is inferred by the parser.
        fields = {"page_number": number, "text": text}
        fields.update(_pdf_explicit_fields(text))
        segments.append(_make_segment(
            f"pdf:page:{number}", text, fields, EvidenceParserStatus.PARSED,
        ))
    if segments:
        return segments
    # OCR fallback only when text extraction is empty. Rendering dependencies
    # are optional and failures remain visible in parser_errors.
    try:
        import pytesseract
        from PIL import Image
        try:
            import fitz
            render_document = document if backend == "pymupdf" else fitz.open(stream=raw, filetype="pdf")
        except ImportError:
            errors.append({"code": "PDF_OCR_RENDERER_UNAVAILABLE", "message": "Install PyMuPDF to render pages for OCR fallback"})
            return []
        for page_number, page in enumerate(render_document, start=1):
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            image = Image.open(BytesIO(pix.tobytes("png"))).convert("RGB")
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            words = [str(value).strip() for value in data.get("text", []) if str(value).strip()]
            text = " ".join(words)
            if text:
                confidences = []
                for value in data.get("conf", []):
                    try:
                        score = float(value)
                        if score >= 0:
                            confidences.append(score / 100.0)
                    except (TypeError, ValueError):
                        continue
                confidence = sum(confidences) / len(confidences) if confidences else None
                segments.append(_make_segment(f"pdf:page:{page_number}:ocr", text, {"page_number": page_number, "ocr_text": text}, EvidenceParserStatus.PARTIAL, confidence))
        if not segments:
            errors.append({"code": "PDF_OCR_NO_TEXT", "message": "PDF OCR completed but found no text"})
        return segments
    except ImportError as exc:
        errors.append({"code": "PDF_OCR_UNAVAILABLE", "message": f"Install PyMuPDF, Pillow, and pytesseract/Tesseract for OCR fallback ({exc})"})
        return []
    except Exception as exc:
        errors.append({"code": "PDF_OCR_ERROR", "message": f"{type(exc).__name__}: {exc}"})
        return []


_PDF_RESOURCE_ID_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|backup|data_flow|tombstone|"
    r"audit_record|marketing|cache|object|legal)_\d+[a-z0-9_-]*\b", re.I,
)
_PDF_SUBJECT_REFERENCE_RE = re.compile(
    r"\bsubject\s+reference\s*[:#]?\s*([A-Za-z][A-Za-z0-9_-]*)\b", re.I,
)
_PDF_RETENTION_RE = re.compile(
    r"\b(?:retain\s+until|retained\s+until|retention\s+until)\s*[:#]?\s*"
    r"(\d{1,2}\s+[A-Za-z]{3}\s+\d{4}(?:\s+\d{1,2}(?::\d{2})?(?:\s+\d{2})?)?"
    r"(?:\s+(?:UTC|GMT|Z|[+-]\d{2}:?\d{2}))?)", re.I,
)
_PDF_RECORDED_RE = re.compile(
    r"\brecorded\s*[:#]?\s*(\d{1,2}\s+[A-Za-z]{3}\s+\d{4}"
    r"\s+\d{1,2}(?::\d{2})?(?:\s+\d{2})?\s+(?:UTC|GMT|Z))\b", re.I,
)


def _normalize_pdf_datetime_text(value: str) -> str:
    """Join PDF layout line wraps in an explicit UTC date/time value."""
    text = " ".join(value.split())
    # PDF text extraction can split HH and MM onto adjacent lines.
    return re.sub(
        r"(\d{1,2}\s+[A-Za-z]{3}\s+\d{4})\s+(\d{1,2})\s+(\d{2})\s+(UTC|GMT|Z)\b",
        r"\1 \2:\3 \4", text, flags=re.I,
    )


def _parse_pdf_datetime(value: str) -> datetime | None:
    """Parse only a fully specified PDF date with an explicit timezone."""
    normalized = _normalize_pdf_datetime_text(value)
    for pattern in ("%d %b %Y %H:%M %Z", "%d %b %Y %H %Z"):
        try:
            parsed = datetime.strptime(normalized, pattern)
        except ValueError:
            continue
        zone = normalized.rsplit(" ", 1)[-1].upper()
        if zone in {"UTC", "GMT", "Z"}:
            return parsed.replace(tzinfo=timezone.utc)
    return _parse_datetime(normalized)


def _pdf_explicit_fields(text: str) -> dict[str, Any]:
    """Extract conservative, labeled identifiers and dates from a PDF page.

    The source text is retained in the same page segment. A resource ID is
    added only when exactly one recognized resource token occurs on the page;
    dates become timestamps only when an explicit timezone is present.
    """
    fields: dict[str, Any] = {}
    resource_ids = {match.group(0) for match in _PDF_RESOURCE_ID_RE.finditer(text)}
    if len(resource_ids) == 1:
        fields["resource_id"] = next(iter(resource_ids))

    subject_match = _PDF_SUBJECT_REFERENCE_RE.search(text)
    if subject_match:
        fields["subject_reference"] = subject_match.group(1)

    retention_match = _PDF_RETENTION_RE.search(text)
    if retention_match:
        raw_value = retention_match.group(1)
        parsed = _parse_pdf_datetime(raw_value)
        if parsed is not None:
            fields["retention_until"] = parsed.isoformat()
        else:
            # Keep the exact textual date for provenance, but do not turn a
            # date without timezone into a Boolean retention policy fact.
            fields["retention_until_text"] = raw_value

    recorded_match = _PDF_RECORDED_RE.search(text)
    if recorded_match:
        parsed = _parse_pdf_datetime(recorded_match.group(1))
        if parsed is not None:
            fields["recorded_at"] = parsed.isoformat()

    if re.search(r"\bCOMPLIANCE JOURNAL\s*[-–]\s*SIGNED RECORD EXTRACT\b", text, re.I):
        fields["document_type"] = "signed_compliance_journal_extract"
    if re.search(r"\bintegrity seal\s+valid\b", text, re.I):
        fields["integrity_status"] = "valid"
    storage_match = re.search(r"\bstorage class\s+([A-Za-z0-9_-]+)", text, re.I)
    if storage_match:
        fields["storage_class"] = storage_match.group(1)
    return fields


def _make_segment(
    locator: str,
    content: str,
    fields: Mapping[str, Any],
    status: EvidenceParserStatus,
    confidence: float | None = None,
) -> dict[str, Any]:
    candidates = _timestamp_candidates(fields)
    parsed = {candidate["parsed"] for candidate in candidates if candidate.get("parsed")}
    timestamp = _parse_datetime(next(iter(parsed))) if len(parsed) == 1 and not any(
        candidate["status"] == "invalid" for candidate in candidates
    ) else None
    return {
        "locator": locator,
        "record_timestamp": timestamp,
        "timestamp_candidates": candidates,
        "extracted_content": str(content),
        "fields": dict(fields),
        "parser_status": status.value,
        "confidence": confidence,
    }


def _timestamp_candidates(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key, value, path in _walk_scalars(fields):
        leaf_key = key.casefold().split(".")[-1]
        if leaf_key not in _RECORD_TIME_KEYS and not _FIELD_TIMESTAMP_RE.search(leaf_key):
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        parsed = _parse_datetime(value)
        result.append({
            "field": path,
            "raw": value,
            "parsed": parsed.isoformat() if parsed else None,
            "status": "parsed" if parsed else "invalid",
        })
    return result


def _failed_record(
    entry: EvidenceManifestEntry,
    message: str,
    code: str,
    raw: bytes | None = None,
) -> EvidenceRecord:
    errors = [{"code": code, "message": message}]
    return EvidenceRecord(
        evidence_id=entry.file_id,
        relative_path=entry.file_path,
        origin=entry.origin,
        captured_at=entry.captured_at,
        record_timestamp=None,
        format=Path(entry.file_path).suffix.lower().lstrip(".") or "unknown",
        locator="file",
        extracted_content=_decode_text(raw) if raw else "",
        structured_fields={
            "records": [], "parser_errors": errors,
            "raw_sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            "raw_size_bytes": len(raw) if raw else None,
        },
        parser_status=EvidenceParserStatus.FAILED,
        confidence=None,
    )


def _aggregate_status(
    segments: Sequence[Mapping[str, Any]],
    errors: Sequence[Mapping[str, str]],
    suffix: str,
) -> EvidenceParserStatus:
    if not segments:
        if suffix in {"png", "pdf"}:
            return EvidenceParserStatus.UNSUPPORTED
        return EvidenceParserStatus.FAILED
    if any(segment.get("parser_status") == EvidenceParserStatus.FAILED.value for segment in segments):
        if all(segment.get("parser_status") == EvidenceParserStatus.FAILED.value for segment in segments):
            return EvidenceParserStatus.FAILED
    if errors or any(segment.get("parser_status") == EvidenceParserStatus.PARTIAL.value for segment in segments):
        return EvidenceParserStatus.PARTIAL
    return EvidenceParserStatus.PARSED


def _file_confidence(segments: Sequence[Mapping[str, Any]]) -> float | None:
    values = [float(segment["confidence"]) for segment in segments if isinstance(segment.get("confidence"), (int, float))]
    return sum(values) / len(values) if values else None


def _walk_scalars(value: Any, path: str = "") -> Iterable[tuple[str, Any, str]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_scalars(item, child)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _walk_scalars(item, f"{path}[{index}]")
    elif isinstance(value, (str, int, float, bool)):
        key = path.split(".")[-1].split("[")[0]
        yield key, value, path


def _format_mapping(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _decode_text(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8-sig", errors="replace")


def _freeze_index(index: Mapping[str, set[str]]) -> dict[str, tuple[str, ...]]:
    return {key: tuple(sorted(refs)) for key, refs in sorted(index.items())}


def _records_for(index: EvidenceIndex, refs: Iterable[str]) -> list[EvidenceRecord]:
    records = index.records_by_id
    return [records[ref] for ref in sorted(set(refs)) if ref in records]


def _subject_identifiers(subject: ResolvedSubject, audit_at: datetime) -> tuple[IdentityIdentifier, ...]:
    selected: dict[tuple[str, str], IdentityIdentifier] = {}
    for identifier in (*subject.current_identifiers, *subject.historical_identifiers):
        if identifier.valid_from and identifier.valid_from > audit_at:
            continue
        # Historical identifiers remain searchable after valid_to; old copies
        # can survive a change and still be present at the audit cutoff.
        key = (identifier.identifier_type.casefold(), identifier.value.casefold())
        selected[key] = identifier
    selected[("user_id", subject.user_id.casefold())] = IdentityIdentifier("user_id", subject.user_id)
    return tuple(selected[key] for key in sorted(selected))


def _matching_identifiers(
    identifiers: Sequence[IdentityIdentifier], fields: Any, content: str,
) -> list[IdentityIdentifier]:
    scalar_values = [(str(value).strip().casefold(), path) for _key, value, path in _walk_scalars(fields)]
    normalized_content = content.casefold()
    matches = []
    for identifier in identifiers:
        needle = identifier.value.strip().casefold()
        if not needle:
            continue
        field_match = any(value == needle for value, _path in scalar_values)
        content_match = _exact_text_match(needle, normalized_content)
        if field_match or content_match:
            matches.append(identifier)
    return matches


def _exact_text_match(needle: str, haystack: str) -> bool:
    if not needle:
        return False
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        before = haystack[index - 1] if index else ""
        after_index = index + len(needle)
        after = haystack[after_index] if after_index < len(haystack) else ""
        if not _identifier_char(before) and not _identifier_char(after):
            return True
        start = index + 1


def _identifier_char(char: str) -> bool:
    return bool(char and (char.isalnum() or char in "_.@+-"))


def _segment_is_available(segment: Mapping[str, Any], audit_at: datetime) -> bool:
    candidates = segment.get("timestamp_candidates", ())
    parsed = [_parse_datetime(candidate.get("parsed")) for candidate in candidates if isinstance(candidate, Mapping) and candidate.get("parsed")]
    return not any(timestamp and timestamp > audit_at for timestamp in parsed)


def _segment_observation_time(segment: Mapping[str, Any]) -> datetime | None:
    candidates = segment.get("timestamp_candidates", ())
    parsed = [_parse_datetime(candidate.get("parsed")) for candidate in candidates if isinstance(candidate, Mapping) and candidate.get("parsed")]
    parsed = [value for value in parsed if value is not None]
    return max(parsed) if parsed else segment.get("record_timestamp")


def _resource_ids(fields: Any) -> list[str]:
    values = set()
    for key, value, _path in _walk_scalars(fields):
        if key.casefold() in _RESOURCE_KEYS and isinstance(value, str) and value.strip():
            values.add(value.strip())
    # A data row may use a resource-like string in a generic id field.
    if not values:
        for _key, value, _path in _walk_scalars(fields):
            if isinstance(value, str) and _RESOURCE_ID_FALLBACK_RE.fullmatch(value.strip()):
                values.add(value.strip())
    return sorted(values)


def _system_ids(fields: Any) -> list[str]:
    values = set()
    for key, value, _path in _walk_scalars(fields):
        leaf = key.casefold()
        if leaf in _SYSTEM_KEYS and isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]*", value.strip(), re.I):
            values.add(value.strip())
    return sorted(values)


def _table_system_ids(segment: Mapping[str, Any]) -> list[str]:
    match = re.match(r"sql:table:([^:]+):", str(segment.get("locator", "")))
    if not match:
        return []
    system = _TABLE_SYSTEM.get(match.group(1))
    return [system] if system else []


def _resource_system_ids(resource_id: str) -> list[str]:
    prefix = resource_id.split("_", 1)[0].casefold()
    systems = {
        "account": "account_service", "search": "search_service",
        "analytics": "analytics_platform", "support": "support_platform",
        "export": "export_service", "backup": "backup_service",
        "data": "integration_service", "tombstone": "identity_service",
        "audit": "security_service", "marketing": "marketing_platform",
        "cache": "cache_service", "object": "object_storage", "legal": "legal_service",
    }
    system = systems.get(prefix)
    return [system] if system else []


def _trace_ids(fields: Any) -> tuple[str, ...]:
    return tuple(sorted({
        value.strip()
        for key, value, _path in _walk_scalars(fields)
        if (
            key.casefold().split(".")[-1] in {"trace_id", "traceid"}
            or (
                key.casefold().split(".")[-1] == "syslog_proc"
                and isinstance(value, str)
                and re.fullmatch(r"tr-[a-z0-9_-]+", value.strip(), re.IGNORECASE)
            )
        )
        and isinstance(value, str) and value.strip()
    }))


def _request_ids(fields: Any) -> tuple[str, ...]:
    """Return exact request IDs used to join rows from the same exported log."""
    return tuple(sorted({
        value.strip()
        for key, value, _path in _walk_scalars(fields)
        if key.casefold().split(".")[-1] in {"request_id", "requestid"}
        and isinstance(value, str) and value.strip()
    }))


def _trace_correlation_relationship(
    record: EvidenceRecord,
    identifier_segment: Mapping[str, Any],
    resource_segment: Mapping[str, Any],
    resource_id: str,
) -> ResourceRelationship:
    identifier_fields = identifier_segment.get("fields", {})
    resource_fields = resource_segment.get("fields", {})
    shared_trace = sorted(set(_trace_ids(identifier_fields)) & set(_trace_ids(resource_fields)))
    trace_id = shared_trace[0] if shared_trace else ""
    systems = _system_ids(resource_fields) or _resource_system_ids(resource_id)
    system_id = systems[0] if systems else "unknown_system"
    state = _data_flow_state(resource_fields, resource_id)
    supported_fields = {
        str(key): value for key, value, _path in _walk_scalars(resource_fields)
        if key.casefold().split(".")[-1] in {"enabled", "scheduler_registered", "last_run"}
    }
    details = _safe_json({
        "correlation": "same_file_trace_id",
        "trace_id": trace_id,
        "evidence_id": record.evidence_id,
        "identifier_locator": identifier_segment.get("locator"),
        "resource_locator": resource_segment.get("locator"),
        "identifier_record_timestamp": identifier_segment.get("record_timestamp"),
        "resource_record_timestamp": resource_segment.get("record_timestamp"),
        "supported_state": state.value if state is not ObservedState.UNKNOWN else None,
        "supported_fields": supported_fields,
    })
    return ResourceRelationship(
        relationship="TRACE_CORRELATED_EVIDENCE",
        system_id=system_id,
        resource_id=resource_id,
        details=details,
    )


def _request_correlation_relationship(
    record: EvidenceRecord,
    identifier_segment: Mapping[str, Any],
    resource_segment: Mapping[str, Any],
    resource_id: str,
    request_id: str,
) -> ResourceRelationship:
    """Preserve a same-file request-ID join without claiming active-flow state."""
    resource_fields = resource_segment.get("fields", {})
    systems = _system_ids(resource_fields) or _resource_system_ids(resource_id)
    system_id = systems[0] if systems else "unknown_system"
    state = _evidence_state(resource_segment, record, resource_id)
    supported_fields = {
        str(key): value for key, value, _path in _walk_scalars(resource_fields)
        if key.casefold().split(".")[-1] in {
            "enabled", "scheduler_registered", "last_run", "result", "http_status",
            "rows", "row_count", "status_code", "profile", "restore_allowed",
            "archive_present", "retention_until", "retained_until", "event",
        }
    }
    details = _safe_json({
        "correlation": "same_file_request_id",
        "request_id": request_id,
        "evidence_id": record.evidence_id,
        "identifier_locator": identifier_segment.get("locator"),
        "resource_locator": resource_segment.get("locator"),
        "identifier_record_timestamp": identifier_segment.get("record_timestamp"),
        "resource_record_timestamp": resource_segment.get("record_timestamp"),
        "supported_state": state.value if state is not ObservedState.UNKNOWN else None,
        "supported_fields": supported_fields,
    })
    return ResourceRelationship(
        relationship="REQUEST_ID_CORRELATED_EVIDENCE",
        system_id=system_id,
        resource_id=resource_id,
        details=details,
    )


def _data_category(fields: Any, resource_id: str | None = None) -> str:
    for key, value, _path in _walk_scalars(fields):
        if key.casefold() in {"data_category", "record_type", "collection_name", "collection", "table"} and isinstance(value, str):
            upper = value.strip().upper()
            if upper in set(_TABLE_CATEGORY.values()):
                return upper
            if value in _TABLE_CATEGORY:
                return _TABLE_CATEGORY[value]
            if value in _TABLE_SYSTEM:
                return _TABLE_CATEGORY.get(value, "UNKNOWN")
    if resource_id and resource_id.casefold().startswith("data_flow_"):
        return "DATA_FLOW"
    return "UNKNOWN"


def _evidence_state(
    segment: Mapping[str, Any], record: EvidenceRecord, resource_id: str | None = None,
) -> ObservedState:
    # A relational snapshot row is direct evidence that a row existed at its
    # internal timestamp. A data-flow state is supported only by explicit
    # scheduler configuration fields in the same correlated evidence.
    if resource_id and _data_flow_state(segment.get("fields", {}), resource_id) is ObservedState.ACTIVE:
        return ObservedState.ACTIVE
    if record.format == "sql" and segment.get("locator", "").startswith("sql:table:"):
        return ObservedState.PRESENT
    if record.format == "json" and _looks_like_record(segment.get("fields", {})):
        return ObservedState.PRESENT
    fields = segment.get("fields", {})
    if (
        record.format == "pdf"
        and resource_id
        and resource_id.casefold().startswith("audit_record_")
        and isinstance(fields, Mapping)
        and fields.get("document_type") == "signed_compliance_journal_extract"
        and str(fields.get("integrity_status", "")).casefold() == "valid"
        and fields.get("storage_class") == "compliance-ledger"
        and fields.get("subject_reference")
        and fields.get("recorded_at")
        and fields.get("retention_until")
    ):
        # This specific document class is an issued extract of a journal entry;
        # it establishes that the referenced entry existed in the named ledger
        # when captured. Other prose mentions of a resource remain UNKNOWN.
        return ObservedState.PRESENT
    return ObservedState.UNKNOWN


def _data_flow_state(fields: Any, resource_id: str) -> ObservedState:
    """Classify explicit scheduler configuration, without using activity claims."""
    if not resource_id.casefold().startswith("data_flow_"):
        return ObservedState.UNKNOWN
    values = {
        key.casefold().split(".")[-1]: value
        for key, value, _path in _walk_scalars(fields)
    }
    enabled = values.get("enabled")
    registered = values.get("scheduler_registered")
    if _is_explicit_true(enabled) and _is_explicit_true(registered):
        return ObservedState.ACTIVE
    if enabled is False or (isinstance(enabled, str) and enabled.strip().casefold() in {"false", "no", "0", "disabled"}):
        return ObservedState.DISABLED
    return ObservedState.UNKNOWN


def _is_explicit_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().casefold() in {"true", "yes", "1"})


def _activity_relationships(events: Sequence[ActivityEvent]) -> tuple[ResourceRelationship, ...]:
    relationships: dict[tuple[str, str, str], ResourceRelationship] = {}
    for event in events:
        # reported_result intentionally excluded: an operation result is not
        # evidence that a record is absent or compliant.
        details = f"{event.event_type}; source={event.source_system}; target={event.target_system}"
        key = (event.target_system, event.resource_id, event.event_type)
        relationships[key] = ResourceRelationship(
            relationship=event.event_type,
            system_id=event.target_system,
            resource_id=event.resource_id,
            details=details,
        )
    return tuple(relationships[key] for key in sorted(relationships))


def _merge_observation(
    target: dict[tuple[Any, ...], ResourceObservation], observation: ResourceObservation,
) -> None:
    key = (
        observation.system_id, observation.resource_id, observation.data_category,
        observation.observed_state, observation.observation_timestamp,
    )
    current = target.get(key)
    if current is None:
        target[key] = observation
        return
    refs = tuple(sorted(set(current.evidence_references) | set(observation.evidence_references)))
    identifiers = {(item.identifier_type, item.value): item for item in (*current.identifiers, *observation.identifiers)}
    relationships = {(item.relationship, item.system_id, item.resource_id, item.details): item for item in (*current.relationships, *observation.relationships)}
    target[key] = ResourceObservation(
        system_id=current.system_id,
        resource_id=current.resource_id,
        data_category=current.data_category,
        observed_state=current.observed_state,
        identifiers=tuple(identifiers[k] for k in sorted(identifiers)),
        observation_timestamp=current.observation_timestamp,
        evidence_references=refs,
        relationships=tuple(relationships[k] for k in sorted(relationships)),
    )


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _searchable_corpus(record: EvidenceRecord) -> str:
    temporal = [record.captured_at.isoformat()]
    for segment in record.structured_fields.get("records", ()):
        if not isinstance(segment, Mapping):
            continue
        for candidate in segment.get("timestamp_candidates", ()):
            if isinstance(candidate, Mapping) and candidate.get("raw"):
                temporal.append(str(candidate["raw"]))
    return " ".join((record.extracted_content, *temporal))


__all__ = [
    "ACTIVITY_COLUMNS", "MANIFEST_COLUMNS", "build_evidence_index", "load_activity",
    "load_evidence", "load_manifest", "search_identifier", "search_resource_id",
    "search_record_time", "search_subject", "search_system_id", "search_text", "search_time",
]
