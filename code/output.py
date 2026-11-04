"""Output CSV writing and challenge-contract validation."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from code.contracts import (
    OUTPUT_COLUMNS,
    DeletionRequest,
    OutputRow,
    validate_evidence_references,
)

EXPECTED_REQUEST_COUNT = 518


@dataclass(frozen=True)
class ValidationReport:
    valid: bool
    errors: tuple[str, ...]
    rows_checked: int
    expected_rows: int = EXPECTED_REQUEST_COUNT

    def raise_for_errors(self) -> None:
        if self.errors:
            raise ValueError("Output validation failed:\n- " + "\n- ".join(self.errors))


def write_output(rows: Sequence[OutputRow], path: str | Path) -> None:
    """Write schema-exact output rows after basic count and ordering checks."""
    output_path = Path(path)
    errors: list[str] = []
    if len(rows) != EXPECTED_REQUEST_COUNT:
        errors.append(f"expected {EXPECTED_REQUEST_COUNT} output rows, found {len(rows)}")
    case_ids = [row.case_id for row in rows]
    if len(case_ids) != len(set(case_ids)):
        errors.append("output rows contain duplicate case_id values")
    if case_ids != sorted(case_ids):
        errors.append("output rows must be sorted by case_id")
    if errors:
        raise ValueError("Cannot write output:\n- " + "\n- ".join(errors))

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow(row.to_dict())


def validate_output(
    path: str | Path,
    requests: Sequence[DeletionRequest],
    dataset_root: str | Path | None = None,
) -> ValidationReport:
    """Validate final output rows, serialization, citations, and challenge counts.

    Evidence references are checked against the participant-facing file, activity,
    and audit IDs under ``dataset_root``. If omitted, the function uses a sibling
    ``dataset/`` directory when ``path`` is at the repository root, or the path's
    parent when the output file itself is inside ``dataset/``.
    """
    output_path = Path(path)
    errors: list[str] = []
    request_ids = [request.case_id for request in requests]
    request_by_id = {request.case_id: request for request in requests}
    request_counts = Counter(request_ids)
    if len(requests) != EXPECTED_REQUEST_COUNT:
        errors.append(f"expected {EXPECTED_REQUEST_COUNT} input requests, found {len(requests)}")
    if any(count != 1 for count in request_counts.values()):
        errors.append("input requests contain duplicate case_id values")

    if not output_path.is_file():
        return ValidationReport(False, (f"output file does not exist: {output_path}", *errors), 0)

    parsed_rows: list[OutputRow] = []
    seen_ids: list[str] = []
    with output_path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle, strict=True)
        try:
            header = next(reader, None)
            if header != list(OUTPUT_COLUMNS):
                errors.append(f"header must be exactly {','.join(OUTPUT_COLUMNS)}")
                return ValidationReport(False, tuple(errors), 0)
            for line_no, raw_row in enumerate(reader, start=2):
                if len(raw_row) != len(OUTPUT_COLUMNS):
                    errors.append(f"line {line_no}: expected 3 columns, found {len(raw_row)}")
                    continue
                case_id, status, steps_json = raw_row
                seen_ids.append(case_id)
                try:
                    parsed_rows.append(OutputRow(case_id, status, steps_json))
                except (TypeError, ValueError) as exc:
                    errors.append(f"line {line_no} ({case_id}): {exc}")
        except csv.Error as exc:
            errors.append(f"invalid CSV: {exc}")

    if len(seen_ids) != EXPECTED_REQUEST_COUNT:
        errors.append(f"expected {EXPECTED_REQUEST_COUNT} output rows, found {len(seen_ids)}")
    output_counts = Counter(seen_ids)
    duplicates = sorted(case_id for case_id, count in output_counts.items() if count > 1)
    if duplicates:
        errors.append("duplicate output case_id values: " + ", ".join(duplicates))
    if seen_ids != sorted(seen_ids):
        errors.append("output rows must be sorted by case_id")
    missing = sorted(set(request_ids) - set(seen_ids))
    extra = sorted(set(seen_ids) - set(request_ids))
    if missing:
        errors.append("missing case_id values: " + ", ".join(missing))
    if extra:
        errors.append("unexpected case_id values: " + ", ".join(extra))

    try:
        evidence_catalog = _load_evidence_reference_catalog(output_path, dataset_root)
    except (OSError, csv.Error, ValueError) as exc:
        errors.append(f"could not load evidence reference catalog: {exc}")
    else:
        from code.contracts import AuditStep

        for row in parsed_rows:
            step_dicts = json.loads(row.steps_json)
            # OutputRow has already validated the exact step shape and decision rules.
            steps = tuple(AuditStep(**step) for step in step_dicts)
            try:
                validate_evidence_references(steps, set(evidence_catalog))
                request = request_by_id.get(row.case_id)
                if request is not None:
                    for step in steps:
                        if not step.evidence_id:
                            continue
                        evidence_time = evidence_catalog[step.evidence_id]
                        if evidence_time is None:
                            errors.append(
                                f"case {row.case_id}: evidence {step.evidence_id} has no timestamp for audit cutoff validation"
                            )
                        elif evidence_time > request.audit_at:
                            errors.append(
                                f"case {row.case_id}: evidence {step.evidence_id} is later than audit_at"
                            )
            except ValueError as exc:
                errors.append(f"case {row.case_id}: {exc}")

    return ValidationReport(not errors, tuple(errors), len(seen_ids))


def _load_evidence_reference_catalog(
    output_path: Path,
    dataset_root: str | Path | None,
) -> dict[str, datetime | None]:
    if dataset_root is not None:
        root = Path(dataset_root)
    elif output_path.parent.name == "dataset":
        root = output_path.parent
    else:
        root = output_path.parent / "dataset"

    references: dict[str, datetime | None] = {}
    inputs: tuple[tuple[str, str, str], ...] = (
        ("evidence_files.csv", "file_id", "captured_at"),
        ("system_activity.csv", "activity_id", "event_time"),
        ("user_audit_log.csv", "audit_id", "event_time"),
    )
    for filename, id_column, time_column in inputs:
        source = root / filename
        if not source.is_file():
            raise FileNotFoundError(source)
        with source.open("r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle, strict=True)
            for required_column in (id_column, time_column):
                if required_column not in (reader.fieldnames or []):
                    raise ValueError(f"{filename} is missing required column {required_column}")
            for row in reader:
                value = row.get(id_column)
                if value:
                    if value in references:
                        raise ValueError(f"duplicate evidence reference ID across catalogs: {value}")
                    references[value] = _parse_optional_timestamp(row.get(time_column))
    return references


def _parse_optional_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


__all__ = ["EXPECTED_REQUEST_COUNT", "ValidationReport", "validate_output", "write_output"]
