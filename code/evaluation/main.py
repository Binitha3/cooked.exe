"""Compare a prediction CSV with an authorized reference CSV.

This utility reports case status accuracy, exact-step precision/recall, field
accuracy, exact ordered sequence accuracy, and per-case mismatches. It does not
locate or read hidden organizer data; both input paths must be supplied explicitly.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from code.contracts import AUDIT_STEP_FIELDS, OUTPUT_COLUMNS, OutputRow


def load_output(path: str | Path) -> dict[str, OutputRow]:
    rows: dict[str, OutputRow] = {}
    with Path(path).open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(OUTPUT_COLUMNS):
            raise ValueError(f"{path} must have columns exactly: {','.join(OUTPUT_COLUMNS)}")
        for line_no, raw in enumerate(reader, start=2):
            row = OutputRow(raw["case_id"], raw["deletion_status"], raw["steps_json"])
            if row.case_id in rows:
                raise ValueError(f"{path}:{line_no}: duplicate case_id {row.case_id}")
            rows[row.case_id] = row
    return rows


def evaluate_outputs(predictions_path: str | Path, reference_path: str | Path) -> dict[str, Any]:
    predictions = load_output(predictions_path)
    reference = load_output(reference_path)
    case_ids = sorted(set(predictions) | set(reference))
    reference_count = len(reference)
    status_correct = 0
    sequence_correct = 0
    field_correct = 0
    field_total = 0
    predicted_steps: Counter[tuple[str, str]] = Counter()
    reference_steps: Counter[tuple[str, str]] = Counter()
    failures: list[str] = []

    for case_id in case_ids:
        predicted = predictions.get(case_id)
        expected = reference.get(case_id)
        predicted_steps_list = json.loads(predicted.steps_json) if predicted is not None else []
        predicted_steps.update((case_id, _canonical(step)) for step in predicted_steps_list)
        if expected is None:
            failures.append(f"unexpected case_id: {case_id}")
            continue
        if predicted is None:
            failures.append(f"missing case_id: {case_id}")
            expected_steps = json.loads(expected.steps_json)
            reference_steps.update((case_id, _canonical(step)) for step in expected_steps)
            field_total += len(expected_steps) * len(AUDIT_STEP_FIELDS)
            continue

        if predicted.deletion_status == expected.deletion_status:
            status_correct += 1
        else:
            failures.append(
                f"{case_id}: status predicted {predicted.deletion_status.value}, expected {expected.deletion_status.value}"
            )

        expected_steps_list = json.loads(expected.steps_json)
        if predicted_steps_list == expected_steps_list:
            sequence_correct += 1
        else:
            failures.append(f"{case_id}: ordered steps differ")

        reference_steps.update((case_id, _canonical(step)) for step in expected_steps_list)
        predicted_by_number = {step["step_no"]: step for step in predicted_steps_list}
        expected_by_number = {step["step_no"]: step for step in expected_steps_list}
        for step_no in set(predicted_by_number) | set(expected_by_number):
            actual_step = predicted_by_number.get(step_no)
            expected_step = expected_by_number.get(step_no)
            for field_name in AUDIT_STEP_FIELDS:
                field_total += 1
                if (
                    actual_step is not None
                    and expected_step is not None
                    and actual_step.get(field_name) == expected_step.get(field_name)
                ):
                    field_correct += 1

    step_true_positives = sum((predicted_steps & reference_steps).values())
    predicted_step_count = sum(predicted_steps.values())
    reference_step_count = sum(reference_steps.values())
    precision = _ratio(step_true_positives, predicted_step_count)
    recall = _ratio(step_true_positives, reference_step_count)
    return {
        "reference_cases": reference_count,
        "prediction_cases": len(predictions),
        "case_status_accuracy": _ratio(status_correct, reference_count),
        "case_status_correct": status_correct,
        "sequence_accuracy": _ratio(sequence_correct, reference_count),
        "exact_sequences": sequence_correct,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": _f1(precision, recall),
        "exact_step_matches": step_true_positives,
        "predicted_steps": predicted_step_count,
        "reference_steps": reference_step_count,
        "field_accuracy": _ratio(field_correct, field_total),
        "matching_fields": field_correct,
        "compared_fields": field_total,
        "failures": failures,
    }


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args()
    metrics = evaluate_outputs(args.predictions, args.reference)
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
