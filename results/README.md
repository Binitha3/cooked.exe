# Results

`partial_validated_rows_not_for_submission.csv` preserves the 381 rows that
passed per-row validation during the 518-request replay. It is a diagnostic
artifact, not the official `output.csv`. Do not rename it or submit it as a
complete result. The official root `output.csv` remains absent until all 518
requests can be validated.


`diagnostic_all_518_with_unresolved.csv` is a diagnostic convenience file: it combines the 381 validated candidate rows with 137 rows marked `UNRESOLVED` and empty step arrays. It is **not** an official output file because `UNRESOLVED` is not an allowed challenge status. Per-case blocker reasons remain in `evaluation/replay_diagnostics.json` and `evaluation/unresolved_case_audit.json`.
