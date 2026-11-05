# Model usage report

## Run status

The final full replay processed all **518** requests independently. It produced **381** per-row validated candidate outputs and recorded **137** unresolved cases; see `replay_diagnostics.json` and `unresolved_case_audit.json`. The 381 rows are preserved separately as `partial_validated_rows_not_for_submission.csv`, with `partial_replay_manifest.json`. This is a diagnostic artifact only. No root `output.csv` was generated because the unresolved cases prevent a valid complete submission.

The pipeline used local deterministic code and participant-visible dataset evidence. No model provider was called during the replay.

| Usage item | Result |
|---|---|
| Requests processed independently | 518 |
| Validated candidate rows | 381 |
| Unresolved requests | 137 |
| Full 518-row `output.csv` generated | No |
| Model providers / model names | None used by the pipeline |
| Model calls | 0 observed |
| Input / output / total model tokens | 0 model tokens; no provider calls |
| Average model tokens per request | 0; no provider calls |
| Estimated model cost | Not applicable; no model run |
| Per-model totals | None |
| Overall model totals | No provider usage |

These values describe actual model usage during the independent replay only. They are not accuracy metrics or a claim that the 518-row submission completed.
