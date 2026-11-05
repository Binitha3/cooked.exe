# Ghost Data Map integration handoff

## Current checkout and compatibility

`ghost_data_map.py` consumes the shared contract types directly:

- `ResourceObservation` values from `search_subject`;
- `EvidenceIndex` from `load_evidence`;
- `ActivityEvent` values from `load_activity`; and
- the timezone-aware `audit_at` already used by the investigation.

Member 4 reviewed the integration shape and found no mismatch with the current
`code/contracts.py`. `code/main.py` is empty in this checkout, and
`identity_resolution.py` and `policy_engine.py` are not present, so there is no
complete investigation orchestrator here to edit or invoke. The integration
adapter accepts the existing pipeline outputs as they are; it does not replace
identity resolution or policy evaluation.

## Exact invocation

The public adapter signature uses only the existing shared contracts:

```python
def build_ghost_data_map_payload(
    observations: Sequence[ResourceObservation],
    evidence_index: EvidenceIndex,
    audit_at: datetime,
    activity: Sequence[ActivityEvent] = (),
) -> str:
```

After the pipeline has produced a contract `ResolvedSubject`, `audit_at`,
`EvidenceIndex`, and activity events, Member 4 can call:

```python
from code.evidence_processing import load_activity, load_evidence, search_subject
from code.ghost_data_map import build_ghost_data_map_payload

evidence_index = load_evidence(dataset_root / "evidence_files.csv", dataset_root)
activity = load_activity(dataset_root / "system_activity.csv")
observations = search_subject(
    resolved_subject, audit_at, evidence_index, activity,
)
ghost_data_map_json = build_ghost_data_map_payload(
    observations, evidence_index, audit_at, activity,
)
```

`ghost_data_map_json` is the complete serialized payload string, ready to pass
to the frontend boundary. If the caller needs a Python mapping instead, use
`build_ghost_data_map(observations, evidence_index, audit_at, activity)`.
The lower-level `serialize_ghost_data_map(graph)` remains available when the
caller has already built the mapping.

The helper does not accept an invented pipeline wrapper type: the shared
contracts remain the source of truth. The caller must pass the same audit time
used to produce subject observations. No contract or frontend files need to be
changed to consume the payload.

## Frontend payload contract

The decoded payload is a `ghost-data-map.v1` object with these top-level keys:

```json
{
  "schema_version": "ghost-data-map.v1",
  "audit_at": "<ISO-8601 timezone-aware cutoff>",
  "nodes": ["<system and resource node objects>"],
  "edges": ["<evidence-backed relationship objects>"],
  "warnings": ["<omitted evidence observations and reasons>"]
}
```

Nodes expose `node_id`, `node_type`, `system_id`, `resource_id`,
`resource_type`, `observed_state`, `visual_state`, `risk_classification`,
`evidence_ids`, and (for resources) `provenance`. Provenance separates
`captured_at` from record timestamps and retains trace IDs and source locators.
Edges expose source and destination node IDs, edge and relationship types,
`active_state` where supported, support status, evidence IDs, traces, locators,
event/record timestamps, capture times, `audit_at`, and `cutoff_status`.

The exact field example is in [`ghost_data_map.md`](ghost_data_map.md), derived
from the standard-library active-flow test fixture.
The machine-readable JSON Schema is [`ghost_data_map.schema.json`](ghost_data_map.schema.json).
It requires top-level `schema_version`, `audit_at`, `nodes`, `edges`, and
`warnings`; node variants are `SYSTEM` and `RESOURCE`, and each edge carries
its endpoint node IDs, evidence/provenance fields, timestamps, and cutoff.

## Safety behavior at integration

- The graph filters capture, observation, event, and record timestamps at
  `audit_at` and annotates included edges with the cutoff.
- Evidence IDs, trace IDs, locators, capture timestamps, and record timestamps
  stay attached to graph objects.
- Activity events are represented as reported claims; `reported_result` is not
  exposed as proof of state or propagation.
- An active flow requires explicit active configuration and explicit endpoint
  systems in eligible evidence before the graph emits directed path edges.
  Trace correlation alone establishes the subject-to-flow association, not a
  destination system. The actual dataset integration test exercises this
  distinction using participant-facing files.
- A backup relationship is emitted only for an explicitly paired resource
  relationship when both endpoint resources already have evidence-backed
  nodes. Eligibility does not imply an active restore.
- Disconnected resources remain disconnected; missing or future evidence is
  omitted with a warning.

## Integration test

Run from the repository root:

```text
python -B -m unittest code.test_ghost_data_map_integration -v
```

The test loads `dataset/evidence_files.csv` and `dataset/system_activity.csv`,
discovers a same-file subject key and active flow sharing a trace, runs the
actual `search_subject` implementation, and serializes the result through the
adapter. It does not hardcode a case, email, trace ID, or resource ID. It skips
only when the participant dataset files are absent.

## Verified results and limitations

On the supplied dataset, full standard-library unittest discovery ran **37
tests: 35 passed and 2 skipped**. The real-dataset integration test passed;
the skips are the integration-interface checks for unavailable
`identity_resolution.py` and `policy_engine.py`. The added boundary test
confirms evidence capture, record time, and activity time equal to `audit_at`
are included, while the existing cutoff test excludes later evidence. Tests
also cover disconnected resources, missing flow endpoints, an evidenced
backup dependency, and omission of a backup dependency whose target lacks an
evidenced graph node. Python's standard library parsed the schema JSON; a
third-party JSON Schema validator is not installed in this environment.

This checkout still has no runnable investigation orchestrator (`main.py` is
empty), identity resolver, or policy engine, so Member 4 must call the adapter
after those pipeline stages produce the shared-contract values. The dataset's
trace-correlated active flow has no explicit source/destination fields; the
payload represents its active flow resource, but correctly emits no directed
propagation path for it. PDF text/OCR extraction also depends on optional
packages documented in `evidence_processing.py` and may be unsupported when
those packages are absent.
