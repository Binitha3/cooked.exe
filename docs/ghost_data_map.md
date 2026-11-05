# Ghost Data Map JSON contract

`code.ghost_data_map.build_ghost_data_map` creates a frontend-ready graph from
subject-scoped `ResourceObservation` values, their `EvidenceIndex`, an
`audit_at` cutoff, and optionally the corresponding activity events. The return
shape is versioned as `ghost-data-map.v1` and is JSON serializable. Use
`serialize_ghost_data_map` for deterministic compact JSON. The
`build_ghost_data_map_payload` adapter combines those two steps for callers
that want the frontend JSON string directly.

```python
from code.evidence_processing import load_activity, load_evidence, search_subject
from code.ghost_data_map import build_ghost_data_map_payload

evidence_index = load_evidence(dataset_root / "evidence_files.csv", dataset_root)
activity = load_activity(dataset_root / "system_activity.csv")
observations = search_subject(resolved_subject, audit_at, evidence_index, activity)
json_payload = build_ghost_data_map_payload(
    observations, evidence_index, audit_at, activity,
)
```

See [`ghost_data_map_integration.md`](ghost_data_map_integration.md) for the
current pipeline architecture, complete invocation and frontend handoff notes.

## Stable fields

Every node has `node_id`, `node_type` (`SYSTEM` or `RESOURCE`), `system_id`,
`resource_id` (null for systems), `resource_type`, `observed_state`,
`visual_state`, `risk_classification`, and `evidence_ids`. Resource nodes also
include provenance entries with distinct capture timestamps, record timestamps,
source locators, and trace IDs.

Every edge has `edge_id`, `source_node_id`, `destination_node_id`, `edge_type`,
`relationship_type`, `active_state` (null when unsupported), `support_status`,
`evidence_ids`, `trace_ids`, `source_locators`, `timestamp`, `captured_at`,
`record_timestamps`, `audit_at`, and `cutoff_status`.

Node `visual_state` distinguishes `REMAINING_RECORD`, `VERIFIED_ABSENT`,
`ANONYMIZED_RECORD`, `ACTIVE_FLOW`, `FLOW_INACTIVE`, and `RESTORE_BLOCKED`.
Explicit backup eligibility without a deletion block yields
`risk_classification="RESTORE_RISK"`; this does not claim a restore is running.

`OBSERVED_IN` edges connect a system to its evidenced resource. Activity edges
use `edge_type="REPORTED_ACTIVITY_CLAIM"`, keep the event type in
`relationship_type`, leave `active_state` null, and omit `reported_result`.
They describe a recorded claim, not confirmed propagation. `ACTIVE_DATA_FLOW`
edges are emitted only when the eligible evidence segment for an active flow
explicitly names both endpoint systems. They form a directed two-leg path
through the flow resource node. An active flow resource without endpoint
evidence remains a node and does not create a guessed path. Explicit resource
IDs paired in a single eligible evidence segment can create dependency edges
when both resources are already evidenced in the graph.

Observations without cutoff-valid cited evidence are omitted and explained in
`warnings`. Timestamps after `audit_at` are excluded independently at capture,
event, and segment levels. System and resource node IDs are deterministic and
encode only their contract identifiers, never names, emails, or other content.

## Example from the active-flow test fixture

The following excerpt comes from
`test_explicit_active_flow_creates_versioned_two_leg_path_with_trace_provenance`.
The fixture's evidence contains a flow resource, explicit source and target
systems, active scheduler fields, one trace, and two line locators.

```json
{
  "schema_version": "ghost-data-map.v1",
  "audit_at": "2026-09-01T12:05:00+00:00",
  "nodes": [
    {
      "node_id": "system:primary_db",
      "node_type": "SYSTEM",
      "system_id": "primary_db",
      "resource_id": null,
      "resource_type": "SYSTEM",
      "observed_state": "UNKNOWN",
      "visual_state": "SYSTEM",
      "risk_classification": null,
      "evidence_ids": ["flow_evidence"]
    },
    {
      "node_id": "resource:integration_service:data_flow_47",
      "node_type": "RESOURCE",
      "system_id": "integration_service",
      "resource_id": "data_flow_47",
      "resource_type": "DATA_FLOW",
      "observed_state": "ACTIVE",
      "visual_state": "ACTIVE_FLOW",
      "risk_classification": "ACTIVE_DATA_FLOW",
      "evidence_ids": ["flow_evidence"],
      "provenance": [
        {
          "evidence_id": "flow_evidence",
          "captured_at": "2026-09-01T12:03:00+00:00",
          "record_timestamps": [
            "2026-09-01T12:01:00+00:00",
            "2026-09-01T12:02:00+00:00"
          ],
          "source_locators": ["line:1", "line:2"],
          "trace_ids": ["trace-17"]
        }
      ]
    },
    {
      "node_id": "system:analytics_service",
      "node_type": "SYSTEM",
      "system_id": "analytics_service",
      "resource_id": null,
      "resource_type": "SYSTEM",
      "observed_state": "UNKNOWN",
      "visual_state": "SYSTEM",
      "risk_classification": null,
      "evidence_ids": ["flow_evidence"]
    }
  ],
  "edges": [
    {
      "edge_id": "edge:06ae4b3396c77d554e90c8be",
      "source_node_id": "system:primary_db",
      "destination_node_id": "resource:integration_service:data_flow_47",
      "edge_type": "ACTIVE_DATA_FLOW",
      "relationship_type": "ACTIVE_DATA_FLOW",
      "path_leg": "SOURCE_TO_FLOW",
      "active_state": "ACTIVE",
      "support_status": "EVIDENCE_BACKED",
      "evidence_ids": ["flow_evidence"],
      "trace_ids": ["trace-17"],
      "source_locators": ["line:2"],
      "timestamp": "2026-09-01T12:02:00+00:00",
      "captured_at": [
        {"evidence_id": "flow_evidence", "captured_at": "2026-09-01T12:03:00+00:00"}
      ],
      "record_timestamps": [
        {"evidence_id": "flow_evidence", "timestamp": "2026-09-01T12:02:00+00:00"}
      ],
      "audit_at": "2026-09-01T12:05:00+00:00",
      "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
      "resource_id": "data_flow_47"
    },
    {
      "edge_id": "edge:5f04a51e65494ed747b16c5d",
      "source_node_id": "resource:integration_service:data_flow_47",
      "destination_node_id": "system:analytics_service",
      "edge_type": "ACTIVE_DATA_FLOW",
      "relationship_type": "ACTIVE_DATA_FLOW",
      "path_leg": "FLOW_TO_DESTINATION",
      "active_state": "ACTIVE",
      "support_status": "EVIDENCE_BACKED",
      "evidence_ids": ["flow_evidence"],
      "trace_ids": ["trace-17"],
      "source_locators": ["line:2"],
      "timestamp": "2026-09-01T12:02:00+00:00",
      "captured_at": [
        {"evidence_id": "flow_evidence", "captured_at": "2026-09-01T12:03:00+00:00"}
      ],
      "record_timestamps": [
        {"evidence_id": "flow_evidence", "timestamp": "2026-09-01T12:02:00+00:00"}
      ],
      "audit_at": "2026-09-01T12:05:00+00:00",
      "cutoff_status": "INCLUDED_AT_OR_BEFORE_AUDIT_AT",
      "resource_id": "data_flow_47"
    }
  ],
  "warnings": []
}
```
