# Office Compact Graph Materialization

Generated: `2026-07-26T05:11:27+00:00`

## Action
- Materialized office-model compact graph records from final split candidates.
- Matched candidate flows by endpoint PCAP, 5-tuple, and timestamp tolerance.
- Ordered bounded pilots by endpoint-PCAP candidate density to reduce one-graph full-PCAP scans.
- Deferred max-flow and memory-floor PCAP stops instead of letting one worst-case scan end the whole pilot.
- Recomputed 92 flow-node features from matched packets via NFStream-derived records.
- Logged per-graph numerical and payload safety flags while building records.
- Saved compact graph manifest to `/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json`.

## Counts
```json
{
  "requested_unique_candidates": 182,
  "materialized_or_existing": 20,
  "missing_count": 152,
  "stop_reason": "completed",
  "newly_materialized_class_counts": {
    "Infiltration": 20
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 20
  },
  "processed_pcaps": 7,
  "deferred_pcaps": [],
  "pcap_health": {
    "enabled": false,
    "manifest_path": "/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json",
    "status": "disabled",
    "skip_pcaps": [],
    "skip_reasons": {}
  },
  "safety_summary": {
    "LOCAL_TEMPORAL_CONTEXT_FALLBACK": 30,
    "matched_zero_packet_graph": 10
  }
}
```

## Safety Samples
```json
[]
```
