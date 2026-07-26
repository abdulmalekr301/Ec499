# Office Compact Graph Materialization

Generated: `2026-07-26T03:23:11+00:00`

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
  "requested_unique_candidates": 23829,
  "materialized_or_existing": 14467,
  "missing_count": 9362,
  "stop_reason": "completed_with_deferred_pcaps",
  "newly_materialized_class_counts": {
    "DoS": 13909
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 13909
  },
  "processed_pcaps": 2,
  "deferred_pcaps": [
    {
      "pcap": "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-16-02-2018/pcap/UCAP172.31.69.25-part2.pcap",
      "status": "preslice_empty",
      "error": "",
      "candidate_count": 9362,
      "matched": 0,
      "flows_scanned": 0,
      "remaining": 9362
    }
  ],
  "pcap_health": {
    "enabled": false,
    "manifest_path": "/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json",
    "status": "disabled",
    "skip_pcaps": [],
    "skip_reasons": {}
  },
  "safety_summary": {
    "LOCAL_TEMPORAL_CONTEXT_FALLBACK": 13909
  }
}
```

## Safety Samples
```json
[]
```
