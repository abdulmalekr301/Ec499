# Office Scaled Bounded Materialization Run

Generated: `2026-07-14T01:25:00+02:00`

## Action

Ran the requested scaled bounded office graph materialization after adding
CIC-IoT2023-style memory guardrails.

Command shape:

```bash
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=<floor> \
SECUREEDGE_MAX_PROCESS_RSS_GB=2 \
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-limit-unique 200 \
  --office-max-pcaps 5 \
  --office-max-flows-per-pcap 100000
```

## Attempts

### 8 GiB Floor

Controlled stop:

```json
{
  "status": "worker_error",
  "error": "MemoryError: available memory is 8.00 GiB, below configured floor 8.00 GiB",
  "pcap": "capDESKTOP-AN3U28N-172.31.64.115",
  "flows_scanned": 1080,
  "matched": 0
}
```

### 7.5 GiB Floor

Controlled stop:

```json
{
  "status": "worker_error",
  "error": "MemoryError: available memory is 7.50 GiB, below configured floor 7.50 GiB",
  "pcap": "capDESKTOP-AN3U28N-172.31.64.115",
  "flows_scanned": 2210,
  "matched": 0
}
```

### 6.5 GiB Floor

Controlled stop:

```json
{
  "status": "worker_error",
  "error": "MemoryError: available memory is 6.50 GiB, below configured floor 6.50 GiB",
  "pcap": "capDESKTOP-AN3U28N-172.31.64.115",
  "flows_scanned": 3340,
  "matched": 0
}
```

### 5 GiB Floor

This run made progress and stopped safely on the fourth endpoint PCAP.

Output manifest:

```text
artifacts/office_model/office_compact_graph_manifest.json
```

Summary:

```json
{
  "requested_unique_candidates": 200,
  "materialized_or_existing": 4,
  "missing_count": 196,
  "stop_reason": "worker_error",
  "processed_pcaps": 4,
  "max_pcaps": 5,
  "safety_summary": {},
  "newly_materialized_class_counts": {
    "Benign": 3
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 3
  }
}
```

Per-PCAP result:

```json
{
  "capDESKTOP-AN3U28N-172.31.64.115": {
    "status": "completed",
    "candidate_count": 1,
    "matched": 1,
    "flows_scanned": 27025,
    "remaining": 0
  },
  "capDESKTOP-AN3U28N-172.31.64.126": {
    "status": "completed",
    "candidate_count": 1,
    "matched": 1,
    "flows_scanned": 7190,
    "remaining": 0
  },
  "capDESKTOP-AN3U28N-172.31.64.84": {
    "status": "completed",
    "candidate_count": 1,
    "matched": 1,
    "flows_scanned": 4183,
    "remaining": 0
  },
  "capDESKTOP-AN3U28N-172.31.65.113": {
    "status": "worker_error",
    "candidate_count": 1,
    "matched": 0,
    "flows_scanned": 8100,
    "remaining": 1,
    "error": "MemoryError: available memory is 5.00 GiB, below configured floor 5.00 GiB"
  }
}
```

Compact records now present:

```text
data/graphs/office_compact/Benign/CSE-CIC-IDS2018_Friday-02-03-2018_144edf574f2397b6af2ad846e398474e49996507486342b118f91951dad0668f.pkl
data/graphs/office_compact/Benign/CSE-CIC-IDS2018_Friday-02-03-2018_41fcfa7850e6d67e23c47e48069591c3e810635044ca12dee22fe5f47fbe0ede.pkl
data/graphs/office_compact/Benign/CSE-CIC-IDS2018_Friday-02-03-2018_c579208d8191c15b0fa3e620668a70115496ff93a8aba46d6d7a33b16884e665.pkl
data/graphs/office_compact/Benign/CSE-CIC-IDS2018_Friday-02-03-2018_e9f02cdb73d9e303ef8557bacc79ac2d98a1cf477a7cd2a978d0cc5fb2f6150e.pkl
```

## Memory State After Run

```text
Mem: 15Gi total, 5.5Gi used, 9.9Gi available
Swap: 7.7Gi total, 2.3Gi used
```

No office materialization worker remained running after the bounded run.

## Takeaway

The memory guardrails are working: the process now stops cleanly instead of
crashing the desktop. However, the current candidate ordering creates a poor
bounded-run shape: many endpoint PCAPs have only one selected candidate, and
NFStream may scan thousands to tens of thousands of flows before reaching it.

The next improvement should be selection-aware batching: group materialization
by endpoint PCAP density, prioritizing PCAPs with more pending candidates per
scan, or build smaller per-class/source pilots that avoid one-candidate sparse
PCAP scans. This should increase graphs-per-worker without reducing the memory
floor further.
