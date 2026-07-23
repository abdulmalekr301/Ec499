# Office Full Graph Generation Attempt

Generated: `2026-07-15T04:36:55+00:00`

## Action
- Started the full health-aware office compact graph materialization with the full-run lock enabled.
- Kept the memory-safety procedures active:
  - `SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1`
  - `SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=5`
  - `SECUREEDGE_MAX_PROCESS_RSS_GB=2`
  - `SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10`
  - `--office-health-aware`
  - `--office-health-min-yield 0.05`
- Interrupted the foreground parent after a guarded NFStream worker `MemoryError` was followed by several minutes of no parent progress.
- Exported readable Markdown graph samples from the compact graph files that were successfully materialized.

## Materialization Outcome
The run did not complete a fresh top-level `office_compact_graph_manifest.json`; that manifest still reflects the earlier bounded pilot. The larger run is represented by per-PCAP summaries under:

`artifacts/office_model/materialization_work`

```json
{
  "work_summary_files": 1101,
  "work_statuses": {
    "completed": 981,
    "worker_error": 118,
    "max_flows_per_pcap_reached": 2
  },
  "candidate_count_sum": 84975,
  "matched_sum": 47931,
  "flows_scanned_sum": 21360735,
  "materialized_path_refs": 47931,
  "materialized_refs_by_class": {
    "Benign": 10733,
    "Infiltration": 23099,
    "Bot": 13687,
    "WebBased": 412
  },
  "all_compact_graph_files_by_class": {
    "Benign": 10764,
    "Infiltration": 23509,
    "Bot": 14172,
    "WebBased": 412
  }
}
```

## Safety Finding
The memory-safety guard worked as intended for worker-level pressure. Problem PCAPs were deferred instead of crashing the desktop session. Examples include:

- `worker_error`: available memory crossed the configured 5 GiB floor during worker scanning.
- `max_flows_per_pcap_reached`: the 100000-flow per-PCAP cap was reached.
- One NFStream child raised `MemoryError` inside `pad_payload`; the parent stayed alive but then stopped emitting progress, so the run was interrupted manually with exit code 130.

Final memory check after interruption:

```text
Mem: 15Gi total, 5.9Gi used, 9.5Gi available
Swap: 7.7Gi total, 4.4Gi used
```

## Readable Graph Samples
Readable Markdown samples were generated here:

`artifacts/office_model/readable_graph_samples`

Manifest:

`artifacts/office_model/readable_graph_samples_manifest.json`

Context note:

`context/83_office_readable_graph_samples.md`

```json
{
  "samples_per_class_requested": 10,
  "per_class_counts": {
    "Benign": 10,
    "BruteForce": 0,
    "DoS": 0,
    "DDoS": 0,
    "WebBased": 10,
    "Bot": 10,
    "Infiltration": 10
  },
  "missing_classes": [
    "BruteForce",
    "DoS",
    "DDoS"
  ],
  "sample_count": 40
}
```

## Important Limitation
The current readable sample set covers 4 of 7 classes. BruteForce, DoS, and DDoS did not yet have compact graph files when the stuck full pass was interrupted, so the requested 10 readable samples for those classes could not be generated in this run.

The next materialization step should be class-targeted or resume-aware for the three missing classes, rather than another unfiltered full pass from the current density order.
