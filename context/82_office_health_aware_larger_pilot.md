# Office Health-Aware Larger Materialization Pilot

Generated: `2026-07-15T01:24:00+00:00`

## Action

- Added a PCAP-health-aware option to office compact graph materialization.
- Used the previous compact materialization manifest to skip known bad PCAPs:
  deferred memory-error PCAPs and prior zero-yield PCAPs.
- Ran a larger bounded pilot, not a full run.
- Preserved the full-run lock: no unbounded materialization was started.

## Command

```bash
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=5 \
SECUREEDGE_MAX_PROCESS_RSS_GB=2 \
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-limit-unique 1000 \
  --office-max-pcaps 20 \
  --office-max-flows-per-pcap 100000 \
  --office-health-aware \
  --office-health-manifest artifacts/office_model/office_compact_graph_manifest.json \
  --office-health-min-yield 0.05
```

## Health Policy

Skipped from the previous manifest:

```json
{
  "skip_pcaps": [
    "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-16-02-2018/pcap/UCAP172.31.69.25-part1.pcap",
    "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-16-02-2018/pcap/UCAP172.31.69.25-part2.pcap",
    "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Wednesday-21-02-2018/pcap/UCAP172.31.69.28 part 1"
  ],
  "skip_reasons": {
    "UCAP172.31.69.25-part1.pcap": "previous worker_error",
    "UCAP172.31.69.25-part2.pcap": "previous low_yield_0.0000",
    "UCAP172.31.69.28 part 1": "previous worker_error"
  }
}
```

## Result

```json
{
  "requested_unique_candidates": 1000,
  "materialized_or_existing": 923,
  "missing_count": 77,
  "processed_pcaps": 20,
  "stop_reason": "max_pcaps_reached",
  "newly_materialized_class_counts": {
    "Benign": 26,
    "Bot": 485,
    "Infiltration": 331
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 842
  },
  "safety_summary": {
    "flagged_graphs": 266
  }
}
```

The final compact graph file count after this pilot is `928`.

## Deferred PCAPs

One new PCAP should be added to the health skip/deprioritize list for the next
batch:

```json
{
  "pcap": "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/capEC2AMAZ-O4EL3NG-172.31.69.13 part3",
  "status": "max_flows_per_pcap_reached",
  "candidate_count": 7,
  "matched": 0,
  "flows_scanned": 100001,
  "remaining": 7
}
```

## Interpretation

This is the strongest materialization signal so far:

- Health-aware skipping avoided the known bad PCAPs from the prior manifest.
- 923/1000 selected candidates were materialized or already existed.
- 19/20 processed PCAP workers completed normally.
- The only non-completed worker hit the configured flow cap and was deferred
  cleanly.
- No memory-floor crash occurred.
- No lingering office materialization worker remained after the run.
- `tests/smoke_checks.py` passed afterward.

The `flagged_graphs` count is still from payload nonzero-fraction outliers, not
non-finite tensors. Most sampled flags are Infiltration zero-payload scan/probe
flows, which were confirmed as legitimate in
`80_office_infiltration_payload_audit.md`. A small number of Benign zero-payload
flows also appeared in the safety samples; they are finite and should not block
graph generation, but they remain useful audit metadata.

## Next Step

The pipeline is ready to move from diagnostic pilots to controlled graph
generation. Keep the full-run lock in place and launch the full materialization
only as an explicit controlled run with health-aware skipping enabled and the
latest manifest as the health source.
