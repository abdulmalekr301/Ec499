# Office Materialization Memory Diagnosis Follow-Up

Generated: `2026-07-14T00:05:20+00:00`

## Actions Taken

- Added a packet-level open-flow diagnostic mode:
  `--mode office-open-flow-diagnostic`.
- Ran the diagnostic on the previously problematic PCAP:
  `Friday-02-03-2018/pcap/capDESKTOP-AN3U28N-172.31.64.115`.
- Implemented density-aware bounded candidate selection for compact graph
  materialization.
- Refined bounded selection so `--office-max-pcaps 5` spreads the pilot
  across the top five dense endpoint PCAPs instead of selecting all 200
  candidates from only the single densest PCAP.
- Added defer handling for memory-floor worker errors and max-flow caps so one
  worst-case PCAP does not end the bounded pilot.
- Re-ran the same bounded pilot shape:
  `--office-limit-unique 200 --office-max-pcaps 5 --office-max-flows-per-pcap 100000`
  with a 5 GiB available-memory floor.

## Open-Flow Diagnostic Result

```json
{
  "pcap": "datasets/cic_ids_2018/raw_pcaps/Friday-02-03-2018/pcap/capDESKTOP-AN3U28N-172.31.64.115",
  "transport_packets_scanned": 84218,
  "opened_flows": 4776,
  "expired_flows": 4776,
  "active_flows_at_scan_end": 0,
  "max_active_flows": 507,
  "idle_timeout_seconds": 120.0,
  "active_timeout_seconds": 1800.0
}
```

Interpretation: the tested PCAP did not show thousands of simultaneously-open
flows. The timeout hypothesis is therefore not strongly confirmed for this
capture. NFStream memory pressure may still be tied to internal per-flow state
or payload/plugin behavior, but the next safe optimization should stay with
batching/defer controls rather than changing `active_timeout` or
`idle_timeout`.

## Bounded Pilot Result

The improved bounded pilot completed cleanly without crashing the desktop or
leaving a worker process behind.

```json
{
  "requested_unique_candidates": 200,
  "materialized_or_existing": 82,
  "missing_count": 118,
  "processed_pcaps": 5,
  "stop_reason": "max_pcaps_reached",
  "newly_materialized_class_counts": {
    "Infiltration": 79,
    "Benign": 2
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 81
  },
  "safety_summary": {
    "flagged_graphs": 81
  }
}
```

Per-PCAP worker outcomes:

| PCAP | Status | Candidates | Matched | Flows scanned | Remaining |
|---|---:|---:|---:|---:|---:|
| `UCAP172.31.69.25-part1.pcap` | memory deferred | 40 | 0 | 87,600 | 40 |
| `UCAP172.31.69.25-part2.pcap` | completed | 40 | 0 | 640 | 40 |
| `UCAP172.31.69.15` | completed | 40 | 40 | 359 | 0 |
| `UCAP172.31.69.7` | completed | 40 | 40 | 391 | 0 |
| `UCAP172.31.69.28 part 1` | memory deferred | 40 | 1 | 2,470 | 39 |

## Safety Notes

- Memory safety worked: two workers hit the 5 GiB floor and were deferred.
- The scheduler continued after deferable failures and finished the bounded
  PCAP budget.
- `flagged_graphs: 81` is from payload nonzero-fraction outliers, mostly
  zero-payload Infiltration graphs. These are numerically finite, but the
  payload distribution should be reviewed before scaling.
- Current compact graph file count after the bounded runs: 86.

## Next Recommended Step

Do not start the full materialization yet. The next useful improvement is a
candidate-time-aware or PCAP-health-aware scheduler that avoids known
low-yield/deferred PCAPs on subsequent bounded runs, while preserving the
same NFStream timeout values.
