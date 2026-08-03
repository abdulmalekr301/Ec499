# Office Thursday-15 DoS GoldenEye/Slowloris 6k Graph Generation

Date: `2026-08-02`

## Summary

Generated enough strict Thursday `DoS-GoldenEye` and `DoS-Slowloris` compact graphs to support a `6,000` graph cap for each subtype.

| Subtype | Target | Materialized unique graphs | Usable after cap |
|---|---:|---:|---:|
| `DoS-GoldenEye` | 6,000 | 6,000 | 6,000 |
| `DoS-Slowloris` | 6,000 | 6,173 | 6,000 |

Total generated pool for these two subtypes: `12,173` unique compact graphs.

## Source Data

Victim endpoint PCAP:

`datasets/cic_ids_2018/raw_pcaps/Thursday-15-02-2018/pcap/UCAP172.31.69.25`

The rows came from the strict true-success Thursday-15 selection:

- exact expected attacker public IP to victim private IP;
- TCP destination port `80`;
- exact subtype label;
- `Attempted Category == -1`;
- no attempted rows included.

## Generation Runs

| Run | Candidate file | Candidates | Matched | Remaining | Notes |
|---|---|---:|---:|---:|---|
| Primary 6k each | `artifacts/office_model/exception_candidates/dos_thursday15_goldeneye_slowloris_strict_true_6000_each.jsonl` | 12,000 | 10,357 | 1,643 | Produced all 6,000 GoldenEye and 4,357 Slowloris |
| Missing Slowloris retry | `artifacts/office_model/exception_candidates/dos_thursday15_slowloris_missing_1643_retry.jsonl` | 1,643 | 0 | 1,643 | Wider 10s timestamp tolerance did not recover the missing rows |
| Slowloris supplement | `artifacts/office_model/exception_candidates/dos_thursday15_slowloris_unused_strict_true_supplement_2490.jsonl` | 2,490 | 1,816 | 674 | Used unused strict-true Slowloris rows to pass the 6k target |

Summary artifacts:

- `artifacts/office_model/materialization_work/dos_thursday15_goldeneye_slowloris_6000_each.summary.json`
- `artifacts/office_model/materialization_work/dos_thursday15_slowloris_missing_1643_retry_10s.summary.json`
- `artifacts/office_model/materialization_work/dos_thursday15_slowloris_unused_strict_true_supplement_2490.summary.json`
- `artifacts/office_model/exception_candidates/dos_thursday15_goldeneye_slowloris_6000_each_graph_generation_manifest.json`

## Validation

Disk validation over `data/graphs/office_compact/DoS/*.pkl` found:

| Check | Result |
|---|---:|
| Actual graph files in generated pool | 12,173 |
| Unique flow hashes | 12,173 |
| Duplicate path hashes | 0 |
| Zero-packet graphs | 0 |
| Missing required metadata records | 0 |

Metadata policy counts:

| Policy | Graphs |
|---|---:|
| `thursday15_dos_strict_true_6000_each_temporal_spread_v1` | 10,357 |
| `thursday15_dos_slowloris_unused_strict_true_supplement_v1` | 1,816 |

## Notes

- The initial balanced 6k candidate set was duplicate-free, but only `4,357 / 6,000` selected Slowloris rows had packet material recoverable from the victim endpoint PCAP.
- The missing `1,643` selected Slowloris rows also failed a targeted 10-second tolerance retry, which indicates the issue is missing/unavailable packet material for those specific CSV rows rather than an overly tight 3-second tolerance.
- The supplement stayed inside the same strict true-success selection rules and used the remaining unused Slowloris strict candidates.
- `DoS-Slowloris` now has `173` extra materialized graphs beyond the 6k target. The final dataset/split manifest should cap this subtype at `6,000` if exact subtype balance is required.
