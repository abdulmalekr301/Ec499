# Office Missing-Class Targeted Recovery Completed

Date: 2026-07-16

## Action

Followed the recommended recovery path from
`85_office_missing_class_targeted_recovery.md`:

1. Reduced BruteForce, DoS, and DDoS PCAP inputs before NFStream.
2. Ran class-targeted compact materialization against the reduced inputs.
3. Regenerated readable graph samples after every previously missing class
   reached at least 10 compact graphs.

## Implementation Notes

- Added attack-class pre-slicing for `BruteForce`, `DoS`, and `DDoS`.
- Added candidate 5-tuple BPF generation.
- Added a streaming candidate-window PCAP slicer for cases where IP-pair or
  5-tuple-only slices remain too large for NFStream.
- Preserved worker isolation and deferral behavior for timeouts, worker
  failures, missing summaries, and unusable pre-slices.

## Targeted Materialization Results

Final compact graph counts:

```json
{
  "Benign": 10764,
  "BruteForce": 200,
  "DoS": 165,
  "DDoS": 20,
  "WebBased": 412,
  "Bot": 14172,
  "Infiltration": 23509
}
```

Class-targeted runs:

```text
BruteForce: 200 requested, 200 matched/materialized
DoS:        200 requested, 165 matched/materialized
DDoS:        20 requested,  20 matched/materialized
```

The DDoS recovery required the tighter streaming candidate-window slice:

```json
{
  "bpf_strategy": "candidate_5tuple",
  "window_seconds": 5.0,
  "packets_written": 201768,
  "output_bytes": 18159144,
  "matched": 20,
  "flows_scanned": 9370
}
```

## Readable Samples

Regenerated readable graph samples with 10 samples per class.

```json
{
  "sample_count": 70,
  "per_class_counts": {
    "Benign": 10,
    "BruteForce": 10,
    "DoS": 10,
    "DDoS": 10,
    "WebBased": 10,
    "Bot": 10,
    "Infiltration": 10
  },
  "missing_classes": []
}
```

Readable sample manifest:

```text
artifacts/office_model/readable_graph_samples_manifest.json
```

## Verification

```bash
.venv/bin/python -m py_compile secureedge/data/office_pipeline.py tests/smoke_checks.py
.venv/bin/python tests/smoke_checks.py
```

Both checks passed.
