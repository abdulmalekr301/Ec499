# Office Gate 7 Split and Leakage Validation

Date: 2026-07-17

## Action

Implemented graph-level split and leakage validation for the CIC-IDS-2018 office track.

Updated:

- `secureedge/office/validate.py`

Generated:

- `artifacts/office_model/gate_reports/gate7_split_leakage.json`

## Command

```bash
.venv/bin/python -m secureedge.office.validate --gate 7
```

## Gate 7 result

```text
gate: G7_SPLIT_LEAKAGE
status: fail
record_count: 49242
hard_failure_count: 1
warning_count: 1
report_hash: 1027eced6ffec53d827aaa7da977a9205c92aac71097bd89f9760644310685f9
```

## Hard failure

```json
[
  {
    "detail": "DDoS",
    "path": "test",
    "reason": "class_missing_from_split"
  }
]
```

Interpretation:

- Gate 7 is working as intended.
- The current office graph dataset is not training-ready because the test split has zero DDoS graphs.
- This is a materialization-completeness blocker, not a split-leakage bug.

## Warning

```json
[
  {
    "detail": "Graph manifest was built from the current partial office compact pool.",
    "path": "/var/home/alucard-00/EC499/artifacts/office_model/office_graph_dataset_manifest.json",
    "reason": "materialization_incomplete"
  }
]
```

## Leakage checks

Gate 7 found no graph-level leakage:

```text
duplicate_candidate_identity_count: 0
duplicate_graph_id_count: 0
cross_split_candidate_identity_overlap_count: 0
cross_split_flow_hash_overlap_count: 0
cross_split_graph_id_overlap_count: 0
```

Dataset-source check:

```json
{
  "cicids2017_by_split": {}
}
```

No CICIDS2017 graph is currently present in any generated graph split. Therefore, there is also no CICIDS2017 leakage into validation or test.

## Split class counts

```json
{
  "train": {
    "Benign": 9002,
    "Bot": 11744,
    "BruteForce": 180,
    "DDoS": 19,
    "DoS": 134,
    "Infiltration": 19587,
    "WebBased": 206
  },
  "val": {
    "Benign": 906,
    "Bot": 1204,
    "BruteForce": 8,
    "DDoS": 1,
    "DoS": 18,
    "Infiltration": 1955,
    "WebBased": 103
  },
  "test": {
    "Benign": 856,
    "Bot": 1224,
    "BruteForce": 12,
    "DDoS": 0,
    "DoS": 13,
    "Infiltration": 1967,
    "WebBased": 103
  }
}
```

## Source distribution

```json
{
  "train": {
    "CSE-CIC-IDS2018": 40872
  },
  "val": {
    "CSE-CIC-IDS2018": 4195
  },
  "test": {
    "CSE-CIC-IDS2018": 4175
  }
}
```

## Next recovery-plan step

Return to targeted materialization before sharding or training:

1. Materialize enough additional DDoS compact graphs to populate the test split.
2. Re-run cumulative manifest reconciliation.
3. Re-run Gate 5.
4. Re-run office PyG conversion.
5. Re-run Gates 6 and 7.

Training should remain blocked until Gate 7 passes.

