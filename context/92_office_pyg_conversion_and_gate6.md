# Office PyG Conversion and Gate 6 Validation

Date: 2026-07-17

## Action

Implemented the office compact-to-PyG graph conversion step and graph-structure validation.

Added:

- `secureedge/office/build_graphs.py`
- Gate 6 support in `secureedge/office/validate.py`

Generated:

- `artifacts/office_model/office_graph_dataset_manifest.json`
- `artifacts/office_model/office_flow_node_scaler.joblib`
- `artifacts/office_model/office_contain_edge_scaler.joblib`
- `artifacts/office_model/office_link_edge_norm_p99.json`
- `artifacts/office_model/gate_reports/gate6_graph_structure.json`
- `data/graphs/office_train/*.pt`
- `data/graphs/office_val/*.pt`
- `data/graphs/office_test/*.pt`

The office converter writes to separate office graph directories and does not modify the original IoT `data/graphs/train`, `data/graphs/val`, or `data/graphs/test` directories.

## Conversion command

```bash
.venv/bin/python -m secureedge.office.build_graphs --overwrite
```

Output:

```json
{
  "manifest": "/var/home/alucard-00/EC499/artifacts/office_model/office_graph_dataset_manifest.json",
  "materialization_incomplete": true,
  "n_test": 4175,
  "n_train": 40872,
  "n_val": 4195,
  "total_graph_count": 49242
}
```

## Graph output sizes

```text
2.0G  data/graphs/office_train
206M  data/graphs/office_val
203M  data/graphs/office_test
9.1M  artifacts/office_model/office_graph_dataset_manifest.json
```

## Split counts

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

The manifest correctly sets:

```text
materialization_incomplete: true
```

because the current compact graph pool is still a partial materialization of the intended office split.

## Gate 6 command

```bash
.venv/bin/python -m secureedge.office.validate --gate 6
```

## Gate 6 result

```text
gate: G6_GRAPH_STRUCTURE
status: pass
record_count: 49242
validated_graph_count: 49242
hard_failure_count: 0
warning_count: 1
report_hash: f89d178e3211efa6139649d7b5b31b28bbd6add70c6a60ca6caa006bd5c19fff
```

The single warning is:

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

- The generated PyG graph objects are structurally valid.
- The office graph dataset is not yet suitable for final model training because DDoS is absent from the test split and several classes remain far below target.
- The warning reflects incomplete materialization, not a graph serialization or schema defect.

## Structural checks performed

Gate 6 validates:

- graph file existence and loadability
- `flow` and `packet` node types
- expected edge types
- flow node dimensions
- packet node dimensions
- contain/reverse-contain edge index and edge attribute dimensions
- packet-link edge dimensions
- finite node and edge features
- graph labels against office class names
- duplicate graph IDs
- per-split and per-class manifest counts
- self-loops and duplicate packet-link edges

## Next recovery-plan step

Implement graph-level split/leakage validation:

1. Check cross-split candidate identity overlap.
2. Confirm CICIDS2017 graphs appear only in train.
3. Report exact per-source and per-day graph distributions.
4. Decide whether to proceed with sharding for smoke training or return to materialization to fill missing DDoS test coverage first.

