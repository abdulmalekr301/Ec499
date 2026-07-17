# Office Compact Graph Gate 5 Validation

Date: 2026-07-17

## Action

Implemented compact graph pool validation for the CIC-IDS-2018 office track.

Added:

- `secureedge/office/validate.py`

Generated:

- `artifacts/office_model/gate_reports/gate5_compact_features.json`

## Command

```bash
.venv/bin/python -m secureedge.office.validate --gate 5
```

## Gate 5 result

```text
gate: G5_COMPACT_FEATURES
status: pass
record_count: 49242
validated_record_count: 49242
hard_failure_count: 0
warning_count: 2
report_hash: 138ad02fe9d964924aebc1207bcf6f15d903b96793cf582daa26e7d153dee720
```

## Class counts

```json
{
  "Benign": 10764,
  "Bot": 14172,
  "BruteForce": 200,
  "DDoS": 20,
  "DoS": 165,
  "Infiltration": 23509,
  "WebBased": 412
}
```

These counts match the cumulative manifest.

## Schema validation

All 49,242 compact graph records matched the expected schema:

```json
{
  "flow_dim": {
    "92": 49242
  },
  "packet_dim": {
    "1500": 49242
  },
  "contain_edge_dim": {
    "4": 49242
  },
  "link_edge_dim": {
    "1": 49242
  }
}
```

All records use the expected compact feature version:

```json
{
  "xgnid_76_plus_temporal_16": 49242
}
```

All records use the expected dtypes:

```json
{
  "flow_x": {
    "float32": 49242
  },
  "packet_x_uint8": {
    "uint8": 49242
  },
  "contain_edge_attr": {
    "float32": 49242
  },
  "link_edge_attr": {
    "float32": 49242
  }
}
```

## Packet-count distribution

```json
{
  "1": 15,
  "2": 24986,
  "3": 217,
  "4": 1381,
  "5": 349,
  "6": 576,
  "7": 522,
  "8": 426,
  "9": 636,
  "10": 14593,
  "11": 310,
  "12": 104,
  "13": 68,
  "14": 115,
  "15": 924,
  "16": 275,
  "17": 331,
  "18": 268,
  "19": 328,
  "20": 2818
}
```

No compact graph had zero packets or more than the configured packet limit.

## Identity leakage audit

Gate 5 checked flow feature names for raw address identity features:

```json
{
  "address_identity_features": [],
  "tuple_context_features": [
    "dst_port",
    "protocol",
    "src_port"
  ]
}
```

Interpretation:

- No raw IP or MAC feature names were found.
- `src_port`, `dst_port`, and `protocol` are present. These are tuple-context features already included in the existing XG-NID-style flow schema, so they are recorded as warnings rather than hard failures.

## Verification

Commands run:

```bash
.venv/bin/python -m py_compile secureedge/office/validate.py secureedge/office/manifests.py secureedge/office/config.py
.venv/bin/python -m secureedge.office.validate --gate 5
```

## Next recovery-plan step

Implement office compact-to-PyG graph conversion and graph-level validation:

1. Resolve split references to compact graph files.
2. Convert compact records to `HeteroData`.
3. Fit scalers on train only.
4. Write an office graph dataset manifest.
5. Run Gate 6 structural validation.

