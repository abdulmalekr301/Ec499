# Training Round 3 Adjustments

> Generated: 2026-06-16
> Source instruction: `context/training-round-3.md`

## Summary

Round 3 confirmed that the current model is not blocked by another hyperparameter
choice. Three different training configurations plateaued around macro F1 0.87,
so the next work is data quality: packet payload verification and oversampling
verification.

No new full training run was started. The round-3 instruction explicitly says not
to continue hyperparameter tuning until the data problems are addressed.

## Changes Applied

### 1. Restored the best-known training default

Updated `secureedge/config.py` so the default label smoothing is back to `0.0`.
This matches training round 3, which recovered the round 1 score after round 2
regressed with label smoothing `0.1`.

The training script still allows overrides through:

```bash
SECUREEDGE_LABEL_SMOOTHING=...
```

### 2. Strengthened packet payload diagnostics

Updated `secureedge/data/payload_diagnostic.py`.

The diagnostic now reports:

- mean packet feature value
- byte-level nonzero fraction
- packet-row fraction with any payload
- zero-mean graph count
- graphs with and without any payload
- a plain-language interpretation

This matters because packet vectors are padded to 1,500 bytes. A low byte-level
nonzero fraction can mean the payload is short, not necessarily that all payloads
are missing.

### 3. Added oversampling metadata for future preprocessing runs

Updated `secureedge/data/preprocess.py`.

Future compact preprocessing manifests will include an `oversampling_summary`
section with:

- available records before split
- real test count
- real train pool count
- final train count
- unique train count
- oversampled duplicate count
- oversampled duplicate fraction
- whether oversampling was required

This makes the duplicate problem visible immediately after preprocessing.

### 4. Added a current oversampling audit tool

Added `secureedge/data/audit_oversampling.py`.

This audits the existing `artifacts/compact_reservoir_manifest.json`, computes
duplicate path usage by class and subtype, and writes:

- `artifacts/oversampling_audit.json`
- `context/26_oversampling_audit.md`

## Validation Commands

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
.venv/bin/python -m secureedge.data.payload_diagnostic --source graphs --split train --limit 500
.venv/bin/python -m secureedge.data.payload_diagnostic --source shards --split train --limit 3
.venv/bin/python -m secureedge.data.audit_oversampling
```

Both compile and smoke checks passed.

## Payload Diagnostic Results

### Individual graph sample

Source: first 500 files from `data/graphs/train`.

```json
{
  "graphs_examined": 500,
  "mean_packet_node_feature_value": 0.10851583028747701,
  "mean_nonzero_fraction": 0.22408204130409284,
  "mean_packet_rows_with_any_payload_fraction": 0.6556278539672494,
  "zero_mean_graphs": 29,
  "nonzero_mean_graphs": 471,
  "graphs_with_any_payload": 471,
  "graphs_without_any_payload": 29
}
```

### Shard sample

Source: first 3 training shards, 3,000 graphs total.

```json
{
  "graphs_examined": 3000,
  "mean_packet_node_feature_value": 0.0700152267947536,
  "mean_nonzero_fraction": 0.15376555077032147,
  "mean_packet_rows_with_any_payload_fraction": 0.7954833358302712,
  "zero_mean_graphs": 161,
  "nonzero_mean_graphs": 2839,
  "graphs_with_any_payload": 2839,
  "graphs_without_any_payload": 161
}
```

Interpretation: packet features are not all zeros, so the current `PacketCapture`
implementation is extracting payload-like bytes for most graphs. However, the
byte-level payload density is still far below the `> 0.80` target in
`training-round-3.md`, so payload quality should not be treated as fully proven.

## Oversampling Audit Results

The current training manifest has severe duplicate-path oversampling in three
classes:

| Class | Train Total | Unique Train | Duplicate Count | Duplicate Fraction |
|---|---:|---:|---:|---:|
| Benign | 20000 | 20000 | 0 | 0.00% |
| DDoS | 20000 | 20000 | 0 | 0.00% |
| DoS | 20000 | 20000 | 0 | 0.00% |
| Mirai | 20000 | 20000 | 0 | 0.00% |
| Recon | 20000 | 11882 | 8118 | 40.59% |
| Spoofing | 20000 | 20000 | 0 | 0.00% |
| WebBased | 20000 | 11691 | 8309 | 41.55% |
| BruteForce | 20000 | 6669 | 13331 | 66.66% |

This confirms the round-3 diagnosis. The current dataset is not suitable for
another serious training run if the target is 0.93 accuracy or higher.

## Current Status Against Round 3 Fixes

| Fix | Status |
|---|---|
| Payload diagnostic | Implemented and run |
| Fix PacketCapture if payloads are zero | Not triggered as an all-zero failure, but payload density remains suspicious |
| Download more minority PCAPs | Still required; cannot be completed locally without new raw data |
| Verify 92 flow node features | Already completed in the earlier 92-feature regeneration |
| Rerun preprocessing after data fixes | Pending new PCAP data |
| Retrain round 4 | Blocked by duplicate-heavy current dataset |

## Next Required Action

Download additional real PCAPs for the underrepresented classes before starting
another full training run:

- `DictionaryBruteForce`
- `Recon-PingSweep`
- `Uploading_Attack`
- `Backdoor_Malware`

After adding more real PCAPs, rerun compact preprocessing and require duplicate
fractions to fall below 20%, especially for BruteForce.
