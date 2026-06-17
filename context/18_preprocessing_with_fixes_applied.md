# Preprocessing Fixes Applied

## Source

Implemented the instructions from `context/preprocessing-with-fixes.md`.

## Main Changes

- Added subtype-group PCAP discovery in `secureedge/data/preprocess.py`.
- Large PCAPs are now represented by ordered split chunk lists instead of flat per-chunk discovery.
- Confirmed discovery covers all `34` subtypes:
  - Benign: `1`
  - BruteForce: `1`
  - DDoS: `12`
  - DoS: `4`
  - Mirai: `3`
  - Recon: `5`
  - Spoofing: `2`
  - WebBased: `6`
- Updated `secureedge/data/extract_worker.py` so one worker processes all chunks for a subtype.
- Temporal feature state now persists across chunks of the same subtype.
- Kept temporal state reset between different subtypes.
- Changed preprocessing to stop after compact `.pkl` extraction and split planning.
- Added `artifacts/compact_reservoir_manifest.json`.
- Added `secureedge/data/build_graphs.py` as the separate PyTorch/PyG graph construction phase.
- Updated graph construction to:
  - fit flow-node scaler on training records only
  - fit contain-edge scaler on training records only
  - fit link-edge p99 normalizer on training records only
  - save p99 to `artifacts/link_edge_norm_p99.json`
  - avoid clipping link-edge outliers above `1.0`
  - clamp negative packet time deltas to `0.0`
- Updated graph manifest with methodology-style fields:
  - `n_train`
  - `n_test`
  - `n_flow_features`
  - `n_temporal_feats`
  - `n_flow_node_feats`
  - `n_packet_feats`
  - `n_contain_edge_feats`
  - `n_link_edge_feats`
  - `class_counts_train`
  - `class_counts_test`
  - `train_files`
  - `test_files`
- Updated `secureedge/data/split_pcaps.py` so it scans top-level `PCAPs/` directly and prefers `editcap` when available, with `tcpdump` as fallback.
- Updated `README.md` execution order to include `python -m secureedge.data.build_graphs`.

## Verification Run

Ran a tiny bounded end-to-end verification with:

```bash
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=8
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=8
SECUREEDGE_MAX_PROCESS_RSS_GB=2
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10
```

Commands completed:

```bash
python -m secureedge.data.preprocess
python -m secureedge.data.build_graphs
python -m secureedge.features.pipeline
```

## Verification Results

- Compact extraction completed without importing PyTorch in the worker.
- Graph construction completed as a separate phase.
- Graph manifest reported:
  - `n_train`: `64`
  - `n_test`: `16`
  - total graphs: `80`
- Packet-node checks passed:
  - max packet nodes per graph: `20`
  - packet feature dimension: `1500`
  - packet values in `[0, 1]`
  - reverse contain edges present
- Scaler checks passed:
  - flow scaler features: `76`
  - contain-edge scaler features: `4`
- Link p99 file written:
  - `artifacts/link_edge_norm_p99.json`

## Notes

The final methodology text expects `92` flow-node features from the paper. The current NFStream 6.6.0 environment yields `60` numeric NFStream features plus `16` temporal features, for `76` flow-node features. The pipeline records the actual feature dimension in the graph manifest and validates against the active config.

This verification intentionally used a tiny bounded sample to avoid repeating prior memory crashes. The full run should still be treated as a controlled batch operation.
