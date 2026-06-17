# Revert to XG-NID Oversampling

Generated: `2026-06-17`

## Summary

Applied the instructions from `context/revert-to-oversampling.md`.

The class-imbalance experiment based on deduped shards, class weights, focal loss,
and online augmentation has been removed from the active training path. The
pipeline now uses the XG-NID-style balanced-pool oversampling strategy:

1. Build a 24,000-record balanced pool per canonical class.
2. Undersample classes with more than 24,000 available records.
3. Randomly oversample classes with fewer than 24,000 available records.
4. Split the balanced pool into 20,000 train and 4,000 test records.
5. Train with plain `CrossEntropyLoss()`.

## Code Changes

### Removed from active training

- Removed `secureedge/models/focal_loss.py`.
- Removed `secureedge/data/deduplicate_shards.py`.
- Removed `secureedge/data/audit_oversampling.py`.
- Removed deduped shard config constants from `secureedge/config.py`.
- Removed class weights, focal loss, and augmentation from `secureedge/models/train.py`.
- Removed `train_shards_deduped` from directory initialization.

### Kept

- NFStream extraction.
- `PacketCapture`.
- `ActiveIdlePlugin`.
- 92-dimensional flow nodes.
- Graph sharding.
- Cosine scheduler.
- Warmup from `3e-4` to `3e-3`.
- Batch size `512`.
- Label smoothing `0.0`.

### Added / changed

- Added `build_balanced_splits()` in `secureedge/data/preprocess.py`.
- Added `SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1` mode to rebuild the compact
  manifest from `data/graphs/_reservoir/` without rerunning PCAP extraction.
- Updated compact preprocessing documentation to show the XG-NID balanced-pool
  split.

## Regenerated Artifacts

Deleted stale class-imbalance and graph artifacts:

- `data/graphs/train_shards_deduped/`
- `data/graphs/train_shards/`
- `data/graphs/test_shards/`
- `data/graphs/train/`
- `data/graphs/test/`
- `artifacts/deduped_manifest.json`
- `artifacts/oversampling_audit.json`
- `artifacts/graph_dataset_manifest.json`
- `artifacts/flow_node_scaler.joblib`
- `artifacts/contain_edge_scaler.joblib`
- `artifacts/link_edge_norm_p99.json`
- `artifacts/best_hgnn.pt`
- `artifacts/metrics.json`

Kept:

- `data/graphs/_reservoir/`

Then regenerated:

- `artifacts/compact_reservoir_manifest.json`
- `data/graphs/train/`
- `data/graphs/test/`
- `artifacts/graph_dataset_manifest.json`
- `data/graphs/train_shards/`
- `data/graphs/test_shards/`
- `artifacts/graph_shard_manifest.json`

## Verification

Commands passed:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Balanced graph counts:

```json
{
  "train_per_class": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 20000,
    "Spoofing": 20000,
    "WebBased": 20000,
    "BruteForce": 20000
  },
  "test_per_class": {
    "Benign": 4000,
    "DDoS": 4000,
    "DoS": 4000,
    "Mirai": 4000,
    "Recon": 4000,
    "Spoofing": 4000,
    "WebBased": 4000,
    "BruteForce": 4000
  },
  "train_shards": 160,
  "test_shards": 32
}
```

Removed artifacts verified:

```json
{
  "deduped_manifest_exists": false,
  "deduped_dir_exists": false,
  "oversampling_audit_exists": false
}
```

## Oversampling Summary

From the regenerated compact manifest:

```json
{
  "Recon": {
    "real_available": 21426,
    "target_total": 24000,
    "oversampled_count": 2574,
    "oversampled_fraction": 0.10725
  },
  "WebBased": {
    "real_available": 20855,
    "target_total": 24000,
    "oversampled_count": 3145,
    "oversampled_fraction": 0.13104166666666667
  },
  "BruteForce": {
    "real_available": 11043,
    "target_total": 24000,
    "oversampled_count": 12957,
    "oversampled_fraction": 0.539875
  }
}
```

All other classes had enough records for a 24,000-record pool and required no
oversampling.

## Round 5 Training Command

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=512 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=50 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
.venv/bin/python -m secureedge.models.train
```
