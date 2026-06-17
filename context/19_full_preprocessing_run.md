# Full Preprocessing Run

## Summary

Completed the full fixed preprocessing pipeline:

1. Compact NFStream extraction from split PCAP chunks.
2. Per-subtype compact reservoirs.
3. Real test split before training oversampling.
4. Separate PyTorch/PyG graph construction.
5. Feature/scaler validation.

## Extraction Command

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_MAX_PROCESS_RSS_GB=6 \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4 \
SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64 \
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=100 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
python -m secureedge.data.preprocess
```

## Graph Build Command

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
python -m secureedge.data.build_graphs
```

## Compact Extraction Result

- Real compact records written: `173,324`
- Compact manifest requested split:
  - Train: `160,000`
  - Test: `32,000`
  - Total: `192,000`
- Compact reservoir size: approximately `3.6 GiB`

Class pools before split:

| Class | Real pool count |
| --- | ---: |
| Benign | 24,000 |
| DDoS | 24,000 |
| DoS | 24,000 |
| Mirai | 24,000 |
| Recon | 21,426 |
| Spoofing | 24,000 |
| WebBased | 20,855 |
| BruteForce | 11,043 |

Classes below the full `24,000` real-flow pool were handled according to the fix document: the test split used real records, and training was oversampled only after test records were selected.

## Graph Materialization Result

- Training graphs: `160,000`
- Test graphs: `32,000`
- Total graphs: `192,000`
- Train directory size: approximately `12 GiB`
- Test directory size: approximately `2.3 GiB`

Per-class graph counts:

| Class | Train | Test |
| --- | ---: | ---: |
| Benign | 20,000 | 4,000 |
| DDoS | 20,000 | 4,000 |
| DoS | 20,000 | 4,000 |
| Mirai | 20,000 | 4,000 |
| Recon | 20,000 | 4,000 |
| Spoofing | 20,000 | 4,000 |
| WebBased | 20,000 | 4,000 |
| BruteForce | 20,000 | 4,000 |

## Feature Dimensions

| Feature group | Dimension |
| --- | ---: |
| Flow node | 76 |
| Packet node | 1,500 |
| Contain edge | 4 |
| Link edge | 1 |

The final methodology text expects `92` flow-node features from the paper. The current NFStream 6.6.0 environment exposes `60` numeric NFStream flow features plus `16` temporal features, for an actual flow-node dimension of `76`.

## Validation Results

Feature pipeline validation passed:

```json
{
  "graph_manifest": "artifacts/graph_dataset_manifest.json",
  "total_graph_count": 192000
}
```

Packet/scaler sample check over 1,000 graphs:

```json
{
  "sample_graphs": 1000,
  "max_packet_nodes": 20,
  "packet_checks": true,
  "flow_scaler_features": 76,
  "edge_scaler_features": 4
}
```

Link p99 normalizer:

```json
{
  "method": "p99_training_link_delta_ms",
  "p99_ms": 29920.0
}
```

DDoS train subtype diversity:

```json
{
  "ddos_train_graphs": 20000,
  "subtypes": 12,
  "max_subtype_count": 1684
}
```

All 12 DDoS subtypes were present. No subtype exceeded the `3,000` fail threshold.

## Temporal Feature Note

The raw `Rolling_SYN_Sum` check showed clear separation between benign and SYN-heavy attacks, but did not reach the rough `> 1,000` expectation from the fix document:

```json
{
  "Benign_mean": 5.232,
  "DDoS_SYN_Flood_mean": 337.078,
  "DDoS_SYN_Flood_max": 375.0
}
```

This is consistent with the current temporal implementation: features are computed from the previous rolling window before appending the current flow, and the configured window size is `375`. For a binary SYN indicator, the theoretical maximum is therefore approximately `375`.

## System Result

The full run completed without a system crash.

Final system state after validation:

- Available memory: approximately `9.3 GiB`
- Swap used: approximately `2.6 GiB`
- Disk available: approximately `340 GiB`

## Outputs

- Compact reservoir: `data/graphs/_reservoir`
- Compact manifest: `artifacts/compact_reservoir_manifest.json`
- Training graphs: `data/graphs/train`
- Test graphs: `data/graphs/test`
- Graph manifest: `artifacts/graph_dataset_manifest.json`
- Flow scaler: `artifacts/flow_node_scaler.joblib`
- Contain edge scaler: `artifacts/contain_edge_scaler.joblib`
- Link p99 normalizer: `artifacts/link_edge_norm_p99.json`
