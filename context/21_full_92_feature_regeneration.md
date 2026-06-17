# SecureEdge Full 92-Feature Regeneration Report

> Generated: 2026-06-15  
> Scope: Regenerated the full compact reservoir, graph dataset, and feature scalers after applying `context/preprocessing-find-missing.md`.

## Summary

This run regenerated the SecureEdge preprocessing outputs so the flow node
feature vector now matches the final methodology:

- 76 flow-level features
- 16 temporal features
- 92 total flow node features

The previous full dataset was stale because it contained 76-dimensional flow
nodes total. The updated extraction now includes the missing 8 active/idle
statistics and 8 derived rate/ratio features before appending the 16 temporal
features.

## Commands Run

### 1. Full compact extraction

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
.venv/bin/python -m secureedge.data.preprocess
```

### 2. Full graph materialization

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
.venv/bin/python -m secureedge.data.build_graphs
```

### 3. Feature/scaler pipeline

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
.venv/bin/python -m secureedge.features.pipeline
```

## Memory-Safety Measures

The run used the crash guardrails added after the earlier PCAP extraction
failures:

- Per-process RSS cap: 6 GiB
- Minimum available-memory floor: 4 GiB
- PCAP chunk threshold: 64 MiB
- Single-threaded BLAS/OpenMP settings
- `MALLOC_ARENA_MAX=2` to reduce allocator fragmentation
- Existing split PCAP chunks were reused instead of loading oversized PCAPs
  directly

During the full extraction, available memory stayed safely above the 4 GiB
floor. Observed available memory was typically around 7-9.6 GiB, and the run
completed without exhausting RAM or swap.

## Compact Reservoir Result

The compact reservoir was regenerated under:

```text
data/graphs/_reservoir
```

The manifest was written to:

```text
artifacts/compact_reservoir_manifest.json
```

Final compact split:

| Split | Count |
|---|---:|
| Train | 160,000 |
| Test | 32,000 |
| Total | 192,000 |

Per-class training counts:

| Class | Count |
|---|---:|
| Benign | 20,000 |
| DDoS | 20,000 |
| DoS | 20,000 |
| Mirai | 20,000 |
| Recon | 20,000 |
| Spoofing | 20,000 |
| WebBased | 20,000 |
| BruteForce | 20,000 |

Per-class test counts:

| Class | Count |
|---|---:|
| Benign | 4,000 |
| DDoS | 4,000 |
| DoS | 4,000 |
| Mirai | 4,000 |
| Recon | 4,000 |
| Spoofing | 4,000 |
| WebBased | 4,000 |
| BruteForce | 4,000 |

Available class pools before balancing:

| Class | Available Pool |
|---|---:|
| Benign | 24,000 |
| DDoS | 24,000 |
| DoS | 24,000 |
| Mirai | 24,000 |
| Recon | 21,426 |
| Spoofing | 24,000 |
| WebBased | 20,855 |
| BruteForce | 11,043 |

Classes with fewer than 24,000 extracted flows were balanced by deterministic
oversampling to meet the methodology's 20,000 train / 4,000 test target.

## Graph Dataset Result

The full graph dataset was regenerated under:

```text
data/graphs/train
data/graphs/test
```

The graph manifest was written to:

```text
artifacts/graph_dataset_manifest.json
```

Final graph counts:

| Split | Count |
|---|---:|
| Train | 160,000 |
| Test | 32,000 |
| Total | 192,000 |

Final feature dimensions from the graph manifest:

| Component | Dimension |
|---|---:|
| Flow node | 92 |
| Packet node | 1500 |
| Contain edge | 4 |
| Link edge | 1 |

## Restored Feature Blocks

The saved flow feature order contains 76 flow-level features before temporal
features are appended.

Active/idle feature block:

```text
bidirectional_mean_active_ms
bidirectional_std_active_ms
bidirectional_max_active_ms
bidirectional_min_active_ms
bidirectional_mean_idle_ms
bidirectional_std_idle_ms
bidirectional_max_idle_ms
bidirectional_min_idle_ms
```

Derived rate/ratio feature block:

```text
bidirectional_bytes_per_second
bidirectional_packets_per_second
src2dst_bytes_per_second
src2dst_packets_per_second
dst2src_bytes_per_second
dst2src_packets_per_second
down_up_bytes_ratio
average_packet_size
```

The saved feature order file is:

```text
artifacts/flow_feature_order.json
```

## Verification Results

### Manifest verification

The graph manifest reports:

```text
n_train = 160000
n_test = 32000
flow_node = 92
packet_node = 1500
contain_edge = 4
link_edge = 1
```

### Tensor/scaler verification

A 1,000-graph sample check confirmed:

```text
sample_graphs = 1000
max_packet_nodes = 20
packet_checks = True
flow_scaler_features = 92
edge_scaler_features = 4
```

The packet check verifies:

- each flow node tensor has 92 columns
- each packet node tensor has 1500 columns
- packet bytes are normalized to the range [0, 1]
- reverse packet-to-flow contain edges are present

### Compact-record verification

A 500-record compact sample confirmed:

```text
dims = [92]
versions = ['xgnid_76_plus_temporal_16']
```

Mean active/idle values from the sample:

```text
[233.164, 43.58, 293.912, 195.776, 3325.74, 500.134, 4089.3, 2863.564]
```

Mean derived feature values from the sample:

```text
[887214.55, 1615.935, 926126.78, 1591.86, 179602.027, 116.259, 3.331, 371.704]
```

These non-zero means confirm the restored blocks are present and populated.

### Smoke and compile checks

The following checks completed successfully:

```text
.venv/bin/python tests/smoke_checks.py
smoke checks passed
```

```text
.venv/bin/python -m compileall secureedge tests
```

## Disk and Memory After Completion

After regeneration:

```text
Filesystem: 952G total, 611G used, 339G available, 65% used
Memory: 15Gi total, about 9.6Gi available
Swap: 7.7Gi total, about 2.4Gi used
```

The compact reservoir occupied about 3.7 GiB during verification. The graph
dataset was successfully rewritten with the updated 92-dimensional flow node
features.

## Problems Encountered and Resolved

### Earlier stale dataset problem

Before this run, the existing full graph dataset still contained 76-dimensional
flow node vectors total. That meant the missing 16 flow-level features had not
actually reached the final graph files.

Resolution:

- Added the active/idle plugin output into compact extraction.
- Added derived rate/ratio features during graph construction.
- Added stale compact-record validation so old compact files with missing
  version metadata or 76-wide final vectors are rejected.
- Regenerated the compact reservoir and graph dataset from scratch.

### Earlier system crash risk

Previous extraction attempts crashed the system by exhausting memory and swap,
especially around large PCAP extraction work.

Resolution:

- Reused bounded PCAP chunks.
- Applied RSS and available-memory guards.
- Limited thread counts.
- Monitored memory and file counts throughout the full run.

No crash occurred during this regeneration.

## Current Status

The preprocessing phase now conforms to the final methodology's 92-feature flow
node requirement. The next project phase can consume:

```text
data/graphs/train
data/graphs/test
artifacts/graph_dataset_manifest.json
artifacts/flow_node_scaler.joblib
artifacts/contain_edge_scaler.joblib
artifacts/link_edge_norm_p99.json
artifacts/flow_feature_order.json
```
