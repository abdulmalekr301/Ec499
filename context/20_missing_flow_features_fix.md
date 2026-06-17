# Missing Flow Features Fix

## Source

Implemented the instructions from `context/preprocessing-find-missing.md`.

## What Changed

- Updated `secureedge/config.py`:
  - `N_FLOW_FEATURES = 76`
  - `N_TEMPORAL_FEATURES = 16`
  - `N_FLOW_NODE_FEATURES = 92`
  - added `N_ACTIVE_IDLE_FEATURES = 8`
  - added `N_DERIVED_FEATURES = 8`
  - added explicit `FLOW_FEATURE_ORDER`
  - added `artifacts/flow_feature_order.json`

- Added `ActiveIdlePlugin` in `secureedge/data/pcap_flows.py`.
  - Tracks active bursts and idle gaps using a `1000 ms` threshold.
  - Emits the 8 active/idle features:
    - `bidirectional_mean_active_ms`
    - `bidirectional_std_active_ms`
    - `bidirectional_max_active_ms`
    - `bidirectional_min_active_ms`
    - `bidirectional_mean_idle_ms`
    - `bidirectional_std_idle_ms`
    - `bidirectional_max_idle_ms`
    - `bidirectional_min_idle_ms`

- Updated NFStream plugin order:

```python
udps = [ActiveIdlePlugin(), PacketCapture(), FlowCapper()]
```

- Added 8 derived rate/ratio features in `secureedge/data/graph_builder.py`:
  - `bidirectional_bytes_per_second`
  - `bidirectional_packets_per_second`
  - `src2dst_bytes_per_second`
  - `src2dst_packets_per_second`
  - `dst2src_bytes_per_second`
  - `dst2src_packets_per_second`
  - `down_up_bytes_ratio`
  - `average_packet_size`

- Updated compact records with:
  - `flow_feature_order`
  - `flow_feature_version = "xgnid_76_plus_temporal_16"`

- Updated `secureedge/data/build_graphs.py` to reject stale compact records.

## Feature Layout

| Range | Group | Count |
| --- | --- | ---: |
| 0-47 | NFStream statistical features | 48 |
| 48-56 | duration/packet/byte core features | 9 |
| 57-59 | source port, destination port, protocol | 3 |
| 60-67 | active/idle features | 8 |
| 68-75 | derived rate/ratio features | 8 |
| 76-91 | temporal features | 16 |

Final flow node dimension: `92`.

## Verification

Compile and smoke checks passed.

An isolated extraction test was run against `PCAPs/Uploading_Attack.pcap` without touching the full dataset:

```bash
python -m secureedge.data.extract_worker \
  --pcap PCAPs/Uploading_Attack.pcap \
  --subtype Uploading_Attack \
  --class-name WebBased \
  --class-index 6 \
  --target 10 \
  --out-dir /tmp/secureedge_feature92_test \
  --summary-path /tmp/secureedge_feature92_test_summary.json
```

Result:

```json
{
  "records": 10,
  "flow_x_dim": 92,
  "flow_feature_order_len": 76,
  "feature_names_len": 92,
  "version": "xgnid_76_plus_temporal_16"
}
```

The isolated records had non-zero active/idle features and non-zero derived rate features.

## Stale Dataset Guard

The existing full compact reservoir was produced before this fix. It has `76` flow-node values total and no `flow_feature_version`. `build_graphs.py` now refuses it:

```text
Compact records are stale and do not contain the 92-dimensional flow node features.
Found version=None, flow_dim=76; expected version='xgnid_76_plus_temporal_16', flow_dim=92.
```

## Required Next Step

The full 192,000-graph dataset must be regenerated from scratch:

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_MAX_PROCESS_RSS_GB=6 \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4 \
SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
python -m secureedge.data.preprocess

SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
python -m secureedge.data.build_graphs
```

The PCAP chunks do not need to be regenerated.
