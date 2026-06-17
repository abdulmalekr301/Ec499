# SecureEdge — Missing Flow Features Fix

> **Generated:** 2026-06-15
> **Applies to:** Full XG-NID replication — final methodology.
> **Prerequisite:** `preprocessing-with-fixes.md` has been applied and the full
> 192,000-graph dataset was produced. This fix corrects the feature count before
> the next training run.

---

## 0. Summary

The full preprocessing run confirmed that NFStream 6.6.0 produces **60 flow
features** (48 statistical + 12 core including ports and protocol). XG-NID
reports **76 flow-level features**. The difference is exactly **16 features**.

This document identifies what those 16 features are, implements them, and
describes the dataset regeneration required.

---

## 1. Root Cause — What NFStream's 48 Statistical Features Actually Cover

NFStream's `statistical_analysis=True` computes exactly 48 post-mortem
statistical features organised into three groups:

| Group | Directions | Values | Count |
|---|---|---|---|
| Packet size (ps) | bidirectional, src2dst, dst2src | min, mean, stddev, max | 12 |
| Inter-arrival time (piat) | bidirectional, src2dst, dst2src | min, mean, stddev, max | 12 |
| TCP flag counts | bidirectional, src2dst, dst2src | SYN, CWR, ECE, URG, ACK, PSH, RST, FIN | 24 |
| **Total** | | | **48** |

Active and idle time statistics are **not included** in these 48. They describe
how a flow alternates between active transmitting bursts and silent idle gaps.
NFStream can compute them but they require either a custom plugin or a version
of NFStream older than what the 48-feature count reflects.

The current feature count and why it reaches exactly 60:

| Group | Count |
|---|---|
| NFStream 48 statistical features | 48 |
| Bidirectional duration, packets, bytes | 3 |
| src2dst duration, packets, bytes | 3 |
| dst2src duration, packets, bytes | 3 |
| src_port, dst_port, protocol | 3 |
| **Total currently in use** | **60** |

---

## 2. What the 16 Missing Features Are

The 16 missing features split into two groups of 8, both absent from NFStream's
default output.

### Group A — Active and Idle Time Statistics (8 features)

These describe the temporal burst structure of the flow. A flow with multiple
bursts of traffic separated by silent gaps has non-trivial active and idle
periods. A continuous flood has only one active period and no idle periods.

| Feature name | Description |
|---|---|
| `bidirectional_mean_active_ms` | Mean duration of active transmitting bursts |
| `bidirectional_std_active_ms` | Standard deviation of burst durations |
| `bidirectional_max_active_ms` | Longest active burst |
| `bidirectional_min_active_ms` | Shortest active burst |
| `bidirectional_mean_idle_ms` | Mean duration of idle gaps between bursts |
| `bidirectional_std_idle_ms` | Standard deviation of idle gaps |
| `bidirectional_max_idle_ms` | Longest idle gap |
| `bidirectional_min_idle_ms` | Shortest idle gap |

**Why these matter for hard classes:** DDoS-SlowLoris maintains connections
with very long active periods and zero idle gaps — its active statistics are
completely unlike normal HTTP traffic. DNS_Spoofing and MITM-ArpSpoofing create
irregular burst-idle patterns that are distinctive from benign DNS traffic.
Without these 8 features, the model cannot see the temporal burst structure that
separates these attacks from benign at the flow level.

**Edge case:** A flow with only one active burst (which most 20-packet capped
flows will be, since they complete quickly) has:
- `active_*` statistics computed from that single burst
- `idle_*` statistics all equal to 0.0 (no idle periods observed)

Zero idle statistics are valid feature values — they distinguish single-burst
flows from multi-burst flows.

### Group B — Derived Rate and Ratio Features (8 features)

These are computable from fields already in NFStream's output but are not
exposed as native features. They are present in CICFlowMeter and are standard
in flow-level network analysis.

| Feature name | Formula |
|---|---|
| `bidirectional_bytes_per_second` | `bidirectional_bytes / (bidirectional_duration_ms / 1000.0)` |
| `bidirectional_packets_per_second` | `bidirectional_packets / (bidirectional_duration_ms / 1000.0)` |
| `src2dst_bytes_per_second` | `src2dst_bytes / (src2dst_duration_ms / 1000.0)` |
| `src2dst_packets_per_second` | `src2dst_packets / (src2dst_duration_ms / 1000.0)` |
| `dst2src_bytes_per_second` | `dst2src_bytes / (dst2src_duration_ms / 1000.0)` |
| `dst2src_packets_per_second` | `dst2src_packets / (dst2src_duration_ms / 1000.0)` |
| `down_up_bytes_ratio` | `dst2src_bytes / src2dst_bytes` |
| `average_packet_size` | `bidirectional_bytes / bidirectional_packets` |

**Division by zero handling:** If `bidirectional_duration_ms == 0` (a flow
completed in under 1 ms), all per-second rates are 0.0. If `src2dst_bytes == 0`
(no forward traffic), `down_up_bytes_ratio` is 0.0. If `bidirectional_packets
== 0` (should never happen but guard anyway), `average_packet_size` is 0.0.

After adding both groups:

| Group | Count |
|---|---|
| NFStream 48 statistical | 48 |
| Core (durations, packets, bytes × 3 directions) | 9 |
| src_port, dst_port, protocol | 3 |
| Active/idle statistics (Group A, NEW) | 8 |
| Derived rate/ratio features (Group B, NEW) | 8 |
| **Total** | **76** |

Flow node input dimension: 76 (NFStream) + 16 (temporal) = **92**, exactly
matching XG-NID's specification.

---

## 3. Fix A — ActiveIdlePlugin

Implement in `secureedge/data/pcap_flows.py`. This plugin tracks transitions
between active and idle states during streaming and computes the 8 active/idle
statistics at flow expiration.

**Definition of active vs idle:** A gap between consecutive packets larger than
`ACTIVE_THRESHOLD_MS = 1000` milliseconds (1 second) is treated as a transition
from active to idle. NFStream uses a similar internal threshold for its activity
period tracking.

```
CLASS ActiveIdlePlugin (extends NFPlugin):

    ACTIVE_THRESHOLD_MS = 1000

    METHOD on_init(packet, flow):
        flow.udps.active_durations = []    # ms duration of each active burst
        flow.udps.idle_durations   = []    # ms duration of each idle gap
        flow.udps.last_packet_ms   = packet.time
        flow.udps.period_start_ms  = packet.time

    METHOD on_update(packet, flow):
        gap_ms = packet.time - flow.udps.last_packet_ms

        IF gap_ms > ACTIVE_THRESHOLD_MS:
            # End of an active period, start of an idle period
            active_dur = flow.udps.last_packet_ms - flow.udps.period_start_ms
            flow.udps.active_durations.append(max(0.0, active_dur))
            flow.udps.idle_durations.append(gap_ms)
            flow.udps.period_start_ms = packet.time

        flow.udps.last_packet_ms = packet.time

    METHOD on_expire(flow):
        # Close the final active period
        final_dur = flow.udps.last_packet_ms - flow.udps.period_start_ms
        flow.udps.active_durations.append(max(0.0, final_dur))

        # Compute statistics — use 0.0 when lists are empty (no idle periods)
        a = flow.udps.active_durations
        d = flow.udps.idle_durations

        flow.udps.bidirectional_mean_active_ms = mean(a)      if a else 0.0
        flow.udps.bidirectional_std_active_ms  = std(a)       if a else 0.0
        flow.udps.bidirectional_max_active_ms  = max(a)       if a else 0.0
        flow.udps.bidirectional_min_active_ms  = min(a)       if a else 0.0
        flow.udps.bidirectional_mean_idle_ms   = mean(d)      if d else 0.0
        flow.udps.bidirectional_std_idle_ms    = std(d)       if d else 0.0
        flow.udps.bidirectional_max_idle_ms    = max(d)       if d else 0.0
        flow.udps.bidirectional_min_idle_ms    = min(d)       if d else 0.0

        # Clean up raw lists to reduce memory footprint in compact records
        del flow.udps.active_durations
        del flow.udps.idle_durations
        del flow.udps.last_packet_ms
        del flow.udps.period_start_ms
```

The 8 resulting attributes (`flow.udps.bidirectional_*_active_ms` and
`flow.udps.bidirectional_*_idle_ms`) must be extracted into the compact record
during flow extraction alongside the standard NFStream statistics.

### Plugin ordering in `udps`

```
udps = [ActiveIdlePlugin(), PacketCapture(), FlowCapper()]
```

`ActiveIdlePlugin` must come before `FlowCapper`. When FlowCapper sets
`flow.expiration_id = -1`, NFStream calls all plugins' `on_expire` methods
in order. `ActiveIdlePlugin.on_expire` must run to finalise the statistics
before the flow record is emitted.

---

## 4. Fix B — Derived Rate and Ratio Features

These 8 features are **not computed during streaming**. They are computed
during graph construction from values already stored in the compact record.
No plugin is needed.

Add a `compute_derived_features(flow_dict)` function in
`secureedge/data/pcap_flows.py` or `secureedge/data/graph_builder.py`:

```
FUNCTION compute_derived_features(record):
    # record contains: bidirectional_duration_ms, bidirectional_packets,
    # bidirectional_bytes, src2dst_duration_ms, src2dst_packets, src2dst_bytes,
    # dst2src_duration_ms, dst2src_packets, dst2src_bytes

    bidi_dur_s  = record["bidirectional_duration_ms"] / 1000.0
    fwd_dur_s   = record["src2dst_duration_ms"]        / 1000.0
    bwd_dur_s   = record["dst2src_duration_ms"]        / 1000.0

    derived = {
        "bidirectional_bytes_per_second":    safe_divide(record["bidirectional_bytes"],   bidi_dur_s),
        "bidirectional_packets_per_second":  safe_divide(record["bidirectional_packets"], bidi_dur_s),
        "src2dst_bytes_per_second":          safe_divide(record["src2dst_bytes"],          fwd_dur_s),
        "src2dst_packets_per_second":        safe_divide(record["src2dst_packets"],        fwd_dur_s),
        "dst2src_bytes_per_second":          safe_divide(record["dst2src_bytes"],          bwd_dur_s),
        "dst2src_packets_per_second":        safe_divide(record["dst2src_packets"],        bwd_dur_s),
        "down_up_bytes_ratio":               safe_divide(record["dst2src_bytes"],          record["src2dst_bytes"]),
        "average_packet_size":               safe_divide(record["bidirectional_bytes"],    record["bidirectional_packets"]),
    }
    RETURN derived


FUNCTION safe_divide(numerator, denominator):
    IF denominator == 0 OR denominator is NaN:
        RETURN 0.0
    RETURN float(numerator) / float(denominator)
```

These 8 derived values are appended to the flow feature vector when the compact
record is converted to a `HeteroData` graph in `build_graphs.py`. They are
appended after the 68 features (48 NFStream statistical + 12 core + 8 active/idle)
to produce the full 76-dimensional flow feature vector.

**Order of features in the flow feature vector:**

```
Indices 0–47:   NFStream 48 statistical features (ps, piat, TCP flags)
Indices 48–50:  bidirectional_duration_ms, bidirectional_packets, bidirectional_bytes
Indices 51–53:  src2dst_duration_ms, src2dst_packets, src2dst_bytes
Indices 54–56:  dst2src_duration_ms, dst2src_packets, dst2src_bytes
Indices 57–59:  src_port, dst_port, protocol
Indices 60–67:  8 active/idle statistics (Group A, from ActiveIdlePlugin)
Indices 68–75:  8 derived rate/ratio features (Group B, computed in build_graphs)
Total:          76 features
```

Save this ordering to `artifacts/flow_feature_order.json` so the same ordering
is applied consistently at inference time.

---

## 5. Config Updates

Update `secureedge/config.py`:

```python
N_FLOW_FEATURES         = 76    # was 60
N_TEMPORAL_FEATURES     = 16
N_FLOW_NODE_FEATURES    = 92    # was 76 — flow node input to HGNN (76 + 16)
N_ACTIVE_IDLE_FEATURES  = 8     # new — from ActiveIdlePlugin
N_DERIVED_FEATURES      = 8     # new — computed in build_graphs
```

The HGNN model's lazy initialisation (`in_channels=-1`) means PyG infers the
flow node input dimension from the first batch. No manual update to the model
architecture is needed. However, verify after the first training batch that the
inferred dimension is 92.

---

## 6. Extracting Active/Idle Values Into the Compact Record

In `pcap_flows.py`, the function that converts an NFStream flow to a compact
record must now also extract the 8 active/idle values from `flow.udps`:

```
FUNCTION nfstream_flow_to_compact(flow, temporal_feats, subtype_name):

    # --- Existing NFStream statistical features (48) ---
    stat_feats = extract_nfstream_stats(flow)   # already implemented

    # --- Existing core features (9) ---
    core_feats = [
        flow.bidirectional_duration_ms,
        flow.bidirectional_packets,
        flow.bidirectional_bytes,
        flow.src2dst_duration_ms,
        flow.src2dst_packets,
        flow.src2dst_bytes,
        flow.dst2src_duration_ms,
        flow.dst2src_packets,
        flow.dst2src_bytes,
    ]

    # --- Port/protocol (3) ---
    id_feats = [flow.src_port, flow.dst_port, flow.protocol]

    # --- NEW: Active/idle (8) from ActiveIdlePlugin ---
    active_idle_feats = [
        flow.udps.bidirectional_mean_active_ms,
        flow.udps.bidirectional_std_active_ms,
        flow.udps.bidirectional_max_active_ms,
        flow.udps.bidirectional_min_active_ms,
        flow.udps.bidirectional_mean_idle_ms,
        flow.udps.bidirectional_std_idle_ms,
        flow.udps.bidirectional_max_idle_ms,
        flow.udps.bidirectional_min_idle_ms,
    ]

    # Concatenate the 68 NFStream-based features into a numpy array
    flow_features_68 = np.array(
        stat_feats + core_feats + id_feats + active_idle_feats,
        dtype=np.float32
    )
    # The remaining 8 derived features are added during graph construction

    RETURN {
        "flow_features_68":  flow_features_68,    # shape [68]
        "temporal_feats":    temporal_feats,       # shape [16]
        "packet_records":    flow.udps.packet_records,
        "label":             ...,
        "subtype_label":     subtype_name,
    }
```

The derived 8 features are NOT stored in the compact record. They are computed
fresh during `build_graphs.py` from the values already in `flow_features_68`.
This avoids storing redundant derived values and keeps the compact record lean.

---

## 7. Updating `build_graphs.py` to Assemble the Full 76-Feature Vector

In `build_graphs.py`, when building a `HeteroData` graph from a compact record,
the flow node feature vector is assembled as follows:

```
FUNCTION build_flow_node_features(record, flow_node_scaler):

    # Extract the 68 base features stored in the compact record
    base_68 = record["flow_features_68"]           # np.float32 [68]

    # Reconstruct the values needed to compute derived features
    # (they are already in base_68 at known indices)
    bidi_duration_ms  = base_68[48]
    bidi_packets      = base_68[49]
    bidi_bytes        = base_68[50]
    fwd_duration_ms   = base_68[51]
    fwd_packets       = base_68[52]
    fwd_bytes         = base_68[53]
    bwd_duration_ms   = base_68[54]
    bwd_packets       = base_68[55]
    bwd_bytes         = base_68[56]

    # Compute 8 derived features
    derived_8 = compute_derived_features_from_values(
        bidi_duration_ms, bidi_packets, bidi_bytes,
        fwd_duration_ms, fwd_packets, fwd_bytes,
        bwd_duration_ms, bwd_packets, bwd_bytes,
    )                                                # np.float32 [8]

    # Concatenate: 68 base + 8 derived = 76 NFStream flow features
    flow_76 = np.concatenate([base_68, derived_8])  # [76]

    # Concatenate with temporal features: 76 + 16 = 92
    temporal_16 = record["temporal_feats"]           # [16]
    raw_flow_92 = np.concatenate([flow_76, temporal_16])  # [92]

    # Apply StandardScaler (fitted on 92-dim training vectors)
    scaled_92 = flow_node_scaler.transform(raw_flow_92.reshape(1, -1))[0]

    RETURN scaled_92                                 # [92]
```

---

## 8. Dataset Regeneration Required

The full 192,000-graph dataset must be regenerated from scratch. The compact
reservoir (pickle records) stored in `data/graphs/_reservoir` is also stale
because it was produced without the active/idle features. Both the compact
records and the graph `.pt` files must be deleted and rebuilt.

### Files to delete

```
data/graphs/_reservoir/       (entire directory — compact records without active/idle)
data/graphs/train/            (entire directory — graphs without active/idle)
data/graphs/test/             (entire directory — graphs without active/idle)
artifacts/compact_reservoir_manifest.json
artifacts/graph_dataset_manifest.json
artifacts/flow_node_scaler.joblib    (fitted on 76-dim, not 92-dim)
artifacts/contain_edge_scaler.joblib (unchanged but re-fit to be safe)
artifacts/link_edge_norm_p99.json    (unchanged but regenerate to be consistent)
artifacts/best_model.pt             (if a model was trained — must retrain)
artifacts/metrics.json
artifacts/ood_threshold.json
artifacts/secureedge_hgnn.ts
```

The PCAP chunks in `PCAPs/chunks/` do NOT need to be regenerated. The chunk
splitting is independent of feature extraction.

### Regeneration commands

```bash
# Step 1: Extract compact records (now includes active/idle via ActiveIdlePlugin)
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_MAX_PROCESS_RSS_GB=6 \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4 \
SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
python -m secureedge.data.preprocess

# Step 2: Build HeteroData graphs (now assembles 76+16=92 flow node features)
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
python -m secureedge.data.build_graphs

# Step 3: Train
python -m secureedge.models.train

# Step 4: Evaluate, OOD, export
python -m secureedge.models.evaluate
python -m secureedge.ood.detector
python -m secureedge.export.export
```

---

## 9. Verification Checkpoints

Run all checks after `build_graphs.py` completes and before starting training.

### Check 1 — Flow node dimension is 92

```python
import torch
g = torch.load("data/graphs/train/DDoS_000001.pt")
assert g['flow'].x.shape == (1, 92), f"Expected (1, 92), got {g['flow'].x.shape}"
print("OK: flow node dimension = 92")
```

### Check 2 — Active/idle features are present and non-trivial for flood attacks

Load 200 DDoS training graphs. Extract the active/idle features (indices 60–67
of the pre-scaling flow feature vector, or equivalently the last 8 values of
`flow_features_68` from the compact record).

For DDoS flood attacks (SYN_Flood, UDP_Flood, etc.) most flows complete within
one burst (20 packets arrive in rapid succession → FlowCapper triggers). These
flows have:
- `bidirectional_mean_active_ms` > 0 (the one active burst has some duration)
- `bidirectional_mean_idle_ms` == 0.0 (no idle gaps observed)

For SlowLoris flows, if any exist in training:
- `bidirectional_mean_active_ms` varies (slow intermittent sends)
- `bidirectional_mean_idle_ms` > 0.0 (gaps between slow header sends)

The key check is that `bidirectional_mean_active_ms` is NOT uniformly zero for
all DDoS graphs. If it is, `on_expire` is not being called correctly.

### Check 3 — Derived features are non-trivial

Load 200 Benign training graphs. Check indices 68–75 (the derived 8 features
in the pre-scaling vector). `bidirectional_bytes_per_second` should be non-zero
for any flow with packets. `average_packet_size` should be in a reasonable range
(64 to 1,500 bytes for typical traffic).

### Check 4 — Scaler is fitted on 92 dimensions

```python
import joblib
scaler = joblib.load("artifacts/flow_node_scaler.joblib")
assert scaler.n_features_in_ == 92, f"Expected 92, got {scaler.n_features_in_}"
print("OK: flow node scaler fitted on 92 features")
```

### Check 5 — Flow feature order file exists

```python
import json
with open("artifacts/flow_feature_order.json") as f:
    order = json.load(f)
assert len(order) == 76, f"Expected 76 feature names, got {len(order)}"
print("OK: flow_feature_order.json contains 76 feature names")
```

---

## 10. Expected Impact on Model Performance

The 16 missing features were the most important for the three classes that
underperformed in the previous training run:

**Spoofing (was 0.769 F1):** DNS_Spoofing produces burst-idle patterns — brief
DNS query floods followed by gaps. `bidirectional_mean_idle_ms` and
`bidirectional_std_idle_ms` provide direct signal for this pattern.

**Recon (was 0.786 F1):** VulnerabilityScan and HostDiscovery produce
probe-wait cycles — short bursts to each target followed by idle periods.
Active/idle statistics encode this probe structure directly.

**DDoS-SlowLoris (weakest DDoS sub-type):** SlowLoris has a highly distinctive
active/idle profile — many very short active sends separated by long idle gaps.
`bidirectional_mean_active_ms` will be small, `bidirectional_mean_idle_ms`
will be large, and `bidirectional_std_idle_ms` will be low (regular pattern).
This is completely unlike both normal HTTP traffic and SYN flooding.

The rate features (Group B) provide additional signal for volumetric attacks:
- DDoS and DoS floods have extremely high `bidirectional_bytes_per_second`
- Recon scanning has low `bidirectional_bytes_per_second` but many short flows
- Benign traffic has moderate, varied rates

Combined, these 16 features should close a significant portion of the gap
between the current 0.850 macro F1 and the 0.97 target.
