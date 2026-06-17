# SecureEdge — Final Methodology: Full XG-NID Replication

> **Revision:** Final
> **Decision:** Replicate XG-NID (arXiv:2408.16021v2) from start to finish.
> **Target:** ≥ 97% macro F1 on CIC-IoT2023, matching the paper's reported result.
> **Hardware:** Training on PC with NVIDIA RTX 4060 8 GB GPU.
>              Inference on NVIDIA Jetson Orin Nano (40 TOPS, 8 GB LPDDR5).

This document supersedes all previous methodology files. Every prior decision about
using a flat MLP is revoked. The model is a Heterogeneous Graph Neural Network
(HGNN) trained on heterogeneous graph objects constructed from raw PCAP files, exactly
as described in the XG-NID paper.

---

## 0. What XG-NID Does — One Paragraph Summary

XG-NID processes raw PCAP files through NFStream to extract 76 flow-level statistical
features per completed flow. Alongside these, up to 20 raw packet payloads are
captured per flow, each represented as a 1,500-dimensional byte vector. A sliding
window of W = 375 recent flows per destination IP is maintained in real time to
compute 16 temporal context features. Each completed flow then becomes a
heterogeneous graph: one flow node (carrying 76 flow features + 16 temporal features
= 92 features), up to 20 packet nodes (each carrying 1,500 features), directed
contain edges from the flow node to each packet node (4 edge features per edge), and
directed link edges between consecutive packet nodes (1 edge feature per edge).
These graph objects are fed into a two-layer Heterogeneous Graph Attention Network
(HGNN), which performs message passing between flow and packet nodes, applies global
mean pooling to produce a fixed-size graph embedding, and passes it through three
fully connected layers to produce an 8-class prediction. The system achieves 97%
macro F1 on CIC-IoT2023.

---

## 1. Environment Setup

### 1.1 Python Environment

Python 3.10 or 3.11. Create a dedicated virtual environment.

### 1.2 Required Libraries

Add all of the following to `requirements.txt`:

```
torch>=2.1.0
torch-geometric>=2.4.0
torch-scatter
torch-sparse
torch-cluster
nfstream>=6.3.3
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
joblib>=1.3.0
tqdm>=4.65.0
```

PyTorch Geometric (PyG) and its sparse dependencies require careful installation.
Install in this exact order to avoid version conflicts:

```
pip install torch --index-url https://download.pytorch.org/whl/cu121
pip install torch-scatter torch-sparse torch-cluster -f https://data.pyg.org/whl/torch-2.1.0+cu121.html
pip install torch-geometric
pip install nfstream scikit-learn numpy pandas joblib tqdm
```

Verify PyG is installed correctly:

```
python -c "import torch_geometric; print(torch_geometric.__version__)"
```

### 1.3 libpcap Dependency for NFStream

NFStream requires `libpcap` on Linux:

```
sudo apt-get install libpcap-dev
```

---

## 2. Dataset and Class Structure

### 2.1 Source

CIC-IoT2023 PCAP files, selectively downloaded — one file per attack sub-type plus
all available files for WebBased and BruteForce sub-types. Files are stored under:

```
PCAPs/
```

### 2.2 Canonical Class Structure

Eight output classes following XG-NID exactly:

| Index | Class | Sub-types (PCAP filename patterns) | Sub-type count |
|---|---|---|---|
| 0 | Benign | `Benign*` | 1 |
| 1 | DDoS | `DDoS-*` | 12 |
| 2 | DoS | `DoS-*` | 4 |
| 3 | Mirai | `Mirai-*` | 3 |
| 4 | Recon | `Recon-*`, `VulnerabilityScan*` | 5 |
| 5 | Spoofing | `DNS_Spoofing*`, `MITM-ArpSpoofing*` | 2 |
| 6 | WebBased | `SqlInjection*`, `XSS*`, `BrowserHijacking*`, `CommandInjection*`, `Uploading_Attack*`, `Backdoor_Malware*` | 6 |
| 7 | BruteForce | `DictionaryBruteForce*` | 1 |

### 2.3 Sub-type to Class Mapping in `config.py`

```python
SUBTYPE_TO_CLASS = {
    # DDoS — 12
    "DDoS-ACK_Fragmentation":  "DDoS",
    "DDoS-HTTP_Flood":         "DDoS",
    "DDoS-ICMP_Flood":         "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-PSHACK_Flood":       "DDoS",
    "DDoS-RSTFINFlood":        "DDoS",
    "DDoS-SYN_Flood":          "DDoS",
    "DDoS-SlowLoris":          "DDoS",
    "DDoS-SynonymousIP_Flood": "DDoS",
    "DDoS-TCP_Flood":          "DDoS",
    "DDoS-UDP_Flood":          "DDoS",
    "DDoS-UDP_Fragmentation":  "DDoS",
    # DoS — 4
    "DoS-HTTP_Flood":          "DoS",
    "DoS-SYN_Flood":           "DoS",
    "DoS-TCP_Flood":           "DoS",
    "DoS-UDP_Flood":           "DoS",
    # Mirai — 3
    "Mirai-greeth_flood":      "Mirai",
    "Mirai-greip_flood":       "Mirai",
    "Mirai-udpplain":          "Mirai",
    # Recon — 5
    "Recon-HostDiscovery":     "Recon",
    "Recon-OSScan":            "Recon",
    "Recon-PingSweep":         "Recon",
    "Recon-PortScan":          "Recon",
    "VulnerabilityScan":       "Recon",
    # Spoofing — 2
    "DNS_Spoofing":            "Spoofing",
    "MITM-ArpSpoofing":        "Spoofing",
    # WebBased — 6
    "SqlInjection":            "WebBased",
    "XSS":                     "WebBased",
    "BrowserHijacking":        "WebBased",
    "CommandInjection":        "WebBased",
    "Uploading_Attack":        "WebBased",
    "Backdoor_Malware":        "WebBased",
    # BruteForce — 1
    "DictionaryBruteForce":    "BruteForce",
    # Benign — 1
    "Benign_Final":            "Benign",
}
```

The sub-type name is extracted from a PCAP filename by stripping trailing digits and
the `.pcap` extension. For example, `DDoS-SYN_Flood1.pcap` → `DDoS-SYN_Flood`.

---

## 3. Phase 1 — PCAP Streaming and Graph Object Construction

This is the most critical phase. It is implemented in `secureedge/data/pcap_flows.py`
and a new module `secureedge/data/graph_builder.py`.

### 3.1 NFStream Configuration and Target Feature Set

XG-NID uses NFStream to extract **76 flow-level features** per completed flow.
The NFStreamer is configured as follows:

```python
NFStreamer(
    source               = pcap_path,
    statistical_analysis = True,
    splt_analysis        = 0,
    n_dissections        = 0,
    idle_timeout         = 120,
    active_timeout       = 1800,
    udps                 = [PacketCapture(), FlowCapper()]
)
```

After streaming one small PCAP, print every field name of a single emitted flow
object. Separate all fields into two groups:

**Metadata — exclude from model features:**
`id`, `expiration_id`, `src_ip`, `src_mac`, `src_port` (see note below),
`dst_ip`, `dst_mac`, `dst_port` (see note), `protocol` (see note),
`ip_version`, `vlan_id`, `tunnel_id`,
`bidirectional_first_seen_ms`, `bidirectional_last_seen_ms`,
`src2dst_first_seen_ms`, `src2dst_last_seen_ms`,
`dst2src_first_seen_ms`, `dst2src_last_seen_ms`,
`application_name`, `application_category_name`,
`application_is_guessed`, `application_confidence`,
`requested_server_name`, `client_fingerprint`, `server_fingerprint`.

**Note on ports and protocol:** `src_port`, `dst_port`, and `protocol` are NOT
identifiers — they are characteristics of the communication. Include them as model
features. Remove them from the metadata exclusion list.

**Feature fields — include in model features:**
All remaining numeric fields. This includes bidirectional and directional packet
counts, byte counts, inter-arrival time statistics (min, max, mean, std), packet
length statistics (min, max, mean, std, variance), TCP flag counts (all 8 flags,
bidirectional and directional), TCP window sizes, active time statistics, idle time
statistics, and any sub-flow statistics present.

**Active and idle statistics:** These fields contain the words `active` or `idle`
in their names. If present, include them — do NOT fill with zero or drop them, as
they carry meaningful information about bursty attack patterns (SlowLoris, for
example, has a distinctive active/idle profile). If a given flow has no idle period,
NFStream will emit `0.0` for idle statistics, which is a valid value.

**After identifying all feature fields, count them.** The count must be saved as
`N_FLOW_FEATURES` in `config.py`. The target is 76 to match the XG-NID paper. If
the installed NFStream version produces a different count, use the actual count and
document it clearly. Do not pad or fabricate features to reach exactly 76.

### 3.2 PacketCapture NFPlugin — NEW

This is a new NFPlugin that must be added to `pcap_flows.py`. It captures per-packet
data during streaming, BEFORE flow statistics are finalized. It runs before
FlowCapper in the plugin chain.

```
CLASS PacketCapture (extends NFPlugin):

    METHOD on_init(packet, flow):
        flow.udps.packet_records = []
        # Initialise the per-packet storage when a new flow entry is created.

    METHOD on_update(packet, flow):
        IF len(flow.udps.packet_records) >= 20:
            RETURN  # Already have 20 packets; ignore further payloads.

        # Extract raw payload bytes (application-layer content above transport).
        raw_payload = packet.ip_payload_bytes or []
        # Truncate or pad to 1,500 bytes.
        if len(raw_payload) > 1500:
            raw_payload = raw_payload[:1500]
        elif len(raw_payload) < 1500:
            raw_payload = raw_payload + [0] * (1500 - len(raw_payload))

        packet_record = {
            "payload":        raw_payload,           # list of 1,500 ints [0–255]
            "direction":      packet.direction,       # 0=forward, 1=backward
            "ip_size":        packet.ip_size,
            "transport_size": packet.transport_size,
            "payload_size":   packet.payload_size,
            "timestamp_ms":   packet.time,           # milliseconds since epoch
        }
        flow.udps.packet_records.append(packet_record)
```

The `packet.ip_payload_bytes` field in NFStream provides the raw bytes above the IP
header. If this field is unavailable in NFStream 6.6.0, use `packet.payload` or
access the raw bytes via `packet.ip_packet` starting at the IP payload offset.
Consult NFStream 6.6.0 documentation for the exact attribute name that exposes raw
packet bytes. The goal is to fill a 1,500-element integer list with values 0–255
for each of the first 20 packets per flow.

### 3.3 FlowCapper NFPlugin — Existing, Keep Unchanged

```
CLASS FlowCapper (extends NFPlugin):

    METHOD on_update(packet, flow):
        IF flow.bidirectional_packets >= 20:
            SET flow.expiration_id = -1
```

In NFStream 6.6.0 this is passed via `udps=[PacketCapture(), FlowCapper()]`.
PacketCapture must appear before FlowCapper so packet data is recorded before
the flow is expired.

### 3.4 NFStream Field Name Mapping for Temporal Extractor

Before passing an emitted flow to the temporal extractor, translate NFStream's
field names into the names that `features/temporal.py` expects:

| `temporal.py` expects | NFStream field |
|---|---|
| `Dst IP` | `flow.dst_ip` |
| `Src Port` | `flow.src_port` |
| `Dst Port` | `flow.dst_port` |
| `Protocol` | `flow.protocol` |
| `SYN Flag Cnt` | `flow.bidirectional_syn_packets` |
| `ACK Flag Cnt` | `flow.bidirectional_ack_packets` |
| `FIN Flag Cnt` | `flow.bidirectional_fin_packets` |
| `RST Flag Cnt` | `flow.bidirectional_rst_packets` |
| `PSH Flag Cnt` | `flow.bidirectional_psh_packets` |
| `Flow Duration` | `flow.bidirectional_duration_ms × 1000` (ms → µs) |
| `Tot Fwd Pkts` | `flow.src2dst_packets` |
| `Tot Bwd Pkts` | `flow.dst2src_packets` |

Implement this as `nfstream_to_temporal_dict(flow)` in `pcap_flows.py`.

### 3.5 Temporal Feature Computation — Existing, Keep Unchanged

Temporal features are computed inside the NFStream streaming loop, before any
reservoir sampling. For each emitted flow, call `TemporalFeatureExtractor.update()`
immediately after applying the field name mapping. The extractor uses a sliding window
of W = 375 recent flows per destination IP and computes 16 temporal features.

The extractor is instantiated once per PCAP file and is reset between PCAP files.
This gives each capture its own independent temporal context, which correctly reflects
the traffic density within each attack scenario.

The 16 temporal features join the 76 NFStream flow features to form the flow node's
feature vector of 92 dimensions.

### 3.6 Graph Object Construction — NEW

This is implemented in a new module: `secureedge/data/graph_builder.py`.

After obtaining an enriched flow record (76 flow features + 16 temporal features +
`udps.packet_records` list of up to 20 packet dicts), construct a PyTorch Geometric
`HeteroData` object:

```
FUNCTION build_hetero_graph(flow_features, temporal_features, packet_records, label):

    data = HeteroData()

    # --- Flow node ---
    # One flow node with 92 features (76 flow + 16 temporal).
    flow_feat_vector = concatenate(flow_features, temporal_features)  # shape: [92]
    data['flow'].x = tensor(flow_feat_vector).unsqueeze(0)            # shape: [1, 92]

    # --- Packet nodes ---
    N = len(packet_records)   # at most 20
    packet_feat_matrix = []

    FOR each pkt in packet_records:
        payload_floats = [byte_val / 255.0 for byte_val in pkt['payload']]
        # Each packet node: 1,500-dimensional payload vector, values in [0, 1].
        packet_feat_matrix.append(payload_floats)

    data['packet'].x = tensor(packet_feat_matrix)     # shape: [N, 1500]

    # --- Contain edges: flow → each packet ---
    # One directed edge from the single flow node (index 0) to each packet node.
    src_flow    = [0] * N
    dst_packets = list(range(N))
    data['flow', 'contains', 'packet'].edge_index = tensor([src_flow, dst_packets])

    # Contain edge features: [direction, ip_size, transport_size, payload_size]
    contain_edge_feats = [
        [pkt['direction'], pkt['ip_size'], pkt['transport_size'], pkt['payload_size']]
        for pkt in packet_records
    ]
    data['flow', 'contains', 'packet'].edge_attr = tensor(contain_edge_feats)  # [N, 4]

    # --- Link edges: packet_i → packet_{i+1} ---
    IF N > 1:
        src_pkts = list(range(N - 1))
        dst_pkts = list(range(1, N))
        data['packet', 'linked_to', 'packet'].edge_index = tensor([src_pkts, dst_pkts])

        # Link edge feature: time delta in milliseconds between consecutive packets.
        deltas = [
            packet_records[i+1]['timestamp_ms'] - packet_records[i]['timestamp_ms']
            for i in range(N - 1)
        ]
        data['packet', 'linked_to', 'packet'].edge_attr = tensor([[d] for d in deltas])
        # shape: [N-1, 1]

    # --- Label ---
    data.y = tensor([label], dtype=long)

    RETURN data
```

**Edge cases:**
- A flow with only 1 packet has no link edges. The
  `('packet', 'linked_to', 'packet')` edge type is simply absent. PyG handles this.
- A flow with 0 packets (e.g., an NFStream record where all payloads were
  inaccessible): skip this flow entirely and do not add it to any reservoir.
- Negative time deltas (clock drift in PCAP): take the absolute value.

### 3.7 Label Assignment

The label (integer 0–7) is assigned from the PCAP filename using `SUBTYPE_TO_CLASS`.
The original sub-type string is stored in `graph.subtype_label` as a string attribute
on the HeteroData object for later sub-classifier training.

---

## 4. Phase 2 — Dataset Preparation

### 4.1 Per-Subtype Reservoir Sampling — Existing, Keep Unchanged

The two-level reservoir from the current implementation is correct and unchanged:

1. Each sub-type gets its own bounded reservoir filled from its PCAP file(s).
2. Sub-type reservoirs are merged into class pools.
3. Class pools are oversampled or undersampled to reach exactly 24,000 per class.

Per-subtype targets:

| Class | Sub-types | Per-subtype target |
|---|---|---|
| DDoS | 12 | 2,000 |
| DoS | 4 | 6,000 |
| Mirai | 3 | 8,000 |
| Recon | 5 | 4,800 |
| Spoofing | 2 | 12,000 |
| WebBased | 6 | 4,000 |
| BruteForce | 1 | 24,000 |
| Benign | 1 | 24,000 |

The reservoir now stores `HeteroData` graph objects instead of flat CSV rows.
Everything else about the reservoir logic is unchanged.

### 4.2 Train/Test Split

From each class pool of 24,000 graph objects: 4,000 go to the test set, 20,000 go to
the training set. The split must happen BEFORE oversampling. Oversample only the
training portion. The test set must contain only real, non-duplicated graph objects.

### 4.3 Feature Normalization

Three separate normalisation steps apply to different parts of each graph:

**Flow node features (92 dimensions):**
Fit a `StandardScaler` on the 92-dimensional flow feature vectors from training
graph objects only. Apply the fitted scaler to both training and test flow node
features. Save the scaler as `artifacts/flow_node_scaler.joblib`.

**Packet node features (1,500 dimensions):**
Already normalised to [0, 1] during graph construction (each byte divided by 255.0).
No additional scaler is needed.

**Contain edge features (4 dimensions):**
Fit a `StandardScaler` on the 4-dimensional contain edge features from training
graphs only. Apply to both training and test edge features. Save as
`artifacts/contain_edge_scaler.joblib`.

**Link edge features (1 dimension — time delta):**
Normalise by dividing by the 99th percentile of time deltas in the training set.
This caps outliers from very long idle periods. Save the percentile value as
`artifacts/link_edge_norm_value.json`.

Apply all four scalers in-place to graph objects before writing them to disk.

### 4.4 Graph Dataset Storage

Save processed graph objects using PyG's `InMemoryDataset` format or as individual
`.pt` files under:

```
data/graphs/train/
data/graphs/test/
```

Each `.pt` file is one `HeteroData` object saved with `torch.save()`. Name each file
by its class and index: `DDoS_000001.pt`, `Benign_000001.pt`, etc.

Save a manifest file:

```
artifacts/graph_dataset_manifest.json
```

containing: total graph count, per-class counts, feature dimensions, and the list
of `.pt` file paths grouped by split and class.

---

## 5. Phase 3 — HGNN Architecture

This is implemented in `secureedge/models/hgnn.py`. The flat MLP in
`secureedge/models/architecture.py` is deprecated and must not be used.

### 5.1 Node Type Dimensions

| Node type | Feature dimension |
|---|---|
| Flow node | 92 (76 NFStream flow features + 16 temporal features) |
| Packet node | 1,500 (raw payload bytes, normalised to [0, 1]) |

### 5.2 Heterogeneous GATConv Layers

XG-NID uses two GATConv layers on a heterogeneous graph. The hyperparameters from
the GNN4ID repository are:

```
hidden_size: 64
attn_size:   32   (attention head output dimension)
eps:         1.0
```

Two approaches are valid for heterogeneous GATConv in PyG. Use whichever produces
cleaner code, but both must produce equivalent results:

**Approach A — HeteroConv wrapper (recommended):**

```
HeteroConv({
    ('flow',   'contains',  'packet'):    GATConv(-1, hidden_size),
    ('packet', 'linked_to', 'packet'):    GATConv(-1, hidden_size),
    ('packet', 'rev_contains', 'flow'):   GATConv(-1, hidden_size),
})
```

Note: PyG recommends adding reverse edges for bidirectional message passing. Adding
`('packet', 'rev_contains', 'flow')` allows packet nodes to send messages back to
the flow node. Add these reverse edges during graph construction by including a
corresponding edge type with the reversed edge index.

**Approach B — to_homogeneous conversion:**
Convert the heterogeneous graph to a homogeneous one by concatenating node type
one-hot encodings, then apply standard GATConv. This is simpler to implement but
loses type-specific weight matrices.

For faithful XG-NID replication, use Approach A.

### 5.3 Full Architecture Specification

```
CLASS SecureEdgeHGNN:

    LAYER conv1:
        HeteroConv over all edge types
        GATConv(in_channels=-1, out_channels=hidden_size=64)
        # -1 means PyG infers in_channels from first batch (lazy initialisation)

    LAYER bn_flow_1:   BatchNorm(hidden_size)  # for flow node embeddings
    LAYER bn_packet_1: BatchNorm(hidden_size)  # for packet node embeddings

    LAYER conv2:
        HeteroConv over all edge types
        GATConv(in_channels=hidden_size=64, out_channels=hidden_size=64)

    LAYER bn_flow_2:   BatchNorm(hidden_size)
    LAYER bn_packet_2: BatchNorm(hidden_size)

    LAYER classifier:
        Linear(hidden_size=64, 32)
        ReLU
        Linear(32, 16)
        ReLU
        Linear(16, 8)
        # Raw logits output — softmax is applied outside during evaluation and OOD

    FORWARD METHOD:
        # x_dict: {'flow': [batch_flow_nodes, 92], 'packet': [batch_pkt_nodes, 1500]}
        # edge_index_dict: all edge types with indices
        # edge_attr_dict: all edge types with attributes
        # batch_dict: PyG batch vector per node type

        # GATConv layer 1
        x_dict = conv1(x_dict, edge_index_dict, edge_attr_dict)
        x_dict['flow']   = LeakyReLU(bn_flow_1(x_dict['flow']))
        x_dict['packet'] = LeakyReLU(bn_packet_1(x_dict['packet']))

        # GATConv layer 2
        x_dict = conv2(x_dict, edge_index_dict)
        x_dict['flow']   = LeakyReLU(bn_flow_2(x_dict['flow']))
        x_dict['packet'] = LeakyReLU(bn_packet_2(x_dict['packet']))

        # Global mean pooling — average ALL node embeddings per graph
        # (both flow and packet nodes contribute equally)
        flow_pooled   = global_mean_pool(x_dict['flow'],   batch_dict['flow'])
        packet_pooled = global_mean_pool(x_dict['packet'], batch_dict['packet'])
        graph_embedding = (flow_pooled + packet_pooled) / 2.0  # shape: [batch_size, 64]

        # Classification head
        out = classifier(graph_embedding)  # shape: [batch_size, 8]
        RETURN out  # raw logits
```

All weights are initialised with PyG/PyTorch defaults (Glorot uniform for linear
layers). BatchNorm momentum defaults to 0.1.

### 5.4 eps Parameter

The `eps: 1.0` parameter in the XG-NID config corresponds to the LeakyReLU negative
slope. Set `torch.nn.LeakyReLU(negative_slope=1.0)` — note that a negative slope of
1.0 is equivalent to a standard linear activation with no rectification. This is an
unusual setting that may simply mean the authors used ReLU with eps applied elsewhere
(e.g., in BatchNorm). Use `LeakyReLU(negative_slope=0.01)` as the safe default
(PyTorch default) if `eps=1.0` produces unstable training.

---

## 6. Phase 4 — Training

### 6.1 PyG DataLoader

Use `torch_geometric.loader.DataLoader` (not the standard PyTorch DataLoader) for
graph-level batching:

```
from torch_geometric.loader import DataLoader

train_loader = DataLoader(train_graph_dataset, batch_size=64, shuffle=True)
test_loader  = DataLoader(test_graph_dataset,  batch_size=64, shuffle=False)
```

PyG's DataLoader merges multiple HeteroData objects into one disconnected supergraph
automatically. The `batch` vector in the resulting batch object identifies which
graph each node belongs to and is used during global mean pooling.

Batch size 64 matches XG-NID's likely setting and is well within the RTX 4060's 8 GB
VRAM capacity. Each batch of 64 graphs contains approximately:
- 64 flow nodes × 92 features ≈ trivial
- 64 × 20 packet nodes × 1,500 features ≈ 117 MB as float32 (before GPU overhead)

If 64 graphs OOM during training, reduce to 32.

### 6.2 Hyperparameters

XG-NID published parameters:

| Parameter | XG-NID value | SecureEdge value |
|---|---|---|
| Learning rate | 0.01 | 0.01 (match exactly) |
| LR warmup | not specified | 5 epochs, 1e-3 → 1e-2 |
| Weight decay | 1e-5 | 1e-5 |
| Batch size | ~32–64 graphs | 64 graphs |
| Max epochs | 30 | 200 (with early stopping) |
| Scheduler | not specified | ReduceLROnPlateau, patience=5, factor=0.5 |
| Min LR | not specified | 1e-6 |
| Early stopping | not specified | patience=20 epochs |
| Gradient clipping | not specified | max norm=1.0 |

**Why we extend beyond XG-NID's 30 epochs:** XG-NID's 30-epoch training with a
constant 0.01 LR almost certainly did not converge fully. With a decaying scheduler
and early stopping at patience 20, the model will naturally stop when it stops
improving, whether that is at epoch 40 or epoch 150.

### 6.3 Optimizer

Adam with lr=0.01 and weight_decay=1e-5:

```python
optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-5)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode='max', factor=0.5, patience=5, min_lr=1e-6
)
```

### 6.4 Loss Function

`torch.nn.CrossEntropyLoss()` applied to raw logits against integer class labels.
No class weighting — XG-NID uses a balanced training set (equal class sizes), so
unweighted loss is appropriate.

### 6.5 Training Loop

```
FOR epoch = 1 TO max_epochs=200:

    # LR warmup for first 5 epochs
    IF epoch <= 5:
        set_lr(optimizer, 1e-3 + (1e-2 - 1e-3) * (epoch / 5))

    model.train()
    FOR each batch in train_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        logits = model(batch.x_dict, batch.edge_index_dict,
                       batch.edge_attr_dict, batch.batch_dict)
        loss = CrossEntropyLoss(logits, batch.y)
        loss.backward()
        clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

    model.eval()
    WITH no_grad():
        compute macro F1 on test_loader
        save checkpoint IF macro_f1 > best_f1

    IF epoch > 5:
        scheduler.step(macro_f1)

    IF no improvement for 20 epochs:
        STOP
```

---

## 7. Phase 5 — Evaluation

### 7.1 Primary Target

```
Macro F1 ≥ 0.97
```

This is the XG-NID paper's reported result and the final project target.

### 7.2 Per-Class Targets

| Class | Minimum F1 |
|---|---|
| DDoS | ≥ 0.97 |
| DoS | ≥ 0.97 |
| Mirai | ≥ 0.97 |
| Recon | ≥ 0.90 |
| Spoofing | ≥ 0.90 |
| Benign | ≥ 0.92 |
| WebBased | ≥ 0.90 |
| BruteForce | ≥ 0.90 |

### 7.3 Per-Subtype DDoS Evaluation

In addition to class-level metrics, evaluate separately for each of the 12 DDoS
sub-types. All 12 must be predicted as DDoS at a rate ≥ 0.90. DDoS-SlowLoris is
historically the hardest DDoS sub-type for flow-level features — the graph's packet
payload nodes are specifically what makes SlowLoris distinguishable (its partial HTTP
headers are visible in the payload). Check SlowLoris recall specifically.

### 7.4 Inference Latency

Record inference time per graph on the PC (RTX 4060) and on the Jetson Orin Nano.
XG-NID reports 6.563 ms per sample. This must be measured on the Jetson to confirm
real-time capability.

---

## 8. Phase 6 — OOD Detection

Unchanged from the current implementation. MSP thresholding calibrated at the 5th
percentile of maximum softmax probabilities from correctly classified training samples.

```
threshold = percentile(MSP_train_correct, 5)
```

At inference: if `max(softmax(logits)) < threshold`, classify as "Unknown Attack" and
trigger an alert rather than assigning a class label.

Save threshold to `artifacts/ood_threshold.json`.

For Gotham 2025 validation (future work after ≥ 0.97 is achieved):
- Part A: classification on known attack types
- Part B: OOD detection rate on novel attacks (Merlin C2, CoAP amplification)

---

## 9. Phase 7 — Edge Deployment on Jetson Orin Nano

### 9.1 PyG on Jetson

PyG must be installed on the Jetson Orin Nano for inference. NVIDIA provides PyTorch
as part of JetPack; PyG's sparse extensions must be compiled from source for the
ARM architecture. Steps:

```
# On Jetson Orin Nano:
pip install torch-geometric
pip install torch-scatter torch-sparse torch-cluster \
    -f https://data.pyg.org/whl/torch-<version>+cpu.html
```

If compilation fails, use the ONNX export path (see 9.2).

### 9.2 TorchScript Export

After reaching ≥ 0.97 macro F1, export the model via `torch.jit.trace()`:

```python
# Create a sample batch of one graph for tracing
sample_batch = next(iter(DataLoader([test_dataset[0]], batch_size=1)))
traced_model = torch.jit.trace(model.eval(), (
    sample_batch.x_dict,
    sample_batch.edge_index_dict,
    sample_batch.edge_attr_dict,
    sample_batch.batch_dict
))
torch.jit.save(traced_model, "artifacts/secureedge_hgnn.ts")
```

Verify that TorchScript logits match PyTorch logits within `1e-5` absolute tolerance
on 100 random test graphs.

### 9.3 Real-Time Inference Pipeline on Jetson

At inference time on the Jetson, the pipeline is:
1. Capture a network packet using libpcap or NFStream in live capture mode.
2. Maintain the per-flow state (FlowCapper logic, packet accumulation, temporal window).
3. When a flow completes (20 packets or 120 s idle), construct the HeteroData graph.
4. Apply the saved scalers (flow node, contain edge, link edge).
5. Run the TorchScript model.
6. Apply softmax, check against OOD threshold, emit class label or alert.

The entire inference path from flow completion to label must complete within 10 ms
to qualify as real-time. The Jetson Orin Nano at 40 TOPS is capable of this for a
two-layer GATConv model with batch size 1.

---

## 10. Gotham 2025 Evaluation (After Main Model Is Validated)

After achieving ≥ 0.97 macro F1 on CIC-IoT2023, evaluate on the Gotham 2025 dataset
(zenodo.org/records/14502760):

**Part A — Known attack classification:** Run the model on Gotham flows belonging to
known attack types shared with CIC-IoT2023 (benign, dos, mirai, reconnaissance).
Report per-class F1.

**Part B — OOD detection:** Run the model on Gotham flows belonging to novel attack
types not present in CIC-IoT2023 (merlin_c2, coap_amplification). Measure what
fraction are correctly flagged as "Unknown Attack" by the OOD detector.

---

## 11. Stage 2 Sub-Classifiers (After Main Model Is Validated)

After achieving ≥ 0.97 macro F1 on the 8-class main classifier, train dedicated
sub-classifiers for each multi-type attack class. Each sub-classifier is a
smaller HGNN (same architecture, fewer output classes) trained only on the enriched
graph objects belonging to its parent class, using `subtype_label` as the target.

| Sub-classifier | Output classes |
|---|---|
| DDoS sub-classifier | 12 DDoS variants |
| DoS sub-classifier | 4 DoS variants |
| Mirai sub-classifier | 3 Mirai variants |
| Recon sub-classifier | 5 Recon variants |
| Spoofing sub-classifier | 2 Spoofing variants |
| WebBased sub-classifier | 6 WebBased variants |

BruteForce has only one sub-type (DictionaryBruteForce). No sub-classifier needed.
Benign has one sub-type. No sub-classifier needed.

At inference, the main classifier runs first. If the prediction is a multi-type class,
the corresponding sub-classifier runs on the same graph object to produce the
fine-grained attack variant label.

---

## 12. What Changes from the Current Implementation

### Remove or Replace

| Current component | Status |
|---|---|
| `secureedge/models/architecture.py` (MLP) | **Replace** with `secureedge/models/hgnn.py` (HGNN) |
| `secureedge/data/dataset.py` (tabular) | **Replace** with PyG `InMemoryDataset` |
| `secureedge/models/train.py` (MLP training) | **Replace** with HGNN training loop using PyG DataLoader |
| `secureedge/models/evaluate.py` (tabular eval) | **Update** for graph-level evaluation |
| `secureedge/features/pipeline.py` (CSV scaling) | **Slim down** — only applies flow node and edge scalers to graph objects |
| `artifacts/best_model.pt` | **Delete and regenerate** |
| `data/processed/*.csv` | **Delete** — replaced by `data/graphs/*.pt` |

### Keep Unchanged

| Current component | Status |
|---|---|
| `secureedge/data/acquire.py` | ✅ Keep — PCAP validation unchanged |
| `secureedge/data/preprocess.py` | ✅ Keep — per-subtype reservoir logic unchanged |
| `secureedge/features/temporal.py` | ✅ Keep — temporal extractor unchanged |
| `secureedge/ood/detector.py` | ✅ Keep — MSP thresholding unchanged |
| `SUBTYPE_TO_CLASS` in config.py | ✅ Keep |
| FlowCapper plugin | ✅ Keep |
| Temporal window W=375 | ✅ Keep |
| 20,000 train / 4,000 test per class | ✅ Keep |
| Per-subtype reservoir targets | ✅ Keep |

### Add New

| New component | Purpose |
|---|---|
| `PacketCapture` NFPlugin in `pcap_flows.py` | Captures up to 20 raw packet payloads per flow |
| `secureedge/data/graph_builder.py` | Builds `HeteroData` from enriched flow records |
| `secureedge/models/hgnn.py` | HGNN architecture (2× GATConv + pooling + FC) |
| `data/graphs/train/*.pt` | Serialised training graph objects |
| `data/graphs/test/*.pt` | Serialised test graph objects |
| `artifacts/flow_node_scaler.joblib` | StandardScaler for 92-dim flow node features |
| `artifacts/contain_edge_scaler.joblib` | StandardScaler for 4-dim contain edge features |
| `artifacts/link_edge_norm_value.json` | 99th-percentile time delta for link edge normalisation |
| `artifacts/graph_dataset_manifest.json` | Graph dataset inventory |
| `artifacts/secureedge_hgnn.ts` | TorchScript export of trained HGNN |

---

## 13. Updated `config.py` Constants

```python
# --- Feature dimensions ---
N_FLOW_FEATURES       = <actual NFStream count including ports/protocol>
N_TEMPORAL_FEATURES   = 16
N_FLOW_NODE_FEATURES  = N_FLOW_FEATURES + N_TEMPORAL_FEATURES   # flow node input dim
N_PACKET_FEATURES     = 1500                                     # packet node input dim
N_CONTAIN_EDGE_FEATS  = 4
N_LINK_EDGE_FEATS     = 1

# --- HGNN hyperparameters (from XG-NID/GNN4ID) ---
HGNN_HIDDEN_SIZE      = 64
HGNN_ATTN_SIZE        = 32

# --- Training hyperparameters ---
BATCH_SIZE            = 64          # graphs per batch
LR_START              = 1e-3        # warmup start
LR_TARGET             = 1e-2        # warmup end (matches XG-NID)
LR_MIN                = 1e-6
WARMUP_EPOCHS         = 5
MAX_EPOCHS            = 200
EARLY_STOPPING_PAT    = 20
SCHEDULER_PAT         = 5
WEIGHT_DECAY          = 1e-5
GRAD_CLIP_NORM        = 1.0

# --- Dataset ---
TEMPORAL_WINDOW       = 375
TRAIN_PER_CLASS       = 20000
TEST_PER_CLASS        = 4000
N_CLASSES             = 8

# --- Paths ---
PCAP_DIR              = "PCAPs/"
GRAPH_TRAIN_DIR       = "data/graphs/train/"
GRAPH_TEST_DIR        = "data/graphs/test/"
ARTIFACT_DIR          = "artifacts/"
```

---

## 14. Implementation Order

Implement and verify in this order. Do not proceed to the next phase before the
verification checkpoint of the current phase passes.

**Step 1 — Verify NFStream feature count**
Run NFStream on one small PCAP with `statistical_analysis=True`. Print all field
names. Count numeric statistic fields. Confirm src_port, dst_port, protocol are
included. Check for active/idle fields. Set `N_FLOW_FEATURES` to the actual count.

**Step 2 — Implement PacketCapture plugin**
Test on one small PCAP. For the emitted flow, confirm `len(flow.udps.packet_records)`
is ≤ 20 and each record contains a 1,500-element payload list.

**Step 3 — Verify graph construction**
Build one HeteroData object from one emitted flow. Print node shapes:
`data['flow'].x.shape == [1, N_FLOW_NODE_FEATURES]` and
`data['packet'].x.shape == [N_packets, 1500]`.
Confirm edge indices are within valid ranges.

**Step 4 — Run full preprocessing and graph building**
Process all PCAPs. Verify per-subtype distribution and class counts.
Run Fix 2 diagnostic: confirm DDoS `Rolling_SYN_Sum` mean >> Benign mean.

**Step 5 — Install PyG and test DataLoader**
Load a small subset of graph objects into a PyG DataLoader. Confirm batching works
and `batch.x_dict`, `batch.edge_index_dict`, `batch.batch_dict` have expected shapes.

**Step 6 — Implement HGNN model**
Instantiate `SecureEdgeHGNN`. Run a forward pass on one batch. Confirm output shape
is `[batch_size, 8]`. Confirm no NaN in output.

**Step 7 — Run full training**
Train for up to 200 epochs with early stopping. Monitor per-class F1 at each epoch.
Target: ≥ 0.97 macro F1.

**Step 8 — OOD calibration and TorchScript export**
After ≥ 0.97 is confirmed, calibrate OOD threshold and export TorchScript model.
