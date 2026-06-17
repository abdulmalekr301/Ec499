# SecureEdge — Preprocessing with All Fixes

> **Generated:** 2026-06-15
> **Supersedes:** All previous preprocessing descriptions.
> **Applies to:** Final XG-NID replication methodology (secureedge_methodology_final.md).

This document describes the complete, final preprocessing pipeline including the
PCAP splitting plan for large files and every fix accumulated across all previous
passes. Give this document to the coding agent alongside the final methodology.

---

## 0. What Changed From the Previous Preprocessing Run

| Component | Previous state | Final state |
|---|---|---|
| Feature extraction | NFStream, no payload | NFStream + PacketCapture plugin (payloads included) |
| Output format | Compact pickle records → CSV | Compact pickle records → HeteroData `.pt` graphs |
| Large PCAP handling | Blocked / crashed | Pre-split to 64 MB chunks before extraction |
| Temporal features | Before sampling ✅ | Before sampling ✅ (unchanged) |
| FlowCapper | 20-packet limit ✅ | 20-packet limit ✅ (unchanged) |
| Per-subtype reservoir | Implemented ✅ | Implemented ✅ (unchanged) |
| Port/protocol as features | Included ✅ | Included ✅ (unchanged) |
| Normalisation | One StandardScaler | Three separate scalers (flow node, contain edge, link edge) |
| Test set oversampling | Applied to whole class pool | Applied to training split only |

---

## 1. Step 0 — Pre-split Large PCAP Files

This step runs once before any extraction. It converts large PCAP files into
64 MB chunks that the extraction subprocess can process without exhausting memory.

### 1.1 Install editcap

```bash
sudo apt-get install wireshark-common
editcap --version   # verify installation
```

### 1.2 Identify which PCAPs need splitting

Any PCAP file larger than 64 MB (67,108,864 bytes) must be split. Run this once
to print the list:

```bash
find PCAPs/ -maxdepth 1 -name "*.pcap" -size +64M -exec ls -lh {} \;
```

Based on the dataset, expect the following to require splitting (approximate sizes):

| PCAP file | Approximate size | Reason |
|---|---|---|
| DDoS-SYN_Flood1.pcap | 1–2 GB | Sustained SYN flood |
| DDoS-UDP_Flood1.pcap | 1–2 GB | Sustained UDP flood |
| DDoS-ICMP_Flood1.pcap | 500 MB–1 GB | ICMP flood |
| DDoS-TCP_Flood1.pcap | 500 MB–1 GB | TCP flood |
| DDoS-PSHACK_Flood1.pcap | 500 MB–1 GB | PSH-ACK flood |
| DDoS-RSTFINFlood1.pcap | 500 MB–1 GB | RST-FIN flood |
| DoS-SYN_Flood1.pcap | 500 MB–1 GB | DoS SYN flood |
| DoS-UDP_Flood1.pcap | 500 MB–1 GB | DoS UDP flood |
| Mirai-greeth_flood1.pcap | 200 MB+ | Mirai GRE-Eth flood |
| Mirai-greip_flood1.pcap | 200 MB+ | Mirai GRE-IP flood |
| BenignTraffic1.pcap | Variable | Long benign capture |
| DNS_Spoofing1.pcap | Variable | Sustained spoofing |
| MITM-ArpSpoofing1.pcap | Variable | Sustained ARP spoofing |

Run the `find` command above and split every file it returns.

### 1.3 Split each large PCAP

For each large PCAP, run:

```bash
mkdir -p PCAPs/chunks/<SubtypeName>

editcap -b 67108864 \
    PCAPs/<SubtypeName>1.pcap \
    PCAPs/chunks/<SubtypeName>/<SubtypeName>_chunk.pcap
```

The `-b 67108864` flag splits by bytes (64 × 1,024 × 1,024 = 67,108,864 bytes).
editcap produces sequentially numbered output files:

```
PCAPs/chunks/DDoS-SYN_Flood/
    DDoS-SYN_Flood_chunk_00001_20231015.pcap
    DDoS-SYN_Flood_chunk_00002_20231015.pcap
    DDoS-SYN_Flood_chunk_00003_20231015.pcap
    ...
```

The date suffix in the filename is the timestamp of the first packet in that chunk.
Ordering is determined by the 5-digit sequence number, not the date suffix.

### 1.4 Directory structure after splitting

```
PCAPs/
├── Backdoor_Malware1.pcap          (< 64 MB, process directly)
├── BrowserHijacking1.pcap          (< 64 MB, process directly)
├── CommandInjection1.pcap          (< 64 MB, process directly)
├── DictionaryBruteForce1.pcap      (< 64 MB, process directly)
├── DDoS-SYN_Flood1.pcap            (large — split, do not process directly)
├── DDoS-UDP_Flood1.pcap            (large — split, do not process directly)
├── ...
└── chunks/
    ├── DDoS-SYN_Flood/
    │   ├── DDoS-SYN_Flood_chunk_00001_<date>.pcap
    │   ├── DDoS-SYN_Flood_chunk_00002_<date>.pcap
    │   └── ...
    ├── DDoS-UDP_Flood/
    │   └── ...
    ├── DoS-SYN_Flood/
    │   └── ...
    └── ...
```

### 1.5 PCAP discovery logic changes in `acquire.py` and `preprocess.py`

Update `discover_pcap_files()` to return a mapping from subtype name to an ordered
list of PCAP paths (original file for small PCAPs, sorted chunk list for large ones):

```
FUNCTION discover_pcap_files():

    result = {}   # subtype_name → [ordered list of pcap paths to process]

    FOR each .pcap file in PCAPs/ (top level only, not in chunks/):
        subtype = extract_subtype_name(filename)
        chunk_dir = PCAPs/chunks/<subtype>/
        file_size = os.path.getsize(pcap_path)

        IF file_size > 67108864 (64 MB):
            IF chunk_dir exists AND contains .pcap files:
                chunks = sorted(glob(chunk_dir/*.pcap), key=sequence_number)
                result[subtype] = chunks
            ELSE:
                LOG warning: "<filename> is > 64 MB and has no chunks.
                              Run editcap to split it first. Skipping."
                SKIP this file
        ELSE:
            result[subtype] = [pcap_path]   # small file, process directly

    RETURN result
```

The sequence number for sorting is the 5-digit number embedded in the editcap
output filename. Extract it with a regex: `(\d{5})` before the date suffix.

### 1.6 Safety check before full run

Before starting the full extraction run, print the discovery result:

```
For each subtype: print(subtype, "→", len(paths), "file(s) to process")
```

Confirm that all 34 sub-types are present and that the large PCAPs now show
multiple chunk paths instead of one. If any large subtype shows only one path,
its chunks have not been created yet.

---

## 2. Step 1 — NFStream Extraction with PacketCapture and FlowCapper

### 2.1 Plugin order

Two NFStream plugins run simultaneously. PacketCapture must appear before
FlowCapper in the `udps` list so packet data is recorded before the flow expires:

```
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

### 2.2 PacketCapture plugin

New plugin in `secureedge/data/pcap_flows.py`. Captures up to 20 packets per flow.
The flow expires when FlowCapper triggers after the 20th packet, so the packet list
is naturally bounded at 20.

```
CLASS PacketCapture (extends NFPlugin):

    METHOD on_init(packet, flow):
        flow.udps.packet_records = []

    METHOD on_update(packet, flow):
        IF len(flow.udps.packet_records) >= 20:
            RETURN   # FlowCapper will fire on this same packet

        raw_payload = get_ip_payload_bytes(packet)
        # Truncate to 1,500 bytes or zero-pad to 1,500 bytes
        IF len(raw_payload) > 1500:
            raw_payload = raw_payload[:1500]
        ELSE:
            raw_payload = raw_payload + [0] * (1500 - len(raw_payload))

        flow.udps.packet_records.append({
            "payload":        raw_payload,        # 1,500 ints, each 0–255
            "direction":      packet.direction,   # 0=forward 1=backward
            "ip_size":        packet.ip_size,
            "transport_size": packet.transport_size,
            "payload_size":   packet.payload_size,
            "timestamp_ms":   packet.time,
        })
```

The exact attribute name for raw payload bytes in NFStream 6.6.0 must be confirmed
by printing `dir(packet)` during one extraction. Common candidates are
`packet.ip_payload_bytes`, `packet.payload`, or `packet.raw_packet`. If NFStream
does not expose raw bytes at the packet level, use `packet.ip_size` to confirm
whether a payload exists and fill the payload vector with zeros — a zero payload
is still a valid packet node feature (indicates no application-layer data).

### 2.3 FlowCapper plugin (unchanged)

```
CLASS FlowCapper (extends NFPlugin):

    METHOD on_update(packet, flow):
        IF flow.bidirectional_packets >= 20:
            SET flow.expiration_id = -1
```

### 2.4 What to do with flows that have zero packet records

If a flow is emitted with `len(flow.udps.packet_records) == 0`, it means the
packet capture was inaccessible for all packets in that flow. Do not add such
flows to any reservoir. Skip and count them separately for the log.

---

## 3. Step 2 — Temporal Feature Computation During Extraction

### 3.1 Timing (unchanged from previous pass)

Temporal features are computed DURING the NFStream streaming loop, after each
flow is emitted and before it is added to the reservoir. They are never
recomputed after sampling.

### 3.2 Temporal state across chunks of the same PCAP

When a large PCAP has been split into chunks, the temporal extractor instance
must be carried across all chunks of that subtype — it must NOT reset between
chunks. Each chunk is a sequential slice of the same continuous capture:

```
PROCEDURE extract_subtype(subtype_name, pcap_paths, reservoir, target):

    temporal_extractor = TemporalFeatureExtractor(window_size=375)
    # One extractor instance per subtype. Shared across all chunks.

    FOR each pcap_path in pcap_paths (in sorted chunk order):

        IF len(reservoir) >= target:
            BREAK   # reservoir full, skip remaining chunks

        FOR each flow emitted by NFStreamer(pcap_path):

            IF len(flow.udps.packet_records) == 0:
                CONTINUE   # skip zero-payload flows

            flow_dict = nfstream_to_temporal_dict(flow)
            temporal_feats = temporal_extractor.update(flow_dict)

            compact_record = {
                "flow_features":   extract_nfstream_stats(flow),  # N_FLOW_FEATURES floats
                "temporal_feats":  temporal_feats,                 # 16 floats
                "packet_records":  flow.udps.packet_records,       # list of ≤20 dicts
                "label":           CANONICAL_CLASS_INDEX[SUBTYPE_TO_CLASS[subtype_name]],
                "subtype_label":   subtype_name,
            }

            IF len(reservoir) < target:
                reservoir.append(compact_record)
            ELSE:
                BREAK   # stop reading this chunk immediately
```

The temporal extractor resetting between subtypes (not between chunks) is
correct: a DDoS-SYN_Flood extractor carries context from chunk 1 into chunk 2
because those are consecutive portions of the same attack capture.

### 3.3 Compact record format for disk storage

During extraction, write compact records to disk as pickle files (`.pkl`),
not as PyG graph objects. This avoids importing PyTorch during the extraction
subprocess and keeps memory usage low. Each compact record is:

```
{
    "flow_features":   np.array([...], dtype=np.float32),   # shape: [N_FLOW_FEATURES]
    "temporal_feats":  np.array([...], dtype=np.float32),   # shape: [16]
    "packet_records": [
        {
            "payload":        np.array([...], dtype=np.uint8),  # shape: [1500]
            "direction":      int,
            "ip_size":        int,
            "transport_size": int,
            "payload_size":   int,
            "timestamp_ms":   float,
        },
        ...   # up to 20 entries
    ],
    "label":           int,     # 0–7
    "subtype_label":   str,
}
```

Using `uint8` for payload (values 0–255) instead of `float32` reduces payload
storage by 4×: 1,500 uint8 = 1.5 KB vs 1,500 float32 = 6 KB per packet node.
Conversion to float32 (dividing by 255.0) happens during graph construction,
not during extraction.

---

## 4. Step 3 — Per-Subtype Reservoir Management (unchanged)

The per-subtype reservoir logic from the previous pass is correct and unchanged.
For reference:

```
Per-subtype targets (train + test combined):

DDoS      12 subtypes × 2,000 = 24,000
DoS        4 subtypes × 6,000 = 24,000
Mirai      3 subtypes × 8,000 = 24,000
Recon      5 subtypes × 4,800 = 24,000
Spoofing   2 subtypes × 12,000 = 24,000
WebBased   6 subtypes × 4,000 = 24,000
BruteForce 1 subtype  × 24,000 = 24,000
Benign     1 subtype  × 24,000 = 24,000
```

When a subtype has fewer raw flows than its target (e.g., Uploading_Attack with
~1,619 flows against a 4,000 target), use all available flows. Compensation via
oversampling happens in Step 5, not here.

---

## 5. Step 4 — Class Pool Construction and Train/Test Split

```
PROCEDURE build_class_pools(subtype_reservoirs):

    FOR each canonical class:

        subtypes = [s for s in SUBTYPE_TO_CLASS if SUBTYPE_TO_CLASS[s] == class]
        class_pool = concatenate subtype_reservoirs for all subtypes in class
        shuffle class_pool

        # --- Split BEFORE oversampling ---
        # The test set must contain only real, non-duplicated records.
        IF len(class_pool) >= 4000:
            test_records  = class_pool[:4000]
            train_pool    = class_pool[4000:]
        ELSE:
            # Very limited data (e.g., some rare subtypes)
            split_idx     = int(len(class_pool) * 0.833)
            test_records  = class_pool[split_idx:]
            train_pool    = class_pool[:split_idx]

        # --- Oversample training pool only ---
        IF len(train_pool) < 20000:
            train_records = oversample(train_pool, target=20000)
        ELIF len(train_pool) > 20000:
            train_records = random_subsample(train_pool, n=20000)
        ELSE:
            train_records = train_pool

        yield class, train_records, test_records
```

Critical rule: oversampling applies only to training records. The test set is
always drawn from the real (non-duplicated) pool before any oversampling occurs.

---

## 6. Step 5 — Feature Normalisation

Three separate normalisation steps are applied after train/test split.

### 6.1 Flow node scaler

Fit a `StandardScaler` on the concatenated `[flow_features, temporal_feats]`
vectors from all 160,000 training records (92 dimensions). Apply to both
train and test records. Save as:

```
artifacts/flow_node_scaler.joblib
```

### 6.2 Packet feature normalisation (no scaler needed)

Convert each payload byte from uint8 (0–255) to float32 divided by 255.0
during graph construction. Values are already in [0, 1]. No scaler is needed.

### 6.3 Contain edge scaler

Fit a `StandardScaler` on the 4-dimensional contain edge feature vectors
(`[direction, ip_size, transport_size, payload_size]`) from all contain edges
in all training graphs. Apply to both train and test edges. Save as:

```
artifacts/contain_edge_scaler.joblib
```

`direction` (values 0 or 1) will be scaled alongside the size features; this
is intentional — the scaler normalises all four dimensions consistently.

### 6.4 Link edge normalisation

Link edge features are time deltas in milliseconds between consecutive packets.
These can range from near-zero (flood attacks with sub-millisecond inter-packet
gaps) to thousands of milliseconds (slow attacks like SlowLoris).

Normalise by dividing by the 99th percentile of time deltas across all link
edges in all training graphs. Using the 99th percentile (not max) avoids the
scaler being dominated by extreme outliers from idle periods:

```
all_deltas = [delta for each link edge in training graphs]
p99 = percentile(all_deltas, 99)
normalised_delta = raw_delta / p99   # values mostly in [0, 1], outliers > 1 are fine
```

Save the p99 value as:

```
artifacts/link_edge_norm_p99.json   # {"p99_ms": <float>}
```

Apply the same p99 divisor (fitted on training only) to test graph link edges.

---

## 7. Step 6 — Graph Object Construction and Serialisation

After all compact records have been collected and scalers have been fitted,
construct PyTorch Geometric `HeteroData` objects. This step imports PyTorch and
PyG — it must run in a separate phase from extraction to avoid memory conflicts.

### 7.1 Graph construction from a compact record

```
FUNCTION build_graph(record, flow_scaler, edge_scaler, link_p99):

    data = HeteroData()

    # Flow node: concatenate flow features and temporal features, then scale
    raw_flow_vec = concatenate(record["flow_features"], record["temporal_feats"])
    scaled_flow_vec = flow_scaler.transform(raw_flow_vec.reshape(1, -1))[0]
    data['flow'].x = tensor(scaled_flow_vec, dtype=float32).unsqueeze(0)  # [1, 92]

    # Packet nodes: convert uint8 payload to float32, divide by 255
    packets = record["packet_records"]
    N = len(packets)

    IF N == 0:
        RAISE ValueError("Cannot build graph from record with zero packet records")

    packet_matrix = []
    FOR each pkt in packets:
        float_payload = pkt["payload"].astype(float32) / 255.0   # [1500]
        packet_matrix.append(float_payload)

    data['packet'].x = tensor(packet_matrix, dtype=float32)   # [N, 1500]

    # Contain edges: flow node (index 0) → each packet node (index 0..N-1)
    src = [0] * N
    dst = list(range(N))
    data['flow', 'contains', 'packet'].edge_index = tensor([src, dst], dtype=long)

    raw_edge_feats = [[pkt["direction"], pkt["ip_size"],
                       pkt["transport_size"], pkt["payload_size"]]
                      for pkt in packets]
    scaled_edge_feats = edge_scaler.transform(raw_edge_feats)
    data['flow', 'contains', 'packet'].edge_attr = tensor(scaled_edge_feats, dtype=float32)

    # Reverse contain edges: packet → flow (enables bidirectional message passing)
    data['packet', 'rev_contains', 'flow'].edge_index = tensor([list(range(N)), [0]*N], dtype=long)
    data['packet', 'rev_contains', 'flow'].edge_attr  = tensor(scaled_edge_feats, dtype=float32)

    # Link edges: packet_i → packet_{i+1} for consecutive packets
    IF N > 1:
        src_link = list(range(N - 1))
        dst_link = list(range(1, N))
        data['packet', 'linked_to', 'packet'].edge_index = tensor([src_link, dst_link], dtype=long)

        raw_deltas = [packets[i+1]["timestamp_ms"] - packets[i]["timestamp_ms"]
                      for i in range(N - 1)]
        # Clamp negative deltas (clock drift) to zero
        raw_deltas = [max(0.0, d) for d in raw_deltas]
        norm_deltas = [[d / link_p99] for d in raw_deltas]
        data['packet', 'linked_to', 'packet'].edge_attr = tensor(norm_deltas, dtype=float32)

    # Label
    data.y = tensor([record["label"]], dtype=long)

    # Store subtype for diagnostics
    data.subtype_label = record["subtype_label"]

    RETURN data
```

### 7.2 Serialisation

Save each graph as an individual `.pt` file using `torch.save()`. Organise by
split and class label for easy loading:

```
data/graphs/
├── train/
│   ├── Benign_000001.pt
│   ├── Benign_000002.pt
│   ├── ...
│   ├── DDoS_000001.pt
│   ├── ...
│   └── BruteForce_020000.pt
└── test/
    ├── Benign_000001.pt
    ├── ...
    └── BruteForce_004000.pt
```

Write a manifest file after all graphs are serialised:

```
artifacts/graph_dataset_manifest.json
{
    "n_train":           160000,
    "n_test":            32000,
    "n_flow_features":   <actual NFStream count>,
    "n_temporal_feats":  16,
    "n_flow_node_feats": <N_FLOW_FEATURES + 16>,
    "n_packet_feats":    1500,
    "n_contain_edge_feats": 4,
    "n_link_edge_feats": 1,
    "class_counts_train": { "Benign": 20000, "DDoS": 20000, ... },
    "class_counts_test":  { "Benign": 4000,  "DDoS": 4000, ... },
    "train_files":       [...],
    "test_files":        [...]
}
```

---

## 8. Safety Settings for the Full Run

The full extraction of 192,000 compact records from 34 PCAP subtypes (some now
chunked) must be run with the following environment settings:

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
```

Graph construction runs separately after extraction is complete:

```bash
python -m secureedge.data.build_graphs
```

Never run extraction and graph construction in the same Python process. Extraction
must not import PyTorch. Graph construction must not open PCAP files.

### Safe development command (reduced sample count for testing the pipeline)

Before running the full extraction, verify the entire pipeline end to end with a
small sample:

```bash
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 \
python -m secureedge.data.preprocess

python -m secureedge.data.build_graphs
python -m secureedge.models.train
python -m secureedge.models.evaluate
```

This produces 200 training and 50 test graphs per class — enough to confirm the
full pipeline runs without crashing but fast enough to iterate on.

---

## 9. Verification Checkpoints

Run all checks after the full extraction and before starting training. Do not
proceed to training if any check fails.

### Check 1 — 20-packet cap confirmed

```python
import pandas as pd, json, torch, glob

max_pkts = 0
for f in glob.glob("data/graphs/train/*.pt")[:1000]:
    g = torch.load(f)
    n = g['packet'].x.shape[0]
    if n > max_pkts: max_pkts = n

assert max_pkts <= 20, f"Found graph with {max_pkts} packet nodes — FlowCapper not working"
print(f"OK: max packet nodes per graph = {max_pkts}")
```

### Check 2 — Temporal features are working (DDoS vs Benign signal)

Load 500 random DDoS training graphs and 500 random Benign training graphs.
Find the index of `Rolling_SYN_Sum` in the flow node feature vector. The DDoS
mean must be substantially higher than the Benign mean:

```
DDoS mean Rolling_SYN_Sum   > 1,000   (expect 5,000+)
Benign mean Rolling_SYN_Sum < 100     (expect < 50)
```

If both are similar or both are near zero, temporal features are not being
computed in the streaming loop — check that `temporal_extractor.update()` is
called before reservoir insertion, not after.

### Check 3 — DDoS subtype diversity

Load all 20,000 DDoS training graphs. Print the distribution of `subtype_label`.
All 12 DDoS subtypes must be present. No single subtype should exceed 10%
(2,000 / 20,000) of the DDoS training set:

```
Expected: each subtype ≈ 1,650 ± 200 samples (varies by raw data availability)
Fail condition: any single subtype > 3,000 samples (indicates reservoir bias)
```

### Check 4 — Packet nodes are present and correctly shaped

Load 100 random graphs. For each, confirm:
- `g['packet'].x.shape[1] == 1500` (packet node feature dimension)
- `g['packet'].x.min() >= 0.0` and `g['packet'].x.max() <= 1.0` (normalised)
- `g['flow', 'contains', 'packet'].edge_index.shape[0] == 2` (valid edge index)
- `g['packet', 'rev_contains', 'flow'].edge_index` exists (reverse edges present)

### Check 5 — Manifest file counts are correct

```
n_train == 160,000
n_test  == 32,000
class_counts_train: all 8 classes present, each == 20,000
class_counts_test:  all 8 classes present, each == 4,000
```

### Check 6 — Scalers are fitted and save/load cleanly

```python
import joblib
flow_scaler = joblib.load("artifacts/flow_node_scaler.joblib")
edge_scaler = joblib.load("artifacts/contain_edge_scaler.joblib")
assert flow_scaler.n_features_in_ == N_FLOW_FEATURES + 16
assert edge_scaler.n_features_in_ == 4
print("OK: scalers loaded cleanly")
```

---

## 10. Summary of New Files Added to the Project

| New file | Purpose |
|---|---|
| `secureedge/data/split_pcaps.py` | Automates editcap splitting for all large PCAPs |
| `secureedge/data/build_graphs.py` | Constructs HeteroData graphs from compact pickle records |
| `PCAPs/chunks/<SubtypeName>/` | Chunk directories created by editcap |
| `data/graphs/train/*.pt` | Serialised training HeteroData graph objects |
| `data/graphs/test/*.pt` | Serialised test HeteroData graph objects |
| `artifacts/graph_dataset_manifest.json` | Graph count and file inventory |
| `artifacts/flow_node_scaler.joblib` | StandardScaler for 92-dim flow node features |
| `artifacts/contain_edge_scaler.joblib` | StandardScaler for 4-dim contain edge features |
| `artifacts/link_edge_norm_p99.json` | 99th-percentile value for link edge time delta normalisation |

### Optional helper script: `secureedge/data/split_pcaps.py`

To automate the editcap splitting instead of running it manually for each PCAP,
implement a script that:

1. Scans `PCAPs/` for files larger than 64 MB.
2. For each, creates the output directory `PCAPs/chunks/<subtype>/`.
3. Calls `subprocess.run(["editcap", "-b", "67108864", input_path, output_path])`.
4. Prints the resulting chunk count and total size.
5. Skips subtypes whose chunk directory already exists and is non-empty.

Run this script once before the extraction:

```bash
python -m secureedge.data.split_pcaps
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 python -m secureedge.data.preprocess
python -m secureedge.data.build_graphs
```
