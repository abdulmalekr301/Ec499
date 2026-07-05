# Payload Path Audit Fixes

## Source Files Reviewed

- `context/codebase-audit-findings.md`
- `context/revert-to-oversampling2.md`
- `secureedge/models/hgnn.py`
- `secureedge/models/train.py`
- `secureedge/data/preprocess.py`
- `secureedge/config.py`

## Fixes Applied

### 1. Packet Payload Sequence Encoder

The audit identified that raw 1,500-byte packet vectors were entering `GATConv`
through a single linear projection. That projection has no local sequence pattern
sharing, so byte signatures such as SQL injection strings, XSS tags, and HTTP
credential bodies are difficult to learn when they appear at different offsets.

Added a shared 1D CNN packet encoder in `secureedge/models/hgnn.py`:

- `Conv1d(1 -> 32, kernel_size=7)`
- `BatchNorm1d`
- `ReLU`
- `Conv1d(32 -> 32, kernel_size=5)`
- `BatchNorm1d`
- `ReLU`
- `AdaptiveMaxPool1d(1)`
- `Dropout(0.1)`
- `Linear(32 -> 64)`
- `ReLU`

Each packet node is now encoded from a 1,500-byte sequence into a 64-dimensional
payload embedding before heterogeneous message passing.

### 2. Concatenated Flow/Packet Readout

The previous graph readout averaged the flow and packet pooled embeddings:

```python
graph_embedding = (flow_pooled + packet_pooled) / 2.0
```

That hard-coded a 50/50 modality mix. The model now concatenates both pooled
embeddings by default:

```python
graph_embedding = torch.cat([flow_pooled, packet_pooled], dim=1)
```

The classifier now receives a 128-dimensional graph embedding so it can learn how
much signal to use from each modality.

### 3. Edge Attributes in Both HGNN Layers

The first `HeteroConv` layer already used edge attributes. The second layer did
not. Updated conv2 so all relation types also receive edge attributes:

- `flow -> packet` contain edges: 4 features
- `packet -> flow` reverse contain edges: 4 features
- `packet -> packet` temporal link edges: 1 feature

This keeps contain metadata and inter-packet timing available across both message
passing layers.

### 4. Oversampling Path Verified

The revert-to-oversampling instructions were already reflected in the current
pipeline:

- Training uses original `data/graphs/train_shards/`.
- Deduped shard artifacts are absent.
- Focal-loss artifacts are absent.
- Training uses plain `torch.nn.CrossEntropyLoss()`.
- No class weights or online augmentation are active.
- The graph dataset manifest reports exactly `20,000` train and `4,000` test
  graphs per class.

## Pre-Training Checks Completed

Ran:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Both passed.

Also ran a bounded real-shard forward check using 4 graphs from:

```text
data/graphs/train_shards/shard_0000.pt
```

Result:

```text
logits_shape=(4, 8)
finite=True
```

## Dataset/Sharding Check

Current graph dataset:

- Train graphs: `160,000`
- Test graphs: `32,000`
- Train class counts: `20,000` per class
- Test class counts: `4,000` per class
- Train shards: `160`
- Test shards: `32`

## Important Training Note

The architecture changed, so older checkpoints from Runs 1-10 should not be
resumed into this model. Start the next training run from scratch.
