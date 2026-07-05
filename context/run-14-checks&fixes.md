# SecureEdge Run 14 — Checks & Fixes After Attacker-MAC Filtering

## Purpose

Run 13 reached very high results after applying attacker-MAC filtering:

- Accuracy: approximately **0.9875**
- Macro-F1: approximately **0.9875**
- Best epoch shown: **20**

This is a major improvement compared with earlier runs that plateaued around **0.90–0.91** even after long training. The improvement strongly suggests that the previous dataset had major label noise caused by assigning attack labels to all flows inside attack PCAP files, including background or unrelated traffic.

However, the jump is large enough that Run 14 should focus on proving that the result is valid and not caused by data leakage, duplicate graphs, or identity shortcuts.

---

## Main Hypothesis

The new high score is probably caused by one or both of the following:

1. **Good explanation:** attacker-MAC filtering removed mislabeled/background traffic and created cleaner labels.
2. **Risky explanation:** the new preprocessing accidentally introduced train/test leakage or made the test set too easy.

Run 14 should verify which explanation is true.

---

# Run 14 Required Checks

## Check 1 — Verify MAC Filtering Logic

### Goal

Confirm that attacker MAC addresses are used only to select the correct rows, not as model features.

### Required behavior

For attack classes:

```python
is_attacker_flow = (
    df["src_mac"].isin(ATTACKER_MACS) |
    df["dst_mac"].isin(ATTACKER_MACS)
)
df_attack = df[is_attacker_flow].copy()
```

For benign traffic:

```python
is_attacker_flow = (
    df["src_mac"].isin(ATTACKER_MACS) |
    df["dst_mac"].isin(ATTACKER_MACS)
)
df_benign = df[~is_attacker_flow].copy()
```

### Important fix

Do **not** write filtering like this:

```python
df[df["src_mac"] != attacker_mac]
```

without assigning the result back to `df`. That does not modify the dataframe.

Correct form:

```python
df = df[df["src_mac"] != attacker_mac].copy()
```

or better:

```python
df = df[~df["src_mac"].isin(ATTACKER_MACS)].copy()
```

---

## Check 2 — Confirm MACs Are Dropped Before Feature Building

### Goal

Prevent the model from learning attacker-device identity instead of attack behavior.

The attacker MACs should be used only for filtering. They must not appear in:

- flow node features
- packet node features
- edge attributes
- graph metadata used by the model
- scaler fitting input
- exported tensors

### Columns that must be removed before graph feature construction

```python
IDENTITY_COLUMNS = [
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "flow_id",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "pcap_file",
    "filename",
    "subtype_label",
]
```

Depending on the actual dataframe schema, also remove any equivalent columns such as:

```python
[
    "src_oui",
    "dst_oui",
    "device_id",
    "capture_id",
    "file_id",
    "attack_file",
    "pcap_path",
]
```

### Validation code

```python
for col in IDENTITY_COLUMNS:
    assert col not in flow_feature_columns, f"Leakage column still in features: {col}"
```

### Expected result

```text
No MAC/IP/file/capture identity columns are present in the final model features.
```

---

## Check 3 — Verify Split Order

### Goal

Make sure oversampling does not duplicate the same graph into both train and test.

### Correct order

```text
1. Load records
2. Apply attacker-MAC filtering
3. Remove identity/leakage columns from model features
4. Split into train/test
5. Fit scalers on train only
6. Oversample train only, if needed
7. Keep test set natural or fixed-balanced without duplicate oversampling leakage
8. Build train/test graph shards separately
```

### Dangerous order

```text
1. Load records
2. Apply attacker-MAC filtering
3. Oversample entire class pool
4. Split into train/test
```

This can place duplicated samples into both train and test and produce artificially high accuracy.

### Required fix

If the current pipeline oversamples before the split, change it to:

```python
train_df, test_df = split_first(filtered_df)
train_df = oversample_train_only(train_df)
# test_df should not receive duplicated train samples
```

---

## Check 4 — Detect Exact Duplicate Rows Across Train and Test

### Goal

Confirm there are no identical flow records in both train and test.

### Suggested method

Create a stable row hash before graph construction.

```python
import hashlib
import pandas as pd

HASH_COLUMNS = [
    col for col in df.columns
    if col not in ["split", "label", "class_label"]
]

def row_hash(row):
    payload = "|".join(str(row[col]) for col in HASH_COLUMNS)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

train_hashes = set(train_df.apply(row_hash, axis=1))
test_hashes = set(test_df.apply(row_hash, axis=1))
leaked_hashes = train_hashes & test_hashes

print("Train/test duplicate rows:", len(leaked_hashes))
assert len(leaked_hashes) == 0
```

### Expected result

```text
Train/test duplicate rows: 0
```

---

## Check 5 — Detect Exact Duplicate Graphs Across Train and Test

### Goal

Even if dataframe rows differ slightly, the final graph tensors may still be identical or near-identical. This check verifies the actual model input.

### Suggested graph hash

Hash the actual tensors used by the model:

- flow node features
- packet node features
- edge indices
- edge attributes
- graph label

Example:

```python
import hashlib
import torch


def tensor_bytes(x):
    if x is None:
        return b"<NONE>"
    if isinstance(x, torch.Tensor):
        return x.detach().cpu().contiguous().numpy().tobytes()
    return str(x).encode("utf-8")


def graph_hash(data):
    h = hashlib.sha256()

    h.update(tensor_bytes(data["flow"].x))
    h.update(tensor_bytes(data["packet"].x))

    for edge_type in data.edge_types:
        h.update(str(edge_type).encode("utf-8"))
        h.update(tensor_bytes(data[edge_type].edge_index))
        edge_attr = getattr(data[edge_type], "edge_attr", None)
        h.update(tensor_bytes(edge_attr))

    h.update(tensor_bytes(data.y))
    return h.hexdigest()

train_graph_hashes = set(graph_hash(g) for g in train_graphs)
test_graph_hashes = set(graph_hash(g) for g in test_graphs)
leaked_graphs = train_graph_hashes & test_graph_hashes

print("Train/test duplicate graphs:", len(leaked_graphs))
assert len(leaked_graphs) == 0
```

### Expected result

```text
Train/test duplicate graphs: 0
```

If duplicate graphs are found, the Run 13 result cannot be trusted as a clean generalization result.

---

## Check 6 — Detect Near-Duplicate Graphs

### Goal

Exact duplicates may not exist, but oversampling or capture reuse may create near-identical train/test samples.

### Practical approach

For each graph, create a lighter fingerprint using rounded statistics:

```python
import numpy as np
import hashlib


def rounded_graph_fingerprint(data, decimals=4):
    flow = data["flow"].x.detach().cpu().numpy().round(decimals)
    packet = data["packet"].x.detach().cpu().numpy().round(decimals)

    summary = {
        "flow": flow.tolist(),
        "packet_mean": packet.mean(axis=0).round(decimals).tolist(),
        "packet_std": packet.std(axis=0).round(decimals).tolist(),
        "num_packets": int(packet.shape[0]),
        "label": int(data.y.item()),
    }

    payload = str(summary).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
```

Then compare train/test fingerprints.

### Expected result

There should be no large overlap between train and test fingerprints.

---

## Check 7 — Verify Scalers Are Fit on Train Only

### Goal

Prevent test-set statistics from leaking into training.

### Correct behavior

```python
scaler.fit(train_features)
train_features = scaler.transform(train_features)
test_features = scaler.transform(test_features)
```

### Dangerous behavior

```python
scaler.fit(all_features)
```

or:

```python
scaler.fit(pd.concat([train_df, test_df]))
```

### Required validation

Log the scaler fitting source:

```text
flow_scaler_fit_split=train
contain_edge_scaler_fit_split=train
link_delta_normalizer_fit_split=train
```

Save this information into the graph manifest.

---

## Check 8 — Verify Class Counts After Filtering and Splitting

### Goal

Make sure every class has the intended number of train and test graphs after filtering.

### Required report

Print counts before and after each stage:

```text
raw counts by class
counts after attacker-MAC filtering
counts after train/test split
counts after train oversampling
final graph counts by class
```

### Example code

```python
def print_counts(name, df):
    print(f"\n{name}")
    print(df["class_label"].value_counts().sort_index())

print_counts("Raw", raw_df)
print_counts("After MAC filtering", filtered_df)
print_counts("Train before oversampling", train_df)
print_counts("Test", test_df)
print_counts("Train after oversampling", train_balanced_df)
```

### Expected final target if reproducing XG-NID

```text
Train: 20,000 graphs per class
Test: 4,000 graphs per class
Total train: 160,000
Total test: 32,000
```

---

## Check 9 — Evaluate on a Harder Split

### Goal

Determine whether the 98.7% result is true generalization or mostly same-capture memorization.

### Recommended harder evaluations

#### Option A — PCAP-held-out split

Train on some PCAP files and test on different PCAP files.

```text
train: subset of PCAP captures
validation/test: different PCAP captures not seen during training
```

#### Option B — Leave-one-PCAP-out

Repeat training/evaluation while holding out one PCAP file or capture group at a time.

```text
fold 1: hold out capture A
fold 2: hold out capture B
fold 3: hold out capture C
...
```

#### Option C — Time-based split

Train on earlier traffic and test on later traffic.

```text
train: earlier timestamps
validation/test: later timestamps
```

### Interpretation

```text
If F1 remains near 0.97–0.98:
    The model is likely learning real attack behavior.

If F1 drops back near 0.90–0.91:
    The current split is too easy or capture-specific.
```

---

## Check 10 — Compare Against an XG-NID-Compatible Baseline

### Goal

Separate preprocessing improvements from model architecture effects.

Run the cleaned dataset using a model closer to XG-NID:

```text
HeteroConv + SAGEConv
2 message-passing layers
mean aggregation
global mean pool flow nodes
global mean pool packet nodes
concatenate flow and packet graph embeddings
classifier: 128 → 64 → 16 → 8
batch_size=64
lr=0.01
epochs=30
```

### Why this matters

Your current GAT-based model may be stronger or weaker than the XG-NID SAGE baseline. To fairly compare with XG-NID, use the same preprocessing and a similar model first.

---

# Recommended Fixes for Run 14

## Fix 1 — Add a Leakage Audit Script

Create:

```text
secureedge/data/leakage_audit.py
```

The script should check:

- duplicate dataframe rows across train/test
- duplicate graph hashes across train/test
- feature-column leakage
- scaler fit source
- class counts at every stage
- PCAP/capture overlap between train and test

Suggested command:

```bash
python -m secureedge.data.leakage_audit \
  --train-manifest artifacts/graphs/train_manifest.json \
  --test-manifest artifacts/graphs/test_manifest.json \
  --report artifacts/training_runs/run_14_leakage_audit.md
```

---

## Fix 2 — Save Split Metadata Per Graph

Each graph should store metadata such as:

```json
{
  "graph_id": "...",
  "split": "train",
  "class_label": "Recon",
  "subtype_label": "Recon-OSScan",
  "source_pcap": "...",
  "source_csv": "...",
  "flow_id_hash": "...",
  "used_attacker_mac_filter": true,
  "num_packets": 20
}
```

Do not store raw MAC/IP values in model features. If needed for auditing, store hashed values only in metadata files, not inside tensors.

---

## Fix 3 — Add Assertions to Stop Bad Runs

The pipeline should fail automatically if leakage is detected.

```python
assert duplicate_row_count == 0, "Train/test duplicate rows detected"
assert duplicate_graph_count == 0, "Train/test duplicate graphs detected"
assert not leaked_columns, f"Identity columns leaked into features: {leaked_columns}"
assert scaler_fit_split == "train", "Scaler was not fit on train split only"
```

---

## Fix 4 — Add Per-Class Filtering Report

Create a report like this:

```text
Class        Raw      After MAC Filter    Removed      Removed %
Benign       ...      ...                 ...          ...
DDoS         ...      ...                 ...          ...
DoS          ...      ...                 ...          ...
Mirai        ...      ...                 ...          ...
Recon        ...      ...                 ...          ...
Spoofing     ...      ...                 ...          ...
WebBased     ...      ...                 ...          ...
BruteForce   ...      ...                 ...          ...
```

This will show whether filtering removed a reasonable amount of traffic or accidentally removed too much/too little.

---

## Fix 5 — Add Hard-Split Evaluation

Create a second evaluation mode:

```bash
python -m secureedge.models.evaluate \
  --checkpoint artifacts/checkpoints/best.pt \
  --split test_pcap_holdout
```

The regular test split can be used for XG-NID-style comparison, but the PCAP-held-out split is more useful for real-world generalization.

---

# Run 14 Decision Rules

## Case 1 — No leakage found, hard split remains high

If:

```text
duplicate rows = 0
duplicate graphs = 0
no identity columns in features
scalers fit on train only
regular test F1 ≈ 0.98
hard-split F1 ≈ 0.95–0.98
```

Then the result is likely valid. The main conclusion is:

> The earlier 0.90–0.91 ceiling was caused mostly by label noise from unfiltered PCAP-level labeling.

## Case 2 — No exact leakage, but hard split drops strongly

If:

```text
regular test F1 ≈ 0.98
hard-split F1 ≈ 0.90
```

Then the regular split is too easy or capture-specific. The model is probably learning capture/device/session patterns in addition to attack behavior.

## Case 3 — Duplicate rows or duplicate graphs found

If:

```text
duplicate rows > 0
```

or:

```text
duplicate graphs > 0
```

Then the Run 13 score is not reliable. Fix the split and oversampling order, rebuild the graphs, and rerun training.

## Case 4 — Identity columns found in features

If columns such as `src_mac`, `dst_mac`, `src_ip`, `dst_ip`, `flow_id`, or `pcap_file` are present in the model features, remove them and rerun.

---

# Recommended Run 14 Report Template

Use the following sections in the Run 14 log:

```markdown
# SecureEdge Training Run 14

## Goal
Validate whether Run 13's 98.7% macro-F1 is a real improvement from attacker-MAC filtering or caused by leakage.

## Dataset Filtering Summary
- Attacker MAC filtering: yes/no
- Raw records per class:
- Records after filtering per class:
- Removed records per class:

## Split Validation
- Split method:
- Oversampling before or after split:
- Train rows per class:
- Test rows per class:

## Leakage Audit
- Duplicate dataframe rows across train/test:
- Duplicate graph hashes across train/test:
- Near-duplicate fingerprint overlap:
- Identity columns in features:
- Scalers fit on train only:

## Training Configuration
- Model:
- Batch size:
- Learning rate:
- Scheduler:
- Epochs:

## Regular Test Results
- Accuracy:
- Macro-F1:
- Per-class F1:

## Hard-Split Results
- Split type:
- Accuracy:
- Macro-F1:
- Per-class F1:

## Conclusion
State whether the 98.7% result appears valid, leaked, or split-dependent.
```

---

# Bottom-Line Recommendation

Do not change the model yet. For Run 14, focus on proving the data pipeline is clean.

The most important checks are:

1. **No duplicate rows across train/test**
2. **No duplicate graphs across train/test**
3. **Oversampling happens after splitting**
4. **MAC/IP/file identity columns are not model features**
5. **Scalers are fit on train only**
6. **A harder PCAP-held-out evaluation is added**

If all of these pass, then the high result is likely a real consequence of fixing label noise with attacker-MAC filtering.
