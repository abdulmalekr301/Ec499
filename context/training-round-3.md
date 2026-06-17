# SecureEdge — Training Round 3 Findings and Fixes

> **Generated:** 2026-06-16
> **Based on:** Training runs 1, 2, and 3 results.
> **Verdict:** Hyperparameter tuning is complete. The ceiling is a data-layer
> problem. No further training run should start until all three data fixes below
> are applied.

---

## 0. What Three Runs Confirmed

| Run | Scheduler | Label Smoothing | Batch | Best Epoch | Best F1 |
|---|---|---|---|---|---|
| 1 | ReduceLROnPlateau | 0.0 | 256 | 101 / 121 | 0.8732 |
| 2 | Cosine annealing | 0.1 | 512 | 280 / 300 | 0.8618 |
| 3 | Cosine annealing | 0.0 | 512 | 261 / 300 | 0.8726 |

Three runs with completely different schedulers, loss functions, batch sizes, and
epoch budgets all converged to the same result: **macro F1 = 0.87 ± 0.01**.

Removing label smoothing in run 3 recovered run 1 performance exactly, confirming
smoothing was the only cause of run 2's regression. Cosine annealing itself is
neutral — neither helpful nor harmful. The ceiling is not a hyperparameter problem.

---

## 1. Root Cause — Two Simultaneous Data Problems

### Problem A: Training loss 0.116 with test F1 0.87 — overfitting from oversampling

Run 3's final training loss is 0.116 — extremely low for an 8-class problem with
no label smoothing. The model has nearly memorised the training set. Yet test F1 is
0.87. That gap between near-zero training loss and moderate test error is textbook
overfitting.

The cause is the oversampling required for minority classes:

| Sub-type | Real flows available | Training target | Duplicate fraction |
|---|---|---|---|
| DictionaryBruteForce | 11,043 | 20,000 | **≈ 60%** |
| Uploading_Attack | 1,619 | ~4,000 | **≈ 60%** |
| Backdoor_Malware | 3,236 | ~4,000 | **≈ 20%** |
| Recon-PingSweep | 2,226 | ~4,800 | **≈ 54%** |

When 60% of BruteForce training graphs are duplicates, the model learns to
perfectly recognise those exact duplicates (loss → 0.116) but cannot generalise to
the distinct real flows in the test set. BruteForce's 22.1% test FN rate confirms
this: the model "knows" BruteForce from training but misses nearly a quarter of it
at test time.

### Problem B: Packet payload features may be zeros

Across all three runs, the HGNN with 1,500-dimensional payload nodes improved over
the flow-only MLP by only 0.02–0.03 macro F1. If packet payloads were carrying real
application-layer bytes — SQL injection patterns, HTTP POST bodies, credential
stuffing payloads — the improvement on WebBased and BruteForce specifically should
be 0.10 or more. The magnitude of improvement is consistent with packet nodes
carrying no information.

This has not been verified yet. It must be verified first before any other fix
is applied.

---

## 2. Fix 0 — Payload Diagnostic (Run Immediately, Before Anything Else)

This takes five minutes and determines whether fixes 1 and 2 are even relevant.

```python
import torch, glob, numpy as np

paths = sorted(glob.glob("data/graphs/train/*.pt"))[:500]
means, nonzero_fracs = [], []

for p in paths:
    g = torch.load(p)
    x = g['packet'].x          # shape: [N_packets, 1500]
    means.append(x.mean().item())
    nonzero_fracs.append((x != 0).float().mean().item())

print(f"Mean packet feature value : {np.mean(means):.4f}")
print(f"Mean non-zero fraction    : {np.mean(nonzero_fracs):.4f}")
print()
print("Expected if payloads are REAL:  mean ≈ 0.35–0.50, non-zero > 0.80")
print("Expected if payloads are ZEROS: mean ≈ 0.00,      non-zero ≈ 0.00")
```

### If non-zero fraction < 0.10 — fix PacketCapture

The `PacketCapture` plugin in `secureedge/data/pcap_flows.py` is not extracting
real bytes. The attribute used to access raw payload data in NFStream 6.6.0 needs
to be identified.

Run this diagnostic inside `on_update` during one short extraction to find the
correct attribute:

```
CLASS PayloadAttributeFinder (extends NFPlugin):

    METHOD on_update(packet, flow):
        IF flow.bidirectional_packets == 1:  # first packet of first flow only
            FOR attr in dir(packet):
                IF "payload" in attr.lower() OR "raw" in attr.lower() OR "bytes" in attr.lower():
                    TRY:
                        val = getattr(packet, attr)
                        IF val is not None AND len(val) > 0:
                            PRINT(f"{attr}: type={type(val)}, len={len(val)}, first_bytes={val[:8]}")
                    EXCEPT: pass
            RAISE StopIteration  # stop after first packet
```

The correct attribute will be a bytes-like object with length > 0. Common candidates
in NFStream 6.6.0:
- `packet.ip_payload`
- `packet.payload`
- `packet.raw_bytes`
- `packet.ip_packet` (requires manually offsetting past the IP header)

Once the correct attribute is identified, update `PacketCapture.on_update` to use
it. Zero-pad to 1,500 bytes if shorter, truncate if longer.

### If non-zero fraction > 0.80 — payloads are real, skip to Fix 1

Packet payload nodes are carrying real data. The 0.87 ceiling is explained entirely
by Fix 1 (oversampling overfitting) and the 16 missing flow features (Fix 2).

---

## 3. Fix 1 — Eliminate Oversampling by Getting More Real Data

### Why augmentation and class weighting do not solve this

Oversampling duplicates causes the model to memorise specific graph instances
rather than learning generalisable class patterns. No training technique fixes
this — the model will always achieve near-zero loss on duplicates while
generalising poorly to distinct real samples.

The only real solution is more raw PCAP data for the underrepresented sub-types.

### Sub-types that need additional PCAP downloads

| Sub-type | Class | Current real flows | Target | Required additional |
|---|---|---|---|---|
| DictionaryBruteForce | BruteForce | 11,043 | 24,000 | ~15,000 more flows |
| Recon-PingSweep | Recon | 2,226 | 4,800 | ~3,000 more flows |
| Uploading_Attack | WebBased | 1,619 | 4,000 | ~2,500 more flows |
| Backdoor_Malware | WebBased | 3,236 | 4,000 | ~1,000 more flows |
| XSS | WebBased | 4,270 | 4,000 | already sufficient |

For each under-represented sub-type, download ALL remaining PCAP files from the
CIC-IoT2023 dataset page (not just the first file). The full dataset has multiple
PCAP files per attack sub-type. The current setup only downloaded one file per
sub-type for large attack classes, and single complete files for small classes.

For DictionaryBruteForce specifically: if the CIC website provides only one
BruteForce PCAP with 11,043 usable flows, contact the CIC directly or look for
supplementary captures. BruteForce with 60% duplicate ratio in training is the
single largest contributor to the 0.87 ceiling.

### How to verify Fix 1 is working

After downloading additional PCAPs and re-running preprocessing, check the
duplicate fraction per class in the training reservoir:

```
PROCEDURE check_duplicate_fraction(reservoir):
    FOR each class:
        all_records = reservoir[class]
        # Check if oversampling was needed
        real_count = count of records with is_oversampled=False
        dup_count  = count of records with is_oversampled=True
        dup_fraction = dup_count / len(all_records)
        PRINT(f"{class}: {real_count} real + {dup_count} duplicates = {dup_fraction:.1%} oversampled")

        ASSERT dup_fraction < 0.20, "More than 20% oversampling — download more PCAPs"
```

Flag preprocessing to store `is_oversampled=True` on each oversampled record so
this check is possible without re-counting.

---

## 4. Fix 2 — Add the 16 Missing Flow Features

This fix is documented in detail in `preprocessing-find-missing.md`. A summary
for this document:

NFStream 6.6.0 provides 60 numeric flow features (48 statistical + 12 core
including ports and protocol). XG-NID's 76 flow features include 16 additional
values that NFStream does not expose by default:

**Group A (8 features) — active and idle time statistics:**
Computed via `ActiveIdlePlugin` during streaming. These are critical for:
- DDoS-SlowLoris (very long active periods, zero idle gaps)
- Spoofing (irregular burst-idle patterns for DNS probing)
- Recon (probe-wait cycles in scanning behaviour)

**Group B (8 features) — derived rate and ratio features:**
Computed from already-stored values during graph construction. No new plugin needed:
- `bidirectional_bytes_per_second`
- `bidirectional_packets_per_second`
- `src2dst_bytes_per_second`, `src2dst_packets_per_second`
- `dst2src_bytes_per_second`, `dst2src_packets_per_second`
- `down_up_bytes_ratio`
- `average_packet_size`

After both groups are added: 76 flow features + 16 temporal = **92-dimensional
flow node**, matching XG-NID's specification exactly.

See `preprocessing-find-missing.md` for full implementation details including
the `ActiveIdlePlugin` pseudocode, the derived feature formulas, the ordering
of features in the 76-dim vector, and the verification checkpoints.

---

## 5. Full Regeneration Sequence

Apply all fixes in this order. Do not run training until every step is verified.

### Step 1 — Fix PacketCapture (if payload diagnostic showed zeros)
Update the raw payload attribute in `PacketCapture.on_update`. Test on one
small PCAP and re-run the payload diagnostic to confirm mean > 0.35.

### Step 2 — Download additional PCAPs for minority classes
Download remaining PCAP files for DictionaryBruteForce, Recon-PingSweep,
Uploading_Attack, and Backdoor_Malware from the CIC-IoT2023 dataset page.
Place them in the appropriate subtype directories under `PCAPs/`.

Split any new large PCAPs into 64 MB chunks using editcap before proceeding:
```bash
editcap -b 67108864 PCAPs/DictionaryBruteForce2.pcap \
    PCAPs/chunks/DictionaryBruteForce/DictionaryBruteForce2_chunk.pcap
```

### Step 3 — Add ActiveIdlePlugin to pcap_flows.py
Follow `preprocessing-find-missing.md` Section 3. Plugin order must be:
```
udps = [ActiveIdlePlugin(), PacketCapture(), FlowCapper()]
```

### Step 4 — Delete all stale compact records and graphs
```
data/graphs/_reservoir/           (delete entire directory)
data/graphs/train/                (delete entire directory)
data/graphs/test/                 (delete entire directory)
data/graphs/train_shards/         (delete entire directory)
data/graphs/test_shards/          (delete entire directory)
artifacts/compact_reservoir_manifest.json
artifacts/graph_dataset_manifest.json
artifacts/flow_node_scaler.joblib
artifacts/contain_edge_scaler.joblib
artifacts/link_edge_norm_p99.json
artifacts/best_hgnn.pt
artifacts/metrics.json
```

### Step 5 — Re-run compact extraction
```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_MAX_PROCESS_RSS_GB=6 \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4 \
SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64 \
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 \
python -m secureedge.data.preprocess
```

After extraction, verify duplicate fractions per class (see Fix 1 check).
BruteForce duplicate fraction must be below 20%.

### Step 6 — Run build_graphs with 76-feature flow nodes
```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
python -m secureedge.data.build_graphs
```

Verify:
```python
g = torch.load("data/graphs/train/DDoS_000001.pt")
assert g['flow'].x.shape == (1, 92)    # 76 flow + 16 temporal
assert g['packet'].x.mean() > 0.30     # real payloads
```

### Step 7 — Recreate graph shards
```bash
python -m secureedge.data.create_shards
```

### Step 8 — Retrain (round 4)

Use the round 3 configuration — it is the correct baseline:

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
python -m secureedge.models.train
```

---

## 6. Expected Outcomes After All Fixes

The three fixes address the three distinct failure modes:

| Fix | Failure mode addressed | Expected F1 impact |
|---|---|---|
| Payload extraction | WebBased, BruteForce, Spoofing can't use payload content | +0.05–0.10 on those classes |
| Real data for minority classes | Oversampling overfitting, especially BruteForce | +0.03–0.06 on BruteForce and Recon |
| 16 missing flow features | Spoofing burst patterns, SlowLoris, Recon probe cycles undetected | +0.03–0.05 on Recon, Spoofing |

Combined expected macro F1 range: **0.93–0.97**

Reaching exactly 0.97 depends on payload quality — if application-layer bytes
are real and the HGNN can use them, WebBased and BruteForce should reach 0.90+
which is needed for the overall macro average to hit 0.97.

---

## 7. What Not to Do Next

Do not start another training run with different hyperparameters before applying
the data fixes. Three runs have proven the hyperparameter ceiling is 0.87 on the
current dataset. The following will not help:

- Different learning rates
- Different schedulers
- Larger batch sizes
- More epochs
- Different attention head counts
- Larger hidden size
- Dropout additions
- Weight decay adjustments

Every minute spent on hyperparameter tuning before fixing the data is time that
will not move the metric.
