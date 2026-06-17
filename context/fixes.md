# SecureEdge — Implementation Fixes

> **Generated:** 2026-06-13
> **Reference:** Progress report v2026-06-13, current macro F1 = 0.774 vs target ≥ 0.97

This document describes every fix required to bring the SecureEdge implementation into
alignment with the XG-NID methodology and reach the macro F1 target. Fixes are ordered
by severity and dependency. Fix 1 and Fix 2 are the root causes of the performance gap
and must both be applied before retraining. Fix 3 is a mechanical consequence of Fix 1.
Fix 4 follows from Fix 3. Fix 5 is the regeneration sequence that ties everything
together.

---

## 0. Summary of Issues

| # | Issue | Severity | Root cause |
|---|---|---|---|
| 1 | Custom `pcap_flows.py` replaced by NFStream | **Critical** | Wrong feature extraction tool |
| 2 | Temporal features computed after sampling | **Critical** | Wrong pipeline order |
| 3 | Feature dimension mismatch in config | **Required** | Depends on Fix 1 |
| 4 | MLP first layer input dimension wrong | **Required** | Depends on Fix 3 |
| 5 | All artifacts must be regenerated | **Required** | Depends on Fixes 1–4 |
| 6 | Balanced test set deviates from methodology | Minor | Methodology preference |

**Expected outcome after all fixes:** Benign, DoS, Recon, DDoS, Mirai should all
exceed 0.90 F1. Spoofing should improve substantially. WebBased and BruteForce will
remain the hardest classes due to the absence of packet payload features but should
improve over the current 0.537–0.538. Overall macro F1 should reach or approach 0.97.

---

## Fix 1 — Replace Custom `pcap_flows.py` with NFStream (Critical)

### Why the current approach produces wrong features

The progress report confirms that `secureedge/data/pcap_flows.py` is a custom-built
packet parser that extracts 80 features directly from raw PCAP bytes. This is the
single most likely cause of the 0.774 macro F1.

The XG-NID paper states explicitly: *"Built upon NFStream (Aouini and Pekar, 2022),
the Flow and Feature Generator computes 76 flow-level features."* NFStream is a
specific Python library with precisely defined algorithms for computing each statistic:
bidirectional inter-arrival times, flag counts, byte distribution metrics, active and
idle time windows, and all directional statistics. A custom parser will produce
different numerical values for the same underlying traffic even if the column names
look identical.

Evidence from the per-class results confirms this diagnosis. Benign achieves only
0.628 F1. Benign flows and DDoS/DoS floods are trivially separable in correct feature
space — low versus extremely high packet rates, byte counts, and inter-arrival times.
A Benign F1 this low indicates that the flow features themselves are producing
unreliable values, not that the model has a structural problem.

### What NFStream is

NFStream is an open-source Python library for network flow metering. It reads PCAP
files in streaming fashion and emits one record per completed flow, computing
statistical features according to well-defined algorithms. It is pip-installable and
does not require external tools or GUIs. XG-NID's entire feature extraction pipeline
is built on NFStream.

### Installation

Add to `requirements.txt`:

```
nfstream>=6.3.3
```

Then install:

```
pip install nfstream
```

NFStream requires `libpcap` on Linux. On Ubuntu this is:

```
sudo apt-get install libpcap-dev
```

### How NFStream replaces `pcap_flows.py`

The entire custom flow extraction loop in `pcap_flows.py` is replaced by a call to
NFStream's `NFStreamer`. NFStream handles packet parsing, bidirectional flow
reconstruction, the flow completion rules, and feature computation internally.

The two flow completion parameters that match the methodology must be configured:

```
max_nflows     — not directly settable per-flow, NFStream handles timeouts
idle_timeout   — maps to NFStream's idle_timeout parameter (set to 120 seconds)
active_timeout — maps to NFStream's active_timeout parameter (set to a high value
                  so flows close on idle timeout, not active timeout)
```

The 20-packet limit from the methodology is applied as a post-processing filter:
after NFStream emits a flow, discard it if `bidirectional_packets > 20` and
re-emit would be ambiguous. NFStream can also be configured with a packet budget
per flow using `splt_analysis`, but the simplest correct approach is to let NFStream
use its standard idle timeout and then cap flows at 20 packets during extraction.

The core NFStreamer usage pattern:

```
NFStreamer(
    source      = "<path_to_pcap>",
    decode_tunnels     = False,
    statistical_analysis = True,
    splt_analysis      = 0,
    n_dissections      = 0,
    idle_timeout       = 120,
    active_timeout     = 1800,
    accounting_mode    = 0,
)
```

With `statistical_analysis=True`, NFStream computes the full set of bidirectional
flow statistics. With `splt_analysis=0` and `n_dissections=0`, per-packet deep
inspection is disabled — exactly what the methodology requires for flow-level features.

### Determining the correct feature list

After running NFStreamer on one small PCAP, inspect the resulting flow object fields.
Print all attribute names of a single flow record and separate them into two groups:

**Metadata fields** (do NOT include as model features):
- `id`, `expiration_id`, `src_ip`, `src_mac`, `src_port`, `dst_ip`, `dst_mac`,
  `dst_port`, `protocol`, `ip_version`, `vlan_id`, `tunnel_id`,
  `bidirectional_first_seen_ms`, `bidirectional_last_seen_ms`,
  `src2dst_first_seen_ms`, `src2dst_last_seen_ms`,
  `dst2src_first_seen_ms`, `dst2src_last_seen_ms`

**Flow statistic fields** (these ARE the model input features):
- All remaining numerical fields: duration, packet counts, byte counts,
  packet length statistics, inter-arrival time statistics, TCP flag counts,
  TCP window sizes, active/idle time statistics — all bidirectional and
  directional variants.

Count the statistic fields. The target is 76, matching the XG-NID paper. If the
installed version of NFStream produces a different count, update `N_FLOW_FEATURES`
in `config.py` to the actual count and regenerate `feature_columns.json` accordingly.

Write the exact field names from NFStream into `config.py` as `FLOW_FEATURE_COLS`.
These replace the current CICFlowMeter-style column names entirely.

### Field name mapping for `features/temporal.py`

The temporal extractor in `temporal.py` currently reads field names from the flow
record using CICFlowMeter-style names such as `Protocol`, `Dst Port`, `SYN Flag Cnt`,
and so on. NFStream uses different naming conventions.

Add a mapping step that translates NFStream field names into the names that
`temporal.py` expects before passing a flow to `TemporalFeatureExtractor.update()`.

The required mapping is:

| temporal.py expects | NFStream field name |
|---|---|
| `Dst IP` | `dst_ip` |
| `Src Port` | `src_port` |
| `Dst Port` | `dst_port` |
| `Protocol` | `protocol` |
| `SYN Flag Cnt` | `bidirectional_syn_packets` |
| `ACK Flag Cnt` | `bidirectional_ack_packets` |
| `FIN Flag Cnt` | `bidirectional_fin_packets` |
| `RST Flag Cnt` | `bidirectional_rst_packets` |
| `PSH Flag Cnt` | `bidirectional_psh_packets` |
| `Flow Duration` | `bidirectional_duration_ms` × 1000 (convert ms → µs) |
| `Tot Fwd Pkts` | `src2dst_packets` |
| `Tot Bwd Pkts` | `dst2src_packets` |

Add a function `nfstream_to_temporal_dict(flow)` in `pcap_flows.py` or
`features/temporal.py` that applies this mapping and returns a plain dictionary
that the temporal extractor can consume.

`Flow Duration` must be multiplied by 1,000 when reading from NFStream because
NFStream reports duration in milliseconds while `Rolling_Average_Duration` in the
temporal extractor expects microseconds, which is the unit used throughout the
XG-NID feature specification.

### Label assignment from filename

The label assignment logic already in `preprocess.py` (deriving class and subtype
from the PCAP filename) is correct and does not change. NFStream produces
`dst_ip`-keyed flows, and the label comes from the source PCAP filename, not from
the flow content. This part of the pipeline is unaffected.

### Verification checkpoint for Fix 1

After completing Fix 1 and running NFStream on a single test PCAP:

1. Confirm the number of statistic fields printed from a flow record matches
   `N_FLOW_FEATURES` in `config.py`.
2. Confirm `feature_columns.json` contains exactly the NFStream statistic field names.
3. Confirm that `temporal.py` receives correctly mapped field names by printing
   the `nfstream_to_temporal_dict` output for one DDoS flow and verifying that
   `SYN Flag Cnt` is non-zero for a SYN flood PCAP.

---

## Fix 2 — Temporal Features Must Be Computed Before Sampling (Critical)

### Why the current order breaks temporal context entirely

The progress report states: *"The temporal context is computed after the sampled
preprocessing output, not across the full original chronological dataset."*

This is a fundamental error. The 16 temporal features derive their meaning from
real traffic density. During a DDoS SYN flood, hundreds of flows arrive at the same
destination within milliseconds. The sliding window of 375 consecutive flows captures
this density: `Rolling_SYN_Sum` might show 7,000 SYN packets in the last 375 flows,
which is an unambiguous attack signal. During normal Benign traffic, 375 flows to
the same destination might span several minutes, and `Rolling_SYN_Sum` might be 3.

When the pipeline samples 20,000 flows from 33 million DDoS flows and THEN computes
temporal features, the 375 flows in the window are 375 randomly chosen DDoS flows
from across the entire capture — not 375 flows that actually arrived consecutively.
The rolling counts become moderate and meaningless, indistinguishable from Benign.
This is the direct cause of Benign's 0.628 F1 and Spoofing's 0.641 F1.

### The correct pipeline order

**Current (broken) order:**

```
PCAP files
    → pcap_flows.py (custom extraction, partial sampling)
    → preprocess.py (class balancing to 20,000)
    → pipeline.py (temporal features applied to balanced output)
    → train_features.csv / test_features.csv
```

**Correct order:**

```
PCAP files
    → NFStream (stream all flows in chronological order)
    → temporal.py (compute 16 temporal features for each flow as it arrives)
    → enriched flow records (80 + 16 = 76+16 = 92 features per flow)
    → preprocess.py (class balancing to 20,000 from enriched records)
    → train_features.csv / test_features.csv
```

The critical rule: **temporal features are computed before any sampling or
balancing. Sampling happens on records that already carry correct temporal values.**

### Practical streaming approach

Processing all 33 million flows before sampling is not required and is impractical
given memory constraints. The PCAP crash during PSHACK extraction proves this.
The correct practical approach is per-PCAP streaming with temporal features computed
during the stream.

Each PCAP file belongs to exactly one attack subtype. Stream each PCAP file through
NFStream, compute temporal features for each flow as it exits NFStream, and add the
enriched record to a bounded per-class reservoir. Stop reading the PCAP when the
reservoir is full. This preserves temporal context within each PCAP while bounding
memory:

```
PROCEDURE extract_with_temporal(pcap_path, class_label, reservoir, reservoir_limit):

    IF reservoir[class_label] is already full:
        SKIP this PCAP entirely   ← (this logic already exists, keep it)

    temporal_extractor = TemporalFeatureExtractor(window_size=375)

    FOR each flow emitted by NFStreamer(pcap_path):

        flow_dict = nfstream_to_temporal_dict(flow)   ← Fix 1 mapping

        temporal_feats = temporal_extractor.update(flow_dict)
        ← computes 16 rolling values based on flows seen SO FAR in this stream

        enriched_record = merge(nfstream_flow_features, temporal_feats)
        enriched_record["label"]        = map_to_canonical_class(class_label)
        enriched_record["subtype_label"] = class_label

        IF reservoir[class_label] has space:
            ADD enriched_record to reservoir[class_label]
        ELSE:
            STOP reading this PCAP   ← reservoir full, no more needed

    RETURN reservoir
```

This is the only change to the control flow in `pcap_flows.py` / `preprocess.py`.
The reservoir logic already exists. The only move is: call `temporal_extractor.update()`
INSIDE the per-packet loop, before the reservoir add decision, not after.

### Removing `features/pipeline.py` temporal application step

The current `pipeline.py` applies temporal features to the already-balanced output
CSVs (`train_standard.csv`, `test_standard.csv`). This step must be removed entirely.
Temporal features must not be recomputed after the fact. The output of the extraction
phase should already contain all 92 columns.

`pipeline.py` should still be responsible for:
- Fitting the `StandardScaler` on the 92 training features
- Applying the scaler to test features
- Writing `train_features.csv`, `test_features.csv`, `feature_scaler.joblib`,
  and `feature_columns.json`

What it must no longer do: call `TemporalFeatureExtractor` or sort-and-recompute
temporal windows.

### Why per-PCAP temporal context is valid

One concern: if temporal features are computed per-PCAP, the window resets between
PCAP files. This is correct behaviour. Each PCAP file is an independent capture of
one attack scenario. The temporal window within a DDoS flood PCAP correctly reflects
the real density of that attack. The window resetting between a DDoS PCAP and a DoS
PCAP is correct — they are separate captures.

The window does NOT need to span across all PCAP files chronologically. XG-NID's
Algorithm 1 processes a continuous stream of traffic from one deployment, not a
concatenation of different attack captures. Per-PCAP temporal computation is the
correct analogue for a dataset of independent capture files.

### Verification checkpoint for Fix 2

After Fix 2 is applied and extraction is complete, run this diagnostic before training:

1. Load `train_features.csv` and group by label.
2. For the DDoS class, print the mean value of `Rolling_SYN_Sum`.
   **Expected: a large value, typically in the hundreds or thousands.**
3. For the Benign class, print the mean value of `Rolling_SYN_Sum`.
   **Expected: a small value, typically below 10.**
4. If DDoS and Benign have similar `Rolling_SYN_Sum` mean values, the temporal
   features are still not working correctly and the pipeline order is still wrong.

This single check is the fastest way to confirm the fix worked before spending time
on a full training run.

---

## Fix 3 — Update Feature Dimensions in `config.py`

This fix is a direct consequence of Fix 1. NFStream produces 76 flow features, not 80.
The following values in `config.py` must be updated:

| Constant | Old value | New value | Reason |
|---|---|---|---|
| `N_FLOW_FEATURES` | `80` | `76` | NFStream produces 76 flow features |
| `INPUT_DIM` | `96` | `92` | 76 flow + 16 temporal = 92 |
| `FLOW_FEATURE_COLS` | CICFlowMeter column names | NFStream statistic field names | Tool change |

`FLOW_FEATURE_COLS` must be replaced with the actual list of NFStream statistic field
names identified during Fix 1 verification. Do not assume the names — inspect a live
NFStream flow object and copy the exact field names.

The `feature_columns.json` artifact, which stores the ordered list of 92 model input
columns, will be regenerated automatically when `pipeline.py` runs after the fixes.
Delete the old version before re-running.

---

## Fix 4 — Update MLP Input Dimension in `models/architecture.py`

The `SecureEdgeMLP` class takes `input_dim` as a constructor argument. The default
value must change from `96` to `92` to match the new `INPUT_DIM` constant.

Change the default argument in the `__init__` signature:

```
# Before
def __init__(self, input_dim=96, ...):

# After
def __init__(self, input_dim=INPUT_DIM, ...):   ← import INPUT_DIM from config
```

Using `INPUT_DIM` from `config.py` directly as the default is the cleaner approach —
it means `config.py` is the single source of truth for the feature count, and
`architecture.py` never needs to be edited again when dimensions change.

The hidden layer widths (256, 128, 64), dropout (0.4), BatchNorm structure, and
raw-logit output are all correct and do not change.

The `train.py` and `evaluate.py` scripts should already be passing `n_classes=8`
to the model constructor. Verify that `input_dim` is not hardcoded anywhere in
`train.py` — it should read from `config.INPUT_DIM` or use the model's default.

The `TorchScript` export in `export.py` passes a dummy tensor of shape
`(1, input_dim)` to trace the model. This dummy tensor must also change from
`torch.zeros(1, 96)` to `torch.zeros(1, INPUT_DIM)`. If `INPUT_DIM` is imported
from `config.py`, this change is automatic.

---

## Fix 5 — Complete Artifact Regeneration Sequence

All existing artifacts must be deleted and regenerated in the order below. Running
any downstream step before its upstream dependency is re-run will produce incorrect
results.

### Step 1 — Delete stale artifacts

```
data/processed/train_standard.csv        ← delete
data/processed/test_standard.csv         ← delete
data/processed/train_features.csv        ← delete
data/processed/test_features.csv         ← delete
artifacts/standard_scaler.joblib         ← delete
artifacts/feature_scaler.joblib          ← delete
artifacts/feature_columns.json           ← delete
artifacts/best_model.pt                  ← delete
artifacts/metrics.json                   ← delete
artifacts/ood_threshold.json             ← delete
artifacts/secureedge_model.ts            ← delete
```

Context documentation files (`context/*.md`) can be kept or regenerated — they do
not affect training.

### Step 2 — Verify NFStream installation

```
python -c "import nfstream; print(nfstream.__version__)"
```

Must print a version number without error before proceeding.

### Step 3 — Run Phase 1 acquisition validation

```
python secureedge/data/acquire.py
```

Confirms all 34 PCAP files are present and all 8 canonical classes are covered.
No code changes here. Output should be identical to the progress report.

### Step 4 — Run Phase 2 preprocessing (now with NFStream + temporal)

```
python secureedge/data/preprocess.py
```

This now uses NFStream for flow extraction and calls the temporal extractor during
streaming (Fix 1 and Fix 2 combined). Produces:

```
data/processed/train_standard.csv   ← 92 features + label + subtype_label
data/processed/test_standard.csv    ← 92 features + label + subtype_label
artifacts/standard_scaler.joblib
```

Run the Fix 2 verification diagnostic after this step completes. Do not proceed to
Step 5 if the `Rolling_SYN_Sum` check fails.

Expected output distribution: unchanged from the progress report (20,000 per class
train, up to 4,000 per class test).

### Step 5 — Run Phase 3 feature pipeline

```
python secureedge/features/pipeline.py
```

This now only scales the already-extracted 92-feature records (temporal features are
already present from Step 4). Produces:

```
data/processed/train_features.csv   ← 92 scaled features
data/processed/test_features.csv    ← 92 scaled features
artifacts/feature_scaler.joblib
artifacts/feature_columns.json      ← must contain exactly 92 column names
```

Verify that `feature_columns.json` contains exactly 92 entries and that all 16
temporal feature names are present.

### Step 6 — Run Phase 5 training

```
python secureedge/models/train.py
```

Training hyperparameters are unchanged:
- Adam, lr warmup 1e-4 → 1e-3, weight decay 1e-5
- ReduceLROnPlateau, scheduler patience 5, min lr 1e-6
- Batch size 1024, max 200 epochs, early stopping patience 20
- Gradient clipping max norm 1.0

Training should show faster convergence than the previous run. DDoS, Mirai, Recon,
and DoS should reach high validation F1 within the first 10–15 epochs. Benign and
Spoofing should separate cleanly once temporal features are working correctly.

Produces:

```
artifacts/best_model.pt
context/05_training.md
```

### Step 7 — Run Phase 6 evaluation

```
python secureedge/models/evaluate.py
```

Produces:

```
artifacts/metrics.json
context/06_evaluation.md
```

Check macro F1 against the 0.97 target. If below target, consult the diagnosis
section at the end of this document before proceeding.

### Step 8 — Run Phase 7 OOD calibration

```
python secureedge/ood/detector.py
```

Recalibrates the MSP threshold on the new model's confidence scores. The threshold
will be different from the previous 0.405 because the new model will have higher
confidence on correctly classified samples.

Produces:

```
artifacts/ood_threshold.json
```

### Step 9 — Run Phase 8 TorchScript export

```
python secureedge/export/export.py
```

The export script must now pass a dummy input of shape `(1, 92)` instead of
`(1, 96)`. Verify this is updated if the tensor shape is hardcoded in `export.py`.
The logit-matching verification (within 1e-5) is unchanged.

Produces:

```
artifacts/secureedge_model.ts
```

---

## Fix 6 — Minor: Balanced Test Set Deviation from Methodology (Low Priority)

The progress report notes the test set is balanced to up to 4,000 per class. The
methodology says the test set should reflect the natural class distribution after
splitting. XG-NID also caps the test set at 4,000 per class (Table 4 of the paper),
so the current approach is consistent with the reference paper even if it differs
from the methodology wording.

This is a documentation inconsistency, not a training issue. Update the methodology
document to match XG-NID's Table 4 behaviour: up to 4,000 test samples per class,
using all available samples for classes with fewer than 4,000.

No code change required. Update `secureedge_methodology.md` Step 4 wording to
explicitly say this matches XG-NID's Table 4.

---

## Diagnosis Guide — If Macro F1 Is Still Below 0.97 After All Fixes

If training completes after all fixes and macro F1 remains below 0.97, work through
these checks in order before changing hyperparameters or architecture.

### Check 1 — Temporal features are actually in the data

```
import pandas as pd
df = pd.read_csv("data/processed/train_features.csv")
temporal_cols = [c for c in df.columns if c.startswith("Rolling_") or c == "Unique_Ports_In_SourceDestination"]
print(f"Temporal columns found: {len(temporal_cols)}")   # must be 16
print(df.groupby("label")["Rolling_SYN_Sum"].mean())
```

DDoS mean `Rolling_SYN_Sum` must be substantially higher than Benign mean.
If they are similar, temporal features are still computed after sampling.

### Check 2 — Feature count is exactly 92

```
import json
with open("artifacts/feature_columns.json") as f:
    cols = json.load(f)
print(f"Feature count: {len(cols)}")   # must be 92
```

If not 92, `N_FLOW_FEATURES` in `config.py` has not been updated or NFStream
is returning a different number of statistics than expected.

### Check 3 — Weak class diagnosis by confusion

Load the confusion matrix from `artifacts/metrics.json` or compute it fresh.

- If Benign is being confused with a specific attack class (not randomly):
  NFStream features for Benign are likely still not matching the attack class
  they are confused with. Inspect raw NFStream values for both classes.
- If WebBased and BruteForce are below 0.80 but above 0.65: this is expected
  without packet payload features. Acceptable for Phase 1.
- If WebBased and BruteForce are below 0.60: the temporal features for
  repeated-connection patterns (BruteForce) and unusual HTTP traffic
  (WebBased) are not working. Recheck temporal feature computation order.
- If Spoofing is below 0.75: DNS spoofing has a distinctive `Rolling_DNS_Sum`
  pattern. If Spoofing is not being detected, temporal features for the
  Spoofing PCAP are not reflecting DNS request density. Inspect NFStream
  output for the `DNS_Spoofing1.pcap` file specifically.

### Check 4 — NFStream version compatibility

Some NFStream versions use different field names or produce different feature counts.
If the feature count from NFStream does not match 76, check the installed version:

```
pip show nfstream
```

If the version is older than 6.3, upgrade:

```
pip install --upgrade nfstream
```

If a newer version produces more than 76 features, that is fine — update
`N_FLOW_FEATURES` to the actual count and retrain. More features is not worse.

---

## Summary of Files That Change

| File | Change |
|---|---|
| `requirements.txt` | Add `nfstream>=6.3.3` |
| `config.py` | `N_FLOW_FEATURES`: 80→76, `INPUT_DIM`: 96→92, `FLOW_FEATURE_COLS`: CICFlowMeter names→NFStream names |
| `secureedge/data/pcap_flows.py` | Replace custom parser with NFStream, add `nfstream_to_temporal_dict()` mapping |
| `secureedge/data/preprocess.py` | Call temporal extractor during NFStream stream, before reservoir add |
| `secureedge/features/pipeline.py` | Remove temporal computation entirely, only scale pre-computed 92-feature records |
| `secureedge/features/temporal.py` | No structural change — ensure it accepts the mapped field names |
| `secureedge/models/architecture.py` | Default `input_dim`: 96→`INPUT_DIM` (imported from config) |
| `secureedge/export/export.py` | Dummy tensor shape: `(1, 96)`→`(1, INPUT_DIM)` |

| File | Delete and regenerate |
|---|---|
| `data/processed/train_standard.csv` | |
| `data/processed/test_standard.csv` | |
| `data/processed/train_features.csv` | |
| `data/processed/test_features.csv` | |
| `artifacts/standard_scaler.joblib` | |
| `artifacts/feature_scaler.joblib` | |
| `artifacts/feature_columns.json` | |
| `artifacts/best_model.pt` | |
| `artifacts/metrics.json` | |
| `artifacts/ood_threshold.json` | |
| `artifacts/secureedge_model.ts` | |
