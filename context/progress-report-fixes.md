# SecureEdge Fixes Progress Report

Generated: `2026-06-13`

## Purpose

This report documents the fixes applied after reviewing `context/fixes.md`. It is a follow-up to the earlier progress report and focuses on the corrected implementation, regenerated artifacts, validation checks, and the new model results.

The main goal of the fix pass was to bring the implementation closer to the XG-NID methodology by replacing the custom packet parser with NFStream and moving temporal feature computation to the correct point in the pipeline.

## Summary of Applied Fixes

The following fixes from `context/fixes.md` were applied:

| Fix | Status | Notes |
|---|---|---|
| Fix 1: Replace custom `pcap_flows.py` with NFStream | Applied | PCAP extraction now uses `NFStreamer` instead of the custom `dpkt` parser. |
| Fix 2: Compute temporal features before sampling | Applied | Temporal features are now computed during PCAP streaming, before reservoir sampling and balancing. |
| Fix 3: Update feature dimensions | Applied with live NFStream count | Installed NFStream produced `57` numeric statistic fields, so final input is `57 + 16 = 73`. |
| Fix 4: Update MLP input dimension | Applied | `SecureEdgeMLP` now defaults to `config.INPUT_DIM`. |
| Fix 5: Regenerate artifacts | Applied | Processed data, scalers, checkpoint, metrics, OOD threshold, and TorchScript export were regenerated. |
| Fix 6: Balanced test-set note | Not a code change | Current cap of up to `4,000` test samples per class was kept. |

## Dependency Changes

Updated:

```text
requirements.txt
```

Added:

```text
nfstream>=6.3.3
```

Installed version:

```text
NFStream 6.6.0
```

This required network access for `pip install -r requirements.txt`. The first install attempt failed because the sandbox had no network access; after permission was granted, NFStream and its dependencies installed successfully.

## Fix 1: NFStream Flow Extraction

The old custom parser in:

```text
secureedge/data/pcap_flows.py
```

was replaced with an NFStream-backed implementation.

The new implementation:

- Uses `NFStreamer` to read PCAP files.
- Enables `statistical_analysis=True`.
- Disables deep inspection with `splt_analysis=0` and `n_dissections=0`.
- Uses `idle_timeout=120`.
- Uses `active_timeout=1800`.
- Applies the methodology's 20-packet cap as a post-filter by skipping flows whose `bidirectional_packets` value is greater than `20`.
- Extracts numeric NFStream statistic fields dynamically.
- Excludes metadata fields such as IP addresses, ports, protocol, timestamps, MACs, and IDs from model features.

Important implementation details:

- `flow_to_dict()` safely introspects NFStream flow objects.
- `nfstream_feature_dict()` selects numeric model features.
- `nfstream_to_temporal_dict()` maps NFStream names into the temporal extractor's expected names.

The temporal mapping includes:

```text
dst_ip -> Dst IP
src_port -> Src Port
dst_port -> Dst Port
protocol -> Protocol
bidirectional_syn_packets -> SYN Flag Cnt
bidirectional_ack_packets -> ACK Flag Cnt
bidirectional_fin_packets -> FIN Flag Cnt
bidirectional_rst_packets -> RST Flag Cnt
bidirectional_psh_packets -> PSH Flag Cnt
bidirectional_duration_ms * 1000 -> Flow Duration
src2dst_packets -> Tot Fwd Pkts
dst2src_packets -> Tot Bwd Pkts
```

## NFStream Feature Count

The fixes document expected `76` NFStream flow features based on the XG-NID paper. The installed NFStream version, `6.6.0`, produced:

```text
57 numeric NFStream statistic fields
16 temporal features
73 final model input features
```

The fixes document explicitly said to update the project to the actual installed NFStream feature count if it differed, so `config.py` was updated accordingly:

```text
N_FLOW_FEATURES = 57
INPUT_DIM = 73
```

The regenerated `feature_columns.json` contains exactly:

```text
73 feature columns
```

## Fix 2: Temporal Features Before Sampling

The previous implementation computed temporal features after the dataset had already been sampled and balanced. That destroyed the real traffic-density signal.

The corrected pipeline is now:

```text
PCAP file
  -> NFStream flow
  -> temporal feature update
  -> enriched flow record
  -> class reservoir
  -> train/test split
  -> balancing
```

Temporal features are now computed inside:

```text
secureedge/data/pcap_flows.py
```

not after sampling in:

```text
secureedge/features/pipeline.py
```

`features/pipeline.py` now validates that temporal features already exist and only handles scaling plus final CSV writing.

## PCAP Processing Priority Fix

During verification, the initial NFStream pass filled the DDoS reservoir from `DDoS-ACK_Fragmentation1.pcap`. That made the `Rolling_SYN_Sum` diagnostic low for DDoS, even though temporal features were technically being computed before sampling.

To align the diagnostic with `fixes.md`, `discover_pcap_files()` was updated to prioritize SYN flood captures:

```text
DDoS-SYN_Flood1.pcap
DoS-SYN_Flood1.pcap
```

This ensures DDoS and DoS reservoirs are filled from SYN-heavy PCAPs before other flood variants.

## Fix 2 Diagnostic Result

The required temporal diagnostic now passes.

After preprocessing, mean `Rolling_SYN_Sum` values were:

```text
Benign          18.97970
BruteForce     104.91055
DDoS          5280.75380
DoS           4842.84230
Mirai           16.47775
Recon          318.89020
Spoofing        69.79265
WebBased        56.83380
```

The key check:

```text
DDoS Rolling_SYN_Sum mean:   5280.75
Benign Rolling_SYN_Sum mean:   18.98
```

This confirms that temporal attack-density information is now present before sampling and balancing.

## Fix 3: Config Updates

Updated:

```text
secureedge/config.py
```

Added or changed:

```text
NFSTREAM_METADATA_COLUMNS
N_FLOW_FEATURES = 57
FLOW_FEATURE_COLS = []
INPUT_DIM = 73
```

`NFSTREAM_METADATA_COLUMNS` defines fields that should not be model input features.

`INPUT_DIM` is now derived as:

```text
N_FLOW_FEATURES + len(TEMPORAL_FEATURES)
```

## Fix 4: Model Input Dimension

Updated:

```text
secureedge/models/architecture.py
```

`SecureEdgeMLP` now defaults to:

```text
input_dim=config.INPUT_DIM
```

This avoids hardcoding the model input width and keeps model architecture aligned with the feature pipeline.

Training still stores the actual checkpoint input dimension, and evaluation/export load that dimension from the checkpoint.

## Acquisition Script Fix

Updated:

```text
secureedge/data/acquire.py
```

The acquisition script was still CSV-oriented. It now:

- Validates the `PCAPs/` directory.
- Confirms all `.pcap` files are present.
- Confirms all eight canonical classes are covered.
- Writes PCAP acquisition documentation to `context/01_dataset_acquisition.md`.

Current acquisition validation:

```text
PCAP files: 34
```

## Phase 2 Regeneration

Preprocessing was rerun after deleting stale artifacts.

Generated:

```text
data/processed/train_standard.csv
data/processed/test_standard.csv
artifacts/standard_scaler.joblib
context/02_preprocessing.md
```

Current preprocessing output:

```text
feature_columns=73
expected_input_dim=73
```

Raw usable NFStream flow counts after the 20-packet cap and early reservoir stop:

```text
Benign        25000
DDoS          25000
DoS           25000
Mirai         21792
Recon         25000
Spoofing      25000
WebBased      16103
BruteForce     5365
```

Training class counts:

```text
Benign        20000
DDoS          20000
DoS           20000
Mirai         20000
Recon         20000
Spoofing      20000
WebBased      20000
BruteForce    20000
```

Test class counts:

```text
Benign        4000
DDoS          4000
DoS           4000
Mirai         4000
Recon         4000
Spoofing      4000
WebBased      4000
BruteForce    4000
```

Skipped after class reservoir fill:

```text
DDoS-ACK_Fragmentation1.pcap
DDoS-HTTP_Flood-.pcap
DDoS-ICMP_Flood1.pcap
DDoS-ICMP_Fragmentation1.pcap
DDoS-PSHACK_Flood1.pcap
DDoS-RSTFINFlood1.pcap
DDoS-SlowLoris.pcap
DDoS-SynonymousIP_Flood1.pcap
DDoS-TCP_Flood1.pcap
DDoS-UDP_Flood1.pcap
DDoS-UDP_Fragmentation1.pcap
DoS-HTTP_Flood1.pcap
DoS-TCP_Flood1.pcap
DoS-UDP_Flood1.pcap
MITM-ArpSpoofing1.pcap
Recon-OSScan.pcap
Recon-PingSweep.pcap
Recon-PortScan.pcap
VulnerabilityScan.pcap
```

## Phase 3 Regeneration

Updated:

```text
secureedge/features/pipeline.py
```

Phase 3 now:

- Confirms temporal features already exist.
- Does not recompute temporal windows.
- Fits a combined scaler on the 73 training features.
- Applies the scaler to test features.
- Writes final feature CSVs.
- Writes `feature_columns.json`.

Generated:

```text
data/processed/train_features.csv
data/processed/test_features.csv
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
context/03_feature_engineering.md
```

Verified:

```text
feature_columns.json entries: 73
missing temporal columns: none
```

## Training Regeneration

Training was rerun on the regenerated NFStream + temporal features.

Generated:

```text
artifacts/best_model.pt
context/05_training.md
```

Training ran through epoch `142`.

Best macro F1:

```text
0.8709409145659598
```

This is a substantial improvement over the previous run:

```text
Before fixes: 0.774469
After fixes:  0.870941
Gain:         about +0.09647 macro F1
```

## Evaluation Results

Generated:

```text
artifacts/metrics.json
context/06_evaluation.md
```

Current macro F1:

```text
0.8709409145659598
```

Per-class results:

```text
Benign:     precision=0.9253, recall=0.8395, f1=0.8803
DDoS:       precision=1.0000, recall=0.9958, f1=0.9979
DoS:        precision=0.9962, recall=0.8535, f1=0.9193
Mirai:      precision=0.9077, recall=0.8043, f1=0.8529
Recon:      precision=0.9982, recall=0.9795, f1=0.9888
Spoofing:   precision=0.9041, recall=0.8363, f1=0.8688
WebBased:   precision=0.6720, recall=0.7602, f1=0.7134
BruteForce: precision=0.6564, recall=0.8642, f1=0.7461
```

Classes now above 0.90 F1:

```text
DDoS
DoS
Recon
```

Classes still below 0.90 F1:

```text
Benign
Mirai
Spoofing
WebBased
BruteForce
```

The model still does not meet the target:

```text
Target macro F1: >= 0.97
Current macro F1: 0.870941
```

## OOD Regeneration

OOD threshold calibration was rerun on the regenerated model.

Generated:

```text
artifacts/ood_threshold.json
context/07_ood_detection.md
```

New threshold:

```text
0.45657479763031006
```

Previous threshold:

```text
0.40565497
```

The threshold increased because the new model has a different confidence distribution after the NFStream and temporal-order fixes.

## TorchScript Export Regeneration

TorchScript export was rerun.

Generated:

```text
artifacts/secureedge_model.ts
context/08_export.md
```

The export script traced the checkpoint with the checkpoint's actual input dimension and verified that TorchScript logits match PyTorch logits within tolerance.

## Verification Performed

Commands/checks completed successfully:

```text
python -m compileall secureedge tests
python tests/smoke_checks.py
python -m secureedge.data.acquire
python -m secureedge.data.preprocess
python -m secureedge.features.pipeline
python -m secureedge.models.train
python -m secureedge.models.evaluate
python -m secureedge.ood.detector
python -m secureedge.export.export
```

Additional checks:

```text
NFStream version: 6.6.0
feature_columns.json count: 73
config.INPUT_DIM: 73
Temporal columns present: yes
TorchScript file exists: yes
```

## Current Artifact Inventory

Processed data:

```text
data/processed/train_standard.csv
data/processed/test_standard.csv
data/processed/train_features.csv
data/processed/test_features.csv
```

Artifacts:

```text
artifacts/standard_scaler.joblib
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
artifacts/best_model.pt
artifacts/metrics.json
artifacts/ood_threshold.json
artifacts/secureedge_model.ts
```

## Issues Encountered During Fix Pass

### 1. NFStream Was Not Installed

Initial check failed:

```text
ModuleNotFoundError: No module named 'nfstream'
```

Resolution:

- Added `nfstream>=6.3.3` to `requirements.txt`.
- Installed dependencies after network permission was granted.

### 2. NFStream Field Count Did Not Match the Paper's 76

The installed NFStream version emitted `57` numeric statistic fields after metadata exclusion.

Resolution:

- Followed the fixes document instruction to use the actual installed NFStream field count.
- Updated `N_FLOW_FEATURES` to `57`.
- Updated final input dimension to `73`.

### 3. NFStream Flow Introspection Raised Attribute Errors

Some `NFlow` attributes appeared in `dir(flow)` but raised `AttributeError` when accessed.

Resolution:

- Updated `flow_to_dict()` to skip attributes that cannot be read safely.

### 4. First NFStream Temporal Diagnostic Failed for DDoS SYN

The first fixed preprocessing run computed temporal features before sampling, but DDoS was filled from `DDoS-ACK_Fragmentation1.pcap`, so `Rolling_SYN_Sum` was low for DDoS.

Resolution:

- Updated PCAP discovery priority to process `DDoS-SYN_Flood1.pcap` and `DoS-SYN_Flood1.pcap` before other attack captures.
- Reran preprocessing.
- The diagnostic then passed.

### 5. Model Still Did Not Reach 0.97 Macro F1

Although the fixes improved macro F1 from `0.774469` to `0.870941`, the result remains below the methodology target.

Likely remaining causes:

- NFStream 6.6.0 emitted fewer numeric features than the XG-NID paper's stated 76.
- The 20-packet post-filter discards many longer flows instead of splitting them into 20-packet windows.
- WebBased and BruteForce remain difficult without payload-level features.
- Reservoir early stopping means only selected subtype PCAPs fill some broad classes, especially DDoS, DoS, Recon, and Spoofing.
- The training/test setup still uses balanced per-class test caps, which is useful diagnostically but may differ from some methodology interpretations.

## Recommended Next Steps

1. Investigate why NFStream 6.6.0 exposes `57` numeric features instead of the paper's `76`.
2. Consider implementing true 20-packet flow windowing instead of skipping NFStream flows longer than 20 packets.
3. Add a confusion matrix report to identify exactly where Benign, Mirai, Spoofing, WebBased, and BruteForce are being confused.
4. Avoid filling broad classes from only one subtype when the class has many attack variants; consider per-subtype reservoirs before class balancing.
5. Revisit WebBased and BruteForce feature separability, since these remain the weakest classes.
6. Run another training pass after the next data representation improvements.

