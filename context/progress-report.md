# SecureEdge Progress Report

Generated: `2026-06-13`

## Overview

This report summarizes the completed SecureEdge implementation work so far. The project began from the SecureEdge methodology and was initially scaffolded around CIC-IoT2023 processing, feature engineering, model training, OOD calibration, and TorchScript export.

The project later shifted from the original CSV-based workflow to the raw PCAP workflow after the PCAP files were added under `PCAPs/`. The current code therefore ignores the old CSV export and builds the dataset directly from PCAP files.

Completed components currently include:

- Dataset acquisition and validation
- PCAP preprocessing and flow extraction
- Feature engineering with 80 standard flow features and 16 temporal features
- MLP architecture
- Training
- Evaluation
- MSP-based OOD threshold calibration
- TorchScript export
- Smoke checks
- Per-phase context documentation under `context/`

## Project Structure Implemented

The following main modules were created or implemented:

```text
secureedge/
├── config.py
├── utils.py
├── data/
│   ├── acquire.py
│   ├── dataset.py
│   ├── pcap_flows.py
│   └── preprocess.py
├── features/
│   ├── temporal.py
│   └── pipeline.py
├── models/
│   ├── architecture.py
│   ├── train.py
│   └── evaluate.py
├── ood/
│   └── detector.py
└── export/
    └── export.py
```

Supporting files were also added:

- `requirements.txt`
- `README.md`
- `tests/smoke_checks.py`
- `.gitignore`
- `context/*.md`

## Phase 1: Dataset Acquisition

The project now uses the PCAP dataset source at:

```text
PCAPs/
```

The old CSV export and `CSV.zip` are no longer used by the active pipeline.

The acquisition/validation logic confirmed:

- `34` PCAP files were found.
- Total PCAP size was approximately `38.30 GiB`.
- All eight Stage 1 canonical classes were represented:

```text
Benign         1
DDoS          12
DoS            4
Mirai          3
Recon          5
Spoofing       2
WebBased       6
BruteForce     1
```

Documentation written:

```text
context/01_dataset_acquisition.md
```

## Phase 2: Preprocessing

Preprocessing was implemented in:

```text
secureedge/data/preprocess.py
secureedge/data/pcap_flows.py
```

The PCAP preprocessing pipeline performs the following:

- Streams PCAP files instead of loading all traffic into memory.
- Extracts bidirectional flow records.
- Completes a flow when it reaches `20` packets or after `120.0` seconds of idle time.
- Maps PCAP filename-derived subtype labels into eight canonical Stage 1 classes.
- Preserves the original fine-grained subtype in `subtype_label`.
- Produces `80` standard PCAP-derived features.
- Cleans infinite and NaN feature values.
- Splits up to `4,000` test samples per class.
- Balances training to exactly `20,000` samples per class.
- Fits `StandardScaler` on training features only.
- Applies the saved scaler to test features.

Generated files:

```text
data/processed/train_standard.csv
data/processed/test_standard.csv
artifacts/standard_scaler.joblib
context/02_preprocessing.md
```

Final training distribution:

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

Final test distribution:

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

## Phase 3: Feature Engineering

Feature engineering was implemented in:

```text
secureedge/features/temporal.py
secureedge/features/pipeline.py
```

The Phase 3 pipeline:

- Preserves the `80` standard flow features.
- Computes the methodology's `16` temporal sliding-window features.
- Uses a temporal window size of `375`.
- Computes windows per destination IP where PCAP metadata is available.
- Sorts flows by timestamp, source file, and source order before temporal feature generation.
- Excludes metadata columns from model input.
- Fits a combined feature scaler on training data only.
- Saves a `96`-feature manifest.

Generated files:

```text
data/processed/train_features.csv
data/processed/test_features.csv
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
context/03_feature_engineering.md
```

Verified feature shape:

```text
80 standard features
16 temporal features
96 total model input features
```

During the latest Phase 3 pass, `Rolling_packets_Sum` and `Rolling_bipackets_Sum` were corrected to use the forward plus backward packet total, matching the methodology wording.

## Phase 4: Model Architecture

The MLP architecture was implemented in:

```text
secureedge/models/architecture.py
```

Architecture:

```text
Input: 96 features
Hidden layer 1: Linear -> BatchNorm -> ReLU -> Dropout(0.4), width 256
Hidden layer 2: Linear -> BatchNorm -> ReLU -> Dropout(0.4), width 128
Hidden layer 3: Linear -> BatchNorm -> ReLU -> Dropout(0.4), width 64
Output: Linear layer with 8 logits
```

The model returns raw logits. Softmax is applied outside the model for metrics and OOD scoring.

Documentation written:

```text
context/04_model_architecture.md
```

## Phase 5: Training

Training was implemented in:

```text
secureedge/models/train.py
```

Training setup:

- Loss: `CrossEntropyLoss`
- Optimizer: Adam
- Learning rate: warmup from `1e-4` to `1e-3`
- Weight decay: `1e-5`
- Batch size: `1024`
- Scheduler: `ReduceLROnPlateau`
- Scheduler patience: `5`
- Minimum learning rate: `1e-6`
- Gradient clipping: max norm `1.0`
- Max epochs: `200`
- Early stopping patience: `20`

Training completed after epoch `51`.

Best validation/test macro F1 observed during training:

```text
0.774469
```

Generated files:

```text
artifacts/best_model.pt
context/05_training.md
```

## Phase 6: Evaluation

Evaluation was implemented in:

```text
secureedge/models/evaluate.py
```

The best checkpoint was evaluated and metrics were saved to:

```text
artifacts/metrics.json
context/06_evaluation.md
```

Current macro F1:

```text
0.774469
```

Per-class results:

```text
Benign:     precision=0.5720, recall=0.6963, f1=0.6280, support=4000
DDoS:       precision=0.9987, recall=0.9822, f1=0.9904, support=4000
DoS:        precision=0.8439, recall=0.9567, f1=0.8968, support=4000
Mirai:      precision=1.0000, recall=0.9945, f1=0.9972, support=4000
Recon:      precision=0.9934, recall=0.9437, f1=0.9679, support=4000
Spoofing:   precision=0.7181, recall=0.5783, f1=0.6406, support=4000
WebBased:   precision=0.4963, recall=0.5877, f1=0.5382, support=4000
BruteForce: precision=0.6350, recall=0.4645, f1=0.5365, support=4000
```

The current model does not yet meet the methodology target:

```text
Target macro F1: >= 0.97
Target per-class F1: >= 0.90
Current macro F1: 0.774469
```

The strongest classes are DDoS, Mirai, and Recon. The weakest classes are WebBased, BruteForce, Benign, and Spoofing.

## Phase 7: OOD Detection

OOD calibration was implemented in:

```text
secureedge/ood/detector.py
```

The detector uses maximum softmax probability. It calibrates a threshold from correctly classified test samples at the 5th percentile.

Saved threshold:

```text
0.40565497
```

Generated files:

```text
artifacts/ood_threshold.json
context/07_ood_detection.md
```

## Phase 8: Export

TorchScript export was implemented in:

```text
secureedge/export/export.py
```

The best PyTorch checkpoint was exported to:

```text
artifacts/secureedge_model.ts
```

The export script verified that TorchScript logits match PyTorch logits within `1e-5` absolute tolerance.

Generated documentation:

```text
context/08_export.md
```

Important note: the methodology says edge deployment should begin only after Phase 6 confirms `>= 97%` macro F1. TorchScript export has been implemented and verified, but the model is not yet ready for real deployment under the stated success criteria.

## Verification Performed

Smoke checks were run successfully:

```text
python tests/smoke_checks.py
```

The smoke checks cover:

- Label mapping for representative labels.
- Temporal extractor output column names and shape.
- MLP forward pass output shape.

Additional manual checks confirmed:

- `feature_columns.json` contains `96` model input columns.
- All `16` temporal feature columns are present.
- `feature_scaler.joblib` exists.
- TorchScript export completed successfully.

## Problems Encountered

### 1. Dataset Format Changed From CSV to PCAP

The methodology document originally describes using the CIC-IoT2023 CSV export. The project later moved to raw PCAP files after the PCAP dataset was added.

Impact:

- The pipeline had to be adapted from CSV ingestion to packet parsing.
- Labels had to be inferred from PCAP filenames instead of a CSV `Attack_type`, `label`, or `Label` column.
- Flow extraction had to be implemented locally.
- Temporal features could use PCAP metadata such as destination IP, source port, destination port, timestamp, and protocol.

Resolution:

- Implemented `secureedge/data/pcap_flows.py`.
- Updated preprocessing to ignore old CSV data.
- Preserved subtype labels from filenames in `subtype_label`.

### 2. Missing Benign PCAP Initially Blocked Class Coverage

At one point, the PCAP directory did not include the benign PCAP file.

Impact:

- The eight-class Stage 1 task could not proceed safely.
- Preprocessing needed all canonical classes represented.

Resolution:

- After `BenignTraffic1.pcap` was added, class coverage validation passed.

### 3. PCAP Extraction Caused a System Crash Around PSHACK

The first PCAP extraction attempt ran into serious memory pressure during `DDoS-PSHACK_Flood1.pcap`.

Likely cause:

- The active flow table could grow very large for high-volume flood PCAPs.
- Parsing every flow from massive attack files was unnecessary once the class had enough samples for the reservoir.

Resolution:

- Added bounded active-flow management in `pcap_flows.py`.
- Added configurable limits:

```text
SECUREEDGE_MAX_ACTIVE_FLOWS
SECUREEDGE_PCAP_RECORD_BUFFER_SIZE
```

- Used conservative runtime settings during extraction:

```text
SECUREEDGE_MAX_ACTIVE_FLOWS=50000
SECUREEDGE_PCAP_RECORD_BUFFER_SIZE=5000
```

- Added reservoir-aware early stopping in preprocessing so the script stops reading a class once its reservoir is full.
- Added skipping for later PCAPs belonging to a class whose reservoir is already full.

### 4. Heavy DDoS Files Were Initially Parsed Longer Than Needed

The reservoir sampling logic originally limited how many rows were retained, but it still kept reading every packet from a class even after enough usable flows had already been collected.

Impact:

- Wasted time.
- Increased memory pressure.
- Made files such as `DDoS-PSHACK_Flood1.pcap` unnecessarily risky.

Resolution:

- Patched `secureedge/data/preprocess.py` to check whether the class reservoir is full.
- Added mid-file stop behavior.
- Added whole-file skip behavior for already-filled classes.

### 5. Methodology Target Was Not Met

The trained MLP reached macro F1 `0.774469`, below the target `0.97`.

Main weak classes:

- `BruteForce`
- `WebBased`
- `Benign`
- `Spoofing`

Likely contributing factors:

- The current PCAP-derived workflow differs from the methodology's CSV-based workflow.
- The test set is balanced to `4,000` samples per class in the current run, while the methodology says the test set should be kept natural after splitting. The current implementation selects up to `4,000` per class, which makes the test set class-balanced when all classes have enough samples.
- The raw PCAP flow extraction may not exactly match CIC's official CSV feature extractor.
- Some minority classes required oversampling, especially BruteForce.
- The temporal context is computed after the sampled preprocessing output, not across the full original chronological dataset.

### 6. Phase 3 Packet Rolling Feature Needed Correction

During the latest Phase 3 pass, the rolling packet total implementation was reviewed against the methodology.

Issue:

- `Rolling_packets_Sum` used the first available packet-count feature rather than explicitly summing forward and backward packet counts.

Resolution:

- Updated `secureedge/features/temporal.py`.
- `Rolling_packets_Sum` and `Rolling_bipackets_Sum` now use forward plus backward packet totals when available.
- Regenerated Phase 3 outputs.

### 7. Sandbox Noise Appeared in Command Output

Many shell commands printed environment-related warnings such as dconf/sysroot messages.

Impact:

- These warnings were noisy but did not prevent the project commands from running.

Resolution:

- Ignored the sandbox warnings when command exit status and relevant project output showed success.

## Current Artifact Inventory

Processed data:

```text
data/processed/train_standard.csv
data/processed/test_standard.csv
data/processed/train_features.csv
data/processed/test_features.csv
```

Model and scaler artifacts:

```text
artifacts/standard_scaler.joblib
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
artifacts/best_model.pt
artifacts/metrics.json
artifacts/ood_threshold.json
artifacts/secureedge_model.ts
```

Context documentation:

```text
context/01_dataset_acquisition.md
context/02_preprocessing.md
context/03_feature_engineering.md
context/04_model_architecture.md
context/05_training.md
context/06_evaluation.md
context/07_ood_detection.md
context/08_export.md
```

## Recommended Next Work

The next work should focus on improving Phase 6 performance before treating Phase 8 as deployment-ready.

Recommended order:

1. Revisit the methodology mismatch between CSV features and PCAP-derived features.
2. Decide whether to return to the official CIC CSV export for score comparison, since the methodology explicitly targets CIC's pre-extracted CSV representation.
3. If remaining on PCAPs, improve parity between `pcap_flows.py` and CIC's official flow feature extraction.
4. Recompute temporal features over a larger chronological sample, ideally before aggressive per-class sampling.
5. Preserve a natural class-distribution test set if strict methodology compliance is required.
6. Investigate weak classes with a confusion matrix, especially BruteForce, WebBased, Benign, and Spoofing.
7. Retrain after the data/feature corrections and compare macro F1 again.

