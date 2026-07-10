# SecureEdge System Design, Progress, and Setbacks

This document summarizes the project design, implementation progress, and the major
setbacks encountered during development. It is written as a high-level project
history and decision record.

## 1. Project Goal

SecureEdge aims to implement an XG-NID-style intrusion detection pipeline for
CIC-IoT2023 traffic.

The final target system:

- reads raw PCAP files
- extracts NFStream flow statistics
- captures raw packet payload bytes
- computes rolling temporal features
- builds heterogeneous graphs
- trains a PyTorch Geometric HGNN
- evaluates 8-class intrusion detection performance
- supports eventual edge deployment through TorchScript export

The eight canonical classes are:

1. `Benign`
2. `DDoS`
3. `DoS`
4. `Mirai`
5. `Recon`
6. `Spoofing`
7. `WebBased`
8. `BruteForce`

## 2. Final System Architecture

## Data Flow

```text
PCAPs
  -> NFStream flow extraction
  -> packet payload capture
  -> temporal rolling-window features
  -> compact graph records
  -> train/val/test split
  -> PyTorch Geometric heterographs
  -> graph shards
  -> HGNN training
  -> evaluation / OOD calibration / export
```

## Graph Design

Each completed flow becomes one heterograph:

- one `flow` node
- up to twenty `packet` nodes
- flow-to-packet contain edges
- packet-to-flow reverse edges
- packet-to-packet temporal link edges

The flow node contains 92 features:

- 76 flow/statistical features
- 16 temporal features

Each packet node contains 1500 payload-byte features.

## Model Design

The final model is `SecureEdgeHGNN`.

Core design:

- two heterogeneous GAT layers
- two attention heads
- attention size 32 per head
- concatenated hidden output of 64 dimensions
- BatchNorm with high epsilon for stability
- global mean pooling
- classifier head over graph embedding

Current training approach:

- `CrossEntropyLoss`
- Adam optimizer
- cosine learning-rate scheduling
- validation macro F1 checkpoint selection
- early stopping
- shard-based loading
- raw graph mode with log1p-derived flow transforms
- AMP disabled in raw mode

## 3. Current Progress

## Implemented Components

- PCAP discovery and subtype-to-class mapping.
- NFStream extraction from PCAPs.
- Packet payload capture through verified NFStream packet attributes.
- Active/idle feature plugin.
- 16-feature temporal rolling-window extractor.
- Compact graph record format.
- Heterogeneous graph materialization.
- Train/validation/test split.
- Proportional split correction for scarce classes.
- WebBased capped-floor subtype balancing.
- BruteForce scarce-class correction through proportional split.
- Attacker-MAC filtering.
- MAC filtering audits.
- Leakage audit across compact records and graph hashes.
- Graph sharding for memory-safe training.
- Graph visualization.
- HGNN model with multi-head GAT.
- Training loop with per-class TP/FP/FN/TN and FP/FN rates.
- Resume-compatible checkpointing with architecture signature checks.
- Evaluation script.
- OOD threshold script.
- TorchScript export script.
- Context documentation after each major phase.

## Current Data State

Latest regenerated graph split:

| Split | Graph Count | Shards |
|---|---:|---:|
| train | 160000 | 160 |
| val | 11843 | 12 |
| test | 11841 | 12 |

Latest proportional class split:

| Class | Train Sampled | Train Unique | Val | Test |
|---|---:|---:|---:|---:|
| Benign | 20000 | 20000 | 2000 | 2000 |
| DDoS | 20000 | 20000 | 2000 | 2000 |
| DoS | 20000 | 20000 | 2000 | 2000 |
| Mirai | 20000 | 20000 | 2000 | 2000 |
| Recon | 20000 | 19286 | 1929 | 1928 |
| Spoofing | 20000 | 13459 | 1346 | 1346 |
| WebBased | 20000 | 3856 | 386 | 385 |
| BruteForce | 20000 | 1820 | 182 | 182 |

Latest major training result:

- Run: `21`
- Best epoch: `143`
- Best validation macro F1: `0.952067`
- Stopped by early stopping after `218` epochs.

## 4. Major Setbacks and How We Handled Them

## Setback 1: Initial CSV Dataset Did Not Match the Methodology

Early work used `CSV.zip`, but that export had only numeric columns and lacked the
complete label/IP/port/timestamp structure needed by the final methodology.

Problem:

- It was not enough to reproduce XG-NID.
- Label handling had to fall back to folder names.
- Temporal features were only best-effort.
- Packet payload nodes were impossible from the CSV export.

Response:

- Implemented an initial CSV-capable pipeline to make progress.
- Later discarded CSV as the active path.
- Moved to raw PCAP processing after the final methodology required XG-NID parity.

Lesson:

The data format controls the model ceiling. A graph model that needs packet payloads
cannot be properly trained from a simplified flow CSV.

## Setback 2: Missing Benign PCAP

At one point, benign traffic was missing from the PCAP directory.

Problem:

- The final 8-class task cannot run without all canonical classes.
- Coverage validation would fail.

Response:

- Waited until `Benign` PCAP was added.
- Implemented class coverage validation so missing classes/subtypes are detected
  early.

## Setback 3: PCAP Extraction Crashed the System

The workstation crashed during heavy PCAP extraction, especially around large PCAPs
and PSHACK extraction.

Problem:

- Full PCAP extraction can consume all RAM and swap.
- Automatic splitting of multi-GiB PCAP files can itself destabilize the machine.
- NFStream and Python object creation are memory-heavy.

Response:

- Added memory guardrails:
  - process RSS checks
  - available-memory checks
  - bounded extraction workers
  - `MALLOC_ARENA_MAX=2`
  - one-thread numeric library settings
- Added PCAP chunking workflow.
- Disabled automatic splitting by default.
- Added safe small-run validation before full runs.
- Introduced compact reservoir reuse to avoid repeating extraction.

Lesson:

For this workstation, memory safety is not optional plumbing; it is part of the
methodology.

## Setback 4: Packet Payload Capture Was Uncertain

NFStream did not initially make it obvious which packet attribute contained raw
packet bytes.

Problem:

- XG-NID requires packet nodes with payload bytes.
- If packet payloads are empty, the graph model loses one of its two modalities.

Response:

- Built `verify_packet_capture.py`.
- Probed packet attributes under NFStream.
- Confirmed `packet.ip_packet` could be used.
- Implemented IP/TCP/UDP header stripping to derive application payload bytes.
- Added payload diagnostics for graph and shard outputs.

Lesson:

Do not trust that a packet feature exists just because the paper says the model
uses packets. Verify the exact library behavior in the local environment.

## Setback 5: Missing 92 Flow Node Features

The final method requires 92 flow node features.

Problem:

- The project initially did not fully align with 76 flow features plus 16 temporal
  features.
- Feature-order drift could make checkpoints meaningless.

Response:

- Implemented complete flow feature ordering.
- Added active/idle derived features.
- Added feature-order artifacts.
- Rebuilt graph records with 92 flow node features.
- Validated dimensions through smoke checks and feature pipeline checks.

Lesson:

Feature count alone is not enough. Feature order and meaning must also remain stable.

## Setback 6: CUDA Confusion and GPU Starvation

The system showed an RTX 4060 in `nvidia-smi`, but training initially appeared to
underuse the GPU.

Problem:

- `nvidia-smi` proves driver visibility, not PyTorch CUDA compatibility.
- Graph workloads often bottleneck on CPU-side data loading and small graph batching.
- Low GPU utilization does not always mean CPU-only training.

Response:

- Verified CUDA through PyTorch directly.
- Documented GPU starvation in `context/training-gpu-starvation.md`.
- Added graph sharding to reduce file-loading overhead.
- Tuned batch size and gradient accumulation.
- Kept DataLoader workers conservative for memory safety.

Lesson:

GPU utilization must be interpreted with the data pipeline in mind. For graph neural
networks, CPU loading can be the narrow part of the pipe.

## Setback 7: VRAM Pressure

Training consumed too much VRAM in some configurations.

Problem:

- Larger batches and raw packet nodes are expensive.
- PyG heterographs carry edge indices, node features, and metadata.

Response:

- Reduced physical batch size.
- Used gradient accumulation to preserve effective batch size.
- Added VRAM safety notes and training commands.
- Kept current recommendation at batch size 256 with accumulation 2.

Lesson:

Effective batch size and physical batch size are different tools. Use accumulation
when VRAM is the limiting factor.

## Setback 8: Non-Finite Logits / NaN Failure

A training run crashed with non-finite logits in epoch 1, batch 1.

Problem:

- Raw derived rate features can become very large.
- Mixed precision can overflow with raw graph values.

Response:

- Added `log1p` transform for derived flow features in raw mode.
- Disabled AMP in raw graph mode.
- Added finite-logit checks to fail early.

Lesson:

Raw features can preserve signal, but they need numerical guardrails.

## Setback 9: Architecture Mismatch with Intended Multi-Head GAT

`HGNN_ATTN_SIZE=32` existed in config but was not originally wired into `GATConv`.

Problem:

- PyG default was effectively single-head attention.
- XG-NID-style configuration expected two heads of size 32.

Response:

- Updated GAT layers to:
  - `out_channels=config.HGNN_ATTN_SIZE`
  - `heads=2`
  - `concat=True`
- Preserved hidden dimension at `2 * 32 = 64`.
- Added architecture signature checks so incompatible checkpoints cannot be resumed
  silently.

Lesson:

Dead config values are dangerous. Configuration must be traced into actual layer
constructors.

## Setback 10: Class Imbalance

CIC-IoT2023 WebBased and BruteForce data were severely underrepresented in the
available PCAPs.

Problem:

Initial split strategy reserved too much scarce data for evaluation:

- WebBased had only 627 real training records out of 4627.
- BruteForce had only 184 real training records out of 2184.

This forced extreme train duplication and poor learning.

Response:

- Added WebBased capped-floor subtype balancing.
- Added class-conditional MAC filtering.
- Audited class distributions.
- Implemented proportional split rule:
  - abundant classes keep fixed 2000/2000 val/test
  - scarce classes use the 20000:2000:2000 ratio proportionally
- Rebuilt splits, graphs, shards, and leakage audit.

Result:

- WebBased train unique increased from 627 to 3856.
- BruteForce train unique increased from 184 to 1820.
- Validation/test became smaller for scarce classes but remained real and clean.

Lesson:

For scarce classes, training diversity is more valuable than oversized evaluation
sets. A model cannot learn what it never sees.

## Setback 11: Leakage Risk from Oversampling

Oversampling can accidentally duplicate examples across train and evaluation if
done before splitting.

Problem:

- Leakage would inflate metrics and invalidate results.

Response:

- Changed methodology to split first, oversample train only.
- Added content-hash grouping.
- Added compact and graph leakage audits.
- Latest leakage audit passed with:
  - zero compact row overlap
  - zero graph hash overlap
  - zero near-duplicate graph fingerprints
  - no identity features in model feature list

Lesson:

Oversampling is acceptable only after evaluation data is sealed away.

## Setback 12: MAC Filtering Strategy

Attacker MAC filtering was needed, but it had to be applied carefully.

Problem:

- If applied blindly, it could remove benign traffic or remove useful attack flows.
- If not applied, background traffic could pollute attack classes.

Response:

- Added attacker MAC list support.
- Applied MAC filtering to attack classes, not blindly to all classes.
- Added audit reports and class-conditional filtering.
- Preserved missing-MAC handling with explicit reason labels.

Lesson:

Filtering is a data-policy decision, not just a code filter.

## Setback 13: External Cyber Attack Evaluation CSV Had No Labels

The file `L1_Cap_10PC_1S_dissec_complete.csv` was inspected.

Problem:

- It contained 3,962,784 rows but only 8 columns.
- There was no explicit label/class/attack column.
- `Protocol` was categorical but represented network protocol, not attack class.

Response:

- Generated `context/60_cyber_attack_eval_features_labels.md`.
- Documented all features and protocol values.
- Did not treat protocol as a ground-truth attack label.

Lesson:

Large data is not automatically useful supervised data. Labels must be explicit or
derived from reliable external ground truth.

## 5. Current Design Decisions

## Active Data Strategy

- Use raw CIC-IoT2023 PCAPs, not the old CSV export.
- Use PCAP filenames/chunk directories as subtype labels.
- Map subtypes into 8 canonical classes.
- Keep compact graph records as the reusable preprocessing layer.
- Split before oversampling.
- Oversample train only.
- Use proportional val/test split for scarce classes.
- Use validation split for model selection.
- Use test split only for final evaluation.

## Active Feature Strategy

- Flow node: 92 features.
- Packet nodes: 1500 payload bytes.
- Raw graph value mode.
- `log1p` transform on derived rate/ratio features.
- No identity columns as model features.
- MAC addresses used only for filtering/auditing, not model input.

## Active Training Strategy

- HGNN with two heterogeneous GAT layers.
- Two attention heads.
- BatchNorm epsilon 1.0.
- Cosine scheduler.
- Validation macro F1 model selection.
- Early stopping.
- Physical batch size 256, gradient accumulation 2.
- AMP disabled in raw mode.
- Graph shards enabled.

## 6. Remaining Risks

## BruteForce Scarcity

BruteForce still has only 1820 unique train records and 182 validation/test records.
The proportional split improved the situation greatly, but the class remains the
smallest and hardest class.

## WebBased Evaluation Noise

WebBased validation/test now have 386/385 records. This is enough to track behavior
but noisier than 2000 examples. The trade-off was accepted to increase training
diversity.

## GPU Pipeline Bottleneck

Even with CUDA, graph loading and PyG batching can bottleneck on CPU. Increasing
workers may help but can increase RAM pressure.

## Methodology vs Hardware

The target paper result is high, but this workstation has 8 GB VRAM and limited
system memory. Some XG-NID settings must be adapted to fit safely.

## External Validation Dataset

The Cyber Attack Evaluation CSV currently has no explicit labels, so it cannot be
used as a supervised evaluation target without a separate labeling source.

## 7. Recommended Next Steps

1. Train from the latest proportional split data.
2. Monitor per-class F1, especially WebBased and BruteForce.
3. Evaluate the best checkpoint on test only after validation behavior is stable.
4. Run leakage audit after any split or graph rebuild.
5. Keep documenting every data-policy change in `context/`.
6. Avoid full PCAP re-extraction unless absolutely necessary.
7. If BruteForce still fails, prefer model/loss/data-policy analysis over blindly
   duplicating more samples.

## 8. Key Reference Files

- `context/59_proportional_split_ratio_fix.md`
- `context/58_proportional_split_class_distribution_report.md`
- `context/logs-21.md`
- `context/60_cyber_attack_eval_features_labels.md`
- `context/training-gpu-starvation.md`
- `context/54_run_16b_nan_diagnosis_fix.md`
- `context/55_raw_mode_amp_overflow_fix.md`
- `context/49_class_conditional_filtering_implementation.md`
- `secureedge/config.py`
- `secureedge/data/preprocess.py`
- `secureedge/data/graph_builder.py`
- `secureedge/models/hgnn.py`
- `secureedge/models/train.py`

