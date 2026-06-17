# SecureEdge Training Cycle Logs 1

> Generated: 2026-06-15  
> Scope: First full CUDA HGNN training cycle after the 92-feature graph dataset
> regeneration.

## Important Note About Log Completeness

The trainer printed per-epoch lines to the terminal, but those terminal lines were
not redirected to a persistent log file during this run. Therefore, this report
records all training-cycle data that was persisted in project artifacts and all
runtime observations captured during inspection.

Available persisted sources:

- `context/05_training.md`
- `artifacts/best_hgnn.pt`
- `artifacts/graph_dataset_manifest.json`
- `secureedge/config.py`
- `secureedge/models/train.py`
- `secureedge/models/hgnn.py`

Unavailable source:

- complete per-epoch terminal log from epochs 1 through 121

## Training Command and Runtime Settings

The active full training process was observed as:

```text
.venv/bin/python -m secureedge.models.train
```

The process environment was observed as:

```text
SECUREEDGE_DEVICE=cuda
SECUREEDGE_BATCH_SIZE=256
SECUREEDGE_NUM_WORKERS=2
SECUREEDGE_PREFETCH_FACTOR=2
SECUREEDGE_MAX_EPOCHS=200
```

The trainer used:

```text
Device: cuda
GPU: NVIDIA GeForce RTX 4060
Batch size: 256 graph objects
Training split: full split
Evaluation split: full split
Max epochs: 200
Early stopping patience: 20
LR scheduler patience: 5
Warmup epochs: 5
Warmup LR: 0.001 -> 0.01
Weight decay: 1e-05
Gradient clipping max norm: 1.0
```

## Dataset Used

The graph dataset manifest reports:

```text
Training graphs: 160,000
Test graphs: 32,000
Total graphs: 192,000
```

Training class counts:

| Class | Train Count |
|---|---:|
| Benign | 20,000 |
| DDoS | 20,000 |
| DoS | 20,000 |
| Mirai | 20,000 |
| Recon | 20,000 |
| Spoofing | 20,000 |
| WebBased | 20,000 |
| BruteForce | 20,000 |

Test class counts:

| Class | Test Count |
|---|---:|
| Benign | 4,000 |
| DDoS | 4,000 |
| DoS | 4,000 |
| Mirai | 4,000 |
| Recon | 4,000 |
| Spoofing | 4,000 |
| WebBased | 4,000 |
| BruteForce | 4,000 |

Feature dimensions:

| Component | Dimension |
|---|---:|
| Flow node | 92 |
| Packet node | 1500 |
| Contain edge | 4 |
| Link edge | 1 |

## Model Architecture

Model:

```text
SecureEdgeHGNN
```

Main architecture:

- two `HeteroConv` layers using `GATConv`
- edge types:
  - `flow -> contains -> packet`
  - `packet -> rev_contains -> flow`
  - `packet -> linked_to -> packet`
- hidden size: 64
- batch normalization for flow embeddings
- batch normalization for packet embeddings
- LeakyReLU activation
- graph embedding from average of flow-node and packet-node global mean pooling
- classifier:
  - `Linear(64, 32)`
  - `ReLU`
  - `Linear(32, 16)`
  - `ReLU`
  - `Linear(16, 8)`

Output classes:

```text
0 Benign
1 DDoS
2 DoS
3 Mirai
4 Recon
5 Spoofing
6 WebBased
7 BruteForce
```

## Training Result

The final training context reports:

```text
Last epoch: 121
Last epoch train loss: 0.1870860183596611
Last epoch macro F1: 0.8714327478929863
Last epoch learning rate: 4.882812500000001e-06
```

The best checkpoint reports:

```text
Best checkpoint path: artifacts/best_hgnn.pt
Best checkpoint modified: 2026-06-15T07:49:54.891301
Best epoch: 101
Best macro F1: 0.8731743172488037
Device: cuda
Training limit per class: 0, meaning full split
Evaluation limit per class: 0, meaning full split
```

Checkpoint feature dimensions:

```json
{
  "flow_node": 92,
  "packet_node": 1500,
  "contain_edge": 4,
  "link_edge": 1
}
```

## Full Evaluation Result

After this report was initially created, full CUDA evaluation was run on the
epoch-101 checkpoint.

Evaluation command:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_NUM_WORKERS=2 \
SECUREEDGE_PREFETCH_FACTOR=2 \
.venv/bin/python -m secureedge.models.evaluate
```

Full evaluation artifacts:

```text
artifacts/metrics.json
artifacts/evaluation_confusion_matrix.json
```

Overall full-test result:

```text
Accuracy: 0.8726875
Correct predictions: 27,926
Incorrect predictions: 4,074
Total test graphs: 32,000
Macro F1: 0.8731743172488037
Target macro F1: 0.97
```

Per-class precision, recall, and F1:

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| Benign | 0.846098 | 0.881000 | 0.863197 | 4,000 |
| DDoS | 0.941944 | 0.920750 | 0.931226 | 4,000 |
| DoS | 0.989310 | 0.971750 | 0.980452 | 4,000 |
| Mirai | 0.974595 | 0.978250 | 0.976419 | 4,000 |
| Recon | 0.846055 | 0.823000 | 0.834368 | 4,000 |
| Spoofing | 0.807377 | 0.837250 | 0.822042 | 4,000 |
| WebBased | 0.731913 | 0.781500 | 0.755894 | 4,000 |
| BruteForce | 0.858622 | 0.788000 | 0.821796 | 4,000 |

## False Positives and False Negatives

False positives and false negatives are reported one-vs-rest per class.

| Class | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| Benign | 3,524 | 641 | 476 | 27,359 |
| DDoS | 3,683 | 227 | 317 | 27,773 |
| DoS | 3,887 | 42 | 113 | 27,958 |
| Mirai | 3,913 | 102 | 87 | 27,898 |
| Recon | 3,292 | 599 | 708 | 27,401 |
| Spoofing | 3,349 | 799 | 651 | 27,201 |
| WebBased | 3,126 | 1,145 | 874 | 26,855 |
| BruteForce | 3,152 | 519 | 848 | 27,481 |

Interpretation:

- `FP` means samples from other classes incorrectly predicted as this class.
- `FN` means samples from this class incorrectly predicted as another class.
- WebBased had the largest false-positive count: 1,145.
- WebBased also had the largest false-negative count: 874.
- BruteForce had the second-largest false-negative count: 848.
- DoS and Mirai were the strongest classes by F1.

## Confusion Matrix

Rows are true labels. Columns are predicted labels.

Column order:

```text
Benign, DDoS, DoS, Mirai, Recon, Spoofing, WebBased, BruteForce
```

| True \ Pred | Benign | DDoS | DoS | Mirai | Recon | Spoofing | WebBased | BruteForce |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 3,524 | 33 | 2 | 2 | 76 | 131 | 135 | 97 |
| DDoS | 50 | 3,683 | 18 | 43 | 56 | 57 | 60 | 33 |
| DoS | 2 | 10 | 3,887 | 10 | 42 | 24 | 18 | 7 |
| Mirai | 1 | 31 | 5 | 3,913 | 6 | 22 | 17 | 5 |
| Recon | 116 | 40 | 6 | 3 | 3,292 | 113 | 347 | 83 |
| Spoofing | 146 | 24 | 6 | 22 | 85 | 3,349 | 264 | 104 |
| WebBased | 157 | 34 | 2 | 14 | 217 | 260 | 3,126 | 190 |
| BruteForce | 169 | 55 | 3 | 8 | 117 | 192 | 304 | 3,152 |

## Why Training Stopped at Epoch 121

Training stopped normally because early stopping triggered.

The best validation macro F1 occurred at epoch 101:

```text
best epoch = 101
best macro F1 = 0.8731743172488037
```

Training continued for 20 more epochs without improving that best score:

```text
last epoch = 121
121 - 101 = 20 stale epochs
```

This matches:

```text
EARLY_STOPPING_PATIENCE = 20
```

The run did not stop because of CUDA failure, memory exhaustion, or a crash.

## Learning Rate State

The final recorded learning rate was:

```text
4.882812500000001e-06
```

This indicates the `ReduceLROnPlateau` scheduler had repeatedly reduced the
learning rate after validation macro F1 plateaued.

## GPU Utilization Observations

During the training cycle, GPU utilization appeared low, often around 1-5%.
This was investigated and documented in:

```text
context/training-gpu-starvation.md
```

Observed facts:

- training process was attached to the RTX 4060
- training process appeared in `nvidia-smi` as type `C`
- CUDA kernels were observed through `nvidia-smi pmon`
- low GPU utilization was due to data pipeline starvation, not CPU-only training

Primary bottleneck:

```text
192,000 individual .pt graph files
```

This causes expensive CPU-side file loading, deserialization, and PyG collation.

## Evaluation Metrics Status

`artifacts/metrics.json` has now been refreshed by full CUDA evaluation of the
epoch-101 checkpoint. The exact confusion matrix and FP/FN counts were also saved
to:

```text
artifacts/evaluation_confusion_matrix.json
```

## Persisted Artifact Timeline

Relevant timestamps:

```text
artifacts/graph_dataset_manifest.json  2026-06-15 03:54:46
artifacts/best_hgnn.pt                 2026-06-15 07:49:54
context/05_training.md                 2026-06-15 08:18:04
artifacts/metrics.json                 refreshed after full evaluation
artifacts/evaluation_confusion_matrix.json generated after full evaluation
```

Interpretation:

- graph dataset was generated before training
- best model checkpoint was saved during full training at epoch 101
- training context was written after training stopped at epoch 121
- metrics file now corresponds to the full epoch-101 checkpoint evaluation

## Known Limitations of This Log

The trainer currently stores only:

- best checkpoint metadata
- final training context
- last epoch summary

It does not persist:

- every epoch's train loss
- every epoch's validation macro F1
- every epoch's learning rate
- per-epoch timestamps

## Recommended Logging Fix for Next Cycle

Before the next long training run, update `secureedge/models/train.py` to write a
full training history JSON/CSV file, for example:

```text
artifacts/training_history.json
artifacts/training_history.csv
```

Each row should include:

```text
epoch
train_loss
macro_f1
learning_rate
epoch_start_time
epoch_end_time
epoch_duration_seconds
best_so_far
stale_epochs
```

This will make future reports exact instead of relying on the final context and
checkpoint metadata.

## Current Status

The first full CUDA HGNN training cycle completed normally with early stopping.

Best available model:

```text
artifacts/best_hgnn.pt
```

Best observed macro F1 during training:

```text
0.8731743172488037
```

Next required step:

```text
Run full evaluation on the saved epoch-101 checkpoint.
```
