# SecureEdge Scripts and Commands Runbook

This file collects the practical commands used to operate the SecureEdge project:
safe checks, PCAP splitting, preprocessing, graph creation, sharding, leakage audits,
training, resume training, evaluation, visualization, and export.

The commands assume the working directory is the EC499 project root:

```bash
cd /home/alucard-00/EC499
source .venv/bin/activate
```

## Script Index

These are the project modules we currently run as scripts:

| Purpose | Module / command |
|---|---|
| CSV/raw acquisition legacy helper | `python -m secureedge.data.acquire` |
| PCAP splitting | `python -m secureedge.data.split_pcaps` |
| Packet byte verification | `python -m secureedge.data.verify_packet_capture` |
| Flow-window verification | `python -m secureedge.data.verify_flow_window` |
| PCAP preprocessing / compact reservoir / splits | `python -m secureedge.data.preprocess` |
| Compact-to-graph materialization | `python -m secureedge.data.build_graphs` |
| Graph sharding | `python -m secureedge.data.create_shards` |
| Feature/schema validation | `python -m secureedge.features.pipeline` |
| Leakage audit | `python -m secureedge.data.leakage_audit` |
| MAC filter audit | `python -m secureedge.data.mac_filter_audit` |
| Payload diagnostics | `python -m secureedge.data.payload_diagnostic` |
| Graph sample visualization | `python -m secureedge.visualize.graph_view` |
| HGNN training | `python -m secureedge.models.train` |
| HGNN evaluation | `python -m secureedge.models.evaluate` |
| OOD threshold calibration | `python -m secureedge.ood.detector` |
| TorchScript export | `python -m secureedge.export.export` |
| Smoke checks | `python tests/smoke_checks.py` |

## 1. Environment Checks

### Check Python and package imports

```bash
.venv/bin/python --version
.venv/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.is_available())"
.venv/bin/python -c "import torch_geometric; print(torch_geometric.__version__)"
.venv/bin/python -c "import nfstream; print('nfstream ok')"
```

### Check GPU visibility

```bash
nvidia-smi
.venv/bin/python -c "import torch; print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CUDA not available')"
```

`nvidia-smi` only proves the driver can see the GPU. The PyTorch check proves
the training process can use CUDA.

### Compile the codebase

```bash
.venv/bin/python -m compileall secureedge tests
```

### Run smoke checks

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python tests/smoke_checks.py
```

This checks label mapping, temporal features, graph/model shape assumptions,
threshold/export behavior, and several safety assumptions.

## 2. Memory-Safe Shell Prefix

Use this prefix for heavy preprocessing commands:

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1
```

Why it exists:

- `MALLOC_ARENA_MAX=2` reduces allocator memory growth.
- `OMP_NUM_THREADS=1`, `MKL_NUM_THREADS=1`, and `OPENBLAS_NUM_THREADS=1` prevent
  hidden CPU thread explosions during numeric work.
- This does not make the task fast; it makes it less likely to consume RAM/swap.

## 3. PCAP Safety Checks and Splitting

### Discover oversized PCAPs and split cautiously

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
.venv/bin/python -m secureedge.data.split_pcaps \
  --threshold-mb 64 \
  --chunk-size-mb 16 \
  --min-available-gb 4
```

Output:

- split chunks under `data/raw/pcap_chunks/`
- context report under `context/15_pcap_splitting.md`

Notes:

- Splitting huge PCAPs was one of the system-crash sources earlier in the project.
- The splitter polls available memory and skips/resumes work instead of blindly
  processing every file.

### Verify NFStream packet bytes

```bash
.venv/bin/python -m secureedge.data.verify_packet_capture \
  --path PCAPs/BenignTraffic.pcap \
  --max-flows 10 \
  --max-packets 20 \
  --n-dissections 0
```

This checks which NFStream packet attributes actually contain byte payloads.
The current implementation uses `packet.ip_packet` and strips IP/TCP/UDP headers
to derive application payload bytes.

### Verify flow-window consistency

```bash
.venv/bin/python -m secureedge.data.verify_flow_window --limit 1000
```

This inspects compact graph records and confirms temporal-window assumptions.

## 4. Preprocessing

### Full current methodology resplit from existing reservoir

Use this when compact reservoir files already exist and you only need to rebuild
train/val/test splits.

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION=0.10 \
SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION=0.30 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.preprocess
```

Important active split behavior:

- Train target: `20000` sampled graphs per class.
- Val/test target for abundant classes: `2000` each.
- Scarce classes use proportional split below threshold `24000`.
- Train is oversampled only after train/val/test are separated.
- Validation and test remain real, non-oversampled records.

### Full extraction from PCAPs

Use only when you intentionally need to re-extract compact graphs from PCAPs.

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_USE_SPLIT_PCAP_CHUNKS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.preprocess
```

This is expensive. Prefer reservoir resplitting when possible.

### Small bounded development preprocessing

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 \
SECUREEDGE_VAL_SAMPLES_PER_CLASS=50 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.preprocess
```

Use this to test code paths without touching the full corpus.

## 5. Graph Materialization

### Build PyTorch Geometric graph files

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
.venv/bin/python -m secureedge.data.build_graphs
```

Outputs:

- graph files under `data/graphs/train/`, `data/graphs/val/`, `data/graphs/test/`
- manifest at `artifacts/graph_dataset_manifest.json`
- feature order at `artifacts/flow_feature_order.json`

Current regenerated graph counts:

```text
train: 160000
val:    11843
test:   11841
```

### Validate graph feature dimensions

```bash
.venv/bin/python -m secureedge.features.pipeline
```

This checks the feature schema and writes `context/03_feature_engineering.md`.

## 6. Sharding

Training from one graph file at a time is slow and filesystem-heavy. Sharding groups
graphs into larger `.pt` files.

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

Outputs:

- `data/graphs/train_shards/`
- `data/graphs/val_shards/`
- `data/graphs/test_shards/`
- `artifacts/graph_shard_manifest.json`

Current shard counts:

```text
train shards: 160
val shards:    12
test shards:   12
```

## 7. Leakage and Data Audits

### Leakage audit

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.data.leakage_audit \
  --report artifacts/training_runs/run_21_proportional_split_leakage_audit.md
```

Required result:

- compact duplicate overlap: `0`
- graph hash duplicate overlap: `0`
- near-duplicate fingerprint overlap: `0`
- leaked identity features: `[]`

### MAC filter audit

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.mac_filter_audit
```

This explains how attacker MAC filtering affects each class and subtype.

### Payload diagnostics

Individual graph files:

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic \
  --source graphs \
  --split train \
  --limit 200
```

Shard files:

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic \
  --source shards \
  --split train \
  --limit 10
```

These checks answer whether packet nodes contain meaningful nonzero payload bytes.

## 8. Graph Visualization

```bash
.venv/bin/python -m secureedge.visualize.graph_view \
  --split train \
  --limit 12 \
  --output-dir artifacts/graph_visualizations
```

Open:

```text
artifacts/graph_visualizations/index.html
```

The visualization renders sample heterographs with flow nodes, packet nodes, contain
edges, and packet-link edges.

## 9. Training

### Current recommended full training command

Use a fresh run id after dataset/split changes.

```bash
SECUREEDGE_RUN_ID=21 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_GRAD_ACCUM_STEPS=2 \
SECUREEDGE_USE_AMP=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=75 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.models.train
```

Notes:

- `SECUREEDGE_USE_AMP=0` is deliberate in raw graph mode because raw values can
  exceed fp16 range and cause non-finite logits.
- `SECUREEDGE_BATCH_SIZE=256` with `SECUREEDGE_GRAD_ACCUM_STEPS=2` gives effective
  batch size `512`.
- Training writes `context/logs-N.md`, `artifacts/training_runs/run_NN_history.json`,
  `artifacts/training_runs/run_NN_history.csv`, and a best checkpoint.

### CPU sanity training

```bash
SECUREEDGE_DEVICE=cpu \
SECUREEDGE_BATCH_SIZE=16 \
SECUREEDGE_MAX_EPOCHS=1 \
SECUREEDGE_TRAIN_LIMIT_PER_CLASS=50 \
SECUREEDGE_EVAL_LIMIT_PER_CLASS=20 \
.venv/bin/python -m secureedge.models.train
```

### Training with DataLoader workers

Default worker count is `0` for stability. On a normal workstation, try:

```bash
SECUREEDGE_NUM_WORKERS=2 \
SECUREEDGE_DEVICE=cuda \
.venv/bin/python -m secureedge.models.train
```

If CPU/RAM pressure climbs, return to `SECUREEDGE_NUM_WORKERS=0`.

## 10. Resume Training

Resume from a compatible checkpoint:

```bash
SECUREEDGE_RESUME_FROM_CHECKPOINT=1 \
SECUREEDGE_RESUME_CHECKPOINT_PATH=artifacts/training_runs/run_21_best_hgnn.pt \
SECUREEDGE_RESUME_LOAD_OPTIMIZER=1 \
SECUREEDGE_RESUME_LOAD_SCHEDULER=1 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_GRAD_ACCUM_STEPS=2 \
SECUREEDGE_USE_AMP=0 \
SECUREEDGE_MAX_EPOCHS=400 \
SECUREEDGE_EARLY_STOP=75 \
.venv/bin/python -m secureedge.models.train
```

The training script checks a model signature before loading:

- flow node dimension
- packet node dimension
- edge dimensions
- hidden size
- attention size
- attention head count
- BatchNorm epsilon
- readout mode
- payload encoder setting

If the signature differs, it refuses to resume because the checkpoint belongs to
a different architecture.

## 11. Evaluation

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.models.evaluate
```

Outputs:

- `artifacts/metrics.json`
- updated `context/06_evaluation.md`

Evaluation reports:

- macro F1
- classification report
- SecureEdge class-order confusion matrix
- XG-NID class-order confusion matrix
- DDoS subtype prediction distribution

## 12. OOD Detection

```bash
.venv/bin/python -m secureedge.ood.detector
```

This calibrates maximum-softmax-probability OOD thresholding from correctly
classified test samples and writes `artifacts/ood_threshold.json`.

## 13. TorchScript Export

```bash
SECUREEDGE_DEVICE=cpu \
.venv/bin/python -m secureedge.export.export
```

Output:

```text
artifacts/secureedge_hgnn.ts
```

The exporter traces a sample graph batch and verifies traced logits match PyTorch
logits within tolerance.

## 14. Class Distribution Reports

Current class distribution report:

```text
context/58_proportional_split_class_distribution_report.md
```

Current proportional split implementation note:

```text
context/59_proportional_split_ratio_fix.md
```

These are the main references for the current train/val/test class counts.

## 15. External CSV Inspection

For the Cyber Attack Evaluation CSV:

```text
context/60_cyber_attack_eval_features_labels.md
artifacts/cyber_attack_eval_features_labels.json
```

Finding:

- `L1_Cap_10PC_1S_dissec_complete.csv` has 8 columns.
- It has no explicit attack/class/ground-truth label column.
- `Protocol` is categorical but is a protocol feature, not an attack label.

## 16. Git Commands

Check status:

```bash
git status --short
```

Commit source and documentation changes:

```bash
git add secureedge tests context README.md requirements.txt .gitignore FOLDER_STRUCTURE.md "Project Context.md"
git commit -m "Document SecureEdge pipeline and current methodology"
git push
```

Do not add raw datasets, graph files, virtual environments, model checkpoints, or
large generated artifacts.
