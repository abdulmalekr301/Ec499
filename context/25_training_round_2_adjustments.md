# SecureEdge Training Round 2 Adjustments

> Generated: 2026-06-15  
> Scope: Implemented the changes requested in `context/training-round-2.md`
> before starting the second full training run.

## Implemented Changes

### Graph sharding

Added:

```text
secureedge/data/create_shards.py
```

This packs individual graph files into shard files:

```text
data/graphs/train_shards/
data/graphs/test_shards/
```

The shard manifest is written to:

```text
artifacts/graph_shard_manifest.json
```

Create or refresh shards with:

```bash
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

### Payload diagnostic

Added:

```text
secureedge/data/payload_diagnostic.py
```

Run on individual graph files:

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic --source graphs --split train --limit 200
```

Run on shard files after sharding:

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic --source shards --split train --limit 3
```

### Round-2 training hyperparameters

Updated defaults and environment overrides:

```text
SECUREEDGE_BATCH_SIZE=512
SECUREEDGE_LR_START=3e-4
SECUREEDGE_LR_TARGET=3e-3
SECUREEDGE_LR_MIN=1e-5
SECUREEDGE_SCHEDULER=cosine
SECUREEDGE_COSINE_T0=50
SECUREEDGE_COSINE_T_MULT=2
SECUREEDGE_MAX_EPOCHS=300
SECUREEDGE_EARLY_STOP=50
SECUREEDGE_LABEL_SMOOTHING=0.1
SECUREEDGE_USE_GRAPH_SHARDS=1
```

### Training loop

Updated `secureedge/models/train.py` to:

- require graph shards by default for round-2 training
- load one shard at a time
- use an in-memory PyG DataLoader per shard with `num_workers=0`
- use `CrossEntropyLoss(label_smoothing=0.1)`
- use `CosineAnnealingWarmRestarts`
- perform manual 5-epoch linear warmup
- apply scheduler steps per batch after warmup
- use early stopping patience of 50 by default
- save optimizer and scheduler state in checkpoints

### Per-epoch metrics

The training script now calculates every epoch:

- validation accuracy
- correct count
- incorrect count
- macro F1
- confusion matrix
- per-class TP, FP, FN, TN
- per-class false-positive rate
- per-class false-negative rate
- per-class precision, recall, and F1

### Run-numbered logs

Every training run now automatically creates:

```text
context/logs-N.md
artifacts/training_runs/run_NN_history.json
artifacts/training_runs/run_NN_history.csv
artifacts/training_runs/run_NN_config.json
```

Since `context/logs-1.md` already exists, the next training run will create:

```text
context/logs-2.md
artifacts/training_runs/run_02_history.json
artifacts/training_runs/run_02_history.csv
artifacts/training_runs/run_02_config.json
```

The markdown log is updated after each epoch, not only at the end.

## Training Command

After creating shards and confirming payload quality, start round 2 from your
terminal:

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
SECUREEDGE_LABEL_SMOOTHING=0.1 \
.venv/bin/python -m secureedge.models.train
```

## Notes

The training script was not launched as part of this adjustment step. The next
full training run should be started manually from the terminal.

## Verification Completed

### Compile and smoke checks

```text
.venv/bin/python -m compileall secureedge tests
passed
```

```text
.venv/bin/python tests/smoke_checks.py
smoke checks passed
```

### Shard creation

Shard creation was completed with:

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

Result:

```text
Train shards: 160
Train graphs: 160,000
Test shards: 32
Test graphs: 32,000
```

Shard storage:

```text
data/graphs/train_shards: 11G
data/graphs/test_shards: 2.2G
artifacts/graph_shard_manifest.json: 15M
```

### Payload diagnostic on individual graphs

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic \
  --source graphs \
  --split train \
  --limit 200
```

Result:

```json
{
  "files_examined": 200,
  "graphs_examined": 200,
  "mean_packet_node_feature_value": 0.1177244371920824,
  "min_packet_node_feature_value": 0.0,
  "max_packet_node_feature_value": 0.49857139587402344,
  "zero_mean_graphs": 11,
  "nonzero_mean_graphs": 189,
  "interpretation": "packet node features are non-zero; proceed with training"
}
```

### Payload diagnostic on shards

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic \
  --source shards \
  --split train \
  --limit 3
```

Result:

```json
{
  "files_examined": 3,
  "graphs_examined": 3000,
  "mean_packet_node_feature_value": 0.0700152267947536,
  "min_packet_node_feature_value": 0.0,
  "max_packet_node_feature_value": 0.500033438205719,
  "zero_mean_graphs": 161,
  "nonzero_mean_graphs": 2839,
  "interpretation": "packet node features are non-zero; proceed with training"
}
```

Both round-2 prerequisites are now satisfied:

```text
graph sharding: complete
payload quality diagnostic: passed
```
