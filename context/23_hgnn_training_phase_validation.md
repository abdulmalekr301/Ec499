# SecureEdge HGNN Training Phase Validation

> Generated: 2026-06-15  
> Scope: Proceeded to the next final-methodology phase after 92-feature graph
> regeneration: HGNN architecture and training validation.

## Summary

The next methodology phase is Phase 4, HGNN training, using the Phase 3
`SecureEdgeHGNN` architecture. A full final training run requires CUDA on the
RTX 4060, but CUDA is not currently available to PyTorch on this machine.

Because of that, this step verified the training and evaluation pipeline with a
bounded CPU run instead of launching a long CPU-only full training job.

## CUDA Status

PyTorch environment check:

```text
torch = 2.12.0+cu130
cuda_available = False
cuda_version = 13.0
device_count = 0
```

`nvidia-smi` failed with:

```text
NVIDIA-SMI has failed because it couldn't communicate with the NVIDIA driver.
```

This means the CUDA-enabled Python stack is installed, but the NVIDIA driver is
not currently visible/working from the runtime. Full training to the 0.97 macro
F1 target should wait until the driver is available.

## Code Changes

Added safe training configuration overrides in `secureedge/config.py`:

```text
SECUREEDGE_BATCH_SIZE
SECUREEDGE_MAX_EPOCHS
SECUREEDGE_EARLY_STOPPING_PATIENCE
SECUREEDGE_LR_SCHEDULER_PATIENCE
SECUREEDGE_TRAIN_LIMIT_PER_CLASS
SECUREEDGE_EVAL_LIMIT_PER_CLASS
SECUREEDGE_DEVICE
```

Updated `secureedge/data/dataset.py` so graph datasets can be loaded with an
optional per-class limit. Defaults remain full-methodology behavior:

```text
TRAIN_LIMIT_PER_CLASS = 0 means use the full train split
EVAL_LIMIT_PER_CLASS = 0 means use the full eval split
```

Updated `secureedge/models/train.py`:

- added explicit device selection
- supports bounded train/eval subsets
- records device and limits in the saved checkpoint
- still defaults to the full graph splits when no limits are set

Updated `secureedge/models/evaluate.py`:

- uses the same explicit device selection
- supports bounded eval subsets

Updated `README.md` with safe CPU sanity-check and full CUDA training commands.

## Validation Commands

### Compile check

```bash
.venv/bin/python -m compileall secureedge tests
```

Result:

```text
passed
```

### Smoke checks

```bash
.venv/bin/python tests/smoke_checks.py
```

Result:

```text
smoke checks passed
```

### HGNN forward/backward check

A small PyG batch was loaded and passed through `SecureEdgeHGNN`.

Result:

```text
graphs = 4
flow = (4, 92)
packet = (45, 1500)
logits = (4, 8)
finite = True
loss = 2.3378069400787354
backward_ok = True
```

## Bounded CPU Training Run

Command:

```bash
SECUREEDGE_DEVICE=cpu \
SECUREEDGE_BATCH_SIZE=16 \
SECUREEDGE_MAX_EPOCHS=1 \
SECUREEDGE_EARLY_STOPPING_PATIENCE=1 \
SECUREEDGE_TRAIN_LIMIT_PER_CLASS=50 \
SECUREEDGE_EVAL_LIMIT_PER_CLASS=20 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
.venv/bin/python -m secureedge.models.train
```

Result:

```text
epoch=1 train_loss=2.00376 macro_f1=0.20280 lr=0.0028
```

The checkpoint was written to:

```text
artifacts/best_hgnn.pt
```

Checkpoint metadata confirms this is a bounded CPU validation checkpoint:

```text
model = SecureEdgeHGNN
best_macro_f1 = 0.20279931093884584
epoch = 1
train_limit_per_class = 50
eval_limit_per_class = 20
device = cpu
```

## Bounded Evaluation Run

Command:

```bash
SECUREEDGE_DEVICE=cpu \
SECUREEDGE_BATCH_SIZE=16 \
SECUREEDGE_EVAL_LIMIT_PER_CLASS=20 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
.venv/bin/python -m secureedge.models.evaluate
```

Result:

```text
macro_f1 = 0.20279931093884584
```

This low value is expected because the run used only one epoch and 50 training
graphs per class. It verifies the training and evaluation mechanics, not final
model quality.

## Full Training Command

After the NVIDIA driver is visible and `torch.cuda.is_available()` returns
`True`, run the full methodology training without sample limits:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_MAX_EPOCHS=200 \
SECUREEDGE_NUM_WORKERS=2 \
.venv/bin/python -m secureedge.models.train
```

Then run full evaluation:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
.venv/bin/python -m secureedge.models.evaluate
```

## Current Status

The HGNN training phase is implemented and validated on a bounded CPU run. The
remaining blocker for the full final-methodology training run is CUDA driver
availability, not the SecureEdge pipeline code.

Important note: `artifacts/best_hgnn.pt` currently contains the bounded CPU
validation checkpoint. It is not the final trained model.
