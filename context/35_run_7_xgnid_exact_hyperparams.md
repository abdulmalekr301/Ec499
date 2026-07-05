# Run 7 XG-NID Exact Hyperparameters

Generated: `2026-06-19`

## Summary

Applied `context/systematic-fix-plan (1).md` for run 7.

Run 6 is complete:

```text
best_epoch=281
best_macro_f1=0.895089
stopped_reason=max_epochs_reached
```

Run 7 keeps the multi-head HGNN architecture and the current graph dataset
fixed, then changes only the training hyperparameters to match the XG-NID paper.

## Code Updates Required Before Run 7

The existing training code did not yet support two settings required by the plan:

- `SECUREEDGE_SCHEDULER=none`
- `SECUREEDGE_WARMUP_EPOCHS=0`

The training script now supports:

- Constant learning rate training with no scheduler.
- Environment-configurable warmup epochs.
- Environment-configurable per-class print interval.
- CSV history fields required by the systematic plan:
  `run`, `epoch`, `train_loss`, `macro_f1`, `learning_rate`, `batch_size`,
  `heads`, `scheduler`, and `seconds`.
- Resume loading when `scheduler=None`, including model and optimizer state.
- Per-run best checkpoints at `artifacts/training_runs/run_XX_best_hgnn.pt`
  in addition to the latest global `artifacts/best_hgnn.pt`.

## Run 7 Command

```bash
PYTHONUNBUFFERED=1 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.01 \
SECUREEDGE_LR_MIN=0.01 \
SECUREEDGE_SCHEDULER=none \
SECUREEDGE_WARMUP_EPOCHS=0 \
SECUREEDGE_MAX_EPOCHS=30 \
SECUREEDGE_EARLY_STOP=30 \
SECUREEDGE_PRINT_CLASS_EVERY=5 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
.venv/bin/python -m secureedge.models.train
```

## Resume Feature Verification

The resume feature remains available for future continuation runs:

```bash
SECUREEDGE_RESUME_FROM_CHECKPOINT=1
SECUREEDGE_RESUME_CHECKPOINT_PATH=artifacts/best_hgnn.pt
SECUREEDGE_RESUME_LOAD_OPTIMIZER=1
SECUREEDGE_RESUME_LOAD_SCHEDULER=1
```

For constant-LR runs with `SECUREEDGE_SCHEDULER=none`, the resume loader skips
scheduler restoration safely while still loading model and optimizer state.
