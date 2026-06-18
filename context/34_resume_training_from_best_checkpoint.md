# Resume Training From Best Checkpoint

Generated: `2026-06-18`

## Summary

Added an explicit resume feature to `secureedge.models.train` so training can
continue beyond a previous epoch limit from the saved best HGNN checkpoint.

The best checkpoint is still saved at:

```text
artifacts/best_hgnn.pt
```

That file contains model weights, optimizer state, scheduler state, the source
run id, and the best epoch.

## New Environment Variables

```bash
SECUREEDGE_RESUME_FROM_CHECKPOINT=1
SECUREEDGE_RESUME_CHECKPOINT_PATH=artifacts/best_hgnn.pt
SECUREEDGE_RESUME_LOAD_OPTIMIZER=1
SECUREEDGE_RESUME_LOAD_SCHEDULER=1
```

`SECUREEDGE_RESUME_CHECKPOINT_PATH` defaults to `artifacts/best_hgnn.pt`.
Optimizer and scheduler state loading are enabled by default when resume mode is
enabled.

## How Resume Works

When `SECUREEDGE_RESUME_FROM_CHECKPOINT=1`, the training script:

1. Loads `model_state_dict` into `SecureEdgeHGNN`.
2. Loads `optimizer_state` if available and enabled.
3. Loads `scheduler_state` if available and enabled.
4. Reads the checkpoint epoch.
5. Starts the new run at `checkpoint_epoch + 1`.
6. Preserves the previous best macro F1 as the score that new epochs must beat.
7. Writes a fresh `logs-n.md`, JSON history, and CSV history for the continuation run.

The new run log includes a `Resume Source` section that records the checkpoint,
source run id, source best epoch, and source best macro F1.

## Example Continuation Command

To continue from the best checkpoint through epoch 450:

```bash
PYTHONUNBUFFERED=1 \
SECUREEDGE_RESUME_FROM_CHECKPOINT=1 \
SECUREEDGE_MAX_EPOCHS=450 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=512 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_EARLY_STOP=50 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
.venv/bin/python -m secureedge.models.train
```

`SECUREEDGE_MAX_EPOCHS` must be greater than the checkpoint epoch. For example,
if the best checkpoint is from epoch 289, setting `SECUREEDGE_MAX_EPOCHS=450`
runs epochs 290 through 450 unless early stopping triggers first.

## Important Compatibility Note

Resume checkpoints must match the active HGNN architecture. A checkpoint from
the old single-head GAT architecture should not be resumed after the round 6
multi-head GAT fix. Future checkpoints produced by the multi-head architecture
can be resumed normally.
