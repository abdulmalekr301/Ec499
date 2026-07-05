# Run 8 Small Batch With Proven Learning Rate

Generated: `2026-06-23`

## Decision From Run 7

Run 7 completed all 30 epochs with the XG-NID constant learning rate of
`0.01` and batch size `64`.

```text
best_epoch=29
best_macro_f1=0.812547
latest_train_loss=0.537250
stopped_reason=max_epochs_reached
```

This was substantially worse than run 6 (`0.895089`). The high constant
learning rate caused noisy convergence, particularly for WebBased,
BruteForce, Spoofing, and Benign.

## Run 8 Change

Run 8 follows `context/systematic-fix-plan (2).md` and isolates batch size:

- Keep the multi-head HGNN architecture from run 6.
- Keep the balanced graph dataset unchanged.
- Use batch size `64` for 2,500 updates per epoch.
- Restore the proven target learning rate `0.003`.
- Restore cosine annealing with 30-epoch cycles.
- Restore five warmup epochs.
- Train for at most 100 epochs with early-stopping patience 30.
- Print per-class F1 every five epochs.

## Command

```bash
PYTHONUNBUFFERED=1 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=30 \
SECUREEDGE_COSINE_T_MULT=1 \
SECUREEDGE_WARMUP_EPOCHS=5 \
SECUREEDGE_MAX_EPOCHS=100 \
SECUREEDGE_EARLY_STOP=30 \
SECUREEDGE_PRINT_CLASS_EVERY=5 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
.venv/bin/python -m secureedge.models.train
```

## Checkpoint And Resume Safety

Run 8 starts from fresh weights so it isolates the revised hyperparameters.
Its best state is saved to both:

```text
artifacts/best_hgnn.pt
artifacts/training_runs/run_08_best_hgnn.pt
```

To continue from run 8 later, set:

```bash
SECUREEDGE_RESUME_FROM_CHECKPOINT=1
SECUREEDGE_RESUME_CHECKPOINT_PATH=artifacts/training_runs/run_08_best_hgnn.pt
SECUREEDGE_RESUME_LOAD_OPTIMIZER=1
SECUREEDGE_RESUME_LOAD_SCHEDULER=1
```
