# Office Training Logging and Accumulation Fix

Date: 2026-07-29

## Trigger

The first office training epoch reported:

```text
Epoch 001/300 | loss=0.0950 | validation_macro_f1=0.9987
```

This is suspiciously strong for the first epoch of a new seven-class office run. It does not prove overfitting by itself, but it is a high-signal warning that the run needs better diagnostics before continuing.

## Fixes Applied

### 1. Gradient Accumulation Scaling

The office trainer previously accumulated gradients without dividing the loss by `SECUREEDGE_GRAD_ACCUM_STEPS` before `backward()`.

That means runs with gradient accumulation greater than 1 used larger effective updates than intended.

The office trainer now matches the IoT trainer pattern:

```python
scaled_loss = loss / root_config.GRAD_ACCUM_STEPS
scaler.scale(scaled_loss).backward()
```

### 2. Richer Startup Logging

The office trainer now prints a JSON startup block with:

- run ID
- run log path
- run config path
- history JSON/CSV paths
- checkpoint paths
- CUDA/device info
- GATv2 architecture marker
- batch size and gradient accumulation
- AMP status and disabled reason
- scheduler and warmup settings
- train/validation/test counts
- train class counts
- class weights
- balanced sampler configuration
- training config hash

### 3. Per-Run Artifacts

Each office run now writes:

| Artifact | Path pattern |
| --- | --- |
| Latest history | `artifacts/office_model/office_training_history.json` |
| Run config | `artifacts/office_model/training_runs/office_run_XX_config.json` |
| Run history JSON | `artifacts/office_model/training_runs/office_run_XX_history.json` |
| Run history CSV | `artifacts/office_model/training_runs/office_run_XX_history.csv` |
| Run checkpoint | `artifacts/office_model/training_runs/office_run_XX_best_office_hgnn.pt` |
| Global office checkpoint | `artifacts/office_model/best_office_hgnn.pt` |
| Markdown log | `context/office-training-logs-XX.md` |

### 4. Per-Epoch Console Logging

The epoch line now includes:

- train loss
- validation accuracy
- validation macro-F1
- validation weighted-F1
- learning rate
- stale epoch count
- best checkpoint marker
- diagnostic warning count

Example shape:

```text
Epoch 001/300 | loss=... | val_acc=... | val_macro_f1=... | val_weighted_f1=... | lr=... | stale=0 | BEST | warnings=...
```

### 5. Per-Class Metrics

The run history and markdown log now include per-class validation metrics:

- support
- TP
- FP
- FN
- precision
- recall
- F1
- false-positive rate
- false-negative rate

### 6. Diagnostic Warnings

The trainer now flags suspicious early results:

| Warning | Meaning |
| --- | --- |
| `first_epoch_validation_macro_f1_ge_0.98` | First epoch validation macro-F1 is unusually high |
| `very_low_train_loss_with_near_perfect_validation_macro_f1` | Loss and validation score are both near perfect very early |
| `webbased_validation_support_is_low` | WebBased validation support is low and high variance |

These warnings are written into the markdown log and printed below the epoch line.

### 7. Scheduler/Warmup Logging Parity

The office trainer now uses and logs the same root scheduler knobs as the IoT trainer:

- `SECUREEDGE_WARMUP_EPOCHS`
- `SECUREEDGE_LR_START`
- `SECUREEDGE_LR_TARGET`
- `SECUREEDGE_LR_MIN`
- `SECUREEDGE_SCHEDULER`
- `SECUREEDGE_COSINE_T0`
- `SECUREEDGE_COSINE_T_MULT`
- `SECUREEDGE_LR_PLATEAU_THRESHOLD`

Office plateau mode currently supports `SECUREEDGE_PLATEAU_MONITOR=val_macro_f1`.

## Verification

Compile check passed:

```bash
.venv/bin/python -m compileall secureedge/office/train.py
```

Synthetic logging helper test passed:

```text
office_logging_helpers_ok
```

The synthetic test also confirmed that the same first-epoch pattern is now flagged:

```text
first_epoch_validation_macro_f1_ge_0.98
very_low_train_loss_with_near_perfect_validation_macro_f1
webbased_validation_support_is_low
```

## Training Guidance

Stop the old office training process if it is still running, because it was started before this fix.

Restart training from scratch with:

```bash
.venv/bin/python -m secureedge.office.train
```

Do not compare the old first epoch directly against the restarted run, because the gradient accumulation behavior and scheduler/warmup handling are now corrected.
