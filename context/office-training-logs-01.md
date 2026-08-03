# Office HGNN Training Run 1

> Run started: `2026-07-29T03:18:22+00:00`
> Last updated: `2026-07-29T04:00:46+00:00`

## Configuration

```text
device=cuda
model_attention_conv=GATv2Conv
batch_size=512
grad_accum_steps=1
effective_batch_size=512
eval_batch_size=512
use_amp=yes
amp_disabled_reason=None
checkpoint_selection_split=val
test_split_loaded_during_training=False
lr_start=0.0003
lr_target=0.003
lr_min=1e-05
scheduler=cosine
plateau_monitor=val_macro_f1
cosine_t0=50
cosine_t_mult=2
weight_decay=1e-05
grad_clip_max_norm=1.0
max_epochs=300
early_stopping_patience=50
print_class_every=10
```

## Dataset

| Class | Train |
| --- | --- |
| Benign | 19503 |
| BruteForce | 20000 |
| DoS | 20000 |
| DDoS | 20000 |
| WebBased | 206 |
| Bot | 20000 |
| Infiltration | 19991 |

## Imbalance Handling

- Loss: `weighted_cross_entropy`.
- Weight method: `effective_number`.
- Count source: `train_split_only`.
- Balanced sampler: `True`.
- Sampler method: `weighted_random_sampler`.

## Current Status

- Stopped reason: `running`.
- Epochs completed: `18`.
- Best epoch: `11`.
- Best validation macro F1: `0.999638`.
- Latest validation accuracy: `0.999336`.
- Latest validation macro F1: `0.999421`.
- Latest validation weighted F1: `0.999336`.
- Latest train loss: `0.000165`.
- Latest learning rate: `0.00025425933`.

## Diagnostic Warnings

- `very_low_train_loss_with_near_perfect_validation_macro_f1`
- `webbased_validation_support_is_low; treat WebBased metrics as high_variance`

## Per-Epoch Summary

| Epoch | Train Loss | Val Acc | Val Macro F1 | Val Weighted F1 | LR | Stale | Best Val F1 | Cycle | Seconds | Warnings | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.226048 | 0.995021 | 0.995659 | 0.995021 | 0.00084 | 0 | 0.995659 | 0 | 146.41 | 2 | yes |
| 2 | 0.001505 | 0.998755 | 0.998914 | 0.998755 | 0.00138 | 0 | 0.998914 | 0 | 152.77 | 2 | yes |
| 3 | 0.000751 | 0.998589 | 0.998769 | 0.998589 | 0.00192 | 1 | 0.998914 | 0 | 142.94 | 2 | no |
| 4 | 0.000381 | 0.999087 | 0.999204 | 0.999087 | 0.00246 | 0 | 0.999204 | 0 | 138.67 | 2 | yes |
| 5 | 0.001026 | 0.998174 | 0.998408 | 0.998174 | 0.003 | 1 | 0.999204 | 0 | 139.56 | 2 | no |
| 6 | 0.000360 | 0.999170 | 0.999276 | 0.999170 | 0.00029971388 | 0 | 0.999276 | 1 | 139.94 | 2 | yes |
| 7 | 0.000280 | 0.999170 | 0.999276 | 0.999170 | 0.00029885663 | 1 | 0.999276 | 1 | 140.39 | 2 | no |
| 8 | 0.000207 | 0.999170 | 0.999276 | 0.999170 | 0.00029743165 | 2 | 0.999276 | 1 | 140.49 | 2 | no |
| 9 | 0.000188 | 0.999253 | 0.999349 | 0.999253 | 0.00029544456 | 0 | 0.999349 | 1 | 139.85 | 2 | yes |
| 10 | 0.000168 | 0.999419 | 0.999493 | 0.999419 | 0.00029290319 | 0 | 0.999493 | 1 | 139.96 | 2 | yes |
| 11 | 0.000203 | 0.999585 | 0.999638 | 0.999585 | 0.00028981759 | 0 | 0.999638 | 1 | 139.85 | 2 | yes |
| 12 | 0.000177 | 0.999502 | 0.999566 | 0.999502 | 0.00028619992 | 1 | 0.999638 | 1 | 140.48 | 2 | no |
| 13 | 0.000151 | 0.999502 | 0.999566 | 0.999502 | 0.00028206447 | 2 | 0.999638 | 1 | 140.43 | 2 | no |
| 14 | 0.000152 | 0.999253 | 0.999349 | 0.999253 | 0.00027742755 | 3 | 0.999638 | 1 | 140.16 | 2 | no |
| 15 | 0.000182 | 0.999419 | 0.999493 | 0.999419 | 0.00027230746 | 4 | 0.999638 | 1 | 140.08 | 2 | no |
| 16 | 0.000150 | 0.999585 | 0.999638 | 0.999585 | 0.00026672442 | 5 | 0.999638 | 1 | 140.34 | 2 | no |
| 17 | 0.000155 | 0.999502 | 0.999566 | 0.999502 | 0.00026070045 | 6 | 0.999638 | 1 | 140.24 | 2 | no |
| 18 | 0.000165 | 0.999336 | 0.999421 | 0.999336 | 0.00025425933 | 7 | 0.999638 | 1 | 140.76 | 2 | no |

## Latest Validation Per-Class Metrics

| Class | Support | TP | FP | FN | Precision | Recall | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 1949 | 1945 | 4 | 4 | 0.997948 | 0.997948 | 0.997948 | 0.000396 | 0.002052 |
| BruteForce | 2000 | 2000 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DoS | 2000 | 2000 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DDoS | 2000 | 2000 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| WebBased | 103 | 103 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| Bot | 2000 | 2000 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| Infiltration | 1999 | 1995 | 4 | 4 | 0.997999 | 0.997999 | 0.997999 | 0.000398 | 0.002001 |

## Artifact Paths

- Latest history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/office_training_history.json`
- Run history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_01_history.json`
- Run history CSV: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_01_history.csv`
- Run config JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_01_config.json`
- Run checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_01_best_office_hgnn.pt`
- Global office checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/best_office_hgnn.pt`
