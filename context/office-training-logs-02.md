# Office HGNN Training Run 2

> Run started: `2026-08-03T01:48:06+00:00`
> Last updated: `2026-08-03T01:48:06+00:00`

## Configuration

```text
device=cpu
model_attention_conv=GATv2Conv
batch_size=4
grad_accum_steps=1
effective_batch_size=4
eval_batch_size=4
use_amp=no
amp_disabled_reason=device_is_not_cuda
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
max_epochs=1
early_stopping_patience=1
print_class_every=1
label_smoothing=0.05
temporal_features_masked=True
temporal_feature_indices=[76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91]
```

## Dataset

| Class | Train |
| --- | --- |
| Benign | 2 |
| BruteForce | 2 |
| DoS | 2 |
| DDoS | 2 |
| WebBased | 2 |
| Bot | 2 |
| Infiltration | 2 |

## Imbalance Handling

- Loss: `weighted_cross_entropy`.
- Weight method: `inverse_sqrt`.
- Count source: `train_split_only`.
- Balanced sampler: `True`.
- Sampler method: `class_subtype_group_graph_weighted_random_sampler`.

## Current Status

- Stopped reason: `max_epochs_reached`.
- Epochs completed: `1`.
- Best epoch: `1`.
- Best validation macro F1: `0.190476`.
- Latest validation accuracy: `0.285714`.
- Latest validation macro F1: `0.190476`.
- Latest validation weighted F1: `0.190476`.
- Latest train loss: `1.949915`.
- Latest learning rate: `0.00084`.

## Diagnostic Warnings

- `webbased_validation_support_is_low; treat WebBased metrics as high_variance`

## Per-Epoch Summary

| Epoch | Train Loss | Val Acc | Val Macro F1 | Val Weighted F1 | LR | Stale | Best Val F1 | Cycle | Seconds | Warnings | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1.949915 | 0.285714 | 0.190476 | 0.190476 | 0.00084 | 0 | 0.190476 | 0 | 0.20 | 1 | yes |

## Latest Validation Per-Class Metrics

| Class | Support | TP | FP | FN | Precision | Recall | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 2 | 0 | 1 | 2 | 0.000000 | 0.000000 | 0.000000 | 0.083333 | 1.000000 |
| BruteForce | 2 | 0 | 0 | 2 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.000000 |
| DoS | 2 | 2 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DDoS | 2 | 0 | 0 | 2 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.000000 |
| WebBased | 2 | 0 | 1 | 2 | 0.000000 | 0.000000 | 0.000000 | 0.083333 | 1.000000 |
| Bot | 2 | 0 | 0 | 2 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.000000 |
| Infiltration | 2 | 2 | 8 | 0 | 0.200000 | 1.000000 | 0.333333 | 0.666667 | 0.000000 |

## Latest Validation Per-Subtype Recall

| Class | Subtype | Support | Correct | Recall |
| --- | --- | --- | --- | --- |
| Benign | BENIGN | 2 | 0 | 0.000000 |
| Bot | Bot | 2 | 0 | 0.000000 |
| BruteForce | SSH-Bruteforce | 2 | 0 | 0.000000 |
| DDoS | DDOS-HOIC | 2 | 0 | 0.000000 |
| DoS | DoS-Hulk | 2 | 2 | 1.000000 |
| Infiltration | Infiltration | 2 | 2 | 1.000000 |
| WebBased | Brute Force-Web | 2 | 0 | 0.000000 |

## Artifact Paths

- Latest history JSON: `/tmp/office_final_smoke_history.json`
- Run history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_02_history.json`
- Run history CSV: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_02_history.csv`
- Run config JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_02_config.json`
- Run checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_02_best_office_hgnn.pt`
- Global office checkpoint: `/tmp/office_final_smoke_hgnn.pt`
