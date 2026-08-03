# Office HGNN Training Run 6

> Run started: `2026-08-03T03:39:47+00:00`
> Last updated: `2026-08-03T03:52:29+00:00`

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
max_epochs=30
early_stopping_patience=5
print_class_every=1
label_smoothing=0.05
temporal_features_masked=True
temporal_feature_indices=[76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91]
```

## Dataset

| Class | Train |
| --- | --- |
| Benign | 18723 |
| BruteForce | 1000 |
| DoS | 3000 |
| DDoS | 3000 |
| WebBased | 234 |
| Bot | 7000 |
| Infiltration | 4000 |

## Imbalance Handling

- Loss: `weighted_cross_entropy`.
- Weight method: `inverse_sqrt`.
- Count source: `train_split_only`.
- Balanced sampler: `True`.
- Sampler method: `class_subtype_group_graph_weighted_random_sampler`.

## Current Status

- Stopped reason: `early_stopping`.
- Epochs completed: `11`.
- Best epoch: `6`.
- Best validation macro F1: `0.980963`.
- Latest validation accuracy: `0.979235`.
- Latest validation macro F1: `0.978956`.
- Latest validation weighted F1: `0.979425`.
- Latest train loss: `0.232159`.
- Latest learning rate: `0.00028981759`.

## Diagnostic Warnings

- None.

## Per-Epoch Summary

| Epoch | Train Loss | Val Acc | Val Macro F1 | Val Weighted F1 | LR | Stale | Best Val F1 | Cycle | Seconds | Warnings | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1.040751 | 0.828669 | 0.730503 | 0.764743 | 0.00084 | 0 | 0.730503 | 0 | 72.01 | 0 | yes |
| 2 | 0.287048 | 0.970831 | 0.960604 | 0.970847 | 0.00138 | 0 | 0.960604 | 0 | 69.20 | 0 | yes |
| 3 | 0.244449 | 0.978401 | 0.971376 | 0.978464 | 0.00192 | 0 | 0.971376 | 0 | 69.49 | 0 | yes |
| 4 | 0.238021 | 0.981804 | 0.980137 | 0.981907 | 0.00246 | 0 | 0.980137 | 0 | 72.65 | 0 | yes |
| 5 | 0.234966 | 0.982707 | 0.980398 | 0.982815 | 0.003 | 0 | 0.980398 | 0 | 71.11 | 0 | yes |
| 6 | 0.234595 | 0.982915 | 0.980963 | 0.983014 | 0.00029971388 | 0 | 0.980963 | 1 | 68.75 | 0 | yes |
| 7 | 0.234140 | 0.978540 | 0.977169 | 0.978708 | 0.00029885663 | 1 | 0.980963 | 1 | 67.54 | 0 | no |
| 8 | 0.230252 | 0.979443 | 0.978209 | 0.979630 | 0.00029743165 | 2 | 0.980963 | 1 | 68.68 | 0 | no |
| 9 | 0.233485 | 0.983610 | 0.980578 | 0.983735 | 0.00029544456 | 3 | 0.980963 | 1 | 68.43 | 0 | no |
| 10 | 0.235378 | 0.978887 | 0.978288 | 0.979083 | 0.00029290319 | 4 | 0.980963 | 1 | 68.35 | 0 | no |
| 11 | 0.232159 | 0.979235 | 0.978956 | 0.979425 | 0.00028981759 | 5 | 0.980963 | 1 | 65.11 | 0 | no |

## Latest Validation Per-Class Metrics

| Class | Support | TP | FP | FN | Precision | Recall | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 2340 | 2335 | 279 | 5 | 0.893267 | 0.997863 | 0.942673 | 0.023136 | 0.002137 |
| BruteForce | 4013 | 4013 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DoS | 559 | 559 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DDoS | 772 | 772 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| WebBased | 138 | 138 | 15 | 0 | 0.901961 | 1.000000 | 0.948454 | 0.001052 | 0.000000 |
| Bot | 2536 | 2535 | 0 | 1 | 1.000000 | 0.999606 | 0.999803 | 0.000000 | 0.000394 |
| Infiltration | 4041 | 3748 | 5 | 293 | 0.998668 | 0.927493 | 0.961765 | 0.000483 | 0.072507 |

## Latest Validation Per-Subtype Recall

| Class | Subtype | Support | Correct | Recall |
| --- | --- | --- | --- | --- |
| Benign | BENIGN | 2340 | 2335 | 0.997863 |
| Bot | Bot | 2536 | 2535 | 0.999606 |
| BruteForce | SSH-Bruteforce | 4013 | 4013 | 1.000000 |
| DDoS | DDOS-LOIC-HTTP | 10 | 10 | 1.000000 |
| DDoS | DDOS-LOIC-UDP | 762 | 762 | 1.000000 |
| DoS | DoS-Hulk | 559 | 559 | 1.000000 |
| Infiltration | Infiltration | 4041 | 3748 | 0.927493 |
| WebBased | Brute Force-Web | 122 | 122 | 1.000000 |
| WebBased | SQL Injection | 16 | 16 | 1.000000 |

## Artifact Paths

- Latest history JSON: `artifacts/office_model/office_final_robust_training_history.json`
- Run history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_06_history.json`
- Run history CSV: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_06_history.csv`
- Run config JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_06_config.json`
- Run checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_06_best_office_hgnn.pt`
- Global office checkpoint: `artifacts/office_model/best_office_final_robust_hgnn.pt`
