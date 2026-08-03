# Office HGNN Training Run 3

> Run started: `2026-08-03T01:57:07+00:00`
> Last updated: `2026-08-03T02:02:02+00:00`

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

- Stopped reason: `running`.
- Epochs completed: `4`.
- Best epoch: `4`.
- Best validation macro F1: `0.988690`.
- Latest validation accuracy: `0.983541`.
- Latest validation macro F1: `0.988690`.
- Latest validation weighted F1: `0.983682`.
- Latest train loss: `0.235380`.
- Latest learning rate: `0.00246`.

## Diagnostic Warnings

- None.

## Per-Epoch Summary

| Epoch | Train Loss | Val Acc | Val Macro F1 | Val Weighted F1 | LR | Stale | Best Val F1 | Cycle | Seconds | Warnings | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1.014786 | 0.886173 | 0.840184 | 0.869863 | 0.00084 | 0 | 0.840184 | 0 | 78.59 | 0 | yes |
| 2 | 0.275057 | 0.977568 | 0.982612 | 0.977657 | 0.00138 | 0 | 0.982612 | 0 | 71.83 | 0 | yes |
| 3 | 0.239141 | 0.982846 | 0.987684 | 0.982971 | 0.00192 | 0 | 0.987684 | 0 | 72.05 | 0 | yes |
| 4 | 0.235380 | 0.983541 | 0.988690 | 0.983682 | 0.00246 | 0 | 0.988690 | 0 | 72.59 | 0 | yes |

## Latest Validation Per-Class Metrics

| Class | Support | TP | FP | FN | Precision | Recall | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 2340 | 2331 | 227 | 9 | 0.911259 | 0.996154 | 0.951817 | 0.018824 | 0.003846 |
| BruteForce | 4013 | 4013 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DoS | 559 | 559 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DDoS | 772 | 772 | 1 | 0 | 0.998706 | 1.000000 | 0.999353 | 0.000073 | 0.000000 |
| WebBased | 138 | 138 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| Bot | 2536 | 2533 | 0 | 3 | 1.000000 | 0.998817 | 0.999408 | 0.000000 | 0.001183 |
| Infiltration | 4041 | 3816 | 9 | 225 | 0.997647 | 0.944321 | 0.970252 | 0.000869 | 0.055679 |

## Latest Validation Per-Subtype Recall

| Class | Subtype | Support | Correct | Recall |
| --- | --- | --- | --- | --- |
| Benign | BENIGN | 2340 | 2331 | 0.996154 |
| Bot | Bot | 2536 | 2533 | 0.998817 |
| BruteForce | SSH-Bruteforce | 4013 | 4013 | 1.000000 |
| DDoS | DDOS-HOIC | 772 | 772 | 1.000000 |
| DoS | DoS-Hulk | 559 | 559 | 1.000000 |
| Infiltration | Infiltration | 4041 | 3816 | 0.944321 |
| WebBased | Brute Force-Web | 122 | 122 | 1.000000 |
| WebBased | SQL Injection | 16 | 16 | 1.000000 |

## Artifact Paths

- Latest history JSON: `artifacts/office_model/office_final_robust_training_history.json`
- Run history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_03_history.json`
- Run history CSV: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_03_history.csv`
- Run config JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_03_config.json`
- Run checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_03_best_office_hgnn.pt`
- Global office checkpoint: `artifacts/office_model/best_office_final_robust_hgnn.pt`
