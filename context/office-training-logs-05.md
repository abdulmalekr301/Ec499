# Office HGNN Training Run 5

> Run started: `2026-08-03T03:32:00+00:00`
> Last updated: `2026-08-03T03:36:53+00:00`

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
- Best validation macro F1: `0.986994`.
- Latest validation accuracy: `0.982985`.
- Latest validation macro F1: `0.986994`.
- Latest validation weighted F1: `0.983096`.
- Latest train loss: `0.237090`.
- Latest learning rate: `0.00246`.

## Diagnostic Warnings

- None.

## Per-Epoch Summary

| Epoch | Train Loss | Val Acc | Val Macro F1 | Val Weighted F1 | LR | Stale | Best Val F1 | Cycle | Seconds | Warnings | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1.149741 | 0.823113 | 0.700224 | 0.770714 | 0.00084 | 0 | 0.700224 | 0 | 72.78 | 0 | yes |
| 2 | 0.287914 | 0.971456 | 0.971723 | 0.971404 | 0.00138 | 0 | 0.971723 | 0 | 73.36 | 0 | yes |
| 3 | 0.241413 | 0.981457 | 0.985221 | 0.981608 | 0.00192 | 0 | 0.985221 | 0 | 73.49 | 0 | yes |
| 4 | 0.237090 | 0.982985 | 0.986994 | 0.983096 | 0.00246 | 0 | 0.986994 | 0 | 73.06 | 0 | yes |

## Latest Validation Per-Class Metrics

| Class | Support | TP | FP | FN | Precision | Recall | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 2340 | 2329 | 222 | 11 | 0.912975 | 0.995299 | 0.952361 | 0.018409 | 0.004701 |
| BruteForce | 4013 | 4013 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| DoS | 559 | 559 | 4 | 0 | 0.992895 | 1.000000 | 0.996435 | 0.000289 | 0.000000 |
| DDoS | 772 | 772 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | 0.000000 | 0.000000 |
| WebBased | 138 | 138 | 2 | 0 | 0.985714 | 1.000000 | 0.992806 | 0.000140 | 0.000000 |
| Bot | 2536 | 2535 | 9 | 1 | 0.996462 | 0.999606 | 0.998031 | 0.000759 | 0.000394 |
| Infiltration | 4041 | 3808 | 8 | 233 | 0.997904 | 0.942341 | 0.969327 | 0.000772 | 0.057659 |

## Latest Validation Per-Subtype Recall

| Class | Subtype | Support | Correct | Recall |
| --- | --- | --- | --- | --- |
| Benign | BENIGN | 2340 | 2329 | 0.995299 |
| Bot | Bot | 2536 | 2535 | 0.999606 |
| BruteForce | SSH-Bruteforce | 4013 | 4013 | 1.000000 |
| DDoS | DDOS-LOIC-HTTP | 10 | 10 | 1.000000 |
| DDoS | DDOS-LOIC-UDP | 762 | 762 | 1.000000 |
| DoS | DoS-Hulk | 559 | 559 | 1.000000 |
| Infiltration | Infiltration | 4041 | 3808 | 0.942341 |
| WebBased | Brute Force-Web | 122 | 122 | 1.000000 |
| WebBased | SQL Injection | 16 | 16 | 1.000000 |

## Artifact Paths

- Latest history JSON: `artifacts/office_model/office_final_robust_training_history.json`
- Run history JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_05_history.json`
- Run history CSV: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_05_history.csv`
- Run config JSON: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_05_config.json`
- Run checkpoint: `/var/home/alucard-00/EC499/artifacts/office_model/training_runs/office_run_05_best_office_hgnn.pt`
- Global office checkpoint: `artifacts/office_model/best_office_final_robust_hgnn.pt`
