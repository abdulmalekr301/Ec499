# SecureEdge Training Run 11

> Run started: `2026-06-24T05:19:56+00:00`
> Last updated: `2026-06-24T05:29:58+00:00`

## Configuration

```text
device=cuda
batch_size=128
grad_accum_steps=4
effective_batch_size=512
use_amp=yes
use_graph_shards=yes
num_workers=0
prefetch_factor=2
lr_start=0.0003
lr_target=0.003
lr_min=1e-05
scheduler=cosine
cosine_t0=50
cosine_t_mult=2
label_smoothing=0.0
max_epochs=300
early_stop_patience=50
print_class_every=10
```

## Current Status

- Stopped reason: `running`.
- Epochs completed: `3`.
- Best epoch: `3`.
- Best macro F1: `0.806052`.
- Latest accuracy: `0.801656`.
- Latest macro F1: `0.806052`.
- Latest train loss: `0.564141`.
- Latest learning rate: `0.00192`.

## Per-Epoch Summary

| Epoch | Train Loss | Accuracy | Macro F1 | LR | Stale | Best F1 | Cycle | Seconds | Best |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.910776 | 0.756781 | 0.766475 | 0.00084 | 0 | 0.766475 | 0 | 195.42 | yes |
| 2 | 0.628959 | 0.787500 | 0.794232 | 0.00138 | 0 | 0.794232 | 0 | 211.58 | yes |
| 3 | 0.564141 | 0.801656 | 0.806052 | 0.00192 | 0 | 0.806052 | 0 | 193.64 | yes |

## Latest Per-Class FP/FN Rates

| Class | TP | FP | FN | TN | F1 | FP Rate | FN Rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Benign | 3319 | 1486 | 681 | 26514 | 0.753890 | 0.053071 | 0.170250 |
| DDoS | 3506 | 47 | 494 | 27953 | 0.928373 | 0.001679 | 0.123500 |
| DoS | 3876 | 35 | 124 | 27965 | 0.979901 | 0.001250 | 0.031000 |
| Mirai | 3903 | 172 | 97 | 27828 | 0.966687 | 0.006143 | 0.024250 |
| Recon | 2768 | 317 | 1232 | 27683 | 0.781369 | 0.011321 | 0.308000 |
| Spoofing | 2674 | 820 | 1326 | 27180 | 0.713638 | 0.029286 | 0.331500 |
| WebBased | 2860 | 2554 | 1140 | 25446 | 0.607606 | 0.091214 | 0.285000 |
| BruteForce | 2747 | 916 | 1253 | 27084 | 0.716952 | 0.032714 | 0.313250 |

## Full Machine-Readable History

- JSON: `artifacts/training_runs/run_11_history.json`
- CSV: `artifacts/training_runs/run_11_history.csv`
