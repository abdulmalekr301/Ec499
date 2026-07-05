# HGNN Training

Generated: `2026-07-05T06:18:27+00:00`

## Action
- Trained `SecureEdgeHGNN` on graph files from `/var/home/alucard-00/EC499/data/graphs/train`.
- Evaluated each epoch on validation graph files from `/var/home/alucard-00/EC499/data/graphs/val`.
- Reserved test graph files under `/var/home/alucard-00/EC499/data/graphs/test` for final evaluation.
- Best validation macro F1: `0.939311`.
- Batch size: `512` graph objects.
- Gradient accumulation steps: `1`.
- Effective batch size: `512` graph objects.
- Evaluation batch size: `512` graph objects.
- AMP enabled: `True`.
- Device: `cuda`.
- Run log: `/var/home/alucard-00/EC499/context/logs-15.md`.
- History JSON: `/var/home/alucard-00/EC499/artifacts/training_runs/run_15_history.json`.
- History CSV: `/var/home/alucard-00/EC499/artifacts/training_runs/run_15_history.csv`.
- Training limit per class: `full split`.
- Validation limit per class: `full split`.
- Warmup: `5` epochs from `0.0003` to `0.003`.
- Weight decay: `1e-05`.
- Scheduler: `cosine`, min LR `1e-05`.
- Label smoothing: `0.0`.
- Resume from checkpoint: `False`.
- Resume checkpoint path: `not used`.
- Loss: plain `CrossEntropyLoss()` with no class weights and no label smoothing.
- Saved this run's best checkpoint to `/var/home/alucard-00/EC499/artifacts/training_runs/run_15_best_hgnn.pt`.
- Promoted to global checkpoint `/var/home/alucard-00/EC499/artifacts/best_hgnn.pt` only if this run beat the existing global macro F1.

## Last Epoch
```json
{
  "run": 15,
  "epoch": 189,
  "train_loss": 0.03078343380475417,
  "accuracy": 0.9391875,
  "macro_f1": 0.9389055797369067,
  "learning_rate": 0.0002798075939155718,
  "batch_size": 512,
  "grad_accum_steps": 1,
  "effective_batch_size": 512,
  "eval_batch_size": 512,
  "use_amp": true,
  "heads": 2,
  "scheduler": "cosine",
  "stale_epochs": 50,
  "best_f1_so_far": 0.939311167648876,
  "is_best": false,
  "epoch_duration_seconds": 153.36275183099497,
  "seconds": 153.36275183099497,
  "cosine_cycle": 3,
  "correct": 30054,
  "incorrect": 1946,
  "total": 32000,
  "per_class": {
    "Benign": {
      "tp": 3704,
      "fp": 542,
      "fn": 296,
      "tn": 27458,
      "support": 4000,
      "predicted_as_class": 4246,
      "precision": 0.8723504474799811,
      "recall": 0.926,
      "f1": 0.8983749696822703,
      "false_positive_rate": 0.019357142857142857,
      "false_negative_rate": 0.074
    },
    "DDoS": {
      "tp": 3982,
      "fp": 18,
      "fn": 18,
      "tn": 27982,
      "support": 4000,
      "predicted_as_class": 4000,
      "precision": 0.9955,
      "recall": 0.9955,
      "f1": 0.9955000000000002,
      "false_positive_rate": 0.0006428571428571428,
      "false_negative_rate": 0.0045
    },
    "DoS": {
      "tp": 3988,
      "fp": 9,
      "fn": 12,
      "tn": 27991,
      "support": 4000,
      "predicted_as_class": 3997,
      "precision": 0.9977483112334251,
      "recall": 0.997,
      "f1": 0.9973740152557209,
      "false_positive_rate": 0.0003214285714285714,
      "false_negative_rate": 0.003
    },
    "Mirai": {
      "tp": 3998,
      "fp": 1,
      "fn": 2,
      "tn": 27999,
      "support": 4000,
      "predicted_as_class": 3999,
      "precision": 0.9997499374843711,
      "recall": 0.9995,
      "f1": 0.9996249531191399,
      "false_positive_rate": 3.571428571428572e-05,
      "false_negative_rate": 0.0005
    },
    "Recon": {
      "tp": 3965,
      "fp": 113,
      "fn": 35,
      "tn": 27887,
      "support": 4000,
      "predicted_as_class": 4078,
      "precision": 0.9722903384011771,
      "recall": 0.99125,
      "f1": 0.9816786333250805,
      "false_positive_rate": 0.004035714285714286,
      "false_negative_rate": 0.00875
    },
    "Spoofing": {
      "tp": 3822,
      "fp": 133,
      "fn": 178,
      "tn": 27867,
      "support": 4000,
      "predicted_as_class": 3955,
      "precision": 0.9663716814159292,
      "recall": 0.9555,
      "f1": 0.9609050911376492,
      "false_positive_rate": 0.00475,
      "false_negative_rate": 0.0445
    },
    "WebBased": {
      "tp": 3539,
      "fp": 912,
      "fn": 461,
      "tn": 27088,
      "support": 4000,
      "predicted_as_class": 4451,
      "precision": 0.7951022242192766,
      "recall": 0.88475,
      "f1": 0.837534019642646,
      "false_positive_rate": 0.03257142857142857,
      "false_negative_rate": 0.11525
    },
    "BruteForce": {
      "tp": 3056,
      "fp": 218,
      "fn": 944,
      "tn": 27782,
      "support": 4000,
      "predicted_as_class": 3274,
      "precision": 0.93341478313989,
      "recall": 0.764,
      "f1": 0.8402529557327467,
      "false_positive_rate": 0.007785714285714286,
      "false_negative_rate": 0.236
    }
  },
  "confusion_matrix": [
    [
      3704,
      0,
      1,
      0,
      0,
      21,
      215,
      59
    ],
    [
      1,
      3982,
      2,
      0,
      6,
      2,
      7,
      0
    ],
    [
      1,
      2,
      3988,
      1,
      6,
      2,
      0,
      0
    ],
    [
      0,
      0,
      0,
      3998,
      0,
      1,
      1,
      0
    ],
    [
      1,
      4,
      0,
      0,
      3965,
      8,
      19,
      3
    ],
    [
      49,
      2,
      3,
      0,
      11,
      3822,
      98,
      15
    ],
    [
      185,
      5,
      1,
      0,
      75,
      54,
      3539,
      141
    ],
    [
      305,
      5,
      2,
      0,
      15,
      45,
      572,
      3056
    ]
  ]
}
```
