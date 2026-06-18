# HGNN Training

Generated: `2026-06-18T06:10:32+00:00`

## Action
- Trained `SecureEdgeHGNN` on graph files from `/var/home/alucard-00/EC499/data/graphs/train`.
- Evaluated each epoch on graph files from `/var/home/alucard-00/EC499/data/graphs/test`.
- Best macro F1: `0.890584`.
- Batch size: `512` graph objects.
- Device: `cuda`.
- Run log: `/var/home/alucard-00/EC499/context/logs-5.md`.
- History JSON: `/var/home/alucard-00/EC499/artifacts/training_runs/run_05_history.json`.
- History CSV: `/var/home/alucard-00/EC499/artifacts/training_runs/run_05_history.csv`.
- Training limit per class: `full split`.
- Evaluation limit per class: `full split`.
- Warmup: `5` epochs from `0.0003` to `0.003`.
- Weight decay: `1e-05`.
- Scheduler: `cosine`, min LR `1e-05`.
- Label smoothing: `0.0`.
- Loss: plain `CrossEntropyLoss()` with no class weights and no label smoothing.
- Saved best checkpoint to `/var/home/alucard-00/EC499/artifacts/best_hgnn.pt`.

## Last Epoch
```json
{
  "epoch": 300,
  "train_loss": 0.14199352890718728,
  "accuracy": 0.88915625,
  "macro_f1": 0.8894927441461621,
  "learning_rate": 6.0835445424955766e-05,
  "stale_epochs": 11,
  "best_f1_so_far": 0.8905844069701818,
  "is_best": false,
  "epoch_duration_seconds": 145.4112425809726,
  "cosine_cycle": 3,
  "correct": 28453,
  "incorrect": 3547,
  "total": 32000,
  "per_class": {
    "Benign": {
      "tp": 3422,
      "fp": 481,
      "fn": 578,
      "tn": 27519,
      "support": 4000,
      "predicted_as_class": 3903,
      "precision": 0.8767614655393288,
      "recall": 0.8555,
      "f1": 0.8660002530684551,
      "false_positive_rate": 0.01717857142857143,
      "false_negative_rate": 0.1445
    },
    "DDoS": {
      "tp": 3673,
      "fp": 221,
      "fn": 327,
      "tn": 27779,
      "support": 4000,
      "predicted_as_class": 3894,
      "precision": 0.943246019517206,
      "recall": 0.91825,
      "f1": 0.9305801874841653,
      "false_positive_rate": 0.007892857142857142,
      "false_negative_rate": 0.08175
    },
    "DoS": {
      "tp": 3901,
      "fp": 44,
      "fn": 99,
      "tn": 27956,
      "support": 4000,
      "predicted_as_class": 3945,
      "precision": 0.9888466413181242,
      "recall": 0.97525,
      "f1": 0.982001258653241,
      "false_positive_rate": 0.0015714285714285715,
      "false_negative_rate": 0.02475
    },
    "Mirai": {
      "tp": 3918,
      "fp": 95,
      "fn": 82,
      "tn": 27905,
      "support": 4000,
      "predicted_as_class": 4013,
      "precision": 0.9763269374532768,
      "recall": 0.9795,
      "f1": 0.9779108947959566,
      "false_positive_rate": 0.0033928571428571428,
      "false_negative_rate": 0.0205
    },
    "Recon": {
      "tp": 3322,
      "fp": 540,
      "fn": 678,
      "tn": 27460,
      "support": 4000,
      "predicted_as_class": 3862,
      "precision": 0.8601760745727602,
      "recall": 0.8305,
      "f1": 0.8450775883998982,
      "false_positive_rate": 0.019285714285714285,
      "false_negative_rate": 0.1695
    },
    "Spoofing": {
      "tp": 3313,
      "fp": 699,
      "fn": 687,
      "tn": 27301,
      "support": 4000,
      "predicted_as_class": 4012,
      "precision": 0.8257726819541376,
      "recall": 0.82825,
      "f1": 0.827009485771343,
      "false_positive_rate": 0.024964285714285713,
      "false_negative_rate": 0.17175
    },
    "WebBased": {
      "tp": 3277,
      "fp": 950,
      "fn": 723,
      "tn": 27050,
      "support": 4000,
      "predicted_as_class": 4227,
      "precision": 0.7752543174828483,
      "recall": 0.81925,
      "f1": 0.7966451926583202,
      "false_positive_rate": 0.033928571428571426,
      "false_negative_rate": 0.18075
    },
    "BruteForce": {
      "tp": 3627,
      "fp": 517,
      "fn": 373,
      "tn": 27483,
      "support": 4000,
      "predicted_as_class": 4144,
      "precision": 0.8752413127413128,
      "recall": 0.90675,
      "f1": 0.8907170923379175,
      "false_positive_rate": 0.018464285714285714,
      "false_negative_rate": 0.09325
    }
  },
  "confusion_matrix": [
    [
      3422,
      47,
      3,
      7,
      95,
      183,
      129,
      114
    ],
    [
      47,
      3673,
      15,
      44,
      75,
      60,
      54,
      32
    ],
    [
      3,
      18,
      3901,
      10,
      28,
      28,
      6,
      6
    ],
    [
      2,
      32,
      4,
      3918,
      4,
      22,
      15,
      3
    ],
    [
      96,
      28,
      6,
      5,
      3322,
      98,
      366,
      79
    ],
    [
      185,
      39,
      11,
      14,
      71,
      3313,
      243,
      124
    ],
    [
      98,
      34,
      3,
      8,
      219,
      202,
      3277,
      159
    ],
    [
      50,
      23,
      2,
      7,
      48,
      106,
      137,
      3627
    ]
  ]
}
```
