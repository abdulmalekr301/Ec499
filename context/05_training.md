# HGNN Training

Generated: `2026-06-17T04:31:15+00:00`

## Action
- Trained `SecureEdgeHGNN` on graph files from `/var/home/alucard-00/EC499/data/graphs/train`.
- Evaluated each epoch on graph files from `/var/home/alucard-00/EC499/data/graphs/test`.
- Best macro F1: `0.874432`.
- Batch size: `512` graph objects.
- Device: `cuda`.
- Run log: `/var/home/alucard-00/EC499/context/logs-4.md`.
- History JSON: `/var/home/alucard-00/EC499/artifacts/training_runs/run_04_history.json`.
- History CSV: `/var/home/alucard-00/EC499/artifacts/training_runs/run_04_history.csv`.
- Training limit per class: `full split`.
- Evaluation limit per class: `full split`.
- Warmup: `5` epochs from `0.0003` to `0.003`.
- Weight decay: `1e-05`.
- Scheduler: `cosine`, min LR `1e-05`.
- Label smoothing: `0.0`.
- Focal gamma: `2.0`.
- Class weights: `[1.0, 1.0, 1.0, 1.0, 1.6832183599472046, 1.0, 1.7107176780700684, 2.998950481414795]`.
- Deduped training shards: `True`.
- Flow noise augmentation: `0.02`.
- Packet mask augmentation: `0.15`.
- Saved best checkpoint to `/var/home/alucard-00/EC499/artifacts/best_hgnn.pt`.

## Last Epoch
```json
{
  "epoch": 300,
  "train_loss": 0.17134579162602223,
  "accuracy": 0.87175,
  "macro_f1": 0.8723003957995186,
  "learning_rate": 6.0836668956540943e-05,
  "stale_epochs": 3,
  "best_f1_so_far": 0.874432291470407,
  "is_best": false,
  "epoch_duration_seconds": 118.7811561760027,
  "cosine_cycle": 3,
  "correct": 27896,
  "incorrect": 4104,
  "total": 32000,
  "per_class": {
    "Benign": {
      "tp": 3541,
      "fp": 669,
      "fn": 459,
      "tn": 27331,
      "support": 4000,
      "predicted_as_class": 4210,
      "precision": 0.8410926365795725,
      "recall": 0.88525,
      "f1": 0.8626065773447016,
      "false_positive_rate": 0.023892857142857143,
      "false_negative_rate": 0.11475
    },
    "DDoS": {
      "tp": 3686,
      "fp": 202,
      "fn": 314,
      "tn": 27798,
      "support": 4000,
      "predicted_as_class": 3888,
      "precision": 0.948045267489712,
      "recall": 0.9215,
      "f1": 0.9345841784989858,
      "false_positive_rate": 0.007214285714285714,
      "false_negative_rate": 0.0785
    },
    "DoS": {
      "tp": 3884,
      "fp": 47,
      "fn": 116,
      "tn": 27953,
      "support": 4000,
      "predicted_as_class": 3931,
      "precision": 0.9880437547697787,
      "recall": 0.971,
      "f1": 0.9794477367292901,
      "false_positive_rate": 0.0016785714285714286,
      "false_negative_rate": 0.029
    },
    "Mirai": {
      "tp": 3905,
      "fp": 107,
      "fn": 95,
      "tn": 27893,
      "support": 4000,
      "predicted_as_class": 4012,
      "precision": 0.9733300099700898,
      "recall": 0.97625,
      "f1": 0.9747878182725911,
      "false_positive_rate": 0.0038214285714285715,
      "false_negative_rate": 0.02375
    },
    "Recon": {
      "tp": 3240,
      "fp": 641,
      "fn": 760,
      "tn": 27359,
      "support": 4000,
      "predicted_as_class": 3881,
      "precision": 0.8348363823756764,
      "recall": 0.81,
      "f1": 0.822230681385611,
      "false_positive_rate": 0.022892857142857142,
      "false_negative_rate": 0.19
    },
    "Spoofing": {
      "tp": 3291,
      "fp": 663,
      "fn": 709,
      "tn": 27337,
      "support": 4000,
      "predicted_as_class": 3954,
      "precision": 0.8323216995447648,
      "recall": 0.82275,
      "f1": 0.8275081719889363,
      "false_positive_rate": 0.023678571428571427,
      "false_negative_rate": 0.17725
    },
    "WebBased": {
      "tp": 3108,
      "fp": 1182,
      "fn": 892,
      "tn": 26818,
      "support": 4000,
      "predicted_as_class": 4290,
      "precision": 0.7244755244755244,
      "recall": 0.777,
      "f1": 0.7498190591073582,
      "false_positive_rate": 0.04221428571428571,
      "false_negative_rate": 0.223
    },
    "BruteForce": {
      "tp": 3241,
      "fp": 593,
      "fn": 759,
      "tn": 27407,
      "support": 4000,
      "predicted_as_class": 3834,
      "precision": 0.8453312467396974,
      "recall": 0.81025,
      "f1": 0.8274189430686751,
      "false_positive_rate": 0.02117857142857143,
      "false_negative_rate": 0.18975
    }
  },
  "confusion_matrix": [
    [
      3541,
      24,
      0,
      0,
      62,
      133,
      122,
      118
    ],
    [
      55,
      3686,
      15,
      55,
      67,
      42,
      51,
      29
    ],
    [
      5,
      17,
      3884,
      13,
      37,
      25,
      14,
      5
    ],
    [
      3,
      45,
      5,
      3905,
      6,
      20,
      11,
      5
    ],
    [
      112,
      32,
      3,
      5,
      3240,
      85,
      426,
      97
    ],
    [
      189,
      22,
      18,
      13,
      70,
      3291,
      272,
      125
    ],
    [
      128,
      20,
      2,
      8,
      300,
      220,
      3108,
      214
    ],
    [
      177,
      42,
      4,
      13,
      99,
      138,
      286,
      3241
    ]
  ]
}
```
