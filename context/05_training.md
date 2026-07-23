# HGNN Training

Generated: `2026-07-07T11:52:22+00:00`

## Action
- Trained `SecureEdgeHGNN` on graph files from `/var/home/alucard-00/EC499/data/graphs/train`.
- Evaluated each epoch on validation graph files from `/var/home/alucard-00/EC499/data/graphs/val`.
- Reserved test graph files under `/var/home/alucard-00/EC499/data/graphs/test` for final evaluation.
- Best validation macro F1: `0.952067`.
- Batch size: `256` graph objects.
- Gradient accumulation steps: `2`.
- Effective batch size: `512` graph objects.
- Evaluation batch size: `256` graph objects.
- AMP enabled: `False`.
- Device: `cuda`.
- Run log: `/var/home/alucard-00/EC499/context/logs-21.md`.
- History JSON: `/var/home/alucard-00/EC499/artifacts/training_runs/run_21_history.json`.
- History CSV: `/var/home/alucard-00/EC499/artifacts/training_runs/run_21_history.csv`.
- Training limit per class: `full split`.
- Validation limit per class: `full split`.
- Warmup: `5` epochs from `0.0003` to `0.003`.
- Weight decay: `1e-05`.
- Scheduler: `cosine`, min LR `1e-05`.
- Label smoothing: `0.0`.
- Resume from checkpoint: `False`.
- Resume checkpoint path: `not used`.
- Loss: plain `CrossEntropyLoss()` with no class weights and no label smoothing.
- Saved this run's best checkpoint to `/var/home/alucard-00/EC499/artifacts/training_runs/run_21_best_hgnn.pt`.
- Promoted to global checkpoint `/var/home/alucard-00/EC499/artifacts/best_hgnn.pt` only if this run beat the existing global macro F1.

## Last Epoch
```json
{
  "run": 21,
  "epoch": 218,
  "train_loss": 0.08050101182307116,
  "accuracy": 0.9679979734864477,
  "macro_f1": 0.9472724711234095,
  "learning_rate": 0.00023460830860972908,
  "batch_size": 256,
  "grad_accum_steps": 2,
  "effective_batch_size": 512,
  "eval_batch_size": 256,
  "use_amp": false,
  "heads": 2,
  "scheduler": "cosine",
  "scheduler_monitor": "cosine",
  "scheduler_metric": 0.9472724711234095,
  "stale_epochs": 75,
  "best_f1_so_far": 0.9520667851047279,
  "is_best": false,
  "epoch_duration_seconds": 130.2276121449977,
  "seconds": 130.2276121449977,
  "cosine_cycle": 3,
  "correct": 11464,
  "incorrect": 379,
  "total": 11843,
  "per_class": {
    "Benign": {
      "tp": 1917,
      "fp": 70,
      "fn": 83,
      "tn": 9773,
      "support": 2000,
      "predicted_as_class": 1987,
      "precision": 0.964771011575239,
      "recall": 0.9585,
      "f1": 0.9616252821670429,
      "false_positive_rate": 0.007111652951335975,
      "false_negative_rate": 0.0415
    },
    "DDoS": {
      "tp": 1984,
      "fp": 12,
      "fn": 16,
      "tn": 9831,
      "support": 2000,
      "predicted_as_class": 1996,
      "precision": 0.9939879759519038,
      "recall": 0.992,
      "f1": 0.9929929929929929,
      "false_positive_rate": 0.0012191405059433099,
      "false_negative_rate": 0.008
    },
    "DoS": {
      "tp": 1979,
      "fp": 10,
      "fn": 21,
      "tn": 9833,
      "support": 2000,
      "predicted_as_class": 1989,
      "precision": 0.9949723479135244,
      "recall": 0.9895,
      "f1": 0.9922286287290047,
      "false_positive_rate": 0.001015950421619425,
      "false_negative_rate": 0.0105
    },
    "Mirai": {
      "tp": 1999,
      "fp": 0,
      "fn": 1,
      "tn": 9843,
      "support": 2000,
      "predicted_as_class": 1999,
      "precision": 1.0,
      "recall": 0.9995,
      "f1": 0.9997499374843711,
      "false_positive_rate": 0.0,
      "false_negative_rate": 0.0005
    },
    "Recon": {
      "tp": 1806,
      "fp": 38,
      "fn": 123,
      "tn": 9876,
      "support": 1929,
      "predicted_as_class": 1844,
      "precision": 0.9793926247288504,
      "recall": 0.9362363919129082,
      "f1": 0.9573283858998144,
      "false_positive_rate": 0.003832963485979423,
      "false_negative_rate": 0.06376360808709176
    },
    "Spoofing": {
      "tp": 1267,
      "fp": 92,
      "fn": 79,
      "tn": 10405,
      "support": 1346,
      "predicted_as_class": 1359,
      "precision": 0.9323031640912436,
      "recall": 0.9413075780089153,
      "f1": 0.9367837338262477,
      "false_positive_rate": 0.008764408878727255,
      "false_negative_rate": 0.058692421991084695
    },
    "WebBased": {
      "tp": 333,
      "fp": 149,
      "fn": 53,
      "tn": 11308,
      "support": 386,
      "predicted_as_class": 482,
      "precision": 0.6908713692946058,
      "recall": 0.8626943005181347,
      "f1": 0.7672811059907834,
      "false_positive_rate": 0.013005149690145762,
      "false_negative_rate": 0.13730569948186527
    },
    "BruteForce": {
      "tp": 179,
      "fp": 8,
      "fn": 3,
      "tn": 11653,
      "support": 182,
      "predicted_as_class": 187,
      "precision": 0.9572192513368984,
      "recall": 0.9835164835164835,
      "f1": 0.970189701897019,
      "false_positive_rate": 0.0006860475087899837,
      "false_negative_rate": 0.016483516483516484
    }
  },
  "confusion_matrix": [
    [
      1917,
      5,
      1,
      0,
      0,
      59,
      14,
      4
    ],
    [
      1,
      1984,
      3,
      0,
      4,
      4,
      3,
      1
    ],
    [
      2,
      1,
      1979,
      0,
      10,
      7,
      1,
      0
    ],
    [
      0,
      0,
      0,
      1999,
      0,
      1,
      0,
      0
    ],
    [
      5,
      5,
      1,
      0,
      1806,
      8,
      103,
      1
    ],
    [
      48,
      1,
      4,
      0,
      0,
      1267,
      26,
      0
    ],
    [
      13,
      0,
      1,
      0,
      24,
      13,
      333,
      2
    ],
    [
      1,
      0,
      0,
      0,
      0,
      0,
      2,
      179
    ]
  ]
}
```
