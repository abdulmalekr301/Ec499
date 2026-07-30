# Office Leave-One-Window-Out Audit

Date: 2026-07-30

## Objective

Run the second stricter robustness audit recommended by `context/99_office_shuffled_label_sanity_test.md`:

```text
leave-one-window-out evaluation
```

Before starting expensive retraining, this audit checks whether each leave-one-window-out fold is statistically valid for the current seven-class office dataset.

## Command

```bash
.venv/bin/python -m secureedge.office.leave_one_window_out_audit
```

## Implementation

Added:

```text
secureedge/office/leave_one_window_out_audit.py
```

The script:

- loads the materialized office graph manifest;
- maps every graph back to candidate metadata using `office_candidate_identity`;
- groups graphs by source dataset, day, class, subtype, and ground-truth window;
- treats each group as a potential held-out fold;
- computes remaining class support if that group is removed from training;
- classifies each fold as runnable, weak-support, or invalid zero-shot.

This pass does not retrain the model. It is the required feasibility check before launching leave-one-window-out training folds.

## Result

| Field | Value |
| --- | ---: |
| Materialized graph groups | 20 |
| Runnable candidate folds | 9 |
| Weak-support folds | 8 |
| Invalid zero-shot folds | 3 |
| Minimum remaining train support per class | 1,000 |
| Minimum held-out eval support | 100 |
| Candidate metadata misses | 0 |

## Fold Status

| Class | Day | Window/subtype | Held out | Remaining same class | Status |
| --- | --- | --- | ---: | ---: | --- |
| Benign | Friday-02-03-2018 | no attack window | 3,366 | 20,037 | runnable |
| Bot | Friday-02-03-2018 | Bot | 24,000 | 0 | invalid zero-shot |
| Benign | Friday-16-02-2018 | no attack window | 3,322 | 20,081 | runnable |
| DoS | Friday-16-02-2018 | DoS-Hulk | 24,000 | 0 | invalid zero-shot |
| Benign | Friday-23-02-2018 | no attack window | 3,360 | 20,043 | runnable |
| WebBased | Friday-23-02-2018 | Brute Force-Web | 122 | 290 | weak support |
| WebBased | Friday-23-02-2018 | Brute Force-XSS | 72 | 340 | weak support |
| WebBased | Friday-23-02-2018 | SQL Injection | 27 | 385 | weak support |
| Benign | Thursday-01-03-2018 | no attack window | 3,362 | 20,041 | runnable |
| Infiltration | Thursday-01-03-2018 | 13:53 to 14:55 | 14,016 | 9,974 | runnable |
| Infiltration | Thursday-01-03-2018 | 18:00 to 19:38 | 9,974 | 14,016 | runnable |
| Benign | Thursday-22-02-2018 | no attack window | 3,391 | 20,012 | runnable |
| WebBased | Thursday-22-02-2018 | Brute Force-Web | 135 | 277 | weak support |
| WebBased | Thursday-22-02-2018 | Brute Force-XSS | 40 | 372 | weak support |
| WebBased | Thursday-22-02-2018 | SQL Injection | 16 | 396 | weak support |
| Benign | Wednesday-14-02-2018 | no attack window | 3,284 | 20,119 | runnable |
| BruteForce | Wednesday-14-02-2018 | SSH-Bruteforce | 24,000 | 0 | invalid zero-shot |
| Benign | Wednesday-21-02-2018 | no attack window | 3,318 | 20,085 | runnable |
| DDoS | Wednesday-21-02-2018 | DDOS-HOIC | 23,961 | 39 | weak support |
| DDoS | Wednesday-21-02-2018 | DDOS-LOIC-UDP | 39 | 23,961 | weak support |

## Interpretation

Full leave-one-window-out training is not a valid 20-fold robustness test for the current office graph dataset.

The reason is structural: some classes only have one attack window. Holding out that window removes all training examples for the class:

- `Bot`
- `DoS`
- `BruteForce`

Those folds would test zero-shot class recognition, not ordinary generalization to an unseen window.

Other folds are technically possible but weak:

- `WebBased` has only 412 materialized graphs total, so every WebBased leave-one-window-out fold leaves fewer than 400 same-class training examples.
- `DDoS` is dominated by `DDOS-HOIC`; holding out `DDOS-HOIC` leaves only 39 DDoS training examples, while holding out `DDOS-LOIC-UDP` gives only 39 held-out evaluation examples.

The only attack-window folds that are clean enough for meaningful LOO retraining right now are the two Infiltration windows. Benign day-level folds are also runnable, but they answer a different question from attack-window generalization.

## Decision

Do not launch a full 20-fold leave-one-window-out training sweep.

Recommended next action:

```text
Run only targeted LOO retraining for the two Infiltration windows if we need an actual model-based window holdout result.
```

Then continue to the next robustness audit:

```text
hold out whole PCAP/day/session groups
```

## Artifacts

```text
artifacts/office_model/robustness/leave_one_window_out/leave_one_window_out_audit.json
artifacts/office_model/robustness/leave_one_window_out/leave_one_window_out_audit.csv
artifacts/office_model/robustness/leave_one_window_out/leave_one_window_out_audit.md
```
