# Office Grouped Validation By Attack Window Audit

Date: 2026-07-30

## Objective

Run the first stricter robustness audit recommended by `context/99_office_shuffled_label_sanity_test.md`:

```text
grouped validation by attack window
```

The goal is to check whether the current validation split contains attack-window/day groups that are also represented in training. This is a robustness audit of the split design, not a retraining experiment.

## Command

```bash
.venv/bin/python -m secureedge.office.grouped_window_audit
```

## Implementation

Added:

```text
secureedge/office/grouped_window_audit.py
```

The script:

- loads the materialized office graph manifest;
- maps each graph back to its candidate metadata using `office_candidate_identity`;
- groups candidates by source dataset, day, class, subtype, and ground-truth attack window;
- evaluates the current checkpoint on validation;
- writes JSON, CSV, and Markdown artifacts under `artifacts/office_model/robustness/grouped_window/`.

## Result

| Field | Value |
| --- | ---: |
| Checkpoint epoch | 11 |
| Validation graphs evaluated | 12,051 |
| Train groups | 20 |
| Validation groups | 20 |
| Test groups | 20 |
| Validation groups present in train | 20 |
| Validation groups absent from train | 0 |
| Candidate metadata misses | 0 |
| Overall validation accuracy | 0.999585 |
| Overall validation macro-F1 | 0.999638 |
| Overall validation weighted-F1 | 0.999585 |

## Group Coverage

Every validation group is represented in training. This means the current graph split is not a strict attack-window-held-out validation split.

| Class | Day | Window/subtype | Train | Val | Test |
| --- | --- | --- | ---: | ---: | ---: |
| Benign | Friday-02-03-2018 | no attack window | 2,808 | 281 | 277 |
| Bot | Friday-02-03-2018 | Bot, 2018-03-02 14:11 to 19:55 | 20,000 | 2,000 | 2,000 |
| Benign | Friday-16-02-2018 | no attack window | 2,798 | 274 | 250 |
| DoS | Friday-16-02-2018 | DoS-Hulk, 2018-02-16 17:45 to 18:19 | 20,000 | 2,000 | 2,000 |
| Benign | Friday-23-02-2018 | no attack window | 2,775 | 274 | 311 |
| WebBased | Friday-23-02-2018 | Brute Force-Web, 2018-02-23 14:03 to 15:03 | 60 | 29 | 33 |
| WebBased | Friday-23-02-2018 | Brute Force-XSS, 2018-02-23 17:00 to 18:10 | 37 | 20 | 15 |
| WebBased | Friday-23-02-2018 | SQL Injection, 2018-02-23 19:05 to 19:18 | 16 | 4 | 7 |
| Benign | Thursday-01-03-2018 | no attack window | 2,809 | 289 | 264 |
| Infiltration | Thursday-01-03-2018 | Infiltration, 2018-03-01 13:53 to 14:55 | 11,722 | 1,121 | 1,173 |
| Infiltration | Thursday-01-03-2018 | Infiltration, 2018-03-01 18:00 to 19:38 | 8,269 | 878 | 827 |
| Benign | Thursday-22-02-2018 | no attack window | 2,840 | 261 | 290 |
| WebBased | Thursday-22-02-2018 | Brute Force-Web, 2018-02-22 14:17 to 15:24 | 70 | 30 | 35 |
| WebBased | Thursday-22-02-2018 | Brute Force-XSS, 2018-02-22 17:50 to 18:29 | 18 | 13 | 9 |
| WebBased | Thursday-22-02-2018 | SQL Injection, 2018-02-22 20:15 to 20:29 | 5 | 7 | 4 |
| Benign | Wednesday-14-02-2018 | no attack window | 2,733 | 278 | 273 |
| BruteForce | Wednesday-14-02-2018 | SSH-Bruteforce, 2018-02-14 18:01 to 19:31 | 20,000 | 2,000 | 2,000 |
| Benign | Wednesday-21-02-2018 | no attack window | 2,740 | 292 | 286 |
| DDoS | Wednesday-21-02-2018 | DDOS-HOIC, 2018-02-21 18:05 to 19:05 | 19,967 | 1,997 | 1,997 |
| DDoS | Wednesday-21-02-2018 | DDOS-LOIC-UDP, 2018-02-21 14:09 to 14:43 | 33 | 3 | 3 |

## Interpretation

This audit raises a real robustness concern.

The shuffled-label sanity test already argued against direct label leakage or a broken evaluator. This grouped-window audit now shows a more plausible explanation for the near-perfect real-label validation score: validation examples come from the same day/window groups as training examples.

That does not prove the model is invalid, and it does not mean graph duplicates are present. It means the current validation score should be treated as an in-distribution graph-level score, not as evidence of generalization to unseen attack windows, days, PCAPs, or sessions.

One metric nuance: per-window macro-F1 can drop to roughly `0.499` for a single-class group with one cross-class error because sklearn averages over labels present in the group or predicted by the model. For isolated one-class windows, group accuracy and weighted-F1 are the clearer read.

## Artifacts

```text
artifacts/office_model/robustness/grouped_window/grouped_validation_by_attack_window.json
artifacts/office_model/robustness/grouped_window/grouped_validation_by_attack_window.csv
artifacts/office_model/robustness/grouped_window/grouped_validation_by_attack_window.md
```

## Next Audit

Proceed to the next recommendation separately:

```text
leave-one-window-out evaluation
```
