# Office Whole-Group Holdout Audit

Date: 2026-07-30

## Objective

Run the third stricter robustness audit recommended by `context/99_office_shuffled_label_sanity_test.md`:

```text
hold out whole PCAP/day/session groups
```

This audit checks whether the current materialized office graph dataset can support strict group-held-out validation at three levels:

- day;
- source PCAP;
- endpoint/service session.

The endpoint/service session key is:

```text
source_dataset | day | src_ip | dst_ip | dst_port | protocol
```

It intentionally excludes `src_port` because source ports are usually ephemeral and would collapse the audit toward per-flow grouping.

## Command

```bash
.venv/bin/python -m secureedge.office.holdout_group_audit
```

## Implementation

Added:

```text
secureedge/office/holdout_group_audit.py
```

The script:

- loads the materialized office graph manifest;
- maps every graph back to candidate metadata using `office_candidate_identity`;
- builds whole-group holdout inventories for day, PCAP, and endpoint/service scopes;
- computes class support remaining after each group is held out;
- classifies each group as runnable, weak-support, or invalid zero-shot.

This pass does not retrain the model. It identifies which whole-group holdout folds are valid enough to justify retraining.

## Result

| Scope | Groups | Runnable | Weak support | Invalid zero-shot |
| --- | ---: | ---: | ---: | ---: |
| Day | 7 | 0 | 2 | 5 |
| PCAP | 3,040 | 26 | 3,011 | 3 |
| Endpoint/service | 20,469 | 21 | 20,446 | 2 |

Candidate metadata misses:

```text
0
```

Full CSV inventory:

```text
23,517 rows
```

## Day-Level Holdout

No whole-day fold is cleanly runnable.

| Held-out day | Held-out graphs | Status | Reason |
| --- | ---: | --- | --- |
| Friday-02-03-2018 | 27,366 | invalid zero-shot | removes all `Bot` training support |
| Friday-16-02-2018 | 27,322 | invalid zero-shot | removes all `DoS` training support |
| Friday-23-02-2018 | 3,581 | weak support | leaves only 191 `WebBased` graphs |
| Thursday-01-03-2018 | 27,352 | invalid zero-shot | removes all `Infiltration` training support |
| Thursday-22-02-2018 | 3,582 | weak support | leaves only 221 `WebBased` graphs |
| Wednesday-14-02-2018 | 27,284 | invalid zero-shot | removes all `BruteForce` training support |
| Wednesday-21-02-2018 | 27,318 | invalid zero-shot | removes all `DDoS` training support |

## PCAP-Level Holdout

PCAP-level holdout is less structurally broken than day-level holdout, but most PCAP folds are too small to be useful as validation folds.

| Field | Value |
| --- | ---: |
| PCAP groups | 3,040 |
| Runnable PCAP folds | 26 |
| Weak-support PCAP folds | 3,011 |
| Invalid zero-shot PCAP folds | 3 |

Largest invalid PCAP folds:

| Day | PCAP | Held-out graphs | Reason |
| --- | --- | ---: | --- |
| Wednesday-14-02-2018 | `UCAP172.31.69.25` | 24,002 | removes all `BruteForce` training support |
| Wednesday-21-02-2018 | `UCAP172.31.69.28 part 1` | 24,001 | removes all `DDoS` training support |
| Friday-16-02-2018 | `UCAP172.31.69.25-part1.pcap` | 24,000 | removes all `DoS` training support |

## Endpoint/Service Holdout

Endpoint/service holdout produces many groups, but most are too small to serve as meaningful validation folds under the current minimum held-out support threshold.

| Field | Value |
| --- | ---: |
| Endpoint/service groups | 20,469 |
| Runnable endpoint/service folds | 21 |
| Weak-support endpoint/service folds | 20,446 |
| Invalid zero-shot endpoint/service folds | 2 |

Largest invalid endpoint/service folds:

| Day | Endpoint/service | Held-out graphs | Reason |
| --- | --- | ---: | --- |
| Friday-16-02-2018 | `18.219.193.20 -> 172.31.69.25:80/6` | 24,000 | removes all `DoS` training support |
| Wednesday-14-02-2018 | `13.58.98.64 -> 172.31.69.25:22/6` | 24,000 | removes all `BruteForce` training support |

## Interpretation

Whole-day holdout is not a valid seven-class robustness evaluation for the current materialized dataset. Most attack classes are day-local, so holding out the day removes that class from training entirely.

PCAP-level and endpoint/service-level holdouts are more promising structurally, but the current graph distribution is heavily fragmented. Most groups fail the minimum held-out support threshold of 100 graphs, which would make validation metrics too noisy.

The cleanest next model-based robustness checks should not be broad whole-day folds. Better candidates are:

- targeted Infiltration leave-one-window-out retraining;
- selected PCAP folds from the 26 runnable PCAP groups;
- selected endpoint/service folds from the 21 runnable endpoint/service groups.

## Artifacts

```text
artifacts/office_model/robustness/holdout_groups/holdout_group_audit.json
artifacts/office_model/robustness/holdout_groups/holdout_group_audit.csv
artifacts/office_model/robustness/holdout_groups/holdout_group_audit.md
```

## Next Audit

Proceed to the next recommendation separately:

```text
nearest-neighbor train/validation similarity audit
```
