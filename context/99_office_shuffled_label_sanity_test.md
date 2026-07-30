# Office Shuffled-Label Sanity Test

Date: 2026-07-30

## Objective

Run a shuffled-label sanity test for the CIC-IDS-2018 office model.

The test randomly permutes the training labels in memory, preserves the original training class distribution, trains for several epochs, and evaluates against the real validation labels.

Expected outcome:

```text
validation performance should collapse toward chance
```

Concerning outcome:

```text
validation performance stays high despite shuffled training labels
```

## Implementation

Added:

```text
secureedge/office/shuffled_label_sanity.py
```

Command used:

```bash
.venv/bin/python -m secureedge.office.shuffled_label_sanity --epochs 3
```

The script does not overwrite:

```text
artifacts/office_model/best_office_hgnn.pt
```

It writes separate sanity-test artifacts under:

```text
artifacts/office_model/sanity/shuffled_labels/
```

## Configuration

| Field | Value |
| --- | --- |
| Seed | 42 |
| Epochs | 3 |
| Device used by sanity run | CPU |
| Model | `SecureEdgeHGNN` |
| Attention convolution | `GATv2Conv` |
| Train graphs | 119,700 |
| Validation graphs | 12,051 |
| Batch size | 512 |
| Gradient accumulation | 1 |
| AMP | disabled because device was CPU |

The run preserved the original training label distribution:

| Class | Shuffled train labels |
| --- | ---: |
| Benign | 19,503 |
| BruteForce | 20,000 |
| DoS | 20,000 |
| DDoS | 20,000 |
| WebBased | 206 |
| Bot | 20,000 |
| Infiltration | 19,991 |

Because the shuffle is a permutation, some samples keep their original label by chance:

```text
train_label_agreement_count = 19,668
train_label_agreement_rate = 0.164311
```

This is expected with the current class distribution.

## Results

| Epoch | Train loss | Validation accuracy | Validation macro-F1 | Validation weighted-F1 | LR | Seconds |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.634133 | 0.006721 | 0.003242 | 0.001342 | 0.00084 | 166.40 |
| 2 | 0.463665 | 0.015932 | 0.023663 | 0.027084 | 0.00138 | 167.32 |
| 3 | 0.415879 | 0.004813 | 0.004028 | 0.004666 | 0.00192 | 172.65 |

Final epoch per-class validation F1:

| Class | Validation F1 |
| --- | ---: |
| Benign | 0.002771 |
| BruteForce | 0.000000 |
| DoS | 0.000000 |
| DDoS | 0.000000 |
| WebBased | 0.000000 |
| Bot | 0.006832 |
| Infiltration | 0.018591 |

## Interpretation

The shuffled-label sanity test passed.

Validation macro-F1 collapsed from the real-label run's near-perfect range:

```text
real-label validation macro-F1 around 0.995 to 0.999
```

to near zero:

```text
shuffled-label validation macro-F1 from 0.003 to 0.024
```

This strongly argues against:

- direct label leakage from graph tensors into the model;
- an evaluation bug that recovers true labels regardless of training labels;
- exact duplicate labels driving validation performance by themselves.

The previous high real-label validation scores are therefore more consistent with:

- train/validation distribution similarity;
- same-day or same-window session similarity;
- endpoint, port, protocol, timing, and traffic-shape shortcuts;
- graph-level splitting being too weak for deployment-style generalization claims.

## Artifact Paths

```text
artifacts/office_model/sanity/shuffled_labels/shuffled_label_sanity_result.json
artifacts/office_model/sanity/shuffled_labels/shuffled_label_sanity_history.csv
artifacts/office_model/sanity/shuffled_labels/shuffled_label_sanity_report.md
```

## Next Recommendation

Proceed with stricter robustness testing rather than spending more time on exact duplicate leakage.

Recommended next audits:

1. grouped validation by attack window;
2. leave-one-window-out evaluation;
3. hold out whole PCAP/day/session groups;
4. nearest-neighbor train/validation similarity audit;
5. feature ablations for ports, protocol, timing, and tuple context.
