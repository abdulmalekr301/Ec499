# Office Nearest-Neighbor Similarity Audit

Date: 2026-07-30

## Objective

Run the fourth stricter robustness audit recommended by `context/99_office_shuffled_label_sanity_test.md`:

```text
nearest-neighbor train/validation similarity audit
```

The goal is to test whether validation graphs are very close to training graphs under compact graph-level traffic-shape features, even though exact duplicate graph leakage previously passed.

## Command

```bash
.venv/bin/python -m secureedge.office.nearest_neighbor_similarity_audit
```

## Implementation

Added:

```text
secureedge/office/nearest_neighbor_similarity_audit.py
```

The script:

- samples train and validation graph paths from the office graph manifest;
- loads each materialized PyG graph;
- maps each graph back to candidate metadata using `office_candidate_identity`;
- builds a compact 126-dimensional graph-stat vector;
- standardizes vectors on the train sample;
- computes validation-to-train nearest neighbors using cosine distance;
- reports same-class, same-day, same-window, same-PCAP, and same endpoint/service nearest-neighbor rates.

This is not an exact duplicate audit and not a learned embedding audit. It is a sampled traffic-shape similarity audit.

## Configuration

| Field | Value |
| --- | ---: |
| Train cap per class | 5,000 |
| Validation cap per class | 500 |
| Train sample size | 30,206 |
| Validation sample size | 3,103 |
| Vector dimension | 126 |
| Candidate metadata misses | 0 |

Sample counts by class:

| Class | Train | Validation |
| --- | ---: | ---: |
| Benign | 5,000 | 500 |
| BruteForce | 5,000 | 500 |
| DoS | 5,000 | 500 |
| DDoS | 5,000 | 500 |
| WebBased | 206 | 103 |
| Bot | 5,000 | 500 |
| Infiltration | 5,000 | 500 |

## Result

| Metric | Value |
| --- | ---: |
| Median nearest-neighbor cosine distance | 0.0000647 |
| 5th percentile distance | 0.000000 |
| 95th percentile distance | 0.008582 |
| Distances <= 0.001 | 2,462 / 3,103 |
| Distances <= 0.01 | 2,969 / 3,103 |
| Distances <= 0.05 | 3,079 / 3,103 |
| Same-class NN rate | 0.999033 |
| Same-day NN rate | 0.859813 |
| Same-window NN rate | 0.847245 |
| Same-PCAP NN rate | 0.678053 |
| Same endpoint/service NN rate | 0.423461 |

## Per-Class Result

| Class | Count | Median dist | P95 dist | Same class | Same day | Same window | Same PCAP | Same endpoint/service |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Benign | 500 | 0.001327 | 0.039112 | 0.998000 | 0.176000 | 0.174000 | 0.012000 | 0.000000 |
| BruteForce | 500 | 0.000024 | 0.000368 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
| DoS | 500 | 0.001090 | 0.009667 | 0.998000 | 0.998000 | 0.998000 | 0.998000 | 0.998000 |
| DDoS | 500 | 0.000056 | 0.000516 | 1.000000 | 1.000000 | 1.000000 | 1.000000 | 0.134000 |
| WebBased | 103 | 0.000465 | 0.015603 | 1.000000 | 0.786408 | 0.786408 | 1.000000 | 0.786408 |
| Bot | 500 | 0.000000 | 0.000140 | 1.000000 | 1.000000 | 1.000000 | 0.158000 | 0.158000 |
| Infiltration | 500 | 0.000020 | 0.001529 | 0.998000 | 1.000000 | 0.924000 | 0.834000 | 0.176000 |

## Interpretation

This audit strongly supports the split-similarity hypothesis.

The nearest validation neighbor is almost always from the same class, and usually from the same day/window. For several attack classes, the nearest neighbor is also from the same PCAP or endpoint/service group:

- `BruteForce`: same class/day/window/PCAP/endpoint-service rates are all 1.0.
- `DoS`: all same-group rates are 0.998.
- `DDoS`: same class/day/window/PCAP rates are 1.0.
- `Bot`: same class/day/window rates are 1.0.
- `Infiltration`: same day rate is 1.0 and same window rate is 0.924.

This does not contradict the duplicate-graph audit. The problem is not exact duplicate leakage; it is that validation graphs are extremely close to training graphs under traffic-shape features and often share the same day, attack window, PCAP, or endpoint context.

This explains why the real-label model can reach near-perfect validation while the shuffled-label sanity test collapses.

## Artifacts

```text
artifacts/office_model/robustness/nearest_neighbor_similarity/nearest_neighbor_similarity_audit.json
artifacts/office_model/robustness/nearest_neighbor_similarity/nearest_neighbor_similarity_audit.csv
artifacts/office_model/robustness/nearest_neighbor_similarity/nearest_neighbor_similarity_audit.md
```

## Next Audit

Proceed to the next recommendation separately:

```text
feature ablations for ports, protocol, timing, and tuple context
```
