# Office DoS-SlowHTTPTest Almost-True Exception Generation

Date: 2026-08-01

## Purpose

The strict office candidate gate leaves `DoS-SlowHTTPTest` with zero eligible samples. To add limited DoS subtype diversity, this run selected and materialized `4,000` almost-true exception samples from the `DoS-SlowHTTPTest` ground-truth window.

This is a stronger bend than the FTP-BruteForce exception: the rows are inside the `DoS-SlowHTTPTest` IP/time window, but their corrected CSV label is `FTP-BruteForce - Attempted` and their corrected CSV class is `BruteForce`.

## Window Audit

| Metric | Count |
|---|---:|
| Ground-truth `DoS-SlowHTTPTest` rows | 105,550 |
| `FTP-BruteForce - Attempted` rows | 105,520 |
| `BENIGN` rows | 30 |
| TCP rows | 105,550 |
| Endpoint PCAP-backed rows | 105,550 |
| Candidate pool after hard filters | 105,520 |

Observed traffic shape:

- Source: `13.59.126.31`
- Destination: `172.31.69.25`
- Protocol: TCP / `6`
- Service port: `21`
- Common flags: SYN, ACK, RST
- Payload bytes: `0`

## Selection Policy

| Field | Value |
|---|---|
| Policy ID | `dos_slowhttptest_almost_true_attempts_v1_temporal_tie_break` |
| Target | 4,000 |
| Selected | 4,000 |
| Assigned training class | `DoS` |
| Preserved original CSV class | `BruteForce` |
| Preserved candidate label | `FTP-BruteForce - Attempted` |

Hard filters:

- Ground-truth window must be `DoS-SlowHTTPTest`.
- Corrected CSV class must be `BruteForce`.
- Corrected CSV label must be `FTP-BruteForce - Attempted`.
- Protocol must be TCP / `6`.
- Source or destination port must be `21`.
- Endpoint PCAP must be available.

Ranking prioritized bidirectional TCP-control evidence, SYN/RST/ACK flags, service-port evidence, packet counts, timing, header length, and packet rate. The highest-evidence bucket contained `46,496` records, so the selected `4,000` were sampled evenly across timestamp order inside that strongest bucket.

| Selection metric | Value |
|---|---:|
| Highest-evidence bucket size | 46,496 |
| Selected from highest-evidence bucket | 4,000 |
| Covered minute buckets | 54 |
| First selected minute | `2018-02-16 14:12` |
| Last selected minute | `2018-02-16 15:05` |
| Max selected records in one minute | 82 |

## Candidate Outputs

| Output | Path |
|---|---|
| Candidate JSONL | `artifacts/office_model/exception_candidates/dos_slowhttptest_almost_true_top4000.jsonl` |
| Selection manifest | `artifacts/office_model/exception_candidates/dos_slowhttptest_almost_true_top4000_manifest.json` |

## Graph Generation

| Metric | Count |
|---|---:|
| Requested candidates | 4,000 |
| Matched candidates | 4,000 |
| Materialized compact graphs | 4,000 |
| Remaining candidates | 0 |
| Zero-packet graphs | 0 |
| Duplicate flow hashes | 0 |
| Local temporal fallback graphs | 4,000 |
| Safety-flagged graphs | 4,000 |

The safety flags are expected for this exception set because these are zero-payload TCP-control attempts. The generic safety rule flags them as `payload_nonzero_fraction_outlier`.

Graph-generation outputs:

| Output | Path |
|---|---|
| Compact graph directory | `data/graphs/office_compact/DoS` |
| Graph-generation manifest | `artifacts/office_model/exception_candidates/dos_slowhttptest_almost_true_graph_generation_manifest.json` |
| Work directory | `artifacts/office_model/materialization_work/dos_slowhttptest_exception` |
| Presliced PCAP | `artifacts/office_model/materialization_work/pcap_slices/UCAP172.31.69.25-part1_21bf134025b00e7a_2e04c7bbf508c4e7.pcap` |

## Metadata Validation

Final compact records preserve the exception lineage:

| Field | Value |
|---|---|
| `class_name` | `DoS` |
| `label` | `2` |
| `gt_subtype` | `DoS-SlowHTTPTest` |
| `candidate_label` | `FTP-BruteForce - Attempted` |
| `original_csv_class` | `BruteForce` |
| `original_label_status` | `excluded_attempted_or_non_success` |
| `exception_policy` | `dos_slowhttptest_almost_true_attempts_v1_temporal_tie_break` |
| `recovered_attempted` | `true` |

## DoS Compact Inventory After Run

| DoS subtype | Compact graph count |
|---|---:|
| Existing standard DoS records without subtype metadata | 24,000 |
| `DoS-SlowHTTPTest` exception records | 4,000 |
| Total DoS compact records | 28,000 |

## Current Integration Status

These `DoS-SlowHTTPTest` exception graphs are compact materialized and auditable, but they have not yet been assigned into train/validation/test splits or converted into PyG `.pt` training graphs. Split assignment should be handled deliberately because these samples are not strict true-success SlowHTTPTest records.
