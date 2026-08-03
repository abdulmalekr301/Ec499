# Office FTP-BruteForce Attempted Graph Generation

Date: 2026-08-01

## Action

Generated compact office graph records for the `FTP-BruteForce` exception candidate pool created by `ftp_bruteforce_strongest_attempts_v2_temporal_tie_break`.

These graphs are intentionally exception-tagged because the source rows remain `FTP-BruteForce - Attempted`, not successful FTP brute-force attacks.

## Inputs

| Input | Value |
|---|---|
| Candidate JSONL | `artifacts/office_model/exception_candidates/ftp_bruteforce_attempted_top12000.jsonl` |
| Candidate count | `12,000` |
| Source endpoint PCAP | `datasets/cic_ids_2018/raw_pcaps/Wednesday-14-02-2018/pcap/UCAP172.31.69.25` |
| Preslice window | `30.0` seconds |
| Timestamp tolerance | `3.0` seconds |
| Temporal context | worker-local fallback |

## Outputs

| Output | Value |
|---|---|
| Compact graph directory | `data/graphs/office_compact/BruteForce` |
| Graph-generation manifest | `artifacts/office_model/exception_candidates/ftp_bruteforce_attempted_graph_generation_manifest.json` |
| Worker summary | `artifacts/office_model/materialization_work/ftp_bruteforce_exception/ftp_bruteforce_attempted_top12000.worker_summary.json` |
| Presliced PCAP | `artifacts/office_model/materialization_work/pcap_slices/UCAP172.31.69_297fe3088e21e102_3e2da389c57f7b08.pcap` |

## Run Summary

| Metric | Count |
|---|---:|
| Requested candidates | 12,000 |
| Matched candidates | 12,000 |
| Materialized compact graphs | 12,000 |
| Remaining candidates | 0 |
| Zero-packet graphs | 0 |
| Duplicate flow hashes | 0 |
| Local temporal fallback graphs | 12,000 |
| Safety-flagged graphs | 12,000 |

The safety flags are expected for this exception set: every graph is a closed-port TCP-control attempt with `payload_nonzero_fraction=0.0`, so the generic payload outlier rule flags them.

## BruteForce Compact Inventory After Run

| BruteForce subtype | Compact graph count |
|---|---:|
| Existing standard BruteForce records without subtype metadata | 24,000 |
| `FTP-BruteForce` exception records | 12,000 |
| Total BruteForce compact records | 36,000 |

## Metadata Fix

During validation, the first materialization pass produced graph tensors but did not preserve exception lineage fields in the compact records. The compact enrichment allowlist in `secureedge/data/office_pipeline.py` was updated to preserve:

- `gt_subtype`
- `candidate_label`
- `recovered_attempted`
- `exception_policy`
- `exception_reason`
- `attempted_category`
- `exception_rank`
- `evidence_score`

The FTP worker was then rerun with overwrite enabled. The final compact records now carry:

| Field | Value |
|---|---|
| `gt_subtype` | `FTP-BruteForce` |
| `candidate_label` | `FTP-BruteForce - Attempted` |
| `exception_policy` | `ftp_bruteforce_strongest_attempts_v2_temporal_tie_break` |
| `recovered_attempted` | `true` |

## Current Integration Status

These graphs are compact materialized and auditable, but they have not yet been assigned to train/validation/test splits or converted into PyG `.pt` graph files. Split assignment should be handled separately so the exception samples can be placed intentionally, rather than silently mixed into the existing BruteForce training set.
