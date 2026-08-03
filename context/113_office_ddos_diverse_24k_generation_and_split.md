# Office DDoS Diverse 24k Generation And Split

Date: 2026-08-02

## Objective

Generate and select a duplicate-free, strict-label DDoS class mix with 24,000 compact graph samples while improving subtype diversity beyond the original HOIC-heavy pool.

## Generation Run

The missing Tuesday LOIC HTTP/UDP candidates were materialized from:

`artifacts/office_model/materialization_work/tuesday20_ddos_loic_victim_attackers_port80.pcap`

Candidate file:

`artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_diverse_24k_missing_generation.jsonl`

Command:

```bash
SECUREEDGE_FLOW_SEGMENT_PACKET_LIMIT=20 .venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-pcap-worker \
  --office-worker-pcap artifacts/office_model/materialization_work/tuesday20_ddos_loic_victim_attackers_port80.pcap \
  --office-worker-candidates artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_diverse_24k_missing_generation.jsonl \
  --office-worker-summary artifacts/office_model/materialization_work/ddos_tuesday20_loic_http_udp_diverse_24k_missing_generation.summary.json \
  --office-timestamp-tolerance-seconds 3.0 \
  --office-max-flows-per-pcap 0 \
  --office-allow-local-temporal-fallback
```

The worker stopped at the configured memory floor:

```text
status: worker_error
candidate_count: 11518
matched: 11488
remaining: 30
flows_scanned: 4653800
zero_packet_flow_hashes: 0
error: available memory is 2.00 GiB, below configured floor 2.00 GiB
```

This was a resource guard stop, not a label-quality failure. The run successfully materialized all requested LOIC-HTTP graphs and all but 30 of the requested Tuesday LOIC-UDP graphs.

## Available DDoS Pool After Generation

| Subtype | Available compact graphs |
| --- | ---: |
| DDOS-HOIC | 23,961 |
| DDOS-LOIC-HTTP | 10,736 |
| DDOS-LOIC-UDP | 2,497 |
| Total | 37,194 |

The LOIC-UDP total includes the earlier Wednesday UDP materialization plus the Tuesday strict-label UDP graphs that were successfully materialized before the memory stop.

## Final 24k DDoS Mix

Because the worker stopped 30 UDP graphs short, the final strict-label 24k mix uses all available LOIC-HTTP, all available LOIC-UDP, and fills the remaining slots with duplicate-free HOIC:

| Subtype | Selected graphs |
| --- | ---: |
| DDOS-HOIC | 10,767 |
| DDOS-LOIC-HTTP | 10,736 |
| DDOS-LOIC-UDP | 2,497 |
| Total | 24,000 |

## Split

| Split | DDOS-HOIC | DDOS-LOIC-HTTP | DDOS-LOIC-UDP | Total |
| --- | ---: | ---: | ---: | ---: |
| train | 8,973 | 8,946 | 2,081 | 20,000 |
| val | 897 | 895 | 208 | 2,000 |
| test | 897 | 895 | 208 | 2,000 |
| Total | 10,767 | 10,736 | 2,497 | 24,000 |

## Duplicate And Label Validation

Validation over the selected 24,000 paths found:

| Check | Result |
| --- | ---: |
| selected rows | 24,000 |
| missing files | 0 |
| zero-packet selected graphs | 0 |
| label/subtype mismatches | 0 |
| duplicate flow hash surplus | 0 |
| duplicate compact tensor hash surplus | 0 |

## Artifacts

| Artifact | Path |
| --- | --- |
| DDoS 24k selection JSONL | `artifacts/office_model/balanced_subtype_sets/ddos_diverse_24k_paths.jsonl` |
| DDoS 24k selection manifest | `artifacts/office_model/balanced_subtype_sets/ddos_diverse_24k_manifest.json` |
| DoS+DDoS diverse cumulative manifest variant | `artifacts/office_model/office_compact_cumulative_manifest_dos_ddos_diverse_24k.json` |
| Worker summary | `artifacts/office_model/materialization_work/ddos_tuesday20_loic_http_udp_diverse_24k_missing_generation.summary.json` |

The active baseline cumulative manifest was not overwritten. The new variant preserves the previous DoS diverse 24k selection and adds this DDoS diverse 24k selection.

## Training Note

For downstream conversion/training with both the diverse DoS and diverse DDoS class selections, use:

`artifacts/office_model/office_compact_cumulative_manifest_dos_ddos_diverse_24k.json`
