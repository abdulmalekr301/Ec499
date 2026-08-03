# Office Tuesday-20 DDoS LOIC Sample Audit

Date: `2026-08-02`

## Summary

The newly added `Tuesday-20-02-2018` CIC-IDS-2018 data contains strong strict true-success support for `DDoS-LOIC-HTTP` and limited but clean support for `DDoS-LOIC-UDP`.

| Subtype | Strict true rows | Label | Protocol | Destination | Time range |
|---|---:|---|---|---|---|
| `DDOS-LOIC-HTTP` | 289,328 | `DDoS-LOIC-HTTP` | TCP/80 | `172.31.69.25` | `2018-02-20 14:13:54.662633` to `2018-02-20 15:16:48.272954` |
| `DDOS-LOIC-UDP` | 797 | `DDoS-LOIC-UDP` | UDP/80 | `172.31.69.25` | `2018-02-20 17:14:17.478355` to `2018-02-20 17:29:15.502209` |

The CSV also contains `80` `DDoS-LOIC-UDP - Attempted` ICMP rows. Those were excluded from the strict true-success pool.

## Selection Rule

Policy: `tuesday20_ddos_loic_strict_true_exact_ip_label_v1`.

Rows were retained only when all of the following were true:

- day is `Tuesday-20-02-2018`;
- source IP is one of the ten listed attacker public IPs;
- destination IP is the victim private IP `172.31.69.25`;
- label is exactly `DDoS-LOIC-HTTP` or `DDoS-LOIC-UDP`;
- `Attempted Category == -1`;
- `DDoS-LOIC-HTTP` uses TCP/80;
- `DDoS-LOIC-UDP` uses UDP/80.

No attempted rows were included.

## Attacker Counts

| Attacker IP | LOIC-HTTP rows | LOIC-UDP rows |
|---|---:|---:|
| `18.216.200.189` | 29,208 | 77 |
| `18.216.24.42` | 28,849 | 80 |
| `18.218.11.51` | 28,774 | 80 |
| `18.218.115.60` | 27,790 | 80 |
| `18.218.229.235` | 29,411 | 80 |
| `18.218.55.126` | 29,041 | 80 |
| `18.219.32.43` | 28,636 | 80 |
| `18.219.5.43` | 28,912 | 80 |
| `18.219.9.1` | 29,528 | 80 |
| `52.14.136.135` | 29,179 | 80 |

## MACs Observed In Victim PCAP

Victim endpoint PCAP:

`datasets/cic_ids_2018/raw_pcaps/Tuesday-20-02-2018/pcap/UCAP172.31.69.25`

Observed Ethernet MACs from `tcpdump -nn -e`:

| Role | IP(s) | MAC |
|---|---|---|
| Attackers | all ten listed public attacker IPs | `02:ca:69:c4:6d:06` |
| Victim | `172.31.69.25` | `02:d8:a9:4e:38:42` |

All ten attacker public IPs appear behind the same attacker-side MAC in this victim endpoint capture.

## Pilot Materialization

A 20-row temporal-spread pilot was created: 10 HTTP rows and 10 UDP rows.

Pilot candidate file:

`artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_strict_true_pilot20.jsonl`

The full 8GB victim PCAP scan was manually stopped after both subtypes had already materialized, because the late UDP rows require a slow full-file scan. No final worker summary was produced.

Partial materialization proof:

| Subtype | Materialized pilot graphs |
|---|---:|
| `DDOS-LOIC-HTTP` | 10 |
| `DDOS-LOIC-UDP` | 5 |
| **Total** | **15** |

Validation over the partial pilot graphs:

| Check | Result |
|---|---:|
| Zero-packet graphs | 0 |
| Duplicate `flow_hash` surplus | 0 |
| Duplicate `compact_tensor_hash` surplus | 0 |
| Missing required metadata records | 0 |

## Artifacts

| Artifact | Path |
|---|---|
| LOIC-HTTP strict candidates | `artifacts/office_model/exception_candidates/ddos_loic_http_tuesday20_strict_true.jsonl` |
| LOIC-UDP strict candidates | `artifacts/office_model/exception_candidates/ddos_loic_udp_tuesday20_strict_true.jsonl` |
| Combined strict candidates | `artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_strict_true.jsonl` |
| Candidate manifest | `artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_strict_true_manifest.json` |
| Pilot candidates | `artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_strict_true_pilot20.jsonl` |
| Partial pilot validation | `artifacts/office_model/exception_candidates/ddos_tuesday20_loic_http_udp_pilot20_partial_validation.json` |

## Recommendation

Use Tuesday-20 as the primary DDoS diversity source:

- `DDOS-LOIC-HTTP` can safely provide a large pool, likely enough for any 6k or 12k subtype target.
- `DDOS-LOIC-UDP` is strict and materializable, but only has `797` true-success rows on Tuesday-20.
- Full graph generation should preslice the 8GB victim PCAP around the HTTP and UDP attack windows before running the materializer. The raw full-file worker scan is too slow for repeated pilot/full generation passes.
