# Office Non-Web Graph Expansion

Date: 2026-07-22

## Objective

Generate additional office compact graphs for every project class except `WebBased`, then rebuild and validate the PyG graph dataset.

## Code fix applied

`secureedge/data/office_pipeline.py` was updated in `build_office_candidate_window_pcap` so candidate-window preslicing can read both classic pcap and pcapng sources through the existing `iter_capture_packets` abstraction. The helper now writes a normalized little-endian classic Ethernet pcap slice for downstream workers.

This fixed the DoS preslice failure seen on:

```text
datasets/cic_ids_2018/raw_pcaps/Friday-16-02-2018/pcap/UCAP172.31.69.25-part1.pcap
```

Previous error:

```text
ValueError('Unsupported PCAP magic; expected classic pcap, not pcapng.')
```

## Materialization runs

Verified compact-record additions after reconciliation:

| Class | Added compact records | Notes |
| --- | ---: | --- |
| Benign | 43 | One bounded pcap run completed. |
| Bot | 200 | One bounded pcap run completed. |
| BruteForce | 200 | One bounded presliced pcap run completed. |
| DDoS | 19 | One bounded presliced pcap run completed. A later small DDoS attempt did not update the manifest and was interrupted after the tool session became stale. |
| DoS | 6 | pcapng-compatible preslice fix allowed the bounded run to complete. |
| Infiltration | 274 | First pcap produced no matches; widened run over four pcaps added 274. |
| WebBased | 0 | Intentionally excluded from this expansion. |

Total verified increase: 742 compact records.

Final reconciled compact manifest:

| Class | Compact records |
| --- | ---: |
| Benign | 10,807 |
| Bot | 14,372 |
| BruteForce | 400 |
| DDoS | 39 |
| DoS | 171 |
| Infiltration | 23,783 |
| WebBased | 412 |
| **Total** | **49,984** |

## Graph rebuild

Command:

```bash
.venv/bin/python -m secureedge.office.build_graphs --overwrite
```

Output manifest:

```text
artifacts/office_model/office_graph_dataset_manifest.json
```

Rebuilt graph counts:

| Split | Graphs |
| --- | ---: |
| Train | 41,497 |
| Validation | 4,250 |
| Test | 4,237 |
| **Total** | **49,984** |

`materialization_incomplete` is now `false`.

## Final split distribution

| Class | Train | Validation | Test | Total |
| --- | ---: | ---: | ---: | ---: |
| Benign | 9,037 | 909 | 861 | 10,807 |
| Bot | 11,922 | 1,213 | 1,237 | 14,372 |
| BruteForce | 348 | 21 | 31 | 400 |
| DDoS | 33 | 3 | 3 | 39 |
| DoS | 139 | 18 | 14 | 171 |
| Infiltration | 19,812 | 1,983 | 1,988 | 23,783 |
| WebBased | 206 | 103 | 103 | 412 |

The previous Gate 7 hard failure caused by DDoS being absent from the test split is resolved.

## Validation

Commands:

```bash
.venv/bin/python -m secureedge.office.validate --gate 5
.venv/bin/python -m secureedge.office.validate --gate 6
.venv/bin/python -m secureedge.office.validate --gate 7
```

Results:

| Gate | Status | Hard failures | Warnings | Output |
| --- | --- | ---: | ---: | --- |
| G5 compact features | pass | 0 | 2 | `artifacts/office_model/gate_reports/gate5_compact_features.json` |
| G6 graph structure | pass | 0 | 0 | `artifacts/office_model/gate_reports/gate6_graph_structure.json` |
| G7 split leakage | pass | 0 | 0 | `artifacts/office_model/gate_reports/gate7_split_leakage.json` |

Gate 5 warnings are unchanged from earlier recovery work:

- Tuple context features are present: `src_port`, `dst_port`, `protocol`.
- No raw IP/MAC feature names were found.

## Remaining notes

- DDoS remains extremely scarce with 39 total graphs, despite now being present in validation and test.
- DoS remains scarce with 171 total graphs.
- `artifacts/office_model/materialization_work/pcap_slices` is large, about 28 GB during this run. Future attack-class materialization should either reuse existing slices deliberately or add a cleanup/cache-retention policy.
- No architecture change was made in this step. The existing attention-based GAT policy remains intact; future architecture changes should use `GATv2Conv`, not `SAGEConv`.
