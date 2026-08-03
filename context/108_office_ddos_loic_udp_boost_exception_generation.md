# Office DDoS LOIC-UDP Boost Exception Generation

## Summary

The requested `DDoS-LOIC-UDP` boost target was `6,000` almost-true samples, using the `1,697` strict eligible rows as the reference profile. The dataset does not contain 6,000 safe unique LOIC-UDP-like rows. The safe unique pool found for this exception was `1,901` rows:

| Selection group | Rows selected | Materialized graphs | Notes |
|---|---:|---:|---|
| `strict_eligible_reference` | 1,697 | 1,697 | Accepted LOIC-UDP rows used as the comparison/reference profile. |
| `same_label_near_window` | 33 | 33 | Same `DDoS-LOIC-UDP` label near the configured window. |
| `attempted_loic_udp` | 171 | 0 | `DDoS-LOIC-UDP - Attempted` ICMP rows; selected for audit but not materialized by the current NFStream graph path. |

Final materialized result: `1,730` unique compact LOIC-UDP graphs.

## Why 6,000 Was Not Filled

The remaining DDoS rows on the day are `DDoS-HOIC` TCP/80 rows, not LOIC-UDP. They were not used because mixing HOIC into a LOIC-UDP subtype boost would contaminate the subtype label. No duplicates were used to inflate the count.

## Selection Artifacts

| Artifact | Path |
|---|---|
| Candidate JSONL | `artifacts/office_model/exception_candidates/ddos_loic_udp_boost_unique_top6000.jsonl` |
| Selection manifest | `artifacts/office_model/exception_candidates/ddos_loic_udp_boost_unique_top6000_manifest.json` |
| Graph-generation manifest | `artifacts/office_model/exception_candidates/ddos_loic_udp_boost_graph_generation_manifest.json` |

Selection policy: `ddos_loic_udp_boost_unique_v1_reference_compare`.

Reference profile: `ddos_loic_udp_strict_eligible_1697`.

Similarity metric: robust-z distance from the strict eligible LOIC-UDP reference profile, converted as `1 / (1 + distance)`.

## Materialization Results

| Metric | Value |
|---|---:|
| Requested target | 6,000 |
| Safe unique selected | 1,901 |
| Unique graphs materialized | 1,730 |
| Missing selected rows | 171 |
| Duplicate selected graph hashes | 0 |
| Current DDoS compact files | 25,691 |

Materialized selected graph breakdown:

| Field | Counts |
|---|---|
| Selection group | `strict_eligible_reference`: 1,697; `same_label_near_window`: 33 |
| Candidate label | `DDoS-LOIC-UDP`: 1,730 |
| Protocol | `17`/UDP: 1,730 |
| Compact subtype label | `DDOS-LOIC-UDP`: 1,730 |
| Shape | `(flow=92, packets=20, packet_width=1500)`: 1,730 |

Missing selected row breakdown:

| Field | Counts |
|---|---|
| Selection group | `attempted_loic_udp`: 171 |
| Candidate label | `DDoS-LOIC-UDP - Attempted`: 171 |
| Protocol | `1`/ICMP: 171 |

## Worker Passes

| Pass | Status | Candidates | Matched | Materialized | Notes |
|---|---|---:|---:|---:|---|
| Partial all-candidate segmented slice | `worker_error` | 1,901 | 1,083 | 1,083 | Stopped at 2 GiB memory floor: available memory reached 1.97 GiB. |
| Fresh exact remaining slice | `worker_error` | 818 | 679 | 627 | Stopped at 2 GiB memory floor: available memory reached 1.99 GiB; 52 matched flows had zero packet graphs. |
| Missing UDP cleanup slice | `completed` | 20 | 20 | 20 | Recovered the last 20 materializable UDP rows. |
| Metadata rewrite slice | `completed` | 9 | 9 | 9 | Overwrote previously existing selected graphs so exception metadata is present. |

All materialized selected graphs now include the exception policy, selection group, reference profile, reference distance, reference similarity, and candidate label metadata.

## Validation

- Duplicate selected graph hashes: `0`.
- Metadata validation failures among selected materialized graphs: `0`.
- Materialized reference similarity range:
  - min: `0.09700047618005081`
  - p25: `0.4844552004359263`
  - median: `0.6351915853808264`
  - p75: `0.7678568295206151`
  - max: `0.9736111785291155`

## Pipeline Fix Applied

The office preslicer previously ignored ICMP packets while building candidate-window slices. It now preserves ICMP packet matches as `(src_ip, dst_ip, 0, 0, 1)` without changing TCP/UDP matching. This was needed so the `attempted_loic_udp` rows could be audited honestly. Even after the preslice fix, the current NFStream materialization path did not produce compact graphs for those ICMP attempted rows, so they remain documented but unmaterialized.

## Status

The LOIC-UDP boost is complete under the safe-selection rule. The result should be treated as a subtype-diversity boost, not a full 6,000-sample class expansion. These compact graphs have not yet been intentionally assigned into train/validation/test splits or converted into PyG `.pt` training graphs.
