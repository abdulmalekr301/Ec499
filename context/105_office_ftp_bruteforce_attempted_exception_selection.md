# Office FTP-BruteForce Attempted Exception Selection

Date: 2026-08-01

## Purpose

The strict office candidate gate leaves `FTP-BruteForce` with zero eligible successful samples because the corrected labels mark the window as attempted/non-success. To preserve BruteForce subtype coverage, this exception selection identifies the strongest FTP-BruteForce attempted flows while keeping the exception explicit and auditable.

## Output

- Candidate JSONL: `/var/home/alucard-00/EC499/artifacts/office_model/exception_candidates/ftp_bruteforce_attempted_top12000.jsonl`
- Manifest: `/var/home/alucard-00/EC499/artifacts/office_model/exception_candidates/ftp_bruteforce_attempted_top12000_manifest.json`
- Target selected records: `12000`
- Selected records: `12000`
- Policy: `ftp_bruteforce_strongest_attempts_v2_temporal_tie_break`

## Hard Filters

| Filter | Requirement |
|---|---|
| Ground-truth window | `FTP-BruteForce` on `Wednesday-14-02-2018` |
| CSV class | `BruteForce` |
| CSV label | contains `FTP`, `BruteForce`, and `Attempted` |
| Protocol | TCP / `6` |
| Service port | source or destination port `21` |
| PCAP availability | endpoint PCAP must exist |

## Selection Counts

| Counter | Count |
|---|---:|
| `gt_subtype_rows` | 190,294 |
| `pool_rows` | 190,294 |

## Label Counts In FTP Window

| Label | Count |
|---|---:|
| `FTP-BruteForce - Attempted` | 190,294 |

## Ranking Rule

Rows were sorted deterministically by an evidence score that prioritizes:

1. Bidirectional packet evidence.
2. SYN plus RST evidence.
3. ACK evidence.
4. FTP service-port evidence.
5. Forward active data packets.
6. Forward and backward byte counts.
7. Total packets, duration, TCP flow time, TCP header length, and packet rate.

When the highest evidence bucket was larger than the requested target, records were selected evenly across timestamp order inside that bucket. This keeps the exception focused on the strongest attempts while avoiding an arbitrary clustered slice.

## Tie Break

```json
[
  {
    "group_size": 85926,
    "method": "temporal_even_selection",
    "score": 11110000021.604002,
    "selected": 12000
  }
]
```

## Score Distribution

| Population | Min | P25 | Median | P75 | Max |
|---|---:|---:|---:|---:|---:|
| Full filtered pool | 11110000020.726 | 11110000021.602 | 11110000021.602 | 11110000021.604 | 11110000021.604 |
| Selected top 12k | 11110000021.604 | 11110000021.604 | 11110000021.604 | 11110000021.604 | 11110000021.604 |

## Temporal Coverage

| Metric | Value |
|---|---:|
| Covered minute buckets | 96 |
| First selected minute | `2018-02-14 14:33` |
| Last selected minute | `2018-02-14 16:08` |
| Max selected records in one minute | 136 |

## Boundary Sample

The last included record, rank 12,000, is:

```json
{
  "attempted_category": "1",
  "dst_ip": "172.31.69.25",
  "dst_port": "21",
  "evidence_rank_tuple": [
    1,
    1,
    1,
    1,
    0.0,
    0.0,
    0.0,
    2.0,
    2.0,
    2.0,
    60.0,
    1000000.0
  ],
  "evidence_score": 11110000021.604002,
  "exception_rank": 12000,
  "flow_id": "18.221.219.4-172.31.69.25-53504-21-6",
  "label": "FTP-BruteForce - Attempted",
  "src_ip": "18.221.219.4",
  "src_port": "53504",
  "timestamp": "2018-02-14 16:08:59.601882"
}
```

## Important Limitation

These are still `FTP-BruteForce - Attempted` flows. They should be carried through the pipeline with `recovered_attempted=true` and `exception_policy=ftp_bruteforce_strongest_attempts_v2_temporal_tie_break`, and they should not be reported as successful FTP brute-force attacks.
