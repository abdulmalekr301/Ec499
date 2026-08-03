# Office Thursday-15 DoS GoldenEye/Slowloris Sample Audit

## Summary

The newly added `Thursday-15-02-2018` CIC-IDS-2018 PCAP/CSV data contains clean, strict true-success samples for two additional DoS subtypes:

| Subtype | Strict true samples | Attempted rows excluded | Time range | Attacker | Victim | Protocol |
|---|---:|---:|---|---|---|---|
| `DoS-GoldenEye` | 22,560 | 4,301 | `2018-02-15 13:27:46.807659` to `2018-02-15 14:02:59.332681` | `18.219.211.138` / `172.31.70.46` | `172.31.69.25` / `18.217.21.148` | TCP/80 |
| `DoS-Slowloris` | 8,490 | 2,280 | `2018-02-15 15:00:12.551313` to `2018-02-15 15:41:34.311278` | `18.217.165.70` / `172.31.70.8` | `172.31.69.25` / `18.217.21.148` | TCP/80 |

Combined strict true pool: `31,050` rows.

## Selection Rule

Policy: `thursday15_dos_strict_true_exact_ip_label_v1`.

Rows were retained only when all of the following were true:

- day is `Thursday-15-02-2018`;
- source is the expected public attacker IP;
- destination is the victim private IP `172.31.69.25`;
- protocol is TCP (`6`);
- destination port is `80`;
- label is exactly the matching true subtype label;
- `Attempted Category` is `-1`.

No attempted rows were included.

## Artifacts

| Artifact | Path |
|---|---|
| GoldenEye candidates | `artifacts/office_model/exception_candidates/dos_goldeneye_thursday15_strict_true.jsonl` |
| Slowloris candidates | `artifacts/office_model/exception_candidates/dos_slowloris_thursday15_strict_true.jsonl` |
| Combined candidates | `artifacts/office_model/exception_candidates/dos_thursday15_goldeneye_slowloris_strict_true.jsonl` |
| Selection manifest | `artifacts/office_model/exception_candidates/dos_thursday15_goldeneye_slowloris_strict_true_manifest.json` |
| Pilot candidates | `artifacts/office_model/exception_candidates/dos_thursday15_goldeneye_slowloris_strict_true_pilot20.jsonl` |
| Pilot summary | `artifacts/office_model/materialization_work/dos_thursday15_goldeneye_slowloris_pilot20_rewrite.summary.json` |

## Pilot Materialization

The victim endpoint PCAP is present at:

`datasets/cic_ids_2018/raw_pcaps/Thursday-15-02-2018/pcap/UCAP172.31.69.25`

Pilot result:

| Metric | Value |
|---|---:|
| Pilot candidates | 20 |
| Matched | 20 |
| Materialized graphs | 20 |
| Remaining | 0 |
| Zero-packet graphs | 0 |
| Flows scanned | 33,297 |

Pilot subtype materialization:

| Subtype | Graphs |
|---|---:|
| `DoS-GoldenEye` | 10 |
| `DoS-Slowloris` | 10 |

The pilot compact graphs preserve:

- `gt_subtype`;
- `selection_policy`;
- `selection_group`;
- attacker private/public IP;
- victim private/public IP;
- CSV attempted category.

## Notes

- These samples are strict true rows, unlike the earlier Friday `DoS-SlowHTTPTest` exception rows.
- The Thursday victim PCAP is much smaller than the older Friday DoS endpoint capture, so full materialization should be practical.
- These candidate files are not yet merged into the official final train/validation/test split manifests.

## Recommended Next Step

Use this strict Thursday pool to improve DoS subtype diversity. A conservative split policy would keep the existing DoS-Hulk support while adding GoldenEye and Slowloris as explicit subtype groups, then reserve at least some Thursday samples for validation/test so DoS evaluation is no longer dominated by a single Friday attack window.
