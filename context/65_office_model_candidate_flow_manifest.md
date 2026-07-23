# Office Model Candidate Flow Manifest

Generated: `2026-07-13T22:13:15+00:00`

## Action
- Built an office-model candidate flow manifest from improved CIC-IDS2018 CSV labels.
- Used streaming CSV reads and reservoir sampling; full CSVs are not loaded into memory.
- Attached the selected endpoint capture file or capture parts for each retained flow.
- Stratified Benign candidates by day using `equal_per_day` sampling.
- Excluded labels containing `Attempted` and the documented BruteForce contamination rules.
- Enforced the IP/time-window cross-check for retained CIC-IDS2018 rows.
- Included audited WebBased attempted rows only when payload evidence justified recovery.

## Run Details
- Target per class: `24000`
- Max rows per day: `None`
- Benign strategy: `equal_per_day`
- Enforce IP/time-window cross-check: `True`
- Recovered WebBased attempted hashes available: `139`

## Outputs
- Manifest: `/var/home/alucard-00/EC499/artifacts/office_model/candidate_flow_manifest.json`
- Candidate JSONL directory: `/var/home/alucard-00/EC499/artifacts/office_model/candidate_flows`

## Candidate Counts

| Class | Candidate records |
|---|---:|
| Benign | 24000 |
| BruteForce | 24000 |
| DoS | 24000 |
| DDoS | 24000 |
| WebBased | 412 |
| Bot | 24000 |
| Infiltration | 24000 |

## Accepted Rows By Day

```json
{
  "Friday-02-03-2018": {
    "Benign": 6168033,
    "Bot": 142921
  },
  "Friday-16-02-2018": {
    "Benign": 5481457,
    "DoS": 1803160
  },
  "Friday-23-02-2018": {
    "Benign": 5976180,
    "WebBased": 221
  },
  "Thursday-01-03-2018": {
    "Benign": 6502903,
    "Infiltration": 39689
  },
  "Thursday-22-02-2018": {
    "Benign": 6070922,
    "WebBased": 191
  },
  "Wednesday-14-02-2018": {
    "Benign": 5610763,
    "BruteForce": 92618
  },
  "Wednesday-21-02-2018": {
    "Benign": 5878382,
    "DDoS": 1076076
  }
}
```

## Excluded Rows By Day

```json
{
  "Friday-02-03-2018": {},
  "Friday-16-02-2018": {
    "Benign": 30,
    "BruteForce": 105520,
    "DoS": 86
  },
  "Friday-23-02-2018": {
    "WebBased": 9
  },
  "Thursday-01-03-2018": {
    "Benign": 8304,
    "Infiltration": 158
  },
  "Thursday-22-02-2018": {
    "WebBased": 17
  },
  "Wednesday-14-02-2018": {
    "BruteForce": 194933
  },
  "Wednesday-21-02-2018": {
    "DDoS": 8118
  }
}
```

## Status Counts

```json
{
  "accepted_but_no_endpoint_file": 662,
  "accepted_label": 44862054,
  "accepted_recovered_webbased_attempted": 139,
  "excluded_attempted_or_non_success": 299299,
  "excluded_csv_attack_no_gt_match": 9681,
  "excluded_csv_benign_gt_attack_match": 8334,
  "unknown_label": 262
}
```

## Endpoint Selection Counts
```json
{
  "dst_multi_part": 2888535,
  "dst_multi_part_preferred": 2,
  "dst_only": 13092402,
  "dst_preferred": 38939,
  "no_endpoint_file": 662,
  "src_multi_part": 26623,
  "src_only": 28797015
}
```

## Limitations

- This manifest selects flow keys and endpoint PCAP files only; it does not materialize graph tensors.
- IP/time-window cross-check is enforced for retained CIC-IDS2018 candidate rows.
- CICIDS2017 WebBased augmentation is not merged by this CSE-CIC-IDS2018 candidate command.
