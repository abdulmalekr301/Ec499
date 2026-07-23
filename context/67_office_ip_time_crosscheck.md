# Office Model IP-Time Cross-Check

Generated: `2026-07-13T20:23:39+00:00`

## Action
- Encoded the CIC-IDS2018 attacker/victim IP and time-window table from `office-model-pretraining-checklist.md`.
- Cross-checked improved CSV labels against IP/time-window ground truth using streaming reads.
- Used a `+4 hour` timestamp shift because the improved CSV timestamps are four hours ahead of the official schedule table.
- Added a strict retention rule for future candidate graph materialization: attacks require CSV/IP-time agreement; benign rows require no IP-time attack match.

## Outputs
- Manifest: `/var/home/alucard-00/EC499/artifacts/office_model/ip_time_crosscheck_manifest.json`

## Run Details
- Max rows per day: `None`
- Samples per non-benign status: `10`

## Total Status Counts
```json
{
  "agreement_attack": 3154746,
  "agreement_benign": 41689302,
  "csv_attack_no_gt_match": 9672,
  "csv_benign_gt_attack_match": 8334,
  "excluded_csv_label_with_gt_match": 296254,
  "excluded_csv_label_without_gt_match": 3045,
  "unknown_csv_label": 262
}
```

## Total CSV Class Counts
```json
{
  "Benign": 41697636,
  "Bot": 142921,
  "BruteForce": 393071,
  "DDoS": 1084194,
  "DoS": 1803246,
  "Infiltration": 39847,
  "WebBased": 438
}
```

## Total IP/Time Ground-Truth Class Counts
```json
{
  "Bot": 143183,
  "BruteForce": 282942,
  "DDoS": 1076243,
  "DoS": 1908796,
  "Infiltration": 48006,
  "WebBased": 426
}
```

## Per-Day Summary

| Day | Rows scanned | Limited | Status counts | Ground-truth subtypes |
|---|---:|---|---|---|
| Wednesday-14-02-2018 | 5898350 | `False` | `{"agreement_attack": 92618, "agreement_benign": 5610799, "csv_attack_no_gt_match": 1579, "excluded_csv_label_with_gt_match": 190324, "excluded_csv_label_without_gt_match": 3030}` | `{"FTP-BruteForce": 190294, "SSH-Bruteforce": 92648}` |
| Friday-16-02-2018 | 7390266 | `False` | `{"agreement_attack": 1803160, "agreement_benign": 5481470, "csv_benign_gt_attack_match": 30, "excluded_csv_label_with_gt_match": 105606}` | `{"DoS-Hulk": 1803246, "DoS-SlowHTTPTest": 105550}` |
| Wednesday-21-02-2018 | 6962593 | `False` | `{"agreement_attack": 1076076, "agreement_benign": 5878399, "csv_attack_no_gt_match": 7947, "excluded_csv_label_with_gt_match": 167, "excluded_csv_label_without_gt_match": 4}` | `{"DDOS-HOIC": 1074379, "DDOS-LOIC-UDP": 1864}` |
| Thursday-22-02-2018 | 6071153 | `False` | `{"agreement_attack": 125, "agreement_benign": 6070945, "excluded_csv_label_with_gt_match": 72, "excluded_csv_label_without_gt_match": 11}` | `{"Brute Force-Web": 137, "Brute Force-XSS": 43, "SQL Injection": 17}` |
| Friday-23-02-2018 | 5976481 | `False` | `{"agreement_attack": 157, "agreement_benign": 5976251, "csv_attack_no_gt_match": 1, "excluded_csv_label_with_gt_match": 72}` | `{"Brute Force-Web": 123, "Brute Force-XSS": 73, "SQL Injection": 33}` |
| Friday-02-03-2018 | 6311371 | `False` | `{"agreement_attack": 142921, "agreement_benign": 6168188, "unknown_csv_label": 262}` | `{"Bot": 143183}` |
| Thursday-01-03-2018 | 6551401 | `False` | `{"agreement_attack": 39689, "agreement_benign": 6503250, "csv_attack_no_gt_match": 145, "csv_benign_gt_attack_match": 8304, "excluded_csv_label_with_gt_match": 13}` | `{"Infiltration": 48006}` |

## Retention Rule

- Attack rows: retain only if CSV class is an attack class and the IP/time-window class matches it.
- Benign rows: retain only if CSV class is Benign and no IP/time-window attack matches.
- Disagreements: flag and exclude from candidate graph materialization.

## Notes

- This is still a label/candidate audit; it does not materialize graph tensors.
- The CICIDS2017 WebBased augmentation remains separate and must be train-only when integrated.
