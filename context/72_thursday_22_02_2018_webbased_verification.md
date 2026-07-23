# Thursday-22-02-2018 WebBased Verification

Generated: `2026-07-13T20:45:00+00:00`

## Action

- Followed `context/thursday-22-02-2018-verification-plan.md`.
- Resolved the Friday `566` discrepancy before trusting Thursday counts.
- Added Thursday-22-02-2018 as a native CIC-IDS2018 WebBased day in the office pipeline.
- Re-ran the IP/time cross-check, WebBased attempted-payload audit, and strict candidate manifest.
- Source-tagged native WebBased candidates by day as `CIC-IDS2018-Thursday` and `CIC-IDS2018-Friday`.

## Discrepancy Resolution

The Friday `566` figure is the original CICFlowMeter CSV raw label total:

```json
{
  "Brute Force -Web": 362,
  "Brute Force -XSS": 151,
  "SQL Injection": 53
}
```

That is not the same counting method used by this project's validated pipeline.
The validated path uses improved CSV labels plus IP/time agreement plus
payload recovery for justified `Attempted` rows. Under that method, Friday
remains `221` audited native CIC-IDS2018 WebBased candidates.

Thursday shows the same pattern. The source document's `249/79/34` values are
the original CSV raw label counts:

```json
{
  "Brute Force -Web": 249,
  "Brute Force -XSS": 79,
  "SQL Injection": 34
}
```

The improved Thursday CSV contains `208` WebBased rows:

```json
{
  "Web Attack - Brute Force": 69,
  "Web Attack - Brute Force - Attempted": 76,
  "Web Attack - XSS": 40,
  "Web Attack - XSS - Attempted": 3,
  "Web Attack - SQL": 16,
  "Web Attack - SQL - Attempted": 4
}
```

## PCAP Structure Check

```json
{
  "Thursday-22-02-2018": {
    "pcap_files": 447,
    "pcap_ips": 447,
    "duplicate_ip_capture_count": 0
  },
  "Friday-23-02-2018": {
    "pcap_files": 446,
    "pcap_ips": 446,
    "duplicate_ip_capture_count": 0
  }
}
```

## Timestamp And IP Verification

The Thursday schedule windows from the plan were shifted by `+4 hours`, matching
the existing CIC-IDS2018 timestamp interpretation:

```json
{
  "Brute Force-Web": "2018-02-22 14:17:00 -> 2018-02-22 15:24:00",
  "Brute Force-XSS": "2018-02-22 17:50:00 -> 2018-02-22 18:29:00",
  "SQL Injection": "2018-02-22 20:15:00 -> 2018-02-22 20:29:00"
}
```

Direct victim-PCAP scan of
`datasets/cic_ids_2018/raw_pcaps/Thursday-22-02-2018/pcap/UCAP172.31.69.28`
found traffic between `18.218.115.60` and `172.31.69.28` in all three shifted
windows:

```json
{
  "Brute Force-Web": 18252,
  "Brute Force-XSS": 11699,
  "SQL Injection": 178
}
```

## IP/Time Cross-Check Result

Output:

```text
artifacts/office_model/ip_time_crosscheck_manifest.json
context/67_office_ip_time_crosscheck.md
```

Thursday-22-02-2018:

```json
{
  "rows_scanned": 6071153,
  "status_counts": {
    "agreement_attack": 125,
    "agreement_benign": 6070945,
    "excluded_csv_label_with_gt_match": 72,
    "excluded_csv_label_without_gt_match": 11
  },
  "csv_class_counts": {
    "Benign": 6070945,
    "WebBased": 208
  },
  "gt_subtype_counts": {
    "Brute Force-Web": 137,
    "Brute Force-XSS": 43,
    "SQL Injection": 17
  }
}
```

## Payload-Retention Audit

Output:

```text
artifacts/office_model/webbased_attempted_payload_audit.json
context/70_webbased_attempted_payload_check.md
```

Native CIC-IDS2018 WebBased attempted rows:

```json
{
  "Thursday-22-02-2018": 83,
  "Friday-23-02-2018": 72
}
```

Payload decisions:

```json
{
  "recover": 139,
  "keep_excluded": 11,
  "manual_review": 5
}
```

By day:

```json
{
  "Thursday-22-02-2018": {
    "recover": 75,
    "keep_excluded": 5,
    "manual_review": 3
  },
  "Friday-23-02-2018": {
    "recover": 64,
    "keep_excluded": 6,
    "manual_review": 2
  }
}
```

Only recovered rows that still pass the IP/time gate are retained in the final
candidate manifest. For Thursday, `66` recovered attempted rows pass that final
gate; `9` recovered attempted rows remain excluded because they do not match the
verified IP/time windows.

## Strict Candidate Manifest Result

Output:

```text
artifacts/office_model/candidate_flow_manifest.json
artifacts/office_model/candidate_flows/WebBased.jsonl
context/65_office_model_candidate_flow_manifest.md
```

Native WebBased candidates:

```json
{
  "Thursday-22-02-2018": 191,
  "Friday-23-02-2018": 221,
  "total_native_cicids2018_webbased": 412
}
```

Source tags in `WebBased.jsonl`:

```json
{
  "CIC-IDS2018-Thursday": 191,
  "CIC-IDS2018-Friday": 221
}
```

Subtype counts:

```json
{
  "Brute Force-Web": 257,
  "Brute Force-XSS": 112,
  "SQL Injection": 43
}
```

Recovered attempted rows retained in `WebBased.jsonl`:

```json
{
  "Thursday-22-02-2018": 66,
  "Friday-23-02-2018": 64
}
```

## Combined WebBased Pool

```json
{
  "CIC-IDS2018-Friday-native": 221,
  "CIC-IDS2018-Thursday-native": 191,
  "CICIDS2017-train-only-augmentation": 167,
  "combined_available_for_training_math": 579
}
```

At a 10-15x oversampling range, the WebBased target should be approximately
`5790-8685`, not `20000`. A practical next target range is `6000-8500`, with
validation/test still protected by the train-only CICIDS2017 leakage guard.

## Validation

```bash
.venv/bin/python -m compileall secureedge tests
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python tests/smoke_checks.py
```

Result:

```text
smoke checks passed
```
