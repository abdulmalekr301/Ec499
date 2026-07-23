# CICIDS2017 WebBased Augmentation

Generated: `2026-07-13T07:40:20+00:00`

## Action
- Started the CICIDS2017 WebBased augmentation path before graph generation.
- Used `datasets/cic_ids_2018/improved-csv/CICIDS2017_improved/thursday.csv` as the corrected label source.
- Used the single PCAP `datasets/cic_ids_2018/cic_ids_2017/raw_pcaps/Thursday-WorkingHours.pcap`.
- Verified the on-wire WebBased path as `172.16.0.1 -> 192.168.10.50` over TCP/80.
- Kept all CICIDS2017 candidates source-tagged and marked `split_scope=train_only`.
- Minimized SQL Injection augmentation by default, per the plan.
- Applied payload-retention auditing to nonzero attempted rows before recovery.

## Outputs
- Manifest: `/var/home/alucard-00/EC499/artifacts/office_model/cicids2017_webbased_augmentation_manifest.json`
- Train-only candidate JSONL: `/var/home/alucard-00/EC499/artifacts/office_model/candidate_flows/WebBased_CICIDS2017_train_only.jsonl`

## Run Details
- Include SQL: `False`
- PCAP size bytes: `8302500180`
- Rows scanned: `362076`
- Max packet records per PCAP during payload audit: `10000000`
- Payload audit stop reason: `completed`
- Timestamp tolerance seconds: `3.0`

## CICIDS2018 Native WebBased Baseline
```json
{
  "Brute Force-Web": 122,
  "Brute Force-XSS": 72,
  "SQL Injection": 27
}
```

## CICIDS2017 Label Counts
```json
{
  "Web Attack - Brute Force": 73,
  "Web Attack - Brute Force - Attempted": 1292,
  "Web Attack - SQL Injection": 13,
  "Web Attack - SQL Injection - Attempted": 5,
  "Web Attack - XSS": 18,
  "Web Attack - XSS - Attempted": 655
}
```

## CICIDS2017 Observed Ranges
```json
{
  "Brute Force-Web": {
    "dst_ips": {
      "192.168.10.50": 1365
    },
    "max_timestamp": "2017-07-06 13:00:10.400480",
    "min_timestamp": "2017-07-06 12:15:54.880049",
    "src_ips": {
      "172.16.0.1": 1365
    }
  },
  "SQL Injection": {
    "dst_ips": {
      "192.168.10.50": 18
    },
    "max_timestamp": "2017-07-06 13:42:50.310628",
    "min_timestamp": "2017-07-06 13:35:27.852814",
    "src_ips": {
      "172.16.0.1": 18
    }
  },
  "XSS": {
    "dst_ips": {
      "192.168.10.50": 673
    },
    "max_timestamp": "2017-07-06 13:35:21.109336",
    "min_timestamp": "2017-07-06 13:15:35.283859",
    "src_ips": {
      "172.16.0.1": 673
    }
  }
}
```

## Candidate Counts
- Final train-only candidates: `167`
- Recovered attempted candidates: `76`

### Final Subtype Counts
```json
{
  "Brute Force-Web": 149,
  "XSS": 18
}
```

### Recovered Attempted Subtype Counts
```json
{
  "Brute Force-Web": 76
}
```

## Payload Audit
### CSV Payload Groups
```json
{
  "nonzero_csv_forward_payload": 190,
  "zero_csv_forward_payload": 1866
}
```

### Audit Decision Counts
```json
{
  "keep_excluded": 1865,
  "manual_review": 6,
  "recover": 76
}
```

### Audit Label Decision Counts
```json
{
  "Web Attack - Brute Force - Attempted": {
    "keep_excluded": 1214,
    "manual_review": 2,
    "recover": 76
  },
  "Web Attack - XSS - Attempted": {
    "keep_excluded": 651,
    "manual_review": 4
  }
}
```

### PCAP Summaries
```json
{
  "/var/home/alucard-00/EC499/datasets/cic_ids_2018/cic_ids_2017/raw_pcaps/Thursday-WorkingHours.pcap": {
    "candidate_count": 82,
    "matched": 82,
    "packets_scanned": 3710059,
    "remaining": 0,
    "scanner": "raw_pcap_ipv4_tcp_payload",
    "status": "completed"
  }
}
```

## Limitations
- Original CICIDS2017 CSV available locally: `False`.
- Only the improved CICIDS2017 thursday.csv exists in the workspace; original-label cross-check remains unavailable locally.
- This step creates candidates only; it does not materialize graph tensors.
- CICIDS2017 augmentation must remain train-only and source-tagged during graph generation and splitting.
