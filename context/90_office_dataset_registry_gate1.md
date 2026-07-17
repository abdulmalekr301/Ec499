# Office Dataset Registry and Gate 1 Validation

Date: 2026-07-17

## Action

Implemented the raw dataset registry and Gate 1 validation step from `context/PROJECT_RECOVERY_AND_IMPLEMENTATION_PLAN.md`.

Added:

- `secureedge/office/registry.py`

Generated:

- `artifacts/office_model/dataset_registry.json`
- `artifacts/office_model/gate_reports/gate1_raw.json`

## Command

The strongest completed pass was:

```bash
.venv/bin/python -m secureedge.office.registry \
  --checksum-csv \
  --count-csv-rows \
  --read-check-pcaps \
  --pcap-read-check-limit 50 \
  --tcpdump-timeout-seconds 10
```

## Gate 1 result

```text
status: pass
hard_failure_count: 0
warning_count: 6190
registry_hash: ec0151a42d0c41dd94c3c4eb6aec286ba314cace410f0c291eba9738320cf979
config_hash: 2ded866b30fca73462ac448fa1967336c528cf245708d3756f49736efc524538
```

Tool availability:

```json
{
  "tcpdump": "/usr/bin/tcpdump",
  "capinfos": null
}
```

`capinfos` is not installed in the current environment. PCAP readability sampling uses `tcpdump`.

## Registry summary

```json
{
  "csv_file_count": 15,
  "csv_sha256_status": {
    "ok": 15
  },
  "csv_status": {
    "ok": 15
  },
  "csv_total_size_bytes": 28244508703,
  "pcap_file_count": 3120,
  "pcap_read_status": {
    "ok": 50,
    "skipped": 3070
  },
  "pcap_sha256_status": {
    "skipped": 3120
  },
  "pcap_total_size_bytes": 434588985313
}
```

## CSV row/header/checksum summary

| Role | Day | Rows | Header columns | SHA-256 prefix |
| --- | --- | ---: | ---: | --- |
| improved | Wednesday-14-02-2018 | 5,898,350 | 91 | `4ceed4ba2697` |
| original | Wednesday-14-02-2018 | 1,048,575 | 80 | `acff8bc61376` |
| improved | Friday-16-02-2018 | 7,390,266 | 91 | `a16b76a454a` |
| original | Friday-16-02-2018 | 1,048,575 | 80 | `1a4919faa0c4` |
| improved | Wednesday-21-02-2018 | 6,962,593 | 91 | `e41d41605d8a` |
| original | Wednesday-21-02-2018 | 1,048,575 | 80 | `a5f4a1c2689e` |
| improved | Thursday-22-02-2018 | 6,071,153 | 91 | `cdfe956ccc1d` |
| original | Thursday-22-02-2018 | 1,048,575 | 80 | `da33c9270182` |
| improved | Friday-23-02-2018 | 5,976,481 | 91 | `67aa9220ec27` |
| original | Friday-23-02-2018 | 1,048,575 | 80 | `d0a7f5059d98` |
| improved | Friday-02-03-2018 | 6,311,371 | 91 | `f4641bab290b` |
| original | Friday-02-03-2018 | 1,048,575 | 80 | `d96f38e7496a` |
| improved | Thursday-01-03-2018 | 6,551,401 | 91 | `55b29d7b05cb` |
| original | Thursday-01-03-2018 | 331,125 | 80 | `b0534c5d7d8b` |
| CICIDS2017 improved | Thursday-06-07-2017 | 362,076 | 91 | `78a4d11eaf47` |

## Warning interpretation

The warnings are expected for this bounded Gate 1 pass:

- 3,120 warnings: full PCAP SHA-256 skipped.
- 3,070 warnings: PCAP readability check skipped outside the first 50 selected PCAPs.

The registry implementation supports `--checksum-pcaps` and unbounded `--read-check-pcaps`, but full PCAP hashing would read approximately 434 GB. That should be run as an explicit long-running validation job, not as part of the default interactive recovery step.

## Next recovery-plan step

Implement the first validation helpers over the compact graph pool:

- full compact schema check
- finite-value check
- class/count check against the cumulative manifest
- optional identity-leakage audit for flow feature names

