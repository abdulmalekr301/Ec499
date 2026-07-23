# Office Pretraining Checklist Implementation

## Scope

Implemented the IP/time-window cross-checks from
`context/office-model-pretraining-checklist.md` in the office-model pipeline.
This is now part of the label gate before any full graph materialization.

## Code Changes

- Added structured CIC-IDS2018 attack-window metadata in
  `secureedge/data/office_pipeline.py`.
- Added `ip-time-crosscheck` CLI mode:

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode ip-time-crosscheck \
  --keep-per-class 10
```

- Added strict candidate retention:
  - attack rows are retained only when CSV class and IP/time-window class agree;
  - benign rows are retained only when no IP/time-window attack match exists;
  - disagreements are counted and excluded from candidate graph materialization.
- Added candidate metadata fields for retained rows:
  - `gt_subtype`
  - `gt_window_start`
  - `gt_window_finish`
- Added smoke checks for:
  - positive DoS-Hulk IP/time match;
  - pre-window DDoS row that should not match;
  - split PCAP filename IP parsing.

## Timestamp Interpretation

The official checklist schedule times are four hours behind the timestamps in
the improved CSV files. The code stores attack windows in improved-CSV time.

Examples used to confirm this:

- DoS-Hulk table time `13:45` appears around `2018-02-16 17:45` in CSV.
- DDoS-LOIC-UDP table time `10:09` appears around `2018-02-21 14:09` in CSV.

## Important Dataset-Specific Corrections

### Bot

The checklist table listed Bot as two windows. The improved CSV labels cover a
continuous Botnet Ares interval from:

```text
2018-03-02 14:13:28.376104 -> 2018-03-02 19:53:46.504106
```

The pipeline therefore treats Bot as one continuous matching interval from
`2018-03-02 14:11:00` to `2018-03-02 19:55:00`.

### Infiltration

The initial strict public-attacker-to-victim rule matched only 69 Infiltration
rows, while the improved CSV contained 39,847 Infiltration rows. Samples showed
the labeled attack traffic is `172.31.69.13` scanning internal targets, e.g.
`172.31.69.13 -> 172.31.69.5`, during the attack windows.

The matcher now treats Infiltration as compromised-host activity when either
endpoint is `172.31.69.13` during the adjusted attack windows.

## Full IP/Time Cross-Check Result

Output:

```text
artifacts/office_model/ip_time_crosscheck_manifest.json
context/67_office_ip_time_crosscheck.md
```

Total status counts:

```json
{
  "agreement_attack": 3154621,
  "agreement_benign": 35618357,
  "csv_attack_no_gt_match": 9672,
  "csv_benign_gt_attack_match": 8334,
  "excluded_csv_label_with_gt_match": 296182,
  "excluded_csv_label_without_gt_match": 3034,
  "unknown_csv_label": 262
}
```

Ground-truth class counts:

```json
{
  "Bot": 143183,
  "BruteForce": 282942,
  "DDoS": 1076243,
  "DoS": 1908796,
  "Infiltration": 48006,
  "WebBased": 229
}
```

## Strict Candidate Manifest Result

Output:

```text
artifacts/office_model/candidate_flow_manifest.json
context/65_office_model_candidate_flow_manifest.md
```

Final retained candidate counts:

| Class | Candidate records |
|---|---:|
| Benign | 20000 |
| BruteForce | 20000 |
| DoS | 20000 |
| DDoS | 20000 |
| WebBased | 157 |
| Bot | 20000 |
| Infiltration | 20000 |

`WebBased` remains scarce in CIC-IDS2018 after excluding attempted labels and
enforcing CSV/IP-time agreement. CICIDS2017 WebBased augmentation is still a
separate train-only step.

## Validation

Compile check:

```bash
.venv/bin/python -m compileall secureedge tests
```

Smoke check:

```bash
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

## Remaining Gate

Full PCAP graph materialization has not started yet. The next safe step is a
bounded pilot extraction from the strict candidate manifest before any full
six-day graph build.
