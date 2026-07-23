# Office Model Pipeline Implementation

## Scope Implemented

Implemented the Stage A/preflight layer for `context/office-model-graph-generation-pipeline.md`.
This creates the auditable foundation needed before any full PCAP graph extraction is started.

New source file:

```text
secureedge/data/office_pipeline.py
```

New commands:

```bash
.venv/bin/python -m secureedge.data.office_pipeline --mode preflight --max-rows 250000 --keep-per-class 5
```

```bash
.venv/bin/python -m secureedge.data.office_pipeline --mode candidate-manifest --max-rows 10000 --target-per-class 100
```

For a full candidate-flow scan later, remove `--max-rows` and use the final target:

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode candidate-manifest \
  --target-per-class 20000
```

That command streams the improved CSVs and can take substantial time because the
CSE-CIC-IDS2018 improved CSV directory is over 20 GiB.

## What the Code Now Supports

- Seven-class office taxonomy:
  - `Benign`
  - `BruteForce`
  - `DoS`
  - `DDoS`
  - `WebBased`
  - `Bot`
  - `Infiltration`
- Per-day class specification:
  - `Wednesday-14-02-2018` -> `BruteForce`
  - `Friday-16-02-2018` -> `DoS`
  - `Wednesday-21-02-2018` -> `DDoS`
  - `Friday-23-02-2018` -> `WebBased`
  - `Friday-02-03-2018` -> `Bot`
  - `Thursday-01-03-2018` -> `Infiltration`
- Improved CSV label normalization.
- Exclusion of labels containing `Attempted`.
- Explicit exclusion rules for documented Wednesday-14-02-2018 BruteForce contamination:
  - FTP closed-port contamination from `18.221.219.4` to `172.31.69.25`
  - SSH zero-attacker-payload flows from `13.58.98.64` to `172.31.69.25`
  - SSH-labeled traffic to FTP port `21`
- Per-day IP-to-PCAP lookup table built from:

```text
datasets/cic_ids_2018/raw_pcaps/<day>/pcap
```

- Candidate endpoint selection that avoids globbing all per-host PCAPs.
- Endpoint PCAP parsing for both normal host captures and split captures such as
  `UCAP172.31.69.25-part1.pcap`.
- Multi-part endpoint tracking through `endpoint_pcaps` while retaining
  `endpoint_pcap` for backward compatibility.
- Benign stratification across all six days.
- Reservoir sampling for candidate flow manifests.
- JSONL candidate outputs under:

```text
artifacts/office_model/candidate_flows/
```

## Generated Reports

Preflight report:

```text
context/64_office_model_graph_generation_pipeline.md
```

Candidate-manifest validation report:

```text
context/65_office_model_candidate_flow_manifest.md
```

Preflight JSON:

```text
artifacts/office_model/preflight_manifest.json
```

Candidate-flow JSON:

```text
artifacts/office_model/candidate_flow_manifest.json
```

## Validation Performed

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

The smoke checks now include office-label normalization, `DDoS-LOIC-UDP`,
`Infiltration - NMAP Portscan`, split-PCAP filename parsing, and exact Benign
stratification target accounting.

## Strict Full Candidate-Manifest Result

The current full candidate-flow scan used:

```text
max_rows_per_day = None
target_per_class = 20000
enforce_ip_time_crosscheck = True
```

It produced:

| Class | Candidate records |
|---|---:|
| Benign | 20000 |
| BruteForce | 20000 |
| DoS | 20000 |
| DDoS | 20000 |
| WebBased | 157 |
| Bot | 20000 |
| Infiltration | 20000 |

The original full pass produced zero candidates for `DoS`, `DDoS`, and
`Infiltration`. The cause was not missing labels; it was endpoint resolution:
the PCAP filename parser only accepted IPs at the end of filenames, so split
captures such as `UCAP172.31.69.25-part1.pcap` were not indexed. The resolver
now extracts IPs from anywhere in the filename and records all selected capture
parts for an endpoint.

The later strict pass applies the IP/time-window cross-check from
`office-model-pretraining-checklist.md`. `WebBased` remains at 157 because only
157 successful CSE-CIC-IDS2018 WebBased flows survived both `Attempted`
exclusion and CSV/IP-time agreement. CICIDS2017 WebBased augmentation is still
intentionally separate and must be source-tagged and train-only when added.

Accepted rows by day from the corrected full scan:

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
    "WebBased": 157
  },
  "Thursday-01-03-2018": {
    "Benign": 6502903,
    "Infiltration": 39689
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

## Blocking Items Before Full Graph Extraction

The improved CSV labels and the IP/time-window table are now both wired into
the candidate gate. Rows that disagree are counted and excluded from candidate
materialization.

Full PCAP graph extraction should still start with a bounded pilot before any
six-day build. The pilot should verify packet extraction, feature ranges,
payload sanity, and graph tensor structure against a small subset of the strict
candidate manifest.

## Next Implementation Step

Extend `secureedge.data.office_pipeline` with a pilot extraction mode for one
day/class:

```text
candidate flow key -> endpoint PCAP -> NFStream extraction -> compact graph record
```

The pilot should run on one class first, preferably `Bot` or `WebBased`, before
attempting all six days.
