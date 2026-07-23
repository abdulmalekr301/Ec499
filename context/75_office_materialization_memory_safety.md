# Office Materialization Memory Safety

Generated: `2026-07-14T00:45:00+02:00`

## Problem

The first office graph materialization attempt overloaded memory and swap while
NFStream was running inside the main Codex/VS Code process. This repeated the
same failure mode previously seen during CIC-IoT2023 graph extraction: a large
PCAP parser workload can destabilize the desktop even when compact graph records
are used.

## Fix Applied

- Kept the office split/candidate logic in the parent process.
- Moved each endpoint-PCAP NFStream scan into a subprocess worker:
  - `--mode office-materialize-pcap-worker`
  - one PCAP candidate JSONL in;
  - one worker summary JSON out.
- Applied the same allocator/thread limits used for CIC-IoT2023:
  - `MALLOC_ARENA_MAX=2`
  - `OMP_NUM_THREADS=1`
  - `OPENBLAS_NUM_THREADS=1`
  - `MKL_NUM_THREADS=1`
- Applied the same hard address-space guard unless unsafe mode is explicitly enabled:
  - `resource.RLIMIT_AS`
  - based on `SECUREEDGE_MAX_PROCESS_RSS_GB`
- Added parent and worker memory checks:
  - stop if parent RSS exceeds `SECUREEDGE_MAX_PROCESS_RSS_GB`;
  - stop if available memory drops below `SECUREEDGE_MIN_AVAILABLE_MEMORY_GB`;
  - worker checks memory every `SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL` scanned flows.
- Added a full-run lock:
  - full office materialization now refuses to start unless
    `SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1` is set.
- Added bounded pilot controls:
  - `--office-limit-unique`
  - `--office-max-pcaps`
  - `--office-max-flows-per-pcap`
- Preserved resumability:
  - existing compact `.pkl` records are reused unless `--office-overwrite-compact` is passed;
  - per-PCAP candidate and summary files are written under
    `artifacts/office_model/materialization_work`.

## Validation

Compile and smoke checks:

```bash
.venv/bin/python -m compileall secureedge/data/office_pipeline.py secureedge/data/graph_builder.py tests/smoke_checks.py
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

Tiny guarded pilot:

```bash
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-limit-unique 20 \
  --office-max-pcaps 1 \
  --office-overwrite-compact \
  --office-max-flows-per-pcap 50000
```

Result:

```json
{
  "requested_unique_candidates": 20,
  "materialized_or_existing": 1,
  "missing_count": 19,
  "stop_reason": "max_pcaps_reached",
  "processed_pcaps": 1,
  "max_pcaps": 1,
  "safety_summary": {},
  "newly_materialized_class_counts": {
    "Benign": 1
  }
}
```

The worker matched `1/1` candidate in the processed PCAP and scanned `21495`
flows. The parent process survived cleanly and memory remained available after
the run.

Full-run lock check:

```bash
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-max-pcaps 1
```

Result: refused before PCAP processing with:

```text
Refusing to start full office graph materialization inside the interactive workspace.
Run a bounded pilot with --office-limit-unique and --office-max-pcaps first.
For a controlled full batch run, set SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1.
```

## Current Status

The final candidate split manifest exists and matches the plan:

```json
{
  "train_real": 120373,
  "train": 126000,
  "val": 12103,
  "test": 12103,
  "materialization_unique": 144579,
  "cicids2017_in_val": 0,
  "cicids2017_in_test": 0
}
```

Full graph materialization has **not** been restarted after the crash. The next
safe step is a gradually scaled bounded run, for example:

```bash
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-limit-unique 200 \
  --office-max-pcaps 5 \
  --office-max-flows-per-pcap 100000
```

Only after bounded runs are stable should the full run be attempted in a
controlled batch session with:

```bash
SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact
```
