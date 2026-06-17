# Memory Safety Patch After PCAP Extraction Crash

Generated: `2026-06-14`

## Problem

Full graph preprocessing crashed the system twice due to memory and swap pressure during PCAP extraction.

The first mitigation used disk-backed graph reservoirs, but temporary reservoir files were still saved as PyTorch/PyG graph objects. That meant preprocessing imported the CUDA 13 PyTorch stack and repeatedly materialized tensor-heavy graph objects while streaming PCAPs.

## Fix Applied

- Changed temporary reservoir storage from Torch/PyG `.pt` graph objects to compact pickle `.pkl` records.
- Compact records store:
  - flow node values as `float32` NumPy arrays
  - packet payloads as `uint8` NumPy arrays
  - contain edge features as `float32`
  - link deltas as `float32`
  - label and metadata
- `HeteroData` graph objects are now materialized only during the final normalized graph-writing phase.
- Removed the PyG dependency check from the streaming phase so Torch/PyG is not imported while NFStream reads PCAPs.
- Added memory guard settings:
  - `SECUREEDGE_MAX_PROCESS_RSS_GB`
  - `SECUREEDGE_MIN_AVAILABLE_MEMORY_GB`

## Verification

Passed:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Preprocessing import memory check:

```text
start_rss_mb=16.3
after_preprocess_import_rss_mb=142.4
torch_imported=False
```

## Current Status

The full extraction run was stopped after the crash report. No full PCAP extraction is currently running.

The next full extraction should be run as a controlled attempt, with memory visible and with the compact reservoir path active.
