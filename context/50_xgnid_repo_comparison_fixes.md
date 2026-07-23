# XG-NID Repo Comparison Fixes

## Source

Implemented fixes from `context/xgnid-repo-comparison-findings.md`.

## Applied Code Changes

### BatchNorm epsilon

- Added `SECUREEDGE_HGNN_BATCHNORM_EPS`.
- Default value is now `1.0`, matching the actual GNN4ID/XG-NID source-code behavior.
- Wired the value into every `BatchNorm1d` layer in `secureedge/models/hgnn.py`.
- Added `batchnorm_eps` to the model signature so old checkpoints with incompatible architecture settings are not silently resumed.

### MAC filtering

- Reverted class-conditional attack filtering.
- `MAC_FILTERED_CLASSES` now means every non-benign class:
  - `BruteForce`
  - `DDoS`
  - `DoS`
  - `Mirai`
  - `Recon`
  - `Spoofing`
  - `WebBased`
- WebBased and BruteForce no longer bypass attacker-MAC filtering when the filter is enabled.
- Benign still drops flows involving known attacker MACs when strict benign enforcement is enabled.

### Raw graph-value mode for Run 16b

- Added `SECUREEDGE_GRAPH_VALUE_MODE`.
- Supported values:
  - `scaled`: current SecureEdge behavior, using flow `StandardScaler`, packet `/255`, contain-edge scaler, and link p99 normalization.
  - `raw`: XG-NID comparison behavior, using raw flow values, raw 0-255 packet bytes, raw contain-edge values, and raw link-edge deltas.
- `raw` mode disables graph scaler fitting and records `disabled_raw_mode` in the graph manifest scaler provenance.
- The leakage audit now accepts either train-only scaled provenance or explicitly disabled raw-mode provenance.

### Plateau scheduler diagnostic support

- Added `SECUREEDGE_PLATEAU_MONITOR`.
- Supported values:
  - `val_macro_f1`: current validation-driven behavior.
  - `train_accuracy`: XG-NID diagnostic behavior for the one-off Run 17 experiment.
- Added `SECUREEDGE_LR_PLATEAU_THRESHOLD`, defaulting to `0.01`.
- Training logs and run config now record the plateau monitor and threshold.

### Tests

- Extended `tests/smoke_checks.py` to verify:
  - uniform non-benign MAC filtering configuration
  - WebBased attacker/background behavior when attacker MAC filtering is enabled
  - HGNN BatchNorm layers use `config.HGNN_BATCHNORM_EPS`

## Verification Performed

```text
.venv/bin/python -m compileall secureedge tests
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt .venv/bin/python tests/smoke_checks.py
SECUREEDGE_GRAPH_VALUE_MODE=raw .venv/bin/python - <<'PY' ...
SECUREEDGE_GRAPH_VALUE_MODE=scaled .venv/bin/python - <<'PY' ...
```

Results:

- Python compile check passed.
- Smoke checks passed.
- Raw graph-value mode kept packet bytes as `[0.0, 255.0]` and disabled graph normalizers.
- Scaled graph-value mode kept packet bytes as `[0.0, 1.0]`.
- Uniform MAC filtering check showed WebBased/BruteForce background flows are dropped when attacker MAC filtering is enabled.

## Artifact Status

No full graph rebuild was launched as part of this fix pass.

The code now supports the requested experiment sequence:

- Run 16a: use the current scaled graph artifacts with `SECUREEDGE_HGNN_BATCHNORM_EPS=1.0`.
- Run 16b: rebuild graphs with `SECUREEDGE_GRAPH_VALUE_MODE=raw` before training.
- Run 17: run the exact plateau diagnostic with `SECUREEDGE_SCHEDULER=plateau`, `SECUREEDGE_PLATEAU_MONITOR=train_accuracy`, `SECUREEDGE_LR_TARGET=0.01`, `SECUREEDGE_BATCH_SIZE=64`, and `SECUREEDGE_MAX_EPOCHS=30`.
- Run 18: regenerate preprocessing artifacts with attacker-MAC filtering enabled to apply uniform attack-class MAC filtering to WebBased and BruteForce as well.

## Important Caveat

Existing graph artifacts were generated before this comparison pass. If they came from the class-conditional MAC-filtered run, they still contain that old data policy until preprocessing and graph materialization are rerun with the updated code.
