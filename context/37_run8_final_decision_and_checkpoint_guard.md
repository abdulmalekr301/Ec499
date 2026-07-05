# Run 8 Final Decision and Checkpoint Guard

## Source Reviewed

- Read `context/systematic-fix-plan (3).md`.
- Reviewed `context/logs-8.md`.
- Checked current training code in `secureedge/models/train.py`.
- Checked current checkpoint artifacts under `artifacts/`.

## Run 8 Result

Run 8 used:

- Batch size: `64`
- Learning rate target: `0.003`
- Scheduler: cosine warm restarts
- Cycle: `T0=30`, `T_mult=1`
- Max epochs: `100`
- Best macro F1: `0.889494` at epoch `93`

This did not beat Run 6, which remains the strongest measured configuration:

- Batch size: `512`
- Learning rate target: `0.003`
- Scheduler: cosine warm restarts
- Cycle: `T0=50`, `T_mult=2`
- Max epochs: `300`
- Best macro F1: `0.895089` at epoch `281`

## Final Decision from Systematic Fix Plan 3

The plan concludes that no more hyperparameter runs are expected to improve the model with the current selective PCAP dataset.

The best measured result is Run 6. The remaining gap to the XG-NID paper result is attributed to dataset coverage and diversity rather than a remaining architecture or training-code mismatch.

## Important Checkpoint Problem Found

The training script was saving every run's best checkpoint to:

```text
artifacts/best_hgnn.pt
```

That meant a later exploratory run could overwrite the global best checkpoint even when it performed worse than an earlier run.

This already happened:

- `artifacts/best_hgnn.pt` currently contains Run 8.
- Run 8 best macro F1 is `0.889494`.
- Run 6 best macro F1 was higher at `0.895089`.
- There is no `artifacts/training_runs/run_06_best_hgnn.pt` file available to restore the Run 6 weights.

The Run 6 metrics and logs are preserved, but the Run 6 checkpoint weights are not currently recoverable from the artifact directory.

## Code Fix Applied

Updated `secureedge/models/train.py` so each run now always saves its own best checkpoint:

```text
artifacts/training_runs/run_XX_best_hgnn.pt
```

The global checkpoint:

```text
artifacts/best_hgnn.pt
```

is now promoted only when the current run's best macro F1 is higher than the existing global checkpoint's macro F1.

This prevents weaker exploratory runs from overwriting the best known model in future experiments.

## Verification

Ran:

```bash
.venv/bin/python -m compileall secureedge tests
```

Result:

- `secureedge/models/train.py` compiled successfully.

## Current Artifact State

Current global checkpoint:

```text
artifacts/best_hgnn.pt
run_id=8
epoch=93
best_macro_f1=0.889494
```

Run 8 checkpoint:

```text
artifacts/training_runs/run_08_best_hgnn.pt
run_id=8
epoch=93
best_macro_f1=0.889494
```

Run 6 checkpoint:

```text
artifacts/training_runs/run_06_best_hgnn.pt
missing
```

## Recommendation

For reporting, use Run 6 as the best measured model because its metrics are the strongest.

For future training, keep the updated checkpoint guard in place. If the Run 6 weights are required again, the practical recovery path is to rerun the Run 6 configuration, because the old Run 6 checkpoint file is not present.
