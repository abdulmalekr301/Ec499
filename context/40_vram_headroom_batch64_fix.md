# VRAM Headroom Batch-64 Fix

## Trigger

Run 11 used:

```text
batch_size=128
grad_accum_steps=4
effective_batch_size=512
use_amp=yes
```

Even with AMP, the RTX 4060 8GB VRAM usage reached about 90% during the first
two epochs. That is too close to the limit for a long run because evaluation,
checkpointing, CUDA allocator fragmentation, or a slightly larger graph batch
could push the process into an out-of-memory error.

## Fix Applied

Updated `secureedge/config.py`:

- Default physical training batch: `64`
- Default gradient accumulation steps: `8`
- Effective batch remains: `512`
- Default evaluation batch: `64`
- AMP remains enabled by default

Updated `secureedge/models/train.py`:

- Added `SECUREEDGE_EVAL_BATCH_SIZE`.
- Evaluation now uses `config.EVAL_BATCH_SIZE` instead of reusing the training
  batch size.
- Run configuration logs now include `eval_batch_size`.

## Why This Helps

Batch `64` roughly halves peak activation memory versus batch `128`, while
gradient accumulation keeps the optimization batch equivalent to `512` graphs.
The separate eval batch prevents validation from becoming the hidden VRAM spike.

## Verification

Ran:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Also imported `secureedge.models.train` directly and confirmed:

```text
batch=64
eval=64
accum=8
```

All checks passed.

## Recommendation

Stop Run 11 and restart from scratch with the batch-64 command. Do not resume
Run 11 because it only completed a few early epochs and the goal is a clean
low-VRAM run.
