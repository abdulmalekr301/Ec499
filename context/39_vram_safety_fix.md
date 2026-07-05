# VRAM Safety Fix

## Problem

After adding the packet payload CNN encoder, the previous physical batch size of
`512` became too large for an 8GB RTX 4060. The CNN processes packet payloads as
`batch_graphs * packets_per_graph * 1500` byte sequences, so activation memory is
much higher than the older raw-linear payload path.

## Fixes Applied

Updated `secureedge/config.py`:

- Default physical batch size changed from `512` to `128`.
- Default gradient accumulation steps set to `4`.
- Default effective batch size remains `512`.
- AMP is enabled by default with `SECUREEDGE_USE_AMP=1`.

Updated `secureedge/models/train.py`:

- Added CUDA automatic mixed precision using `torch.amp.autocast`.
- Added `torch.amp.GradScaler`.
- Added gradient accumulation controlled by `SECUREEDGE_GRAD_ACCUM_STEPS`.
- Added run-log fields for:
  - physical batch size
  - gradient accumulation steps
  - effective batch size
  - AMP status

## Safe Training Configuration

Use:

```text
SECUREEDGE_BATCH_SIZE=128
SECUREEDGE_GRAD_ACCUM_STEPS=4
SECUREEDGE_USE_AMP=1
```

This keeps the effective batch size at `512` while reducing peak VRAM pressure
to roughly one quarter of the old physical batch size, with additional savings
from mixed precision.

## Verification

Ran:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Both passed.

## Operational Note

If VRAM remains full after a crash, the likely cause is a stale Python training
process still alive in the user's terminal session. From a normal terminal, run:

```bash
nvidia-smi
```

Then stop only the stale training PID shown in the process table:

```bash
kill <PID>
```

If it does not exit after a few seconds:

```bash
kill -9 <PID>
```

Do not start another training run until `nvidia-smi` shows the VRAM has been
released.
