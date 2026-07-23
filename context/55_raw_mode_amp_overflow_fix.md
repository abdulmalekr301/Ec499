# Raw Mode AMP Overflow Fix

## Trigger

The Run 16b restart crashed immediately:

```text
FloatingPointError: Non-finite logits detected during epoch 1, batch 1.
```

This occurred before the first optimizer step, so the failure was a forward-pass
numerical issue, not training divergence.

## Diagnosis

The rebuilt graph tensors were finite, and the CPU forward-pass smoke check was
finite. The remaining difference was CUDA AMP.

Actual graph-shard inspection found finite but fp16-incompatible raw values:

```text
Rolling_Average_Duration: 2.25247e+08
bidirectional_duration_ms: 243012
src2dst_duration_ms: 243012
dst2src_duration_ms: 242623
```

`float16` max finite value is about `65504`, so AMP can overflow these raw
features during the forward pass.

## Fix

Training now automatically disables AMP when:

```text
SECUREEDGE_GRAPH_VALUE_MODE=raw
```

The run config and markdown log record:

```text
amp_disabled_reason=raw_graph_values_can_exceed_fp16_range
```

This keeps raw graph mode numerically fp32 while leaving AMP available for
scaled graph mode.

## VRAM Adjustment

Because fp32 uses more VRAM than AMP, the next run should use:

```text
SECUREEDGE_BATCH_SIZE=256
SECUREEDGE_GRAD_ACCUM_STEPS=2
SECUREEDGE_EVAL_BATCH_SIZE=256
```

This keeps the effective training batch size at 512 while reducing physical
per-step GPU memory pressure.
