# SecureEdge Training Run 18

> Run started: `2026-07-06T01:28:45+00:00`
> Last updated: `2026-07-06T01:28:46+00:00`

## Configuration

```text
device=cuda
batch_size=512
grad_accum_steps=1
effective_batch_size=512
eval_batch_size=512
use_amp=yes
use_graph_shards=yes
checkpoint_selection_split=val
num_workers=0
prefetch_factor=2
lr_start=0.0003
lr_target=0.003
lr_min=1e-05
scheduler=cosine
plateau_monitor=val_macro_f1
plateau_threshold=0.01
cosine_t0=50
cosine_t_mult=2
label_smoothing=0.0
max_epochs=300
early_stop_patience=50
print_class_every=10
```

## Current Status

- Stopped reason: `running`.
- Epochs completed: `0`.
- Best epoch: `None`.
- Best validation macro F1: `-1.000000`.
