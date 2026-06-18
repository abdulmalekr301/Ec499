# Round 6 Multi-Head GAT Fix

Generated: `2026-06-18`

## Summary

Applied the remaining XG-NID architectural alignment before starting training
round 6.

Round 5 completed all 300 epochs before this change was made. Its best result
was:

```text
best_epoch=289
best_macro_f1=0.890584
latest_accuracy=0.889156
latest_macro_f1=0.889493
stopped_reason=max_epochs_reached
```

## Problem

`secureedge/config.py` defined:

```python
HGNN_ATTN_SIZE = 32
HGNN_HIDDEN_SIZE = 64
```

but `secureedge/models/hgnn.py` instantiated `GATConv` with `hidden_size`
directly and did not pass `heads`. PyTorch Geometric defaults `heads=1`, so all
previous HGNN training rounds used single-head graph attention.

That left `HGNN_ATTN_SIZE` as dead configuration and did not match the XG-NID
style setting where two 32-dimensional attention heads concatenate into a
64-dimensional hidden representation.

## Code Change

Updated all relation-specific `GATConv` modules in both HGNN layers:

```python
GATConv(
    (-1, -1),
    config.HGNN_ATTN_SIZE,
    heads=2,
    concat=True,
    edge_dim=...,
    add_self_loops=False,
)
```

For the second HGNN layer, which does not pass edge attributes:

```python
GATConv(
    (-1, -1),
    config.HGNN_ATTN_SIZE,
    heads=2,
    concat=True,
    add_self_loops=False,
)
```

Because `2 * HGNN_ATTN_SIZE = 64`, the output still matches
`HGNN_HIDDEN_SIZE`. BatchNorm and classifier dimensions did not need to change.

## Expected Effect

The model now learns two independent attention patterns per graph relation
instead of one. This is important for SecureEdge's heterogeneous graph because
flow nodes carry 92-dimensional NFStream statistics while packet nodes carry
1,500-dimensional payload byte features.

## Verification

Before launching round 6, the code was checked with:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Round 6 uses the same balanced XG-NID oversampling dataset and training command
as round 5, with the HGNN architecture fix applied.
