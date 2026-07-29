# Office GATv2 Architecture Switch

Date: 2026-07-29

## Objective

Switch the office model training path from `GATConv` to `GATv2Conv` before starting Phase 7 training.

## Decision

The shared `SecureEdgeHGNN` implementation now uses PyTorch Geometric `GATv2Conv` for all heterogeneous attention relations.

Updated relations:

| Layer | Relation | Convolution |
| --- | --- | --- |
| `conv1` | `flow -> contains -> packet` | `GATv2Conv` |
| `conv1` | `packet -> rev_contains -> flow` | `GATv2Conv` |
| `conv1` | `packet -> linked_to -> packet` | `GATv2Conv` |
| `conv2` | `flow -> contains -> packet` | `GATv2Conv` |
| `conv2` | `packet -> rev_contains -> flow` | `GATv2Conv` |
| `conv2` | `packet -> linked_to -> packet` | `GATv2Conv` |

The model exposes:

```text
model.attention_conv = "GATv2Conv"
```

## Files Updated

| File | Change |
| --- | --- |
| `secureedge/models/hgnn.py` | Replaced `GATConv` import and instantiations with `GATv2Conv`; updated architecture documentation text |
| `configs/office_cic_ids_2018.yaml` | Set `architecture_policy.current_attention_conv` to `GATv2Conv` |
| `secureedge/office/config.py` | Added validation that office training uses `GATv2Conv` |
| `secureedge/office/train.py` | Records `model_attention_conv` in training history and checkpoints |
| `secureedge/office/evaluate.py` | Records `model_attention_conv` in evaluation metrics |

## Config Status

Office config now records:

```yaml
architecture_policy:
  current_attention_conv: GATv2Conv
  future_attention_conv: GATv2Conv
  do_not_use: SAGEConv
```

Current office config hash after the switch:

```text
84716b5cc7aa1e0e58c5c50ca9a3661d2c624180506c56045435c7c898411dc1
```

## Verification

Compile check passed:

```bash
.venv/bin/python -m compileall secureedge/models/hgnn.py secureedge/office/config.py secureedge/office/train.py secureedge/office/evaluate.py
```

Model instantiation check passed:

```text
attention_conv GATv2Conv
conv_types ['GATv2Conv', 'HeteroConv']
gatv2_model_instantiation_ok
```

Office graph forward-pass smoke test passed on one validation graph per class:

```text
batch_graphs 7
logits_shape (7, 7)
attention_conv GATv2Conv
gatv2_office_forward_ok
```

## Training Implication

The next office training run will be a GATv2 run, not the older GAT baseline. Checkpoints and training history will include:

```json
"model_attention_conv": "GATv2Conv"
```

This should be treated as an architecture-change run when comparing against older SecureEdge GAT results.
