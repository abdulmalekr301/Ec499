# MODEL-001 Architecture Verification

Date: 2026-07-16

## Action

Verified the live HGNN implementation referenced by `context/PROJECT_RECOVERY_AND_IMPLEMENTATION_PLAN.md`.

## Finding

The current model implementation in `secureedge/models/hgnn.py` imports and instantiates `torch_geometric.nn.GATConv`, not `GATv2Conv`.

Relevant implementation facts:

- `require_pyg_layers()` imports `GATConv`, `HeteroConv`, and `global_mean_pool`.
- `SecureEdgeHGNN` builds two `HeteroConv` layers.
- Each relation uses `GATConv`.
- Both convolution layers pass edge attributes with `edge_dim`.
- BatchNorm epsilon is read from `config.HGNN_BATCHNORM_EPS`, currently defaulting to `1.0`.
- Readout is controlled by `config.HGNN_READOUT_MODE`, currently defaulting to `concat`.

## Interpretation

The Codex report statement that the model used `GATv2Conv` was incorrect for the current workspace. The live architecture is a two-layer heterogeneous `GATConv` model.

The recovery plan also states that the Run-21/XG-NID-faithful architecture should be `SAGEConv`. That claim conflicts with several existing local context notes describing the current GAT path as an intentional SecureEdge implementation or enhancement.

## Decision

No architecture change was made in this pass.

Reason:

- Switching from `GATConv` to `SAGEConv` would change model semantics before the CIC-IDS-2018 office graph dataset is complete.
- The current implementation uses edge attributes through both convolution layers; replacing this with `SAGEConv` requires a deliberate design decision because plain PyG `SAGEConv` does not consume edge attributes in the same way.
- Training is not currently the blocker; office graph materialization and validation are.

## Required follow-up before office training

Before any office training run:

1. Decide whether the office model should use the current SecureEdge GAT implementation or a separate SAGEConv comparison arm.
2. If SAGEConv is required, implement it as an explicit configurable architecture option rather than replacing the current model silently.
3. Add an architecture assertion test that checks the selected convolution class.
4. Record the selected architecture in the office training manifest.

## User architecture decision

On 2026-07-17, the project owner made the architecture direction explicit:

- Do not switch the office model from attention-based aggregation to `SAGEConv`.
- Keep attention-based aggregation because uniform mean aggregation is not desired for this project.
- When the architecture-change phase begins, switch the attention operator from `GATConv` to `GATv2Conv`.

The office configuration now records this policy as:

```yaml
architecture_policy:
  current_attention_conv: GATConv
  future_attention_conv: GATv2Conv
  do_not_use: SAGEConv
```
