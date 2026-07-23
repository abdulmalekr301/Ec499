# HGNN Architecture

Generated: `2026-07-07T04:01:19+00:00`

## Action
- Deprecated the flat MLP path and added `secureedge.models.hgnn.SecureEdgeHGNN`.
- Implemented two heterogeneous GAT layers with flow-to-packet, packet-to-flow, and packet-to-packet edge types.
- Flow node input dimension: `92`.
- Packet node input dimension: `1500`.
- Optional packet payload CNN encoder enabled: `False`.
- Hidden size: `64`.
- BatchNorm epsilon: `1.0`.
- GAT attention: `heads=2`, `attention size=32`, concatenated output `64`.
- Note: multi-head GAT remains a SecureEdge enhancement; the XG-NID repo comparison showed `attn_size` is dead code in the upstream model.
- Both HGNN layers receive edge attributes for contain, reverse-contain, and packet-link relations.
- Graph readout mode: `concat`.
- With concat readout, the classifier head receives a 128-dimensional flow+packet embedding.
