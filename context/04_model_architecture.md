# HGNN Architecture

Generated: `2026-07-05T08:35:55+00:00`

## Action
- Deprecated the flat MLP path and added `secureedge.models.hgnn.SecureEdgeHGNN`.
- Implemented two heterogeneous GAT layers with flow-to-packet, packet-to-flow, and packet-to-packet edge types.
- Flow node input dimension: `92`.
- Packet node input dimension: `1500`.
- Optional packet payload CNN encoder enabled: `False`.
- Hidden size: `64`.
- GAT attention: `heads=2`, `attention size=32`, concatenated output `64`.
- Both HGNN layers receive edge attributes for contain, reverse-contain, and packet-link relations.
- Graph readout mode: `concat`.
- With concat readout, the classifier head receives a 128-dimensional flow+packet embedding.
