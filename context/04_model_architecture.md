# HGNN Architecture

Generated: `2026-06-16T18:34:52+00:00`

## Action
- Deprecated the flat MLP path and added `secureedge.models.hgnn.SecureEdgeHGNN`.
- Implemented two heterogeneous GAT layers with flow-to-packet, packet-to-flow, and packet-to-packet edge types.
- Flow node input dimension: `92`.
- Packet node input dimension: `1500`.
- Hidden size: `64`.
- Graph embeddings are produced by mean-pooling flow and packet node embeddings and averaging the two pooled vectors.
- The classifier head is `Linear(64, 32) -> ReLU -> Linear(32, 16) -> ReLU -> Linear(16, 8)`.
