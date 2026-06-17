# Graph Feature Engineering

Generated: `2026-06-15T01:54:54+00:00`

## Action
- Validated the final XG-NID graph feature artifacts.
- Flow node features are the NFStream numeric feature vector plus the 16 temporal features.
- Packet node features are 1,500 normalized payload-byte values per packet.
- Contain edge features are standardized direction, IP size, transport size, and payload size.
- Link edge features are packet-to-packet time deltas normalized by the 99th percentile from training graphs.

## Manifest
```json
{
  "train_count": 160000,
  "test_count": 32000,
  "feature_dimensions": {
    "flow_node": 92,
    "packet_node": 1500,
    "contain_edge": 4,
    "link_edge": 1
  },
  "scalers": {
    "flow_node": "/var/home/alucard-00/EC499/artifacts/flow_node_scaler.joblib",
    "contain_edge": "/var/home/alucard-00/EC499/artifacts/contain_edge_scaler.joblib",
    "link_edge": "/var/home/alucard-00/EC499/artifacts/link_edge_norm_p99.json"
  }
}
```
