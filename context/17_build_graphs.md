# Graph Construction From Compact Records

Generated: `2026-07-07T00:35:21+00:00`

## Action
- Loaded compact records from `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json`.
- Fitted flow-node and contain-edge `StandardScaler` objects on training records only.
- Fitted link-edge p99 normalization on training link deltas only.
- Converted compact pickle records into PyG `HeteroData` graph objects.
- Saved training graphs under `/var/home/alucard-00/EC499/data/graphs/train`.
- Saved validation graphs under `/var/home/alucard-00/EC499/data/graphs/val`.
- Saved test graphs under `/var/home/alucard-00/EC499/data/graphs/test`.
- Saved graph manifest to `/var/home/alucard-00/EC499/artifacts/graph_dataset_manifest.json`.

## Counts
```json
{
  "n_train": 160000,
  "n_val": 11843,
  "n_test": 11841,
  "class_counts_train": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 20000,
    "Spoofing": 20000,
    "WebBased": 20000,
    "BruteForce": 20000
  },
  "class_counts_val": {
    "Benign": 2000,
    "DDoS": 2000,
    "DoS": 2000,
    "Mirai": 2000,
    "Recon": 1929,
    "Spoofing": 1346,
    "WebBased": 386,
    "BruteForce": 182
  },
  "class_counts_test": {
    "Benign": 2000,
    "DDoS": 2000,
    "DoS": 2000,
    "Mirai": 2000,
    "Recon": 1928,
    "Spoofing": 1346,
    "WebBased": 385,
    "BruteForce": 182
  },
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
