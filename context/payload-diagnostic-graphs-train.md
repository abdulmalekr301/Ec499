# Payload Quality Diagnostic

Generated: `2026-06-16T17:46:12+00:00`

## Result
```json
{
  "source": "graphs",
  "split": "train",
  "files_examined": 500,
  "graphs_examined": 500,
  "mean_packet_node_feature_value": 0.10851583028747701,
  "min_packet_node_feature_value": 0.0,
  "max_packet_node_feature_value": 0.49857139587402344,
  "mean_nonzero_fraction": 0.22408204130409284,
  "min_nonzero_fraction": 0.0,
  "max_nonzero_fraction": 0.9840666651725769,
  "mean_packet_rows_with_any_payload_fraction": 0.6556278539672494,
  "min_packet_rows_with_any_payload_fraction": 0.0,
  "max_packet_rows_with_any_payload_fraction": 1.0,
  "zero_mean_graphs": 29,
  "nonzero_mean_graphs": 471,
  "graphs_with_any_payload": 471,
  "graphs_without_any_payload": 29,
  "interpretation": "packet features are non-zero but sparse; inspect payload extraction quality before assuming payloads are fully informative"
}
```

- Saved machine-readable output to `/var/home/alucard-00/EC499/artifacts/payload_diagnostic_graphs_train.json`.
