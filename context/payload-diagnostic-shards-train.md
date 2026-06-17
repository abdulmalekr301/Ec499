# Payload Quality Diagnostic

Generated: `2026-06-16T18:06:30+00:00`

## Result
```json
{
  "source": "shards",
  "split": "train",
  "files_examined": 3,
  "graphs_examined": 3000,
  "mean_packet_node_feature_value": 0.0700152267947536,
  "min_packet_node_feature_value": 0.0,
  "max_packet_node_feature_value": 0.500033438205719,
  "mean_nonzero_fraction": 0.15376555077032147,
  "min_nonzero_fraction": 0.0,
  "max_nonzero_fraction": 0.9910333156585693,
  "mean_packet_rows_with_any_payload_fraction": 0.7954833358302712,
  "min_packet_rows_with_any_payload_fraction": 0.0,
  "max_packet_rows_with_any_payload_fraction": 1.0,
  "zero_mean_graphs": 161,
  "nonzero_mean_graphs": 2839,
  "graphs_with_any_payload": 2839,
  "graphs_without_any_payload": 161,
  "interpretation": "packet features are non-zero but sparse; inspect payload extraction quality before assuming payloads are fully informative",
  "per_class": {
    "Benign": {
      "graphs_examined": 390,
      "mean_packet_node_feature_value": 0.10046653144124251,
      "mean_nonzero_fraction": 0.2083326714632746,
      "mean_packet_rows_with_any_payload_fraction": 0.7122644884655109,
      "zero_mean_graphs": 19,
      "payload_gate": "adequate for payload-heavy class"
    },
    "DDoS": {
      "graphs_examined": 353,
      "mean_packet_node_feature_value": 0.05149338948831428,
      "mean_nonzero_fraction": 0.14445417033354738,
      "mean_packet_rows_with_any_payload_fraction": 0.8252322167242553,
      "zero_mean_graphs": 41,
      "payload_gate": "adequate for payload-heavy class"
    },
    "DoS": {
      "graphs_examined": 366,
      "mean_packet_node_feature_value": 0.029647423822465838,
      "mean_nonzero_fraction": 0.0873626172768405,
      "mean_packet_rows_with_any_payload_fraction": 0.9064277231367559,
      "zero_mean_graphs": 13,
      "payload_gate": "adequate for payload-heavy class"
    },
    "Mirai": {
      "graphs_examined": 357,
      "mean_packet_node_feature_value": 0.16680093543442273,
      "mean_nonzero_fraction": 0.33635799821429685,
      "mean_packet_rows_with_any_payload_fraction": 0.9973389356076217,
      "zero_mean_graphs": 0,
      "payload_gate": "adequate for payload-heavy class"
    },
    "Recon": {
      "graphs_examined": 388,
      "mean_packet_node_feature_value": 0.012624873263252383,
      "mean_nonzero_fraction": 0.02939420858801333,
      "mean_packet_rows_with_any_payload_fraction": 0.8747813295688212,
      "zero_mean_graphs": 7,
      "payload_gate": "adequate for payload-heavy class"
    },
    "Spoofing": {
      "graphs_examined": 386,
      "mean_packet_node_feature_value": 0.11759476262428846,
      "mean_nonzero_fraction": 0.23861550397892275,
      "mean_packet_rows_with_any_payload_fraction": 0.6065739613180797,
      "zero_mean_graphs": 47,
      "payload_gate": "adequate for payload-heavy class"
    },
    "WebBased": {
      "graphs_examined": 381,
      "mean_packet_node_feature_value": 0.04481160994404481,
      "mean_nonzero_fraction": 0.10709126337009404,
      "mean_packet_rows_with_any_payload_fraction": 0.7870706192210434,
      "zero_mean_graphs": 20,
      "payload_gate": "below 0.10 payload-heavy class gate; inspect PacketCapture before round-4 training"
    },
    "BruteForce": {
      "graphs_examined": 379,
      "mean_packet_node_feature_value": 0.039378424738500006,
      "mean_nonzero_fraction": 0.08624737787519343,
      "mean_packet_rows_with_any_payload_fraction": 0.6758066673903164,
      "zero_mean_graphs": 14,
      "payload_gate": "below 0.10 payload-heavy class gate; inspect PacketCapture before round-4 training"
    }
  }
}
```

- Saved machine-readable output to `/var/home/alucard-00/EC499/artifacts/payload_diagnostic_shards_train.json`.
