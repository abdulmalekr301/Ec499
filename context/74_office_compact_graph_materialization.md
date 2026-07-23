# Office Compact Graph Materialization

Generated: `2026-07-22T22:13:04+00:00`

## Action
- Materialized office-model compact graph records from final split candidates.
- Matched candidate flows by endpoint PCAP, 5-tuple, and timestamp tolerance.
- Ordered bounded pilots by endpoint-PCAP candidate density to reduce one-graph full-PCAP scans.
- Deferred max-flow and memory-floor PCAP stops instead of letting one worst-case scan end the whole pilot.
- Recomputed 92 flow-node features from matched packets via NFStream-derived records.
- Logged per-graph numerical and payload safety flags while building records.
- Saved compact graph manifest to `/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json`.

## Counts
```json
{
  "requested_unique_candidates": 491,
  "materialized_or_existing": 274,
  "missing_count": 212,
  "stop_reason": "max_pcaps_reached",
  "newly_materialized_class_counts": {
    "Infiltration": 274
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 274
  },
  "processed_pcaps": 4,
  "deferred_pcaps": [],
  "pcap_health": {
    "enabled": false,
    "manifest_path": "/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json",
    "status": "disabled",
    "skip_pcaps": [],
    "skip_reasons": {}
  },
  "safety_summary": {
    "flagged_graphs": 167,
    "matched_zero_packet_graph": 5
  }
}
```

## Safety Samples
```json
[
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "d22287144e00d359357509d710b026f3dafe5d7a0bfa82233e3b8e73d6a7b9f0",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 55581.0,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "b793ce53bc89c6ea124d3013033b983b78db7c9589b7efde8dfd981f035f63b7",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 750892.875,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "6f561d5c9be4bd488e03cec81a7c5b3057440e7a6ed84190947a0fa921cb32e4",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 53318.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "1477495ca70ad30d173cdace9b3543d8264937dffcc0177f8fe349fb5b236cc7",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 939062.5,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "1bc17bbc543139836a360c041aefa99c92d9112b566cfa1941dc23c62ab0f55b",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1309589.75,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "5780f786eddd10d2d5c5f154a5b39d78792b993414e7ef8da3b44f97c4b1b437",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 53317.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "53ca4256fdaa95042f0215ed5ab4d0691e3819af967116ef7517683402e8200f",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 55592.0,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "d0ddd90bd076f235a565b62f250252a8bf0e55ff5c81f30eac83c8fcf0d18b8f",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 114066.6640625,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "f771e458b1d4e5a15330ceaf409a7079c75337f027e86484a1f374ff3c992838",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 150298.671875,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "7ac10fbed42473107f7a4a8df4909b30411719b62e4f47ac4992726c1d909534",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 222496.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "7916c9b0b4d876f99e6af4197b1b47cdca34a51af0f5623d9497b40484c5e6ec",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 226994.671875,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "84e9100e4bb1313822ac9ea686732e1df730f709d21b6ca74fe73515bbbb96fe",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 293816.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "9cecc52c0c40f91bde9fdcbdf53a4ec56c49561416f74dacc2b71795aec6cfc7",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 353754.65625,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "3c31968dcb8cd635864dacbf0dadfa169749d212789f9eaaf75a09a1be8b7a7b",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 317632.0,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "88445595344a2908c457aa31a1fa06c599650fc02c52f05d870a4a26c1627b70",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 382578.65625,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "6e6faffc039e18e5215813b6333cf982fcdad33aaa8962f52a2066c5184dfce2",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 50903.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "0a77de49522b8aabc4a9c5b53bf633424b7044d98c9aefc90f29b6df4c10f896",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 184204.078125,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "1a4cbf694997225a899517b6a6b40cc8a9fda486dee4aebd5a69c5f29172d43f",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 5,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 50914.0,
      "flow_min": 0.0,
      "link_edges": 4,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 5,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "06cfad9bc888f5220d9381ddb3aa0234cfb77796a38a5bd596544247f44035d2",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 56112.0,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "bebf46b8b2ef4a0e5436c96b30a1c3c2f6a77ef01d8d8472e6826a8fc86c267c",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 178565.328125,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "d59ee2d8b815e3b53a18ddfded85a5c3e55030abe74bd1ccc67b7c08fdc6c4f0",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 234634.671875,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "1fde74831616f66e5d00e714b97d4dec4393c0fffe958024c20b8470af630649",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 236384.0,
      "flow_min": 0.0,
      "link_edges": 3,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 4,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "69dc74db4c0b926f833fe59f64a05ad7f5a62bc2030ce9a8c84f7fc1a72ce845",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 3,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 238314.671875,
      "flow_min": 0.0,
      "link_edges": 2,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 3,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "167c66ed82b5af352ada7cef840aff5bcad38156f9019081ff9bc05d99b93cd4",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 2,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 263525.34375,
      "flow_min": 0.0,
      "link_edges": 1,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 2,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Infiltration",
    "day": "Thursday-01-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "a28a2bad1e20be30fdd30d9ce3e9a3c9144f8edacf4ac8ce5aef1490fdb89950",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 45408.0,
      "flow_min": 0.0,
      "link_edges": 6,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 7,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  }
]
```
