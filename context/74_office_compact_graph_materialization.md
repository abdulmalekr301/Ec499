# Office Compact Graph Materialization

Generated: `2026-07-26T18:15:01+00:00`

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
  "requested_unique_candidates": 1978,
  "materialized_or_existing": 1593,
  "missing_count": 382,
  "stop_reason": "completed",
  "newly_materialized_class_counts": {
    "Benign": 1593
  },
  "newly_materialized_source_counts": {
    "CSE-CIC-IDS2018": 1593
  },
  "processed_pcaps": 400,
  "deferred_pcaps": [],
  "pcap_health": {
    "enabled": false,
    "manifest_path": "/var/home/alucard-00/EC499/artifacts/office_model/office_compact_graph_manifest.json",
    "status": "disabled",
    "skip_pcaps": [],
    "skip_reasons": {}
  },
  "safety_summary": {
    "LOCAL_TEMPORAL_CONTEXT_FALLBACK": 1596,
    "flagged_graphs": 91,
    "matched_zero_packet_graph": 3
  }
}
```

## Safety Samples
```json
[
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "9b3c97a7cb00455d84397480d6f84340fba7c541c3f456ad7b5400678e4b0967",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1107361.125,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "478018a1dfd508322875ea5c9fc6166730b6858cec4bed329d2a3d43578ef78a",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 44370660.0,
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
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "227204937ff71e308e1d294633b67712605ddaf03e4c74994afb19f8e69d2195",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 2088904.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "90d6c5437adfd83f84b4d7f3a86f42b93218acd38c524baa529be7d46ace5cea",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 2004952.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "9a5b127ef26f16e9030786121de7f1b4a4b53c91074e91ab72b77ae5c4d8c4ae",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 2083100.875,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "f4642ab396fbcbe27c012244bb58e4330a08c72721d7a3109205f91b6176eb95",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 49263992.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "fd7f605c7a5a722cc82d7869ecb4fb20ce6350a09e0a2f478eacf06e6c6b6d47",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1990858.625,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-02-03-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "83390177b4def21f6482b633c9d0483f9e62cd8cc71eac463dbf61835df61de3",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1928472.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "227b31474dd5f1a4a39b548e65930266146cc270c16fa949cc0dbdf73f9264df",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1078000.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "8310e68d655a5e77a07fe5f35deffbb6067f461a4be704b43127deece38174d8",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1144000.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "49970edd941baa293c6f52179c0478a8d8d38595a2d371594af006da4c06fdcb",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 4,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1736000.0,
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
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "0369fbe211560e8738c9faf7baf5aecf652e59135c573f871d9b190e9320dcf8",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 7355757.5,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "b92cff645fce970b7bcaf7c37221760a1a3484abeb9ad04cf9b419deaa316021",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 2106106.75,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "37ea3426179d638dfbd4c25ec596486e6dc73cb976bf77cb166c5c621de86558",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 2,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 49186.0,
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
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "17614e9e296d28db74aa1a83f2c9354571f19db057622c1c8197eb16be4b998f",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1406931.375,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "94dec92596070407563dde71307f050b826373c4cd28de3ec67cf4ff27577ec2",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 3613626.75,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "c6b67ca9744a2eea528a0055aead44d69d2bc76bb0525bc9fafe8c1dfed7e521",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 7,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 7005096.0,
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
    "class_name": "Benign",
    "day": "Friday-16-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "908ad51d0a006847ae0daae8e7b739bef470545f5190bac1d1dfc34193a7091b",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 3,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 10252384.0,
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
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "aaf45da4165a5791c19fddb845ecf726011ac9612d7270adc409280293c903f4",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 20,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 105244000.0,
      "flow_min": 0.0,
      "link_edges": 19,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 20,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "13b89cc6a4300e641d6f51c84e7f12939bdb4b84122bfbd88500b9324e34e4eb",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 68838408.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "360baec4c52ebe186a94dd79649aec0aa96722b62f56decb493cb8b84156654c",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 63862840.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "4e1716d4278d685c372420fd5a9820f454e161b1b1f41a9040608b5347085ce8",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 10334251.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "916242b3dd59e18312e1cf0c1f6e197870caf0414044259c508c13b2e6b52b67",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 1740770.875,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "f64905d4a7250911cd1f3b36985c148b04aa6bca7bc7073255631ee63a786e1f",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 31455362.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  },
  {
    "class_name": "Benign",
    "day": "Friday-23-02-2018",
    "flags": [
      "payload_nonzero_fraction_outlier"
    ],
    "flow_hash": "3b3235a2c0f70f371523a497860dd6ea44d32fbffde3ce899d26eb24a8c7414d",
    "source_dataset": "CSE-CIC-IDS2018",
    "stats": {
      "contain_edges": 6,
      "contain_finite": true,
      "flow_features": 92,
      "flow_finite": true,
      "flow_max": 10013611.0,
      "flow_min": 0.0,
      "link_edges": 5,
      "link_finite": true,
      "packet_feature_width": 1500,
      "packet_nodes": 6,
      "payload_mean": 0.0,
      "payload_nonzero_fraction": 0.0
    }
  }
]
```
