# Office Infiltration Payload Audit

Generated: `2026-07-14T01:14:22+00:00`

## Action
- Audited materialized Infiltration compact graphs that were flagged for payload nonzero-fraction outliers.
- Checked retained payload bytes, packet edge payload sizes, candidate endpoint evidence, and the `172.31.69.13` attack-window rule.
- Classified zero-payload TCP-control graphs as scan/probe-like only when graph and candidate evidence aligned.
- Saved audit JSON to `/var/home/alucard-00/EC499/artifacts/office_model/infiltration_payload_audit_manifest.json`.

## Summary
```json
{
  "candidate_missing": 0,
  "decision_counts": {
    "confirmed_zero_payload_scan_probe": 79
  },
  "endpoint_counts": {
    "compromised_host_endpoint": 79
  },
  "graphs_audited": 79,
  "packet_node_counts": {
    "2": 76,
    "7": 3
  },
  "payload_size_counts": {
    "all_zero_payload_size": 79
  }
}
```

## Sample Audits
```json
[
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "80",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "038dc63adadae484f8a54d491657fe242c1c84f499a52df67832c07b2890baf5",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_038dc63adadae484f8a54d491657fe242c1c84f499a52df67832c07b2890baf5.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.165158",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "554",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "06a37c74e3d8784666fc907a4cbdb3b4239857469f2286434ba8f6d8b8e9d555",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_06a37c74e3d8784666fc907a4cbdb3b4239857469f2286434ba8f6d8b8e9d555.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.165421",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "587",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "0e946df34e714997d9d405f70255a3865eeb2e1c9661f104fd9c1fe81b5d5ce1",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_0e946df34e714997d9d405f70255a3865eeb2e1c9661f104fd9c1fe81b5d5ce1.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.165863",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "667",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "15935834c83108576f7c54b5610a30dedd06ddbf27b631a3ba6bf50faa53f6cd",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_15935834c83108576f7c54b5610a30dedd06ddbf27b631a3ba6bf50faa53f6cd.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.168501",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.7",
    "dst_port": "554",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.7"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "17d8ae4cc8670cbd7e2132b32af85cdedc9beecc907f1e8f03c67b5fffea13ef",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_17d8ae4cc8670cbd7e2132b32af85cdedc9beecc907f1e8f03c67b5fffea13ef.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.7",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "59149",
    "timestamp": "2018-03-01 14:14:19.479792",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "256",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "18d0849d1d168b0d7579eac04e1d718868396ef1f5a079069cc63f1e31514d7e",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_18d0849d1d168b0d7579eac04e1d718868396ef1f5a079069cc63f1e31514d7e.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.165119",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.7",
    "dst_port": "25",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.7"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "1ab4152f391907fca2dc001d32127807ce91127643310b27fa05b7aef0befb1d",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_1ab4152f391907fca2dc001d32127807ce91127643310b27fa05b7aef0befb1d.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.7",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "59149",
    "timestamp": "2018-03-01 14:14:19.479818",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.15",
    "dst_port": "5080",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.15"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "1c508e9b6ca686a63180ba4ed55e6f2dd014781b6d2d4e3e39e67f1adc47a154",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_1c508e9b6ca686a63180ba4ed55e6f2dd014781b6d2d4e3e39e67f1adc47a154.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.15",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "43299",
    "timestamp": "2018-03-01 14:22:20.167284",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.7",
    "dst_port": "993",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.7"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "2083a5abefe7b0a9228eeef1a581cbf4a2794d71862d23569342b72bef1b4ec7",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_2083a5abefe7b0a9228eeef1a581cbf4a2794d71862d23569342b72bef1b4ec7.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.7",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "59149",
    "timestamp": "2018-03-01 14:14:19.479711",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  },
  {
    "all_payload_sizes_zero": true,
    "class_name": "Infiltration",
    "compromised_host_endpoint": true,
    "day": "Thursday-01-03-2018",
    "decision": "confirmed_zero_payload_scan_probe",
    "directions": [
      0.0,
      1.0
    ],
    "dst_ip": "172.31.69.7",
    "dst_port": "1025",
    "endpoint_pcaps": [
      "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Thursday-01-03-2018/pcap/UCAP172.31.69.7"
    ],
    "endpoint_rule_match": true,
    "endpoint_selection": "dst_preferred",
    "flow_hash": "2a3ee11b7075dd0dea2ed5fa19bb934f00569b1326a282239df4541efdfed222",
    "gt_window_finish": "2018-03-01 14:55:00",
    "gt_window_start": "2018-03-01 13:53:00",
    "ip_sizes": [
      44.0,
      40.0
    ],
    "label": "Infiltration - NMAP Portscan",
    "nonzero_payload_bytes": 0,
    "packet_nodes": 2,
    "path": "/var/home/alucard-00/EC499/data/graphs/office_compact/Infiltration/CSE-CIC-IDS2018_Thursday-01-03-2018_2a3ee11b7075dd0dea2ed5fa19bb934f00569b1326a282239df4541efdfed222.pkl",
    "payload_nonzero_fraction": 0.0,
    "payload_sample": {
      "ascii": "",
      "hex": ""
    },
    "payload_sizes": [
      0.0,
      0.0
    ],
    "protocol": "6",
    "source_file": "UCAP172.31.69.7",
    "source_file_matches_endpoint": true,
    "src_ip": "172.31.69.13",
    "src_port": "59149",
    "timestamp": "2018-03-01 14:14:19.481458",
    "total_payload_size_from_edges": 0.0,
    "transport_sizes": [
      24.0,
      20.0
    ]
  }
]
```
