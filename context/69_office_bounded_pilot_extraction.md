# Office Bounded Pilot Extraction

Generated: `2026-07-13T05:00:15+00:00`

## Action
- Ran a bounded pilot graph extraction from the strict office candidate manifest.
- Streamed selected endpoint PCAPs only; did not glob all per-host captures.
- Matched candidate flows by 5-tuple with timestamp tolerance.
- Wrote compact graph records for matched flows.

## Run Details
- Classes: `['WebBased']`
- Target per class: `3`
- Requested candidates: `3`
- Materialized graphs: `3`
- Stop reason: `completed`
- Max flows per PCAP: `200000`
- Timestamp tolerance seconds: `3.0`

## Output
- Manifest: `/var/home/alucard-00/EC499/artifacts/office_model/pilot_extraction_manifest.json`
- Graph directory: `/var/home/alucard-00/EC499/artifacts/office_model/pilot_graphs`

## Class Counts
```json
{
  "WebBased": 3
}
```

## PCAP Summaries
```json
{
  "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-23-02-2018/pcap/UCAP172.31.69.28": {
    "candidate_count": 3,
    "flows_scanned": 3247,
    "matched": 3,
    "remaining_candidates_for_pcap": 0,
    "status": "completed"
  }
}
```

## Graph Stats
```json
[
  {
    "candidate_timestamp": "2018-02-23 14:13:04.229043",
    "candidate_timestamp_seconds": 1519395184.229043,
    "class_name": "WebBased",
    "contain_edges": 20,
    "contain_finite": true,
    "flow_features": 92,
    "flow_finite": true,
    "flow_hash": "1d148bb7a20029e0101c8d860763f1861f0ca4593b1b8f882535afeaae9e30d2",
    "flow_max": 56048736.0,
    "flow_min": 0.0,
    "flow_timestamp_seconds": 1519395184.229,
    "gt_subtype": "Brute Force-Web",
    "link_edges": 19,
    "link_finite": true,
    "packet_feature_width": 1500,
    "packet_nodes": 20,
    "path": "/var/home/alucard-00/EC499/artifacts/office_model/pilot_graphs/WebBased/0001_Brute_Force-Web.pkl",
    "payload_mean": 0.09653751633986928,
    "payload_nonzero_fraction": 0.26603333333333334,
    "pcap": "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-23-02-2018/pcap/UCAP172.31.69.28",
    "timestamp_delta_seconds": 4.291534423828125e-05
  },
  {
    "candidate_timestamp": "2018-02-23 14:04:30.193975",
    "candidate_timestamp_seconds": 1519394670.193975,
    "class_name": "WebBased",
    "contain_edges": 20,
    "contain_finite": true,
    "flow_features": 92,
    "flow_finite": true,
    "flow_hash": "785f6d9b340297e57ada1b37206fd51fb23c2efc091655c7f846963be7c3213c",
    "flow_max": 58976816.0,
    "flow_min": 0.0,
    "flow_timestamp_seconds": 1519394670.193,
    "gt_subtype": "Brute Force-Web",
    "link_edges": 19,
    "link_finite": true,
    "packet_feature_width": 1500,
    "packet_nodes": 20,
    "path": "/var/home/alucard-00/EC499/artifacts/office_model/pilot_graphs/WebBased/0002_Brute_Force-Web.pkl",
    "payload_mean": 0.13588562091503267,
    "payload_nonzero_fraction": 0.33166666666666667,
    "pcap": "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-23-02-2018/pcap/UCAP172.31.69.28",
    "timestamp_delta_seconds": 0.0009748935699462891
  },
  {
    "candidate_timestamp": "2018-02-23 19:06:38.746558",
    "candidate_timestamp_seconds": 1519412798.746558,
    "class_name": "WebBased",
    "contain_edges": 11,
    "contain_finite": true,
    "flow_features": 92,
    "flow_finite": true,
    "flow_hash": "3f37c33edd35bbc21fd1214b5c05bd7af937caeb98fe32c40beba6c91b707121",
    "flow_max": 40852348.0,
    "flow_min": 0.0,
    "flow_timestamp_seconds": 1519412798.746,
    "gt_subtype": "SQL Injection",
    "link_edges": 10,
    "link_finite": true,
    "packet_feature_width": 1500,
    "packet_nodes": 11,
    "path": "/var/home/alucard-00/EC499/artifacts/office_model/pilot_graphs/WebBased/0003_SQL_Injection.pkl",
    "payload_mean": 0.049875698158051096,
    "payload_nonzero_fraction": 0.11987878787878788,
    "pcap": "/var/home/alucard-00/EC499/datasets/cic_ids_2018/raw_pcaps/Friday-23-02-2018/pcap/UCAP172.31.69.28",
    "timestamp_delta_seconds": 0.0005578994750976562
  }
]
```
