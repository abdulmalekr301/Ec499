# Office NFStream RSS Diagnostic

Generated: `2026-07-14T01:14:08+00:00`

## Action
- Ran real NFStream extraction with the configured plugins, without candidate matching or graph construction.
- Logged process RSS and available system memory at bounded flow intervals.
- Kept the diagnostic bounded; this was not a larger materialization run.
- Saved diagnostic JSON to `/var/home/alucard-00/EC499/artifacts/office_model/nfstream_rss_diagnostic_manifest.json`.

## Summary
```json
{
  "pcap": "datasets/cic_ids_2018/raw_pcaps/Friday-02-03-2018/pcap/capDESKTOP-AN3U28N-172.31.64.115",
  "status": "max_flows_reached",
  "error": "",
  "flows_scanned": 5000,
  "packet_records_seen": 60094,
  "retained_payload_bytes_seen": 19110271,
  "final_rss_gb": 0.1450042724609375,
  "peak_rss_gb": 0.14501953125,
  "rss_delta_from_first_report_gb": 0.00146484375,
  "final_available_memory_gb": 5.967609405517578
}
```

## Last Reports
```json
[
  {
    "flows_scanned": 3250,
    "rss_gb": 0.14463043212890625,
    "peak_rss_gb": 0.14463043212890625,
    "available_memory_gb": 5.977996826171875,
    "packet_records_seen": 37432,
    "retained_payload_bytes_seen": 12337214
  },
  {
    "flows_scanned": 3500,
    "rss_gb": 0.14467239379882812,
    "peak_rss_gb": 0.14467239379882812,
    "available_memory_gb": 5.975719451904297,
    "packet_records_seen": 40505,
    "retained_payload_bytes_seen": 12768597
  },
  {
    "flows_scanned": 3750,
    "rss_gb": 0.14471817016601562,
    "peak_rss_gb": 0.14471817016601562,
    "available_memory_gb": 5.9756011962890625,
    "packet_records_seen": 43773,
    "retained_payload_bytes_seen": 13251410
  },
  {
    "flows_scanned": 4000,
    "rss_gb": 0.14476776123046875,
    "peak_rss_gb": 0.14476776123046875,
    "available_memory_gb": 5.976539611816406,
    "packet_records_seen": 46738,
    "retained_payload_bytes_seen": 13725240
  },
  {
    "flows_scanned": 4250,
    "rss_gb": 0.144805908203125,
    "peak_rss_gb": 0.144805908203125,
    "available_memory_gb": 5.971408843994141,
    "packet_records_seen": 49612,
    "retained_payload_bytes_seen": 14284712
  },
  {
    "flows_scanned": 4500,
    "rss_gb": 0.14486312866210938,
    "peak_rss_gb": 0.14486312866210938,
    "available_memory_gb": 5.973243713378906,
    "packet_records_seen": 52713,
    "retained_payload_bytes_seen": 15070224
  },
  {
    "flows_scanned": 4750,
    "rss_gb": 0.1449127197265625,
    "peak_rss_gb": 0.1449127197265625,
    "available_memory_gb": 5.966705322265625,
    "packet_records_seen": 56513,
    "retained_payload_bytes_seen": 17385789
  },
  {
    "flows_scanned": 5000,
    "rss_gb": 0.14501953125,
    "peak_rss_gb": 0.14501953125,
    "available_memory_gb": 5.967845916748047,
    "packet_records_seen": 60094,
    "retained_payload_bytes_seen": 19110271
  }
]
```
