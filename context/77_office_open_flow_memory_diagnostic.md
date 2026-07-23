# Office Open-Flow Memory Diagnostic

Generated: `2026-07-14T00:00:20+00:00`

## Action
- Ran a packet-level approximation of NFStream's simultaneously-open flow table.
- Used the same `idle_timeout` and `active_timeout` values for expiry pressure, without changing NFStream extraction settings.
- Saved diagnostic JSON to `/var/home/alucard-00/EC499/artifacts/office_model/open_flow_diagnostic_manifest.json`.

## Summary
```json
{
  "pcap": "datasets/cic_ids_2018/raw_pcaps/Friday-02-03-2018/pcap/capDESKTOP-AN3U28N-172.31.64.115",
  "transport_packets_scanned": 84218,
  "elapsed_seconds": 7561.414217948914,
  "opened_flows": 4776,
  "expired_flows": 4776,
  "active_flows_at_scan_end": 0,
  "max_active_flows": 507,
  "protocol_counts": {
    "6": 81644,
    "17": 2556,
    "2": 18
  },
  "final_process_rss_gb": 0.14620590209960938,
  "final_available_memory_gb": 10.037960052490234
}
```

## Last Reports
```json
[
  {
    "transport_packets": 40000,
    "timestamp": 1519999325.971889,
    "elapsed_seconds": 4519.19673705101,
    "active_flows": 89,
    "max_active_flows": 507,
    "opened_flows": 2596,
    "expired_flows": 2507,
    "process_rss_gb": 0.14620590209960938,
    "available_memory_gb": 10.052837371826172
  },
  {
    "transport_packets": 50000,
    "timestamp": 1520000360.712947,
    "elapsed_seconds": 5553.937794923782,
    "active_flows": 100,
    "max_active_flows": 507,
    "opened_flows": 3155,
    "expired_flows": 3055,
    "process_rss_gb": 0.14620590209960938,
    "available_memory_gb": 10.052837371826172
  },
  {
    "transport_packets": 60000,
    "timestamp": 1520001080.973828,
    "elapsed_seconds": 6274.198676109314,
    "active_flows": 79,
    "max_active_flows": 507,
    "opened_flows": 3583,
    "expired_flows": 3504,
    "process_rss_gb": 0.14620590209960938,
    "available_memory_gb": 10.052837371826172
  },
  {
    "transport_packets": 70000,
    "timestamp": 1520001657.441826,
    "elapsed_seconds": 6850.6666741371155,
    "active_flows": 92,
    "max_active_flows": 507,
    "opened_flows": 4118,
    "expired_flows": 4026,
    "process_rss_gb": 0.14620590209960938,
    "available_memory_gb": 10.052837371826172
  },
  {
    "transport_packets": 80000,
    "timestamp": 1520002130.838278,
    "elapsed_seconds": 7324.063126087189,
    "active_flows": 146,
    "max_active_flows": 507,
    "opened_flows": 4579,
    "expired_flows": 4433,
    "process_rss_gb": 0.14620590209960938,
    "available_memory_gb": 10.052837371826172
  }
]
```
