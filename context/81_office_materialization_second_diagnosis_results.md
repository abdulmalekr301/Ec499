# Office Materialization Second Diagnosis Results

Generated: `2026-07-14T01:14:45+00:00`

## Actions Taken

- Added and ran a real NFStream/plugin RSS diagnostic without candidate
  matching or graph construction.
- Added and ran a content-level Infiltration payload audit over the
  materialized compact graph sample.
- Kept both checks bounded. No larger materialization run and no full run were
  started.

## NFStream RSS Diagnostic

Command shape:

```bash
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=5 \
SECUREEDGE_MAX_PROCESS_RSS_GB=2 \
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10 \
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-nfstream-rss-diagnostic \
  --office-nfstream-rss-pcap datasets/cic_ids_2018/raw_pcaps/Friday-02-03-2018/pcap/capDESKTOP-AN3U28N-172.31.64.115 \
  --office-nfstream-rss-max-flows 5000 \
  --office-nfstream-rss-report-interval 250
```

Result:

```json
{
  "status": "max_flows_reached",
  "flows_scanned": 5000,
  "packet_records_seen": 60094,
  "retained_payload_bytes_seen": 19110271,
  "final_rss_gb": 0.1450042724609375,
  "peak_rss_gb": 0.14501953125,
  "rss_delta_from_first_report_gb": 0.00146484375,
  "final_available_memory_gb": 5.967609405517578
}
```

Interpretation: real NFStream plus the configured plugins did not show a
cumulative RSS leak over this bounded 5,000-flow scan. RSS stayed essentially
flat while the diagnostic observed 60,094 retained packet records and about
19 MB of retained payload bytes flowing through the iterator. This points away
from a raw NFStream/plugin leak as the main memory driver. The remaining
memory pressure is more likely in the materialization wrapper/worker path,
candidate batching around difficult PCAPs, or graph write/materialization
behavior.

## Infiltration Payload Audit

Result:

```json
{
  "graphs_audited": 79,
  "candidate_missing": 0,
  "decision_counts": {
    "confirmed_zero_payload_scan_probe": 79
  },
  "payload_size_counts": {
    "all_zero_payload_size": 79
  },
  "endpoint_counts": {
    "compromised_host_endpoint": 79
  },
  "packet_node_counts": {
    "2": 76,
    "7": 3
  }
}
```

Evidence checked for each audited graph:

- Candidate label was `Infiltration - NMAP Portscan`.
- Either source or destination endpoint was `172.31.69.13`.
- Candidate timestamp matched the established Infiltration attack window.
- Compact graph source file matched the selected endpoint PCAP.
- Protocol was TCP.
- Retained payload bytes were zero.
- Packet edge payload sizes were all zero.
- Packet sizes were consistent with TCP control/probe packets, commonly
  `ip_size: 44/40` and `transport_size: 24/20`.

Interpretation: the payload flags are expected for these materialized
Infiltration graphs. They are genuine zero-payload NMAP-style scan/probe
traffic, not an extraction artifact or endpoint-matching artifact in the
audited sample. The universal payload nonzero-fraction threshold should not be
used as a quality-failure gate for this class.

## Outputs

- NFStream RSS JSON:
  `artifacts/office_model/nfstream_rss_diagnostic_manifest.json`
- NFStream RSS context:
  `context/79_office_nfstream_rss_diagnostic.md`
- Infiltration payload JSON:
  `artifacts/office_model/infiltration_payload_audit_manifest.json`
- Infiltration payload context:
  `context/80_office_infiltration_payload_audit.md`

## Next Recommendation

The two second-diagnosis blockers are resolved for the bounded sample:

- No evidence of a raw NFStream/plugin cumulative RSS leak.
- Infiltration zero-payload flags are confirmed as expected scan/probe
  behavior.

The next step should still be bounded, not full-scale: run a larger
PCAP-health-aware pilot that skips or deprioritizes known low-yield/deferred
PCAPs from the previous materialization manifest, while preserving the full-run
lock.
