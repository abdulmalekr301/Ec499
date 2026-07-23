# Office Missing-Class Targeted Recovery

Date: 2026-07-15

## Request

Start the next materialization step as class-targeted or resume-aware for the three missing classes, rather than another unfiltered full pass from the current density order.

Missing classes before this run:

```json
{
  "BruteForce": 0,
  "DoS": 0,
  "DDoS": 0,
  "Benign": 10764,
  "Bot": 14172,
  "Infiltration": 23509,
  "WebBased": 412
}
```

## Code Changes

Implemented class-targeted compact materialization:

- Added `--office-target-class`, repeatable, to `office-materialize-compact`.
- Added `target_classes` filtering to the office materialization candidate loader.
- Stored `target_classes` in the compact materialization manifest.

Implemented a targeted packet payload capture guard:

- Added optional `flow_key_filter` support to `iter_flow_records`.
- Added filtered packet capture to `NFStreamPacketCapture`.
- Wired the office materialization worker to pass the candidate forward and reverse 5-tuples into `iter_flow_records`.

Intent: keep the run class-targeted and avoid retaining packet payload records for flows that cannot satisfy the selected materialization candidates.

Compilation check passed:

```bash
.venv/bin/python -m py_compile secureedge/data/pcap_flows.py secureedge/data/office_pipeline.py
```

## Targeted Runs

All runs preserved the full-run lock and memory guards:

```bash
SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=5
SECUREEDGE_MAX_PROCESS_RSS_GB=2
SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=10
SECUREEDGE_PCAP_WORKER_TIMEOUT_SECONDS=900
```

The class runs used:

```bash
.venv/bin/python -m secureedge.data.office_pipeline \
  --mode office-materialize-compact \
  --office-target-class <CLASS> \
  --office-max-pcaps 1 \
  --office-max-flows-per-pcap 0
```

### BruteForce

Primary PCAP:

```text
datasets/cic_ids_2018/raw_pcaps/Wednesday-14-02-2018/pcap/UCAP172.31.69.25
```

Summary:

```json
{
  "status": "worker_error",
  "candidate_count": 24000,
  "matched": 0,
  "flows_scanned": 182990,
  "remaining": 24000,
  "error": "available memory is 5.00 GiB, below configured floor 5.00 GiB"
}
```

This value is from the retry after the packet-capture filter was added.

### DoS

Primary PCAP:

```text
datasets/cic_ids_2018/raw_pcaps/Friday-16-02-2018/pcap/UCAP172.31.69.25-part1.pcap
```

Summary:

```json
{
  "status": "worker_error",
  "candidate_count": 24000,
  "matched": 0,
  "flows_scanned": 86270,
  "remaining": 24000,
  "error": "available memory is 5.00 GiB, below configured floor 5.00 GiB"
}
```

### DDoS

Primary PCAP:

```text
datasets/cic_ids_2018/raw_pcaps/Wednesday-21-02-2018/pcap/UCAP172.31.69.28 part 1
```

Summary:

```json
{
  "status": "worker_error",
  "candidate_count": 24000,
  "matched": 0,
  "flows_scanned": 1990,
  "remaining": 24000,
  "error": "available memory is 4.64 GiB, below configured floor 5.00 GiB"
}
```

## Result

No compact graphs were produced for the three missing classes:

```json
{
  "BruteForce": 0,
  "DoS": 0,
  "DDoS": 0,
  "Benign": 10764,
  "Bot": 14172,
  "Infiltration": 23509,
  "WebBased": 412
}
```

The targeted class filter and packet-retention filter reduce the intended working set, but they do not prevent NFStream from scanning and maintaining enough internal flow state to hit the memory floor before any missing-class candidates match.

## Interpretation

Another unfiltered full pass is not appropriate.

Another NFStream-based targeted pass over these full PCAPs is also low-value unless the PCAP input is reduced first. The worker is not failing because too many output graphs are being written; it is failing before the first candidate match. The bottleneck is the full-PCAP scan/state growth required before reaching the relevant target flows.

## Recommended Next Step

Use a PCAP-windowing or candidate-driven extraction step before compact materialization:

1. Build per-class candidate time windows and 5-tuples for BruteForce, DoS, and DDoS.
2. Create bounded temporary PCAP slices around those windows, or use a lower-level packet scanner that only retains packets matching the candidate 5-tuples and timestamps.
3. Run compact materialization against those reduced inputs.
4. Regenerate readable graph samples once each missing class has at least 10 materialized compact graphs.

Until this is done, the readable sample set remains available only for Benign, Bot, Infiltration, and WebBased.
