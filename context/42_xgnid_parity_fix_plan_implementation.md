# XG-NID Parity Fix Plan Implementation

## Source

Implemented the actionable parts of:

```text
context/xgnid-parity-fix-plan.md
```

## Fix 1: Attacker-MAC Filtering

Implemented guarded attacker-MAC filtering in the PCAP extraction path.

Changed files:

- `secureedge/config.py`
- `secureedge/data/pcap_flows.py`
- `secureedge/data/extract_worker.py`
- `secureedge/data/preprocess.py`

New configuration:

```text
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1
SECUREEDGE_ATTACKER_MACS="aa:bb:cc:dd:ee:ff,..."
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt
SECUREEDGE_BENIGN_ONLY_ENFORCE=1
```

Behavior:

- Attack class PCAPs keep only flows where `src_mac` or `dst_mac` is in the attacker-MAC set.
- Benign PCAPs drop attacker-involved flows when `SECUREEDGE_BENIGN_ONLY_ENFORCE=1`.
- Flows with missing MAC fields are kept and logged instead of being silently dropped.
- Extraction summaries now include:
  - filter enabled/disabled
  - attacker MAC count
  - kept flow count
  - dropped flow count
  - missing-MAC kept count
  - first five observed `src_mac`/`dst_mac` pairs

Important blocker:

- The official CIC-IoT2023 attacker MAC list is not present in the repo/context files.
- Public search did not surface a reliable official MAC list.
- The code is ready, but full MAC-filtered regeneration should not be run until the official MAC list is supplied through `SECUREEDGE_ATTACKER_MACS` or `SECUREEDGE_ATTACKER_MACS_FILE`.

Synthetic behavior check passed:

```text
attack attacker-involved flow -> kept
attack background flow -> dropped
benign attacker-involved flow -> dropped
```

## Fix 2: 20-Packet Window Consistency

Added diagnostic:

```text
secureedge/data/verify_flow_window.py
```

Ran:

```bash
.venv/bin/python -m secureedge.data.verify_flow_window --limit 5000
```

Result:

```text
records_examined=5000
mismatch_count=0
mismatch_fraction=0.0
max_flow_bidirectional_packets=20.0
max_packet_node_count=20
conclusion=no_mismatch_observed_flowcapper_consistent
```

Conclusion:

- The current `FlowCapper` and `PacketCapture` are already consistent.
- No subflow segmentation change was applied because the mismatch was not confirmed.

## Fix 3: Concatenated Readout

Already applied and kept.

Current default:

```text
SECUREEDGE_HGNN_READOUT_MODE=concat
```

The classifier receives a 128-dimensional concatenated flow+packet graph embedding.

## Fix 4: Edge Attributes in conv2

Already applied and kept.

Both GAT layers now receive edge attributes for:

- flow contains packet
- packet reverse-contains flow
- packet linked-to packet

## Deferred: Payload CNN Encoder

The parity plan says the CNN payload encoder is an enhancement, not a parity fix.

Updated default:

```text
SECUREEDGE_USE_PAYLOAD_ENCODER=0
```

The CNN encoder remains available for later experiments:

```text
SECUREEDGE_USE_PAYLOAD_ENCODER=1
```

## Checkpoint Safety

Training checkpoints now include a model architecture signature. Incompatible older
checkpoints are ignored for global-best comparison and rejected for resume/evaluation
under the current architecture.

This matters because Run 12 used the CNN payload encoder, while the parity default now
uses raw packet vectors.

## Evaluation Reporting

Updated `secureedge/models/evaluate.py` so metrics include both:

- SecureEdge class order
- XG-NID class order

Confusion matrices are name-keyed and reordered for reporting without renumbering
SecureEdge classes.

## Verification

Ran:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
.venv/bin/python -m secureedge.data.verify_flow_window --limit 1000
```

All checks passed.

Current parity defaults:

```text
batch_size=512
grad_accum_steps=1
payload_encoder=False
readout=concat
attacker_mac_filter=False
attacker_mac_count=0
```
