# PacketCapture Verification

Generated: `2026-06-16`

## Summary

`PacketCapture` was verified directly against NFStream packet objects from the
payload-heavy attack PCAPs. The current implementation is not broken.

NFStream exposes usable raw packet bytes through `packet.ip_packet`. The current
`packet_payload_bytes()` function correctly derives TCP/UDP/ICMP payload bytes
from that IP packet. No richer raw payload attribute was found when enabling
NFStream dissections.

## Files Added

- `secureedge/data/verify_packet_capture.py`

This verifier samples packet objects directly from selected PCAP files, compares
available NFStream packet attributes, and writes machine-readable reports under
`artifacts/`.

## Commands Run

```bash
.venv/bin/python -m secureedge.data.verify_packet_capture \
  --pcap PCAPs/Uploading_Attack.pcap \
  --pcap PCAPs/SqlInjection.pcap \
  --pcap PCAPs/DictionaryBruteForce.pcap \
  --max-flows 80 \
  --max-packets 800 \
  --n-dissections 0
```

```bash
.venv/bin/python -m secureedge.data.verify_packet_capture \
  --pcap PCAPs/SqlInjection.pcap \
  --pcap PCAPs/DictionaryBruteForce.pcap \
  --max-flows 30 \
  --max-packets 400 \
  --n-dissections 20
```

Outputs:

- `artifacts/packetcapture_verification_nd0.json`
- `artifacts/packetcapture_verification_nd20.json`

## Verification Results With Current Extraction Settings

The production extraction path uses `n_dissections=0`.

| PCAP | Packets Examined | Packets With Extracted Payload | Mean Payload Length | Max Payload Length | Mean Nonzero Bytes |
|---|---:|---:|---:|---:|---:|
| Uploading_Attack.pcap | 800 | 578 | 76.12 | 1448 | 68.35 |
| SqlInjection.pcap | 800 | 560 | 122.08 | 2856 | 113.90 |
| DictionaryBruteForce.pcap | 800 | 453 | 100.39 | 8448 | 98.56 |

In all three PCAPs, `ip_packet` was present and byte-bearing for every sampled
packet:

| PCAP | `ip_packet` Packets Seen | `ip_packet` Nonzero | Mean `ip_packet` Length | Max `ip_packet` Length |
|---|---:|---:|---:|---:|
| Uploading_Attack.pcap | 800 | 800 | 117.51 | 1500 |
| SqlInjection.pcap | 800 | 800 | 165.00 | 2908 |
| DictionaryBruteForce.pcap | 800 | 800 | 150.52 | 8500 |

The other candidate attributes found by NFStream, such as `payload_size` and
`raw_size`, are scalar integers, not byte arrays. They are not valid replacements
for `ip_packet`.

## NFStream Dissection Comparison

Running with `n_dissections=20` did not expose a better raw payload byte
attribute. `ip_packet` remained the only useful byte-bearing source.

| PCAP | Packets Examined | Packets With Extracted Payload | Mean Payload Length | Max Payload Length | Mean Nonzero Bytes |
|---|---:|---:|---:|---:|---:|
| SqlInjection.pcap | 400 | 334 | 142.34 | 2856 | 127.34 |
| DictionaryBruteForce.pcap | 400 | 209 | 91.70 | 8448 | 89.87 |

## Interpretation

The earlier low per-class graph means for WebBased and BruteForce do not mean
that `PacketCapture` is returning all zeros. They are explained by:

- padding every packet vector to 1,500 bytes
- many TCP control or handshake packets having zero application payload
- payload-heavy packets being mixed with short DNS, TLS, HTTP header, and control
  packets
- graph-level averages spreading payload bytes across up to 20 packet rows and
  1,500 columns per row

Examples from the sampled payloads confirm application/content bytes are being
captured, including HTTP-like `GET ...` bytes and TLS/DNS-like payloads.

## Decision

No `PacketCapture` code change is recommended before round-4 training.

The next training run can proceed using the class-imbalance fixes:

- deduped shards
- class-weighted focal loss
- online flow and packet augmentation

The remaining risk is dataset signal quality, not an obvious raw payload extraction
bug.
