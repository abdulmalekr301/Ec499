from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from secureedge.data.pcap_flows import _packet_bytes_from_attr, packet_payload_bytes
from secureedge.utils import write_context, write_json
from secureedge import config


CANDIDATE_NAMES = (
    "ip_payload_bytes",
    "payload",
    "ip_packet",
    "transport_payload",
    "packet",
    "raw_bytes",
    "raw",
    "frame",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify NFStream packet attributes used by PacketCapture.")
    parser.add_argument("--pcap", action="append", required=True, help="PCAP file to inspect. May be repeated.")
    parser.add_argument("--max-flows", type=int, default=100)
    parser.add_argument("--max-packets", type=int, default=1000)
    parser.add_argument("--n-dissections", type=int, default=0)
    return parser.parse_args()


def candidate_attr_names(packet: object) -> list[str]:
    names = set(CANDIDATE_NAMES)
    for name in dir(packet):
        lower = name.lower()
        if any(token in lower for token in ("payload", "raw", "bytes", "packet", "frame")):
            names.add(name)
    return sorted(name for name in names if hasattr(packet, name))


def value_len(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return 0


class PacketAttributeProbe:
    def on_init(self, packet: object, flow: object) -> None:
        flow.udps.packet_attr_probe_records = []
        self._inspect(packet, flow)

    def on_update(self, packet: object, flow: object) -> None:
        self._inspect(packet, flow)

    def _inspect(self, packet: object, flow: object) -> None:
        records = getattr(flow.udps, "packet_attr_probe_records", None)
        if records is None:
            records = []
            flow.udps.packet_attr_probe_records = records
        max_packets = int(getattr(self, "max_packets", 1000))
        if len(records) >= max_packets:
            return

        candidates: dict[str, dict[str, object]] = {}
        for name in candidate_attr_names(packet):
            try:
                value = getattr(packet, name)
            except Exception as exc:  # pragma: no cover - defensive for NFStream attrs
                candidates[name] = {"error": str(exc)}
                continue
            raw = _packet_bytes_from_attr(value)
            candidates[name] = {
                "type": type(value).__name__,
                "len": value_len(value),
                "bytes_len": len(raw),
                "nonzero_bytes": int(sum(1 for byte in raw if byte != 0)),
                "first_hex": raw[:16].hex(),
            }

        extracted = packet_payload_bytes(packet)
        records.append(
            {
                "current_extractor_len": len(extracted),
                "current_extractor_nonzero_bytes": int(sum(1 for byte in extracted if byte != 0)),
                "current_extractor_first_hex": extracted[:16].hex(),
                "packet_direction": int(getattr(packet, "direction", 0) or 0),
                "packet_ip_size": float(getattr(packet, "ip_size", 0) or 0),
                "packet_payload_size": float(getattr(packet, "payload_size", 0) or 0),
                "candidates": candidates,
            }
        )


def summarize_records(records: list[dict[str, object]]) -> dict[str, object]:
    attr_seen: Counter[str] = Counter()
    attr_nonzero: Counter[str] = Counter()
    attr_bytes: defaultdict[str, list[int]] = defaultdict(list)
    extractor_lengths = []
    extractor_nonzero = []
    for record in records:
        extractor_lengths.append(int(record["current_extractor_len"]))
        extractor_nonzero.append(int(record["current_extractor_nonzero_bytes"]))
        for name, item in dict(record["candidates"]).items():
            attr_seen[name] += 1
            bytes_len = int(item.get("bytes_len", 0))
            nonzero = int(item.get("nonzero_bytes", 0))
            attr_bytes[name].append(bytes_len)
            if bytes_len > 0 and nonzero > 0:
                attr_nonzero[name] += 1

    attrs = {}
    for name in sorted(attr_seen):
        lengths = np.asarray(attr_bytes[name], dtype=np.float64)
        attrs[name] = {
            "packets_seen": int(attr_seen[name]),
            "packets_with_nonzero_bytes": int(attr_nonzero[name]),
            "mean_bytes_len": float(lengths.mean()) if lengths.size else 0.0,
            "max_bytes_len": int(lengths.max()) if lengths.size else 0,
        }

    extractor_lengths_np = np.asarray(extractor_lengths, dtype=np.float64)
    extractor_nonzero_np = np.asarray(extractor_nonzero, dtype=np.float64)
    return {
        "packets_examined": len(records),
        "current_extractor": {
            "packets_with_payload": int(np.sum(extractor_lengths_np > 0)) if extractor_lengths_np.size else 0,
            "packets_with_nonzero_payload": int(np.sum(extractor_nonzero_np > 0)) if extractor_nonzero_np.size else 0,
            "mean_payload_len": float(extractor_lengths_np.mean()) if extractor_lengths_np.size else 0.0,
            "max_payload_len": int(extractor_lengths_np.max()) if extractor_lengths_np.size else 0,
            "mean_nonzero_bytes": float(extractor_nonzero_np.mean()) if extractor_nonzero_np.size else 0.0,
        },
        "attributes": attrs,
        "sample_records": records[:5],
    }


def inspect_pcap(path: Path, max_flows: int, max_packets: int, n_dissections: int) -> dict[str, object]:
    try:
        from nfstream import NFPlugin, NFStreamer
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError("NFStream is required for PacketCapture verification.") from exc

    class NFStreamPacketAttributeProbe(PacketAttributeProbe, NFPlugin):
        pass

    probe = NFStreamPacketAttributeProbe()
    probe.max_packets = max_packets
    streamer = NFStreamer(
        source=str(path),
        decode_tunnels=False,
        statistical_analysis=False,
        splt_analysis=0,
        n_dissections=n_dissections,
        idle_timeout=int(config.FLOW_IDLE_TIMEOUT_SECONDS),
        active_timeout=1800,
        accounting_mode=0,
        udps=[probe],
    )

    records = []
    flows_seen = 0
    for flow in streamer:
        flows_seen += 1
        records.extend(list(getattr(getattr(flow, "udps", object()), "packet_attr_probe_records", []) or []))
        if flows_seen >= max_flows or len(records) >= max_packets:
            break

    records = records[:max_packets]
    summary = summarize_records(records)
    summary.update(
        {
            "pcap": str(path),
            "pcap_size_mb": path.stat().st_size / (1024 * 1024),
            "flows_seen": flows_seen,
            "max_flows": max_flows,
            "max_packets": max_packets,
            "n_dissections": n_dissections,
        }
    )
    return summary


def main() -> None:
    args = parse_args()
    reports = [inspect_pcap(Path(path), args.max_flows, args.max_packets, args.n_dissections) for path in args.pcap]
    output = {
        "reports": reports,
        "interpretation": (
            "If current_extractor.packets_with_nonzero_payload is high and ip_packet has nonzero bytes, "
            "PacketCapture is receiving usable packet bytes. Low WebBased/BruteForce feature means can then be "
            "caused by short HTTP payloads, padding to 1500 bytes, or captures dominated by headers/handshakes."
        ),
    }
    output_path = config.ARTIFACTS_DIR / f"packetcapture_verification_nd{args.n_dissections}.json"
    write_json(output_path, output)
    write_context(
        "30_packetcapture_verification.md",
        "PacketCapture Verification",
        [
            "## Action",
            "- Sampled NFStream packet objects directly from selected PCAPs.",
            "- Compared packet attributes against the current `packet_payload_bytes()` extraction path.",
            f"- Saved machine-readable output to `{output_path}`.",
            "",
            "## Summary",
            "```json",
            json.dumps(
                [
                    {
                        "pcap": report["pcap"],
                        "flows_seen": report["flows_seen"],
                        "packets_examined": report["packets_examined"],
                        "current_extractor": report["current_extractor"],
                        "top_attributes": {
                            name: item
                            for name, item in sorted(
                                report["attributes"].items(),
                                key=lambda pair: pair[1]["packets_with_nonzero_bytes"],
                                reverse=True,
                            )[:8]
                        },
                    }
                    for report in reports
                ],
                indent=2,
            ),
            "```",
        ],
    )
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
