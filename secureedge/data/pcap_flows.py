from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import numpy as np

from secureedge import config
from secureedge.features.temporal import TemporalFeatureExtractor


def _packet_bytes_from_attr(value: object) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, list | tuple):
        try:
            return bytes(int(item) & 0xFF for item in value)
        except (TypeError, ValueError):
            return b""
    return b""


def packet_payload_bytes(packet: object) -> bytes:
    if hasattr(packet, "ip_payload_bytes"):
        payload = _packet_bytes_from_attr(getattr(packet, "ip_payload_bytes", None))
        if payload:
            return payload
    if hasattr(packet, "payload"):
        payload = _packet_bytes_from_attr(getattr(packet, "payload", None))
        if payload:
            return payload
    if hasattr(packet, "ip_packet"):
        payload = application_payload_from_ip_packet(_packet_bytes_from_attr(getattr(packet, "ip_packet", None)))
        if payload:
            return payload
    for attr in ("transport_payload", "packet"):
        if hasattr(packet, attr):
            payload = _packet_bytes_from_attr(getattr(packet, attr, None))
            if payload:
                return payload
    return b""


def application_payload_from_ip_packet(ip_packet: bytes) -> bytes:
    if len(ip_packet) < 20:
        return ip_packet
    version = ip_packet[0] >> 4
    if version != 4:
        return ip_packet
    ip_header_len = (ip_packet[0] & 0x0F) * 4
    if len(ip_packet) <= ip_header_len:
        return b""
    protocol = ip_packet[9]
    transport = ip_packet[ip_header_len:]
    if protocol == 6 and len(transport) >= 20:
        tcp_header_len = (transport[12] >> 4) * 4
        return transport[tcp_header_len:]
    if protocol == 17 and len(transport) >= 8:
        return transport[8:]
    return transport


def pad_payload(payload: bytes) -> list[int]:
    payload = payload[: config.N_PACKET_FEATURES]
    values = list(payload)
    if len(values) < config.N_PACKET_FEATURES:
        values.extend([0] * (config.N_PACKET_FEATURES - len(values)))
    return values


class PacketCapture:
    def on_init(self, packet: object, flow: object) -> None:
        flow.udps.packet_records = []
        self.on_update(packet, flow)

    def on_update(self, packet: object, flow: object) -> None:
        records = getattr(flow.udps, "packet_records", None)
        if records is None:
            records = []
            flow.udps.packet_records = records
        if len(records) >= config.FLOW_PACKET_LIMIT:
            return
        payload = packet_payload_bytes(packet)
        records.append(
            {
                "payload": pad_payload(payload),
                "direction": int(getattr(packet, "direction", 0) or 0),
                "ip_size": float(getattr(packet, "ip_size", 0) or 0),
                "transport_size": float(getattr(packet, "transport_size", 0) or 0),
                "payload_size": float(getattr(packet, "payload_size", len(payload)) or 0),
                "timestamp_ms": float(getattr(packet, "time", 0) or 0),
            }
        )


class FlowCapper:
    def on_update(self, packet: object, flow: object) -> None:
        if getattr(flow, "bidirectional_packets", 0) >= config.FLOW_PACKET_LIMIT:
            flow.expiration_id = -1


class ActiveIdlePlugin:
    ACTIVE_THRESHOLD_MS = 1000.0

    def on_init(self, packet: object, flow: object) -> None:
        timestamp = float(getattr(packet, "time", 0) or 0)
        flow.udps.active_durations = []
        flow.udps.idle_durations = []
        flow.udps.last_packet_ms = timestamp
        flow.udps.period_start_ms = timestamp

    def on_update(self, packet: object, flow: object) -> None:
        timestamp = float(getattr(packet, "time", 0) or 0)
        last_packet_ms = float(getattr(flow.udps, "last_packet_ms", timestamp) or timestamp)
        period_start_ms = float(getattr(flow.udps, "period_start_ms", last_packet_ms) or last_packet_ms)
        gap_ms = timestamp - last_packet_ms
        if gap_ms > self.ACTIVE_THRESHOLD_MS:
            active_dur = max(0.0, last_packet_ms - period_start_ms)
            flow.udps.active_durations.append(active_dur)
            flow.udps.idle_durations.append(max(0.0, gap_ms))
            flow.udps.period_start_ms = timestamp
        flow.udps.last_packet_ms = timestamp

    def on_expire(self, flow: object) -> None:
        last_packet_ms = float(getattr(flow.udps, "last_packet_ms", 0) or 0)
        period_start_ms = float(getattr(flow.udps, "period_start_ms", last_packet_ms) or last_packet_ms)
        active_durations = list(getattr(flow.udps, "active_durations", []) or [])
        idle_durations = list(getattr(flow.udps, "idle_durations", []) or [])
        active_durations.append(max(0.0, last_packet_ms - period_start_ms))

        def stat(values: list[float], name: str) -> float:
            if not values:
                return 0.0
            array = np.asarray(values, dtype=np.float32)
            if name == "mean":
                return float(array.mean())
            if name == "std":
                return float(array.std())
            if name == "max":
                return float(array.max())
            if name == "min":
                return float(array.min())
            return 0.0

        flow.udps.bidirectional_mean_active_ms = stat(active_durations, "mean")
        flow.udps.bidirectional_std_active_ms = stat(active_durations, "std")
        flow.udps.bidirectional_max_active_ms = stat(active_durations, "max")
        flow.udps.bidirectional_min_active_ms = stat(active_durations, "min")
        flow.udps.bidirectional_mean_idle_ms = stat(idle_durations, "mean")
        flow.udps.bidirectional_std_idle_ms = stat(idle_durations, "std")
        flow.udps.bidirectional_max_idle_ms = stat(idle_durations, "max")
        flow.udps.bidirectional_min_idle_ms = stat(idle_durations, "min")

        for name in ("active_durations", "idle_durations", "last_packet_ms", "period_start_ms"):
            if hasattr(flow.udps, name):
                delattr(flow.udps, name)


def flow_to_dict(flow: object) -> dict[str, Any]:
    if hasattr(flow, "to_dict"):
        return dict(flow.to_dict())
    if hasattr(flow, "__dict__"):
        return {key: value for key, value in vars(flow).items() if not key.startswith("_")}
    result: dict[str, Any] = {}
    for name in dir(flow):
        if name.startswith("_"):
            continue
        try:
            value = getattr(flow, name)
        except AttributeError:
            continue
        if not callable(value):
            result[name] = value
    return result


def is_number(value: object) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def nfstream_feature_dict(flow_data: dict[str, Any]) -> dict[str, float]:
    return {
        name: float(value)
        for name, value in flow_data.items()
        if name not in config.NFSTREAM_METADATA_COLUMNS and is_number(value)
    }


def active_idle_feature_dict(flow: object) -> dict[str, float]:
    udps = getattr(flow, "udps", object())
    return {
        name: float(getattr(udps, name, 0.0) or 0.0)
        for name in config.ACTIVE_IDLE_FEATURES
    }


def flow_mac_pair(flow_data: dict[str, Any]) -> tuple[str, str]:
    return (
        config.normalize_mac_address(flow_data.get("src_mac", "")),
        config.normalize_mac_address(flow_data.get("dst_mac", "")),
    )


def nfstream_to_temporal_dict(flow_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "Dst IP": flow_data.get("dst_ip", "global"),
        "Src Port": flow_data.get("src_port", 0),
        "Dst Port": flow_data.get("dst_port", 0),
        "Protocol": flow_data.get("protocol", 0),
        "SYN Flag Cnt": flow_data.get("bidirectional_syn_packets", 0),
        "ACK Flag Cnt": flow_data.get("bidirectional_ack_packets", 0),
        "FIN Flag Cnt": flow_data.get("bidirectional_fin_packets", 0),
        "RST Flag Cnt": flow_data.get("bidirectional_rst_packets", 0),
        "PSH Flag Cnt": flow_data.get("bidirectional_psh_packets", 0),
        "Flow Duration": float(flow_data.get("bidirectional_duration_ms", 0) or 0) * 1000.0,
        "Tot Fwd Pkts": flow_data.get("src2dst_packets", 0),
        "Tot Bwd Pkts": flow_data.get("dst2src_packets", 0),
    }


def iter_flow_records(
    path: Path,
    subtype_label: str,
    extractor: TemporalFeatureExtractor | None = None,
) -> Iterable[dict[str, object]]:
    try:
        from nfstream import NFPlugin, NFStreamer
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "NFStream is required for PCAP extraction. Install dependencies with "
            "`pip install -r requirements.txt` and ensure libpcap is available."
        ) from exc

    class NFStreamFlowCapper(FlowCapper, NFPlugin):
        pass

    class NFStreamPacketCapture(PacketCapture, NFPlugin):
        pass

    class NFStreamActiveIdlePlugin(ActiveIdlePlugin, NFPlugin):
        pass

    if extractor is None:
        extractor = TemporalFeatureExtractor(window_size=config.TEMPORAL_WINDOW_SIZE)
    streamer = NFStreamer(
        source=str(path),
        decode_tunnels=False,
        statistical_analysis=True,
        splt_analysis=0,
        n_dissections=0,
        idle_timeout=int(config.FLOW_IDLE_TIMEOUT_SECONDS),
        active_timeout=1800,
        accounting_mode=0,
        udps=[NFStreamActiveIdlePlugin(), NFStreamPacketCapture(), NFStreamFlowCapper()],
    )

    for source_order, flow in enumerate(streamer):
        flow_data = flow_to_dict(flow)
        flow_data.update(active_idle_feature_dict(flow))
        src_mac, dst_mac = flow_mac_pair(flow_data)
        feature_values = nfstream_feature_dict(flow_data)
        temporal_values = extractor.transform_row(nfstream_to_temporal_dict(flow_data))
        first_seen_ms = float(flow_data.get("bidirectional_first_seen_ms", 0) or 0)
        packet_records = list(getattr(getattr(flow, "udps", object()), "packet_records", []) or [])
        record: dict[str, object] = {
            **feature_values,
            **temporal_values,
            "flow_features": feature_values,
            "temporal_features": temporal_values,
            "packet_records": packet_records,
            "timestamp": first_seen_ms / 1000.0,
            "src_ip": flow_data.get("src_ip", ""),
            "dst_ip": flow_data.get("dst_ip", ""),
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_port": flow_data.get("src_port", 0),
            "dst_port": flow_data.get("dst_port", 0),
            "protocol": flow_data.get("protocol", 0),
            config.LABEL_COLUMN: subtype_label,
            config.SUBTYPE_COLUMN: subtype_label,
            config.SOURCE_FILE_COLUMN: path.name,
            config.SOURCE_ORDER_COLUMN: source_order,
        }
        yield record
