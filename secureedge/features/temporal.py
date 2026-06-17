from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from secureedge import config


def first_present(row: pd.Series, candidates: tuple[str, ...], default: Any = 0) -> Any:
    for name in candidates:
        if name in row and pd.notna(row[name]):
            return row[name]
    return default


def destination_key(row: pd.Series) -> str:
    return str(first_present(row, ("dst_ip", "Dst IP", "Destination IP", "Destination", "dest_ip"), "global"))


def source_port(row: pd.Series) -> int:
    value = first_present(row, ("src_port", "Src_Port", "Src Port", "Source Port", "sport"), 0)
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def destination_port(row: pd.Series) -> int:
    for name in ("dst_port", "Dst_Port", "Dst Port", "Destination Port", "dport"):
        if name in row and pd.notna(row[name]):
            try:
                return int(float(row[name]))
            except (TypeError, ValueError):
                return 0
    if float(first_present(row, ("HTTP",), 0)) > 0:
        return 80
    if float(first_present(row, ("HTTPS",), 0)) > 0:
        return 443
    if float(first_present(row, ("DNS",), 0)) > 0:
        return 53
    if float(first_present(row, ("Telnet",), 0)) > 0:
        return 23
    if float(first_present(row, ("SSH",), 0)) > 0:
        return 22
    if float(first_present(row, ("SMTP",), 0)) > 0:
        return 25
    return 0


def numeric(row: pd.Series, *names: str) -> float:
    return float(first_present(row, names, 0) or 0)


def numeric_sum(row: pd.Series, *names: str) -> float:
    total = 0.0
    found = False
    for name in names:
        if name in row and pd.notna(row[name]):
            total += float(row[name] or 0)
            found = True
    return total if found else 0.0


def snapshot(row: pd.Series) -> dict[str, Any]:
    dst_port = destination_port(row)
    packet_total = numeric_sum(row, "Fwd_Packet_Count", "Bwd_Packet_Count", "Tot Fwd Pkts", "Tot Bwd Pkts")
    if packet_total == 0.0:
        packet_total = numeric(row, "Number", "Total Packets")
    protocol = int(numeric(row, "protocol", "Protocol", "Protocol Type"))
    return {
        "udp": numeric(row, "UDP") or float(protocol == 17),
        "tcp": numeric(row, "TCP") or float(protocol == 6),
        "ack": numeric(row, "ack_count", "ack_flag_number", "ACK Flag Cnt"),
        "fin": numeric(row, "fin_count", "fin_flag_number", "FIN Flag Cnt"),
        "rst": numeric(row, "rst_count", "rst_flag_number", "RST Flag Cnt"),
        "psh": numeric(row, "psh_flag_number", "PSH Flag Cnt"),
        "syn": numeric(row, "syn_count", "syn_flag_number", "SYN Flag Cnt"),
        "icmp": numeric(row, "ICMP") or float(protocol == 1),
        "http_port": 1.0 if dst_port in config.HTTP_PORTS or numeric(row, "HTTP", "HTTPS") > 0 else 0.0,
        "duration": numeric(row, "Flow_Duration", "Flow Duration", "Duration", "IAT"),
        "dns": 1.0 if dst_port == 53 or numeric(row, "DNS") > 0 else 0.0,
        "vulnerable": 1.0 if dst_port in config.VULNERABLE_PORTS else 0.0,
        "packets": packet_total,
        "bipackets": packet_total,
        "source_port": source_port(row),
    }


@dataclass
class TemporalFeatureExtractor:
    window_size: int = config.TEMPORAL_WINDOW_SIZE
    windows: dict[str, deque[dict[str, Any]]] = field(default_factory=lambda: defaultdict(deque))

    def transform_row(self, row: pd.Series) -> dict[str, float]:
        key = destination_key(row)
        window = self.windows[key]
        values = list(window)
        count = len(values)

        def total(name: str) -> float:
            return float(sum(item[name] for item in values))

        duration = total("duration") / count if count else 0.0
        features = {
            "Rolling_UDP_Sum": total("udp"),
            "Rolling_TCP_Sum": total("tcp"),
            "Rolling_ACK_Sum": total("ack"),
            "Rolling_FIN_Sum": total("fin"),
            "Rolling_RST_Sum": total("rst"),
            "Rolling_fin_Sum": total("fin"),
            "Rolling_psh_Sum": total("psh"),
            "Rolling_SYN_Sum": total("syn"),
            "Rolling_ICMP_Sum": total("icmp"),
            "Rolling_http_port": total("http_port"),
            "Rolling_Average_Duration": duration,
            "Rolling_DNS_Sum": total("dns"),
            "Rolling_vulnerable_port": total("vulnerable"),
            "Rolling_packets_Sum": total("packets"),
            "Rolling_bipackets_Sum": total("bipackets"),
            "Unique_Ports_In_SourceDestination": float(len({item["source_port"] for item in values if item["source_port"]})),
        }

        window.append(snapshot(row))
        while len(window) > self.window_size:
            window.popleft()
        return features

    def transform_frame(self, frame: pd.DataFrame) -> pd.DataFrame:
        temporal_rows = [self.transform_row(row) for _, row in frame.iterrows()]
        return pd.DataFrame(temporal_rows, columns=config.TEMPORAL_FEATURES, index=frame.index)
