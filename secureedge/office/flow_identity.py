from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any


@dataclass(frozen=True, order=True)
class CanonicalFlowKey:
    day: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    first_seen_ms: int

    def tuple_without_time(self) -> tuple[str, int, str, int, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)


def _int_value(value: object) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def flow_key_from_record(day: str, record: dict[str, Any]) -> CanonicalFlowKey:
    timestamp = record.get("bidirectional_first_seen_ms")
    if timestamp is None:
        timestamp = float(record.get("timestamp", 0.0) or 0.0) * 1000.0
    return CanonicalFlowKey(
        day=str(day),
        src_ip=str(record.get("src_ip", "") or ""),
        src_port=_int_value(record.get("src_port", 0)),
        dst_ip=str(record.get("dst_ip", "") or ""),
        dst_port=_int_value(record.get("dst_port", 0)),
        protocol=_int_value(record.get("protocol", 0)),
        first_seen_ms=_int_value(timestamp),
    )


def direction_normalized_flow_hash(key: CanonicalFlowKey, *, bucket_ms: int = 1000) -> str:
    left = (key.src_ip, key.src_port)
    right = (key.dst_ip, key.dst_port)
    endpoints = sorted([left, right])
    payload = {
        "day": key.day,
        "protocol": key.protocol,
        "endpoint_a": endpoints[0],
        "endpoint_b": endpoints[1],
        "first_seen_bucket_ms": (key.first_seen_ms // bucket_ms) * bucket_ms if bucket_ms > 0 else key.first_seen_ms,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def directed_flow_identity(key: CanonicalFlowKey) -> str:
    canonical = json.dumps(asdict(key), sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()
