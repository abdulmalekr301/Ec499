from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureedge import config
from secureedge.data.pcap_flows import iter_flow_records
from secureedge.features.temporal import TemporalFeatureExtractor
from secureedge.office.flow_identity import CanonicalFlowKey, directed_flow_identity, flow_key_from_record
from secureedge.office.manifests import atomic_write_text, stable_json_hash


DAY_PATTERN = re.compile(r"\w+-\d{2}-\d{2}-\d{4}")


@dataclass(frozen=True)
class TemporalIndexEntry:
    key: CanonicalFlowKey
    flow_identity: str
    temporal_features: dict[str, float]
    source_pcap: str
    source_order: int
    context_status: str


@dataclass(frozen=True)
class TemporalIndex:
    schema_version: int
    window_size: int
    entries: list[TemporalIndexEntry]
    manifest: dict[str, Any]


def infer_day_from_path(path: Path) -> str:
    for part in path.parts:
        if DAY_PATTERN.fullmatch(part):
            return part
    return path.parent.name


def _entry_to_json(entry: TemporalIndexEntry) -> dict[str, Any]:
    return {
        "key": asdict(entry.key),
        "flow_identity": entry.flow_identity,
        "temporal_features": entry.temporal_features,
        "source_pcap": entry.source_pcap,
        "source_order": entry.source_order,
        "context_status": entry.context_status,
    }


def _entry_from_json(value: dict[str, Any]) -> TemporalIndexEntry:
    key_value = value["key"]
    return TemporalIndexEntry(
        key=CanonicalFlowKey(
            day=str(key_value["day"]),
            src_ip=str(key_value["src_ip"]),
            src_port=int(key_value["src_port"]),
            dst_ip=str(key_value["dst_ip"]),
            dst_port=int(key_value["dst_port"]),
            protocol=int(key_value["protocol"]),
            first_seen_ms=int(key_value["first_seen_ms"]),
        ),
        flow_identity=str(value["flow_identity"]),
        temporal_features={str(key): float(item) for key, item in value["temporal_features"].items()},
        source_pcap=str(value["source_pcap"]),
        source_order=int(value["source_order"]),
        context_status=str(value.get("context_status", "full")),
    )


def load_temporal_index(path: Path) -> TemporalIndex:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return TemporalIndex(
        schema_version=int(payload["schema_version"]),
        window_size=int(payload["window_size"]),
        entries=[_entry_from_json(item) for item in payload["entries"]],
        manifest=dict(payload["manifest"]),
    )


def _candidate_timestamp_ms(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            timestamp = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return int(round(timestamp.timestamp() * 1000.0))
        except ValueError:
            continue
    return None


def candidate_lookup_from_jsonl(
    paths: list[Path],
    *,
    target_classes: set[str],
) -> dict[tuple[str, tuple[str, int, str, int, int]], list[int]]:
    lookup: dict[tuple[str, tuple[str, int, str, int, int]], list[int]] = {}
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                candidate = json.loads(line)
                class_name = str(candidate.get("class_name", ""))
                if target_classes and class_name not in target_classes:
                    continue
                timestamp_ms = _candidate_timestamp_ms(candidate.get("timestamp"))
                if timestamp_ms is None:
                    continue
                try:
                    flow_tuple = (
                        str(candidate.get("src_ip", "")),
                        int(float(candidate.get("src_port", 0) or 0)),
                        str(candidate.get("dst_ip", "")),
                        int(float(candidate.get("dst_port", 0) or 0)),
                        int(float(candidate.get("protocol", 0) or 0)),
                    )
                except (TypeError, ValueError):
                    continue
                lookup.setdefault((str(candidate.get("day", "")), flow_tuple), []).append(timestamp_ms)
    return lookup


def key_matches_candidate_lookup(
    key: CanonicalFlowKey,
    candidate_lookup: dict[tuple[str, tuple[str, int, str, int, int]], list[int]] | None,
    *,
    tolerance_ms: int,
) -> bool:
    if candidate_lookup is None:
        return True
    timestamps = candidate_lookup.get((key.day, key.tuple_without_time()), [])
    return any(abs(key.first_seen_ms - timestamp_ms) <= tolerance_ms for timestamp_ms in timestamps)


def build_temporal_index(
    pcap_paths: list[Path],
    *,
    window_size: int,
    output_path: Path,
    candidate_lookup: dict[tuple[str, tuple[str, int, str, int, int]], list[int]] | None = None,
    tolerance_ms: int = 3000,
) -> dict[str, object]:
    entries: list[TemporalIndexEntry] = []
    by_day: dict[str, list[Path]] = {}
    for path in pcap_paths:
        by_day.setdefault(infer_day_from_path(path), []).append(path)

    for day in sorted(by_day):
        extractor = TemporalFeatureExtractor(window_size=window_size)
        day_entries: list[TemporalIndexEntry] = []
        for pcap_path in sorted(by_day[day], key=lambda item: str(item)):
            for source_order, flow_record in enumerate(
                iter_flow_records(
                    pcap_path,
                    "office_temporal_index",
                    extractor=extractor,
                    temporal_mode="calculate",
                    require_external_extractor=True,
                )
            ):
                key = flow_key_from_record(day, flow_record)
                if key_matches_candidate_lookup(key, candidate_lookup, tolerance_ms=tolerance_ms):
                    day_entries.append(
                        TemporalIndexEntry(
                            key=key,
                            flow_identity=directed_flow_identity(key),
                            temporal_features={
                                name: float(flow_record.get("temporal_features", {}).get(name, 0.0))
                                for name in config.TEMPORAL_FEATURES
                            },
                            source_pcap=str(pcap_path),
                            source_order=source_order,
                            context_status="full",
                        )
                    )
        entries.extend(sorted(day_entries, key=lambda item: (item.key.first_seen_ms, item.key.tuple_without_time(), item.source_order)))

    payload = {
        "schema_version": 1,
        "window_size": int(window_size),
        "entries": [_entry_to_json(entry) for entry in entries],
        "manifest": {
            "pcap_count": len(pcap_paths),
            "days": sorted(by_day),
            "entry_count": len(entries),
            "context_status": "full",
            "candidate_filtered": candidate_lookup is not None,
        },
    }
    payload["manifest"]["temporal_index_hash"] = stable_json_hash(payload["entries"])
    atomic_write_text(output_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload["manifest"]


def lookup_temporal_features(
    index: TemporalIndex,
    candidate_key: CanonicalFlowKey,
    tolerance_ms: int,
) -> dict[str, float]:
    matches = [
        entry
        for entry in index.entries
        if entry.key.day == candidate_key.day
        and entry.key.tuple_without_time() == candidate_key.tuple_without_time()
        and abs(entry.key.first_seen_ms - candidate_key.first_seen_ms) <= tolerance_ms
    ]
    if not matches:
        raise KeyError(f"TEMPORAL_CONTEXT_MISSING for {candidate_key}")
    matches.sort(key=lambda entry: (abs(entry.key.first_seen_ms - candidate_key.first_seen_ms), entry.source_order))
    if len(matches) > 1:
        best_delta = abs(matches[0].key.first_seen_ms - candidate_key.first_seen_ms)
        second_delta = abs(matches[1].key.first_seen_ms - candidate_key.first_seen_ms)
        if best_delta == second_delta:
            raise ValueError(f"AMBIGUOUS_TEMPORAL_CONTEXT for {candidate_key}")
    if matches[0].context_status != "full":
        raise ValueError(f"TEMPORAL_CONTEXT_NOT_FULL for {candidate_key}: {matches[0].context_status}")
    return dict(matches[0].temporal_features)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a chronological office temporal feature index.")
    parser.add_argument("--output", type=Path, default=config.ARTIFACTS_DIR / "office_model" / "office_temporal_index.json")
    parser.add_argument("--window-size", type=int, default=config.TEMPORAL_WINDOW_SIZE)
    parser.add_argument("--tolerance-ms", type=int, default=3000)
    parser.add_argument("--candidate-jsonl", type=Path, action="append", default=[])
    parser.add_argument("--target-class", action="append", default=[])
    parser.add_argument("pcaps", type=Path, nargs="+")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    candidate_lookup = (
        candidate_lookup_from_jsonl(
            args.candidate_jsonl,
            target_classes={str(item) for item in args.target_class},
        )
        if args.candidate_jsonl
        else None
    )
    manifest = build_temporal_index(
        args.pcaps,
        window_size=args.window_size,
        output_path=args.output,
        candidate_lookup=candidate_lookup,
        tolerance_ms=args.tolerance_ms,
    )
    print(json.dumps({"output": str(args.output), **manifest}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
