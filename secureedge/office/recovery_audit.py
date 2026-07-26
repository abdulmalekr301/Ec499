from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureedge import config
from secureedge.data.office_pipeline import (
    OFFICE_ARTIFACT_DIR,
    OFFICE_FINAL_SPLIT_MANIFEST_PATH,
    build_ip_to_pcap_lookup,
    candidate_endpoint_paths,
    candidate_flow_tuple,
    candidate_timestamp_seconds,
    iter_capture_packets,
    materialization_identity,
    packet_flow_tuple,
    read_candidate_jsonl,
    reverse_flow_tuple,
)
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, atomic_write_text, stable_json_hash


DEFAULT_OUTPUT_PATH = OFFICE_ARTIFACT_DIR / "benign_infiltration_recovery_audit.json"


@dataclass
class ProbeCandidate:
    index: int
    identity: str
    class_name: str
    split: str
    day: str
    timestamp: float | None
    flow_hash: str
    forward: tuple[str, str, str, str, str]
    reverse: tuple[str, str, str, str, str]
    primary_endpoints: tuple[str, ...]
    alternate_endpoints: tuple[str, ...]
    best_primary_delta: float | None = None
    best_primary_direction: str = ""
    best_alternate_delta: float | None = None
    best_alternate_direction: str = ""
    primary_window_match: bool = False
    alternate_window_match: bool = False
    missing_primary_pcaps: int = 0
    missing_alternate_pcaps: int = 0


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_materialized_identities(cumulative_path: Path) -> set[str]:
    manifest = json.loads(cumulative_path.read_text(encoding="utf-8"))
    return {
        str(record.get("candidate_identity", ""))
        for record in manifest.get("records", [])
        if record.get("candidate_identity")
    }


def load_remaining_candidates(
    *,
    target_classes: set[str],
    cumulative_path: Path,
    limit_per_class: int,
) -> list[dict[str, object]]:
    materialized = load_materialized_identities(cumulative_path)
    split_manifest = json.loads(OFFICE_FINAL_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    candidates = read_candidate_jsonl(Path(str(split_manifest["paths"]["materialization_unique"])))
    by_class: dict[str, list[dict[str, object]]] = defaultdict(list)
    for candidate in candidates:
        class_name = str(candidate.get("class_name", ""))
        if class_name not in target_classes:
            continue
        if materialization_identity(candidate) in materialized:
            continue
        by_class[class_name].append(candidate)

    selected: list[dict[str, object]] = []
    for class_name in sorted(by_class):
        class_candidates = by_class[class_name]
        if limit_per_class > 0:
            endpoint_counts = Counter(primary_endpoint(candidate) for candidate in class_candidates)
            class_candidates = sorted(
                class_candidates,
                key=lambda item: (
                    -endpoint_counts[primary_endpoint(item)],
                    str(item.get("day", "")),
                    str(item.get("timestamp", "")),
                    str(item.get("flow_hash", "")),
                ),
            )[:limit_per_class]
        selected.extend(class_candidates)
    return selected


def primary_endpoint(candidate: dict[str, object]) -> str:
    paths = candidate_endpoint_paths(candidate)
    return paths[0] if paths else ""


def alternate_endpoints(candidate: dict[str, object]) -> tuple[str, ...]:
    day = str(candidate.get("day", ""))
    lookup = build_ip_to_pcap_lookup(day)
    paths: list[str] = []
    for ip_key in ("src_ip", "dst_ip"):
        paths.extend(str(path) for path in lookup.get(str(candidate.get(ip_key, "")), []))
    primary = set(candidate_endpoint_paths(candidate))
    return tuple(sorted(path for path in set(paths) if path not in primary))


def make_probe_candidates(candidates: list[dict[str, object]]) -> list[ProbeCandidate]:
    probes: list[ProbeCandidate] = []
    for index, candidate in enumerate(candidates):
        forward = candidate_flow_tuple(candidate)
        probes.append(
            ProbeCandidate(
                index=index,
                identity=materialization_identity(candidate),
                class_name=str(candidate.get("class_name", "")),
                split=str(candidate.get("candidate_split", "")),
                day=str(candidate.get("day", "")),
                timestamp=candidate_timestamp_seconds(candidate),
                flow_hash=str(candidate.get("flow_hash", "")),
                forward=forward,
                reverse=reverse_flow_tuple(forward),
                primary_endpoints=tuple(candidate_endpoint_paths(candidate)),
                alternate_endpoints=alternate_endpoints(candidate),
            )
        )
    return probes


def update_best_delta(
    probe: ProbeCandidate,
    *,
    timestamp: float,
    direction: str,
    endpoint_kind: str,
    window_seconds: float,
) -> None:
    if probe.timestamp is None:
        return
    delta = timestamp - probe.timestamp
    abs_delta = abs(delta)
    if endpoint_kind == "primary":
        if probe.best_primary_delta is None or abs_delta < abs(probe.best_primary_delta):
            probe.best_primary_delta = delta
            probe.best_primary_direction = direction
        if abs_delta <= window_seconds:
            probe.primary_window_match = True
    else:
        if probe.best_alternate_delta is None or abs_delta < abs(probe.best_alternate_delta):
            probe.best_alternate_delta = delta
            probe.best_alternate_direction = direction
        if abs_delta <= window_seconds:
            probe.alternate_window_match = True


def scan_pcap_for_probes(
    pcap_path: str,
    probe_refs: list[tuple[int, str]],
    probes: list[ProbeCandidate],
    *,
    window_seconds: float,
) -> dict[str, object]:
    path = Path(pcap_path)
    if not path.exists():
        for probe_index, endpoint_kind in probe_refs:
            if endpoint_kind == "primary":
                probes[probe_index].missing_primary_pcaps += 1
            else:
                probes[probe_index].missing_alternate_pcaps += 1
        return {"pcap": pcap_path, "status": "missing_pcap", "probe_count": len(probe_refs)}

    tuple_refs: dict[tuple[str, str, str, str, str], list[tuple[int, str, str]]] = defaultdict(list)
    for probe_index, endpoint_kind in probe_refs:
        probe = probes[probe_index]
        tuple_refs[probe.forward].append((probe_index, endpoint_kind, "forward"))
        tuple_refs[probe.reverse].append((probe_index, endpoint_kind, "reverse"))

    packets_scanned = 0
    tuple_packets = 0
    try:
        for timestamp, packet in iter_capture_packets(path):
            packets_scanned += 1
            parts = packet_flow_tuple(packet)
            if parts is None:
                continue
            refs = tuple_refs.get(parts)
            if not refs:
                continue
            tuple_packets += 1
            for probe_index, endpoint_kind, direction in refs:
                update_best_delta(
                    probes[probe_index],
                    timestamp=timestamp,
                    direction=direction,
                    endpoint_kind=endpoint_kind,
                    window_seconds=window_seconds,
                )
    except Exception as exc:  # noqa: BLE001 - audit records failures for later inspection.
        return {
            "pcap": pcap_path,
            "status": "scan_error",
            "error": repr(exc),
            "probe_count": len(probe_refs),
            "packets_scanned": packets_scanned,
            "tuple_packets": tuple_packets,
        }

    return {
        "pcap": pcap_path,
        "status": "completed",
        "probe_count": len(probe_refs),
        "packets_scanned": packets_scanned,
        "tuple_packets": tuple_packets,
    }


def endpoint_work(
    probes: list[ProbeCandidate],
    *,
    max_pcaps: int,
    include_alternate_endpoints: bool,
) -> dict[str, list[tuple[int, str]]]:
    by_pcap: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for probe in probes:
        for path in probe.primary_endpoints:
            by_pcap[path].append((probe.index, "primary"))
        if include_alternate_endpoints:
            for path in probe.alternate_endpoints:
                by_pcap[path].append((probe.index, "alternate"))
    ordered = sorted(by_pcap.items(), key=lambda item: (-len(item[1]), item[0]))
    if max_pcaps > 0:
        ordered = ordered[:max_pcaps]
    return dict(ordered)


def classify_probe(probe: ProbeCandidate) -> str:
    if probe.primary_window_match:
        return "primary_tuple_within_window"
    if probe.alternate_window_match:
        return "alternate_tuple_within_window"
    if probe.best_primary_delta is not None:
        return "primary_tuple_outside_window"
    if probe.best_alternate_delta is not None:
        return "alternate_tuple_outside_window"
    if probe.missing_primary_pcaps and probe.missing_primary_pcaps >= len(probe.primary_endpoints):
        return "primary_pcap_missing"
    return "tuple_not_seen_in_scanned_pcaps"


def probe_to_json(probe: ProbeCandidate) -> dict[str, object]:
    return {
        "identity": probe.identity,
        "class_name": probe.class_name,
        "split": probe.split,
        "day": probe.day,
        "flow_hash": probe.flow_hash,
        "classification": classify_probe(probe),
        "primary_window_match": probe.primary_window_match,
        "alternate_window_match": probe.alternate_window_match,
        "best_primary_delta_seconds": probe.best_primary_delta,
        "best_primary_direction": probe.best_primary_direction,
        "best_alternate_delta_seconds": probe.best_alternate_delta,
        "best_alternate_direction": probe.best_alternate_direction,
        "primary_endpoints": list(probe.primary_endpoints),
        "alternate_endpoints": list(probe.alternate_endpoints),
        "flow_tuple": list(probe.forward),
    }


def build_recovery_audit(
    *,
    target_classes: set[str],
    cumulative_path: Path,
    output_path: Path,
    limit_per_class: int,
    max_pcaps: int,
    window_seconds: float,
    sample_limit: int,
    include_alternate_endpoints: bool,
) -> dict[str, object]:
    candidates = load_remaining_candidates(
        target_classes=target_classes,
        cumulative_path=cumulative_path,
        limit_per_class=limit_per_class,
    )
    probes = make_probe_candidates(candidates)
    work = endpoint_work(
        probes,
        max_pcaps=max_pcaps,
        include_alternate_endpoints=include_alternate_endpoints,
    )

    pcap_summaries = []
    for pcap_path, refs in work.items():
        pcap_summaries.append(
            scan_pcap_for_probes(
                pcap_path,
                refs,
                probes,
                window_seconds=window_seconds,
            )
        )

    by_class: dict[str, Counter[str]] = defaultdict(Counter)
    by_class_split: dict[str, Counter[str]] = defaultdict(Counter)
    for probe in probes:
        classification = classify_probe(probe)
        by_class[probe.class_name][classification] += 1
        by_class_split[f"{probe.class_name}:{probe.split}"][classification] += 1

    sample_by_class: dict[str, list[dict[str, object]]] = defaultdict(list)
    for probe in probes:
        samples = sample_by_class[probe.class_name]
        if len(samples) < sample_limit:
            samples.append(probe_to_json(probe))

    manifest = {
        "schema_version": 1,
        "pipeline": "benign_infiltration_recovery_audit",
        "generated_at": utc_now(),
        "target_classes": sorted(target_classes),
        "cumulative_manifest_path": str(cumulative_path),
        "candidate_limit_per_class": limit_per_class,
        "max_pcaps": max_pcaps,
        "window_seconds": window_seconds,
        "include_alternate_endpoints": include_alternate_endpoints,
        "candidate_count": len(probes),
        "pcap_count": len(work),
        "pcap_summaries": pcap_summaries,
        "classification_by_class": {key: dict(counter) for key, counter in sorted(by_class.items())},
        "classification_by_class_split": {key: dict(counter) for key, counter in sorted(by_class_split.items())},
        "samples": {key: value for key, value in sorted(sample_by_class.items())},
    }
    manifest["audit_hash"] = stable_json_hash(
        {
            "target_classes": manifest["target_classes"],
            "candidate_count": manifest["candidate_count"],
            "pcap_summaries": manifest["pcap_summaries"],
            "classification_by_class": manifest["classification_by_class"],
        }
    )
    atomic_write_text(output_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit remaining Benign/Infiltration candidates against endpoint PCAP packet headers.")
    parser.add_argument("--target-class", action="append", default=[])
    parser.add_argument("--cumulative-manifest", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--limit-per-class", type=int, default=0)
    parser.add_argument("--max-pcaps", type=int, default=0)
    parser.add_argument("--window-seconds", type=float, default=3600.0)
    parser.add_argument("--sample-limit", type=int, default=20)
    parser.add_argument("--include-alternate-endpoints", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target_classes = {str(item) for item in args.target_class} or {"Benign", "Infiltration"}
    manifest = build_recovery_audit(
        target_classes=target_classes,
        cumulative_path=args.cumulative_manifest,
        output_path=args.output,
        limit_per_class=args.limit_per_class,
        max_pcaps=args.max_pcaps,
        window_seconds=args.window_seconds,
        sample_limit=args.sample_limit,
        include_alternate_endpoints=args.include_alternate_endpoints,
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "candidate_count": manifest["candidate_count"],
                "pcap_count": manifest["pcap_count"],
                "classification_by_class": manifest["classification_by_class"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
