from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from secureedge import config as root_config
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, load_compact_record
from secureedge.training.engine import manifest_class_names


DEFAULT_OUTPUT_DIR = (
    root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "nearest_neighbor_similarity_compact"
)
SUBTYPE_DISPLAY_NAMES = {
    "SSH-Bruteforce": "SSH",
    "FTP-BruteForce": "FTP",
    "DoS-Hulk": "Hulk",
    "DoS-GoldenEye": "GoldenEye",
    "DoS-Slowloris": "Slowloris",
    "DoS-SlowHTTPTest": "SlowHTTPTest",
    "DDOS-HOIC": "HOIC",
    "DDOS-LOIC-HTTP": "LOIC-HTTP",
    "DDOS-LOIC-UDP": "LOIC-UDP",
}
REQUESTED_SUBTYPE_ROWS = [
    ("BruteForce", "SSH-Bruteforce"),
    ("BruteForce", "FTP-BruteForce"),
    ("DoS", "DoS-Hulk"),
    ("DoS", "DoS-GoldenEye"),
    ("DoS", "DoS-Slowloris"),
    ("DDoS", "DDOS-HOIC"),
    ("DDoS", "DDOS-LOIC-HTTP"),
    ("DDoS", "DDOS-LOIC-UDP"),
]
SUBTYPE_TABLE_CLASSES = {"BruteForce", "DoS", "DDoS"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def compact_root(manifest: dict[str, Any]) -> Path:
    return Path(str(manifest["compact_root"]))


def compact_manifest_class_names(manifest: dict[str, Any]) -> list[str]:
    try:
        return manifest_class_names(manifest)
    except ValueError:
        pass
    by_label: dict[int, str] = {}
    first_seen: list[str] = []
    for record in manifest.get("records", []):
        class_name = str(record.get("class_name", ""))
        if not class_name:
            continue
        if class_name not in first_seen:
            first_seen.append(class_name)
        label = record.get("label")
        if isinstance(label, int):
            by_label.setdefault(label, class_name)
    if by_label:
        return [class_name for _, class_name in sorted(by_label.items())]
    if first_seen:
        return first_seen
    raise ValueError("Compact manifest must contain records with class_name values.")


def records_by_split_and_class(manifest: dict[str, Any]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    output: dict[str, dict[str, list[dict[str, Any]]]] = {
        "train": defaultdict(list),
        "val": defaultdict(list),
        "test": defaultdict(list),
    }
    for record in manifest.get("records", []):
        split = str(record.get("split", ""))
        if split not in output:
            continue
        output[split][str(record.get("class_name", ""))].append(record)
    return output


def record_compact_path(root: Path, record: dict[str, Any]) -> Path:
    return root / Path(str(record["path"]))


def metadata_for_sampling(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "subtype_label",
        "gt_subtype",
        "day",
        "source_dataset",
        "source_file",
        "endpoint_pcap",
        "gt_window_start",
        "gt_window_finish",
    )
    if all(record.get(key) not in (None, "") for key in ("subtype_label", "day")) and (
        record.get("source_file") not in (None, "") or record.get("endpoint_pcap") not in (None, "")
    ):
        return record
    try:
        compact = load_compact_record(record_compact_path(root, record))
    except Exception:
        return record
    output = dict(record)
    for key in keys:
        if output.get(key) in (None, "") and compact.get(key) not in (None, ""):
            output[key] = compact.get(key)
    return output


def sampling_group_key(root: Path, record: dict[str, Any]) -> tuple[str, str, str, str]:
    item = metadata_for_sampling(root, record)
    source_dataset = str(item.get("source_dataset", "unknown") or "unknown")
    day = str(item.get("day", "unknown") or "unknown")
    subtype = subtype_name(item)
    start = str(item.get("gt_window_start") or "")
    finish = str(item.get("gt_window_finish") or "")
    pcap = pcap_name(item)
    if start or finish:
        window_or_pcap = f"{start}->{finish}|{pcap}"
    else:
        window_or_pcap = pcap
    return (subtype, source_dataset, day, window_or_pcap)


def stratified_take(records: list[dict[str, Any]], target: int, *, root: Path, rng: random.Random) -> list[dict[str, Any]]:
    if target <= 0 or target >= len(records):
        output = list(records)
        rng.shuffle(output)
        return output
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[sampling_group_key(root, record)].append(record)
    buckets = []
    for key, bucket in sorted(groups.items(), key=lambda item: item[0]):
        shuffled = list(bucket)
        rng.shuffle(shuffled)
        buckets.append({"key": key, "records": shuffled, "cursor": 0})

    selected: list[dict[str, Any]] = []
    while len(selected) < target:
        progressed = False
        for bucket in buckets:
            cursor = int(bucket["cursor"])
            records_for_bucket = bucket["records"]
            if cursor >= len(records_for_bucket):
                continue
            selected.append(records_for_bucket[cursor])
            bucket["cursor"] = cursor + 1
            progressed = True
            if len(selected) == target:
                break
        if not progressed:
            break
    return selected


def selected_records(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    per_class: int,
    seed: int,
    root: Path,
    sampling_strategy: str,
) -> list[dict[str, Any]]:
    rng = random.Random(seed + (0 if split == "train" else 1009))
    by_split_class = records_by_split_and_class(manifest)
    records: list[dict[str, Any]] = []
    for class_name in class_names:
        class_records = list(by_split_class[split].get(class_name, []))
        if sampling_strategy == "stratified":
            class_records = stratified_take(class_records, per_class, root=root, rng=rng)
        else:
            rng.shuffle(class_records)
        if per_class > 0 and sampling_strategy != "stratified":
            class_records = class_records[:per_class]
        records.extend(class_records)
    return records


def tensor_stats(values: Any, *, include_features: bool = False) -> list[float]:
    array = np.asarray(values, dtype=np.float32)
    if array.size == 0:
        feature_count = int(array.shape[-1]) if include_features and array.ndim >= 2 else 0
        return [0.0] * (4 + feature_count)
    flat = array.reshape(-1)
    stats = [
        float(flat.mean()),
        float(flat.std()),
        float(flat.min()),
        float(flat.max()),
    ]
    if include_features:
        if array.ndim == 1:
            stats.extend(float(item) for item in array.tolist())
        else:
            stats.extend(float(item) for item in array.mean(axis=0).tolist())
    return stats


def compact_vector(compact: dict[str, Any]) -> np.ndarray:
    flow_x = np.asarray(compact.get("flow_x", []), dtype=np.float32)
    packet_x = np.asarray(compact.get("packet_x_uint8", []), dtype=np.float32)
    contain_attr = np.asarray(compact.get("contain_edge_attr", []), dtype=np.float32)
    link_attr = np.asarray(compact.get("link_edge_attr", []), dtype=np.float32)
    packet_count = int(packet_x.shape[0]) if packet_x.ndim >= 1 else 0
    contain_edges = int(contain_attr.shape[0]) if contain_attr.ndim >= 1 else 0
    link_edges = int(link_attr.shape[0]) if link_attr.ndim >= 1 else 0
    values: list[float] = [
        1.0,
        float(packet_count),
        float(contain_edges),
        float(contain_edges),
        float(link_edges),
    ]
    values.extend(tensor_stats(flow_x, include_features=True))
    values.extend(tensor_stats(packet_x, include_features=False))
    values.extend(tensor_stats(contain_attr, include_features=True))
    values.extend(tensor_stats(contain_attr, include_features=True))
    values.extend(tensor_stats(link_attr, include_features=True))
    return np.asarray(values, dtype=np.float32)


def pcap_name(row: dict[str, Any]) -> str:
    value = row.get("endpoint_pcap") or row.get("source_file") or ""
    text = str(value or "")
    return Path(text).name if text else "missing_pcap"


def subtype_name(row: dict[str, Any]) -> str:
    return str(row.get("gt_subtype") or row.get("subtype_label") or row.get("label") or "no_subtype")


def window_key(row: dict[str, Any]) -> str:
    source_dataset = str(row.get("source_dataset", row.get("source", "unknown")) or "unknown")
    day = str(row.get("day", "unknown") or "unknown")
    class_name = str(row.get("class_name", "unknown") or "unknown")
    subtype = subtype_name(row)
    start = str(row.get("gt_window_start") or "")
    finish = str(row.get("gt_window_finish") or "")
    if start or finish:
        return "|".join([source_dataset, day, class_name, subtype, start, finish])
    return "|".join([source_dataset, day, class_name, subtype, pcap_name(row)])


def endpoint_service_key(row: dict[str, Any]) -> str:
    source_dataset = str(row.get("source_dataset", row.get("source", "unknown")) or "unknown")
    day = str(row.get("day", "unknown") or "unknown")
    return "|".join(
        [
            source_dataset,
            day,
            str(row.get("src_ip") or row.get("attacker_public_ip") or row.get("attacker_private_ip") or "unknown"),
            str(row.get("dst_ip") or row.get("victim_private_ip") or row.get("victim_public_ip") or "unknown"),
            str(row.get("dst_port") or "unknown"),
            str(row.get("protocol") or "unknown"),
        ]
    )


def row_from_record(record: dict[str, Any], compact: dict[str, Any], path: Path) -> dict[str, Any]:
    row = {**record}
    for key in (
        "candidate_identity",
        "class_name",
        "day",
        "source_dataset",
        "source_file",
        "subtype_label",
        "gt_subtype",
        "label",
        "gt_window_start",
        "gt_window_finish",
        "endpoint_pcap",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "attacker_public_ip",
        "attacker_private_ip",
        "victim_private_ip",
        "victim_public_ip",
    ):
        if row.get(key) in (None, "") and compact.get(key) not in (None, ""):
            row[key] = compact.get(key)
    row["abs_path"] = str(path)
    return row


def load_samples(
    records: list[dict[str, Any]],
    root: Path,
) -> tuple[np.ndarray, list[dict[str, Any]], list[dict[str, str]]]:
    vectors: list[np.ndarray] = []
    rows: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    for record in records:
        rel_path = Path(str(record["path"]))
        path = root / rel_path
        if not path.exists():
            missing.append({"path": str(path), "candidate_identity": str(record.get("candidate_identity", ""))})
            continue
        compact = load_compact_record(path)
        vectors.append(compact_vector(compact))
        rows.append(row_from_record(record, compact, path))
    return np.vstack(vectors).astype(np.float32), rows, missing


def nearest_rows(
    *,
    train_rows: list[dict[str, Any]],
    val_rows: list[dict[str, Any]],
    distances: np.ndarray,
    indices: np.ndarray,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for val_index, val_row in enumerate(val_rows):
        nearest_index = int(indices[val_index, 0])
        train_row = train_rows[nearest_index]
        distance = float(distances[val_index, 0])
        rows.append(
            {
                "val_candidate_identity": val_row.get("candidate_identity", ""),
                "train_candidate_identity": train_row.get("candidate_identity", ""),
                "val_class": val_row.get("class_name", ""),
                "train_class": train_row.get("class_name", ""),
                "val_subtype": subtype_name(val_row),
                "train_subtype": subtype_name(train_row),
                "val_day": val_row.get("day", ""),
                "train_day": train_row.get("day", ""),
                "val_pcap": pcap_name(val_row),
                "train_pcap": pcap_name(train_row),
                "cosine_distance": distance,
                "cosine_similarity": float(1.0 - distance),
                "same_class": bool(val_row.get("class_name") == train_row.get("class_name")),
                "same_subtype": bool(subtype_name(val_row) == subtype_name(train_row)),
                "same_day": bool(val_row.get("day") == train_row.get("day")),
                "same_window": bool(window_key(val_row) == window_key(train_row)),
                "same_pcap": bool(pcap_name(val_row) == pcap_name(train_row)),
                "same_endpoint_service": bool(endpoint_service_key(val_row) == endpoint_service_key(train_row)),
            }
        )
    return rows


def rate(rows: list[dict[str, Any]], field: str) -> float:
    if not rows:
        return 0.0
    return float(sum(1 for row in rows if row[field]) / len(rows))


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    return float(np.percentile(np.asarray(values, dtype=np.float64), q))


def summarize_neighbors(rows: list[dict[str, Any]], class_names: list[str]) -> dict[str, Any]:
    distances = [float(row["cosine_distance"]) for row in rows]
    summary = {
        "count": len(rows),
        "distance_min": percentile(distances, 0),
        "distance_p01": percentile(distances, 1),
        "distance_p05": percentile(distances, 5),
        "distance_median": percentile(distances, 50),
        "distance_p95": percentile(distances, 95),
        "distance_max": percentile(distances, 100),
        "same_class_rate": rate(rows, "same_class"),
        "same_subtype_rate": rate(rows, "same_subtype"),
        "same_day_rate": rate(rows, "same_day"),
        "same_window_rate": rate(rows, "same_window"),
        "same_pcap_rate": rate(rows, "same_pcap"),
        "same_endpoint_service_rate": rate(rows, "same_endpoint_service"),
        "distance_le_0_001": int(sum(1 for value in distances if value <= 0.001)),
        "distance_le_0_01": int(sum(1 for value in distances if value <= 0.01)),
        "distance_le_0_05": int(sum(1 for value in distances if value <= 0.05)),
    }
    by_class: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_class[str(row["val_class"])].append(row)
    per_class: dict[str, dict[str, Any]] = {}
    for class_name in class_names:
        class_rows = by_class.get(class_name, [])
        class_distances = [float(row["cosine_distance"]) for row in class_rows]
        per_class[class_name] = {
            "count": len(class_rows),
            "distance_min": percentile(class_distances, 0),
            "distance_median": percentile(class_distances, 50),
            "distance_p95": percentile(class_distances, 95),
            "same_class_rate": rate(class_rows, "same_class"),
            "same_subtype_rate": rate(class_rows, "same_subtype"),
            "same_day_rate": rate(class_rows, "same_day"),
            "same_window_rate": rate(class_rows, "same_window"),
            "same_pcap_rate": rate(class_rows, "same_pcap"),
            "same_endpoint_service_rate": rate(class_rows, "same_endpoint_service"),
        }
    summary["per_class"] = per_class
    summary["per_subtype"] = summarize_neighbors_by_subtype(rows)
    return summary


def summarize_neighbors_by_subtype(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_subtype: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_subtype[(str(row["val_class"]), str(row["val_subtype"]))].append(row)
    output: dict[str, dict[str, Any]] = {}
    for (class_name, subtype), subtype_rows in sorted(by_subtype.items()):
        distances = [float(row["cosine_distance"]) for row in subtype_rows]
        key = f"{class_name}|{subtype}"
        output[key] = {
            "class_name": class_name,
            "subtype": subtype,
            "display_subtype": SUBTYPE_DISPLAY_NAMES.get(subtype, subtype),
            "count": len(subtype_rows),
            "distance_median": percentile(distances, 50),
            "distance_p95": percentile(distances, 95),
            "same_subtype_rate": rate(subtype_rows, "same_subtype"),
            "same_window_rate": rate(subtype_rows, "same_window"),
            "same_pcap_rate": rate(subtype_rows, "same_pcap"),
            "same_endpoint_rate": rate(subtype_rows, "same_endpoint_service"),
        }
    return output


def subtype_table_items(summary: dict[str, Any]) -> list[dict[str, Any]]:
    per_subtype = summary.get("per_subtype", {})
    rows: list[dict[str, Any]] = []
    emitted: set[str] = set()
    for class_name, subtype in REQUESTED_SUBTYPE_ROWS:
        key = f"{class_name}|{subtype}"
        item = per_subtype.get(key)
        if item is None:
            item = {
                "class_name": class_name,
                "subtype": subtype,
                "display_subtype": SUBTYPE_DISPLAY_NAMES.get(subtype, subtype),
                "count": 0,
                "distance_median": None,
                "same_subtype_rate": None,
                "same_window_rate": None,
                "same_pcap_rate": None,
                "same_endpoint_rate": None,
            }
        rows.append(item)
        emitted.add(key)
    for key, item in sorted(per_subtype.items()):
        if key in emitted or item["class_name"] not in SUBTYPE_TABLE_CLASSES:
            continue
        rows.append(item)
    return rows


def format_metric(value: object) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.6f}"


def summarize_sample_groups(rows: list[dict[str, Any]], class_names: list[str]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for class_name in class_names:
        class_rows = [row for row in rows if str(row.get("class_name")) == class_name]
        output[class_name] = {
            "count": len(class_rows),
            "by_subtype": dict(sorted(Counter(subtype_name(row) for row in class_rows).items())),
            "by_day": dict(sorted(Counter(str(row.get("day", "")) for row in class_rows).items())),
            "by_pcap": dict(sorted(Counter(pcap_name(row) for row in class_rows).items())),
            "group_count": len({window_key(row) for row in class_rows}),
        }
    return output


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "val_candidate_identity",
        "train_candidate_identity",
        "val_class",
        "train_class",
        "val_subtype",
        "train_subtype",
        "val_day",
        "train_day",
        "val_pcap",
        "train_pcap",
        "cosine_distance",
        "cosine_similarity",
        "same_class",
        "same_subtype",
        "same_day",
        "same_window",
        "same_pcap",
        "same_endpoint_service",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    lines = [
        "# Office Compact Nearest-Neighbor Train/Validation Similarity Audit",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Compact manifest: `{report['compact_manifest_path']}`.",
        f"- Train sample size: `{report['train_sample_count']}`.",
        f"- Validation sample size: `{report['validation_sample_count']}`.",
        f"- Train cap per class: `{report['train_per_class']}`.",
        f"- Validation cap per class: `{report['val_per_class']}`.",
        f"- Sampling strategy: `{report['sampling_strategy']}`.",
        f"- Vector dimension: `{report['vector_dimension']}`.",
        f"- Median nearest-neighbor cosine distance: `{summary['distance_median']:.6f}`.",
        f"- 5th percentile nearest-neighbor cosine distance: `{summary['distance_p05']:.6f}`.",
        f"- Same-class nearest-neighbor rate: `{summary['same_class_rate']:.6f}`.",
        f"- Same-subtype nearest-neighbor rate: `{summary['same_subtype_rate']:.6f}`.",
        f"- Same-day nearest-neighbor rate: `{summary['same_day_rate']:.6f}`.",
        f"- Same-window nearest-neighbor rate: `{summary['same_window_rate']:.6f}`.",
        f"- Same-PCAP nearest-neighbor rate: `{summary['same_pcap_rate']:.6f}`.",
        f"- Same endpoint/service nearest-neighbor rate: `{summary['same_endpoint_service_rate']:.6f}`.",
        f"- Nearest distances <= 0.001: `{summary['distance_le_0_001']}`.",
        f"- Nearest distances <= 0.01: `{summary['distance_le_0_01']}`.",
        f"- Nearest distances <= 0.05: `{summary['distance_le_0_05']}`.",
        "",
        "## Per-Class Summary",
        "",
        "| Class | Count | Median dist | P95 dist | Same class | Same subtype | Same day | Same window | Same PCAP | Same endpoint/service |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for class_name, item in summary["per_class"].items():
        lines.append(
            f"| {class_name} | {item['count']} | {item['distance_median']:.6f} | {item['distance_p95']:.6f} | "
            f"{item['same_class_rate']:.6f} | {item['same_subtype_rate']:.6f} | {item['same_day_rate']:.6f} | "
            f"{item['same_window_rate']:.6f} | {item['same_pcap_rate']:.6f} | {item['same_endpoint_service_rate']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Per-Subtype Summary",
            "",
            "| Class | Subtype | Median NN distance | Same subtype | Same window | Same PCAP | Same endpoint |",
            "| ---------- | --------- | -----------------: | -----------: | ----------: | --------: | ------------: |",
        ]
    )
    for item in subtype_table_items(summary):
        lines.append(
            f"| {item['class_name']} | {item['display_subtype']} | "
            f"{format_metric(item['distance_median'])} | "
            f"{format_metric(item['same_subtype_rate'])} | "
            f"{format_metric(item['same_window_rate'])} | "
            f"{format_metric(item['same_pcap_rate'])} | "
            f"{format_metric(item['same_endpoint_rate'])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This is a sampled nearest-neighbor audit over compact graph-stat vectors. The vector mirrors the original PyG nearest-neighbor audit fields: graph size, flow feature stats, packet byte stats, contain edge stats, reverse-contain proxy stats, and packet-link edge stats.",
            "",
            "For records without explicit ground-truth window timestamps, `same_window` falls back to source dataset, day, class, subtype, and source PCAP.",
            "",
            "## Artifact Paths",
            "",
            f"- JSON: `{report['artifact_paths']['json']}`",
            f"- CSV: `{report['artifact_paths']['csv']}`",
            f"- Markdown: `{report['artifact_paths']['markdown']}`",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_compact_nearest_neighbor_similarity_audit(
    *,
    compact_manifest_path: Path = DEFAULT_CUMULATIVE_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    train_per_class: int = 5000,
    val_per_class: int = 500,
    seed: int = 42,
    n_neighbors: int = 5,
    sampling_strategy: str = "random",
) -> dict[str, Any]:
    manifest = load_json(compact_manifest_path)
    class_names = compact_manifest_class_names(manifest)
    root = compact_root(manifest)
    train_records = selected_records(
        manifest,
        "train",
        class_names,
        per_class=train_per_class,
        seed=seed,
        root=root,
        sampling_strategy=sampling_strategy,
    )
    val_records = selected_records(
        manifest,
        "val",
        class_names,
        per_class=val_per_class,
        seed=seed,
        root=root,
        sampling_strategy=sampling_strategy,
    )
    train_vectors, train_rows, missing_train = load_samples(train_records, root)
    val_vectors, val_rows, missing_val = load_samples(val_records, root)

    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_vectors).astype(np.float32)
    val_scaled = scaler.transform(val_vectors).astype(np.float32)
    train_scaled = np.nan_to_num(train_scaled, copy=False)
    val_scaled = np.nan_to_num(val_scaled, copy=False)

    neighbors = NearestNeighbors(
        n_neighbors=min(n_neighbors, train_scaled.shape[0]),
        metric="cosine",
        algorithm="brute",
        n_jobs=-1,
    )
    neighbors.fit(train_scaled)
    distances, indices = neighbors.kneighbors(val_scaled)
    rows = nearest_rows(train_rows=train_rows, val_rows=val_rows, distances=distances, indices=indices)
    summary = summarize_neighbors(rows, class_names)
    train_counts = Counter(str(row["class_name"]) for row in train_rows)
    val_counts = Counter(str(row["class_name"]) for row in val_rows)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "nearest_neighbor_similarity_compact_audit.json"
    csv_path = output_dir / "nearest_neighbor_similarity_compact_audit.csv"
    markdown_path = output_dir / "nearest_neighbor_similarity_compact_audit.md"
    report = {
        "pipeline": "office_compact_nearest_neighbor_train_validation_similarity",
        "generated_at": utc_now(),
        "compact_manifest_path": str(compact_manifest_path),
        "compact_manifest_hash": str(manifest.get("manifest_hash", "")),
        "class_names": class_names,
        "seed": int(seed),
        "sampling_strategy": sampling_strategy,
        "train_per_class": int(train_per_class),
        "val_per_class": int(val_per_class),
        "train_sample_count": len(train_rows),
        "validation_sample_count": len(val_rows),
        "train_sample_counts_by_class": {class_name: int(train_counts.get(class_name, 0)) for class_name in class_names},
        "validation_sample_counts_by_class": {class_name: int(val_counts.get(class_name, 0)) for class_name in class_names},
        "train_sample_group_summary": summarize_sample_groups(train_rows, class_names),
        "validation_sample_group_summary": summarize_sample_groups(val_rows, class_names),
        "vector_dimension": int(train_vectors.shape[1]),
        "n_neighbors": int(min(n_neighbors, train_scaled.shape[0])),
        "summary": summary,
        "nearest_neighbors": rows,
        "closest_validation_examples": sorted(rows, key=lambda row: row["cosine_distance"])[:50],
        "missing_compact_records": {
            "train": missing_train,
            "val": missing_val,
        },
        "artifact_paths": {
            "json": str(json_path),
            "csv": str(csv_path),
            "markdown": str(markdown_path),
        },
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_csv(csv_path, rows)
    write_markdown(markdown_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit nearest-neighbor similarity between train and validation compact office graphs."
    )
    parser.add_argument("--compact-manifest", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--train-per-class", type=int, default=5000)
    parser.add_argument("--val-per-class", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-neighbors", type=int, default=5)
    parser.add_argument("--sampling-strategy", choices=("random", "stratified"), default="random")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_compact_nearest_neighbor_similarity_audit(
        compact_manifest_path=args.compact_manifest,
        output_dir=args.output_dir,
        train_per_class=args.train_per_class,
        val_per_class=args.val_per_class,
        seed=args.seed,
        n_neighbors=args.n_neighbors,
        sampling_strategy=args.sampling_strategy,
    )
    print(
        json.dumps(
            {
                "pipeline": report["pipeline"],
                "generated_at": report["generated_at"],
                "train_sample_count": report["train_sample_count"],
                "validation_sample_count": report["validation_sample_count"],
                "sampling_strategy": report["sampling_strategy"],
                "vector_dimension": report["vector_dimension"],
                "summary": report["summary"],
                "artifact_paths": report["artifact_paths"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
