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
import torch
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from secureedge import config as root_config
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.grouped_window_audit import DEFAULT_SPLIT_DIR, graph_identity_from_path, group_key, load_split_candidates
from secureedge.office.holdout_group_audit import pcap_name, scope_key
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "nearest_neighbor_similarity"


def selected_paths(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    per_class: int,
    seed: int,
) -> list[str]:
    rng = random.Random(seed + (0 if split == "train" else 1009))
    paths: list[str] = []
    paths_by_class = manifest["splits"][split]["paths"]
    for class_name in class_names:
        class_paths = list(paths_by_class.get(class_name, []))
        rng.shuffle(class_paths)
        if per_class > 0:
            class_paths = class_paths[:per_class]
        paths.extend(class_paths)
    return paths


def tensor_stats(tensor: torch.Tensor, *, include_features: bool = False) -> list[float]:
    if tensor.numel() == 0:
        return [0.0] * (4 + (int(tensor.shape[-1]) if include_features and tensor.ndim >= 2 else 0))
    values = tensor.detach().float().cpu()
    flat = values.reshape(-1)
    stats = [
        float(flat.mean()),
        float(flat.std(unbiased=False)),
        float(flat.min()),
        float(flat.max()),
    ]
    if include_features:
        if values.ndim == 1:
            stats.extend(float(item) for item in values.tolist())
        else:
            stats.extend(float(item) for item in values.mean(dim=0).tolist())
    return stats


def graph_vector(graph: Any) -> np.ndarray:
    flow_x = graph.x_dict["flow"].detach().float().cpu()
    packet_x = graph.x_dict["packet"].detach().float().cpu()
    contain_key = ("flow", "contains", "packet")
    rev_key = ("packet", "rev_contains", "flow")
    link_key = ("packet", "linked_to", "packet")
    contain_attr = graph.edge_attr_dict.get(contain_key, torch.empty((0, 4)))
    rev_attr = graph.edge_attr_dict.get(rev_key, torch.empty((0, 4)))
    link_attr = graph.edge_attr_dict.get(link_key, torch.empty((0, 1)))
    values: list[float] = [
        float(flow_x.shape[0]),
        float(packet_x.shape[0]),
        float(graph.edge_index_dict.get(contain_key, torch.empty((2, 0))).shape[1]),
        float(graph.edge_index_dict.get(rev_key, torch.empty((2, 0))).shape[1]),
        float(graph.edge_index_dict.get(link_key, torch.empty((2, 0))).shape[1]),
    ]
    values.extend(tensor_stats(flow_x, include_features=True))
    values.extend(tensor_stats(packet_x, include_features=False))
    values.extend(tensor_stats(contain_attr, include_features=True))
    values.extend(tensor_stats(rev_attr, include_features=True))
    values.extend(tensor_stats(link_attr, include_features=True))
    return np.asarray(values, dtype=np.float32)


def load_samples(
    paths: list[str],
    candidate_by_identity: dict[str, dict[str, Any]],
) -> tuple[np.ndarray, list[dict[str, Any]], list[dict[str, str]]]:
    vectors: list[np.ndarray] = []
    rows: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    for path in paths:
        graph = torch.load(path, map_location="cpu", weights_only=False)
        identity = str(getattr(graph, "office_candidate_identity", ""))
        if not identity:
            identity = graph_identity_from_path(path)
        candidate = candidate_by_identity.get(identity)
        if candidate is None:
            missing.append({"path": str(path), "candidate_identity": identity})
            continue
        vectors.append(graph_vector(graph))
        rows.append({"path": str(path), "candidate_identity": identity, **candidate})
    return np.vstack(vectors).astype(np.float32), rows, missing


def same_window(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return group_key(left) == group_key(right)


def same_endpoint_service(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return scope_key(left, "endpoint_service") == scope_key(right, "endpoint_service")


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
                "val_candidate_identity": val_row["candidate_identity"],
                "train_candidate_identity": train_row["candidate_identity"],
                "val_class": val_row["class_name"],
                "train_class": train_row["class_name"],
                "val_day": val_row.get("day", ""),
                "train_day": train_row.get("day", ""),
                "val_pcap": pcap_name(val_row.get("endpoint_pcap")),
                "train_pcap": pcap_name(train_row.get("endpoint_pcap")),
                "cosine_distance": distance,
                "cosine_similarity": float(1.0 - distance),
                "same_class": bool(val_row["class_name"] == train_row["class_name"]),
                "same_day": bool(val_row.get("day") == train_row.get("day")),
                "same_window": bool(same_window(val_row, train_row)),
                "same_pcap": bool(pcap_name(val_row.get("endpoint_pcap")) == pcap_name(train_row.get("endpoint_pcap"))),
                "same_endpoint_service": bool(same_endpoint_service(val_row, train_row)),
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
            "same_day_rate": rate(class_rows, "same_day"),
            "same_window_rate": rate(class_rows, "same_window"),
            "same_pcap_rate": rate(class_rows, "same_pcap"),
            "same_endpoint_service_rate": rate(class_rows, "same_endpoint_service"),
        }
    summary["per_class"] = per_class
    return summary


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "val_candidate_identity",
        "train_candidate_identity",
        "val_class",
        "train_class",
        "val_day",
        "train_day",
        "val_pcap",
        "train_pcap",
        "cosine_distance",
        "cosine_similarity",
        "same_class",
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
        "# Office Nearest-Neighbor Train/Validation Similarity Audit",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Train sample size: `{report['train_sample_count']}`.",
        f"- Validation sample size: `{report['validation_sample_count']}`.",
        f"- Train cap per class: `{report['train_per_class']}`.",
        f"- Validation cap per class: `{report['val_per_class']}`.",
        f"- Vector dimension: `{report['vector_dimension']}`.",
        f"- Median nearest-neighbor cosine distance: `{summary['distance_median']:.6f}`.",
        f"- 5th percentile nearest-neighbor cosine distance: `{summary['distance_p05']:.6f}`.",
        f"- Same-class nearest-neighbor rate: `{summary['same_class_rate']:.6f}`.",
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
        "| Class | Count | Median dist | P95 dist | Same class | Same day | Same window | Same PCAP | Same endpoint/service |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for class_name, item in summary["per_class"].items():
        lines.append(
            f"| {class_name} | {item['count']} | {item['distance_median']:.6f} | {item['distance_p95']:.6f} | "
            f"{item['same_class_rate']:.6f} | {item['same_day_rate']:.6f} | {item['same_window_rate']:.6f} | "
            f"{item['same_pcap_rate']:.6f} | {item['same_endpoint_service_rate']:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This is a sampled nearest-neighbor audit over compact graph-stat vectors, not an exact duplicate check and not a learned embedding analysis.",
            "",
            "High same-class, same-day, or same-window nearest-neighbor rates indicate that validation graphs are close to training graphs under traffic-shape features even when exact graph duplicates are absent.",
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


def run_nearest_neighbor_similarity_audit(
    *,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    split_dir: Path = DEFAULT_SPLIT_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    train_per_class: int = 5000,
    val_per_class: int = 500,
    seed: int = 42,
    n_neighbors: int = 5,
) -> dict[str, Any]:
    manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(manifest)
    candidate_by_identity = load_split_candidates(split_dir)
    train_paths = selected_paths(manifest, "train", class_names, per_class=train_per_class, seed=seed)
    val_paths = selected_paths(manifest, "val", class_names, per_class=val_per_class, seed=seed)
    train_vectors, train_rows, missing_train = load_samples(train_paths, candidate_by_identity)
    val_vectors, val_rows, missing_val = load_samples(val_paths, candidate_by_identity)
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
    json_path = output_dir / "nearest_neighbor_similarity_audit.json"
    csv_path = output_dir / "nearest_neighbor_similarity_audit.csv"
    markdown_path = output_dir / "nearest_neighbor_similarity_audit.md"
    report = {
        "pipeline": "office_nearest_neighbor_train_validation_similarity",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "candidate_split_dir": str(split_dir),
        "class_names": class_names,
        "seed": int(seed),
        "train_per_class": int(train_per_class),
        "val_per_class": int(val_per_class),
        "train_sample_count": len(train_rows),
        "validation_sample_count": len(val_rows),
        "train_sample_counts_by_class": {class_name: int(train_counts.get(class_name, 0)) for class_name in class_names},
        "validation_sample_counts_by_class": {class_name: int(val_counts.get(class_name, 0)) for class_name in class_names},
        "vector_dimension": int(train_vectors.shape[1]),
        "n_neighbors": int(min(n_neighbors, train_scaled.shape[0])),
        "summary": summary,
        "nearest_neighbors": rows,
        "closest_validation_examples": sorted(rows, key=lambda row: row["cosine_distance"])[:50],
        "missing_candidate_metadata": {
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
    parser = argparse.ArgumentParser(description="Audit nearest-neighbor similarity between office train and validation graphs.")
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--split-dir", type=Path, default=DEFAULT_SPLIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--train-per-class", type=int, default=5000)
    parser.add_argument("--val-per-class", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-neighbors", type=int, default=5)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_nearest_neighbor_similarity_audit(
        graph_manifest_path=args.graph_manifest,
        split_dir=args.split_dir,
        output_dir=args.output_dir,
        train_per_class=args.train_per_class,
        val_per_class=args.val_per_class,
        seed=args.seed,
        n_neighbors=args.n_neighbors,
    )
    print(
        json.dumps(
            {
                "pipeline": report["pipeline"],
                "generated_at": report["generated_at"],
                "train_sample_count": report["train_sample_count"],
                "validation_sample_count": report["validation_sample_count"],
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
