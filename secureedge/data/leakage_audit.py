from __future__ import annotations

import argparse
import hashlib
import json
import pickle
from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np
import torch

from secureedge import config
from secureedge.utils import ensure_directories

IDENTITY_COLUMNS = {
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "src_oui",
    "dst_oui",
    "flow_id",
    "device_id",
    "capture_id",
    "file_id",
    "attack_file",
    "pcap_path",
    "pcap_file",
    "filename",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit SecureEdge graph splits for leakage.")
    parser.add_argument("--compact-manifest", type=Path, default=config.COMPACT_RESERVOIR_MANIFEST_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=config.GRAPH_MANIFEST_PATH)
    parser.add_argument("--shard-manifest", type=Path, default=config.GRAPH_SHARD_MANIFEST_PATH)
    parser.add_argument("--report", type=Path, default=config.ARTIFACTS_DIR / "training_runs" / "run_14_leakage_audit.md")
    parser.add_argument("--near-decimals", type=int, default=4)
    return parser.parse_args()


def read_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def tensor_bytes(value: object) -> bytes:
    if value is None:
        return b"<NONE>"
    if isinstance(value, torch.Tensor):
        return value.detach().cpu().contiguous().numpy().tobytes()
    return str(value).encode("utf-8")


def graph_hash(data) -> str:
    h = hashlib.sha256()
    h.update(tensor_bytes(data["flow"].x))
    h.update(tensor_bytes(data["packet"].x))
    for edge_type in sorted(data.edge_types):
        h.update(str(edge_type).encode("utf-8"))
        h.update(tensor_bytes(data[edge_type].edge_index))
        h.update(tensor_bytes(getattr(data[edge_type], "edge_attr", None)))
    h.update(tensor_bytes(data.y))
    return h.hexdigest()


def rounded_graph_fingerprint(data, decimals: int) -> str:
    flow = data["flow"].x.detach().cpu().numpy().round(decimals)
    packet = data["packet"].x.detach().cpu().numpy().round(decimals)
    summary = {
        "flow": flow.tolist(),
        "packet_mean": packet.mean(axis=0).round(decimals).tolist(),
        "packet_std": packet.std(axis=0).round(decimals).tolist(),
        "num_packets": int(packet.shape[0]),
        "label": int(data.y.item()),
    }
    return hashlib.sha256(json.dumps(summary, sort_keys=True).encode("utf-8")).hexdigest()


def compact_row_hash(path: str | Path) -> str:
    with Path(path).open("rb") as handle:
        record = pickle.load(handle)
    h = hashlib.sha256()
    h.update(np.asarray(record["flow_x"], dtype=np.float32).tobytes())
    h.update(np.asarray(record["packet_x_uint8"], dtype=np.uint8).tobytes())
    h.update(np.asarray(record["contain_edge_attr"], dtype=np.float32).tobytes())
    h.update(np.asarray(record["link_edge_attr"], dtype=np.float32).tobytes())
    h.update(str(record["label"]).encode("utf-8"))
    return h.hexdigest()


def split_paths_from_compact(manifest: dict, split: str) -> list[str]:
    return list(manifest["splits"].get(split, {}).get("paths", []))


def split_shards(shard_manifest: dict, split: str) -> list[dict]:
    return list(shard_manifest["splits"].get(split, {}).get("shards", []))


def load_shard(path: str | Path) -> list:
    graphs = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(graphs, list):
        raise TypeError(f"Expected {path} to contain a list of graphs.")
    return graphs


def hash_graph_split(shards: Iterable[dict], decimals: int) -> tuple[set[str], set[str], Counter[str], Counter[str]]:
    exact: set[str] = set()
    near: set[str] = set()
    class_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    for entry in shards:
        graphs = load_shard(entry["path"])
        for graph in graphs:
            exact.add(graph_hash(graph))
            near.add(rounded_graph_fingerprint(graph, decimals))
            class_counts[str(getattr(graph, "class_name", ""))] += 1
            source_counts[str(getattr(graph, "source_file", ""))] += 1
        del graphs
    return exact, near, class_counts, source_counts


def compact_hash_split(paths: Iterable[str]) -> set[str]:
    return {compact_row_hash(path) for path in paths}


def overlap_count(left: set[str], right: set[str]) -> int:
    return len(left & right)


def write_report(path: Path, results: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Run 14 Leakage Audit",
        "",
        "## Summary",
        "",
        "```json",
        json.dumps(results["summary"], indent=2),
        "```",
        "",
        "## Class Counts",
        "",
        "```json",
        json.dumps(results["class_counts"], indent=2),
        "```",
        "",
        "## Source PCAP Overlap",
        "",
        "Source overlap is reported for harder-split analysis. It is not treated as leakage unless the exact records/graphs overlap.",
        "",
        "```json",
        json.dumps(results["source_overlap"], indent=2),
        "```",
        "",
        "## Scaler Fit Source",
        "",
        "```json",
        json.dumps(results["scaler_fit_source"], indent=2),
        "```",
        "",
        "## Identity Feature Check",
        "",
        "```json",
        json.dumps(results["identity_feature_check"], indent=2),
        "```",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def audit(args: argparse.Namespace) -> dict[str, object]:
    ensure_directories()
    compact_manifest = read_json(args.compact_manifest)
    graph_manifest = read_json(args.graph_manifest)
    shard_manifest = read_json(args.shard_manifest)

    compact_hashes = {
        split: compact_hash_split(split_paths_from_compact(compact_manifest, split))
        for split in ("train", "val", "test")
    }
    graph_hashes: dict[str, set[str]] = {}
    near_hashes: dict[str, set[str]] = {}
    class_counts: dict[str, dict[str, int]] = {}
    source_counts: dict[str, Counter[str]] = {}
    for split in ("train", "val", "test"):
        exact, near, counts, sources = hash_graph_split(split_shards(shard_manifest, split), args.near_decimals)
        graph_hashes[split] = exact
        near_hashes[split] = near
        class_counts[split] = dict(counts)
        source_counts[split] = sources

    feature_names = set(str(name) for name in graph_manifest.get("flow_feature_names", []))
    leaked_features = sorted(feature_names & IDENTITY_COLUMNS)
    scaler_fit_source = dict(graph_manifest.get("scaler_fit_source", {}))
    expected_scalers = {
        "flow_scaler_fit_split": "train",
        "contain_edge_scaler_fit_split": "train",
        "link_delta_normalizer_fit_split": "train",
    }

    duplicate_compact = {
        "train_val": overlap_count(compact_hashes["train"], compact_hashes["val"]),
        "train_test": overlap_count(compact_hashes["train"], compact_hashes["test"]),
        "val_test": overlap_count(compact_hashes["val"], compact_hashes["test"]),
    }
    duplicate_graphs = {
        "train_val": overlap_count(graph_hashes["train"], graph_hashes["val"]),
        "train_test": overlap_count(graph_hashes["train"], graph_hashes["test"]),
        "val_test": overlap_count(graph_hashes["val"], graph_hashes["test"]),
    }
    near_duplicate_graphs = {
        "train_val": overlap_count(near_hashes["train"], near_hashes["val"]),
        "train_test": overlap_count(near_hashes["train"], near_hashes["test"]),
        "val_test": overlap_count(near_hashes["val"], near_hashes["test"]),
    }
    source_overlap = {
        "train_val": len(set(source_counts["train"]) & set(source_counts["val"])),
        "train_test": len(set(source_counts["train"]) & set(source_counts["test"])),
        "val_test": len(set(source_counts["val"]) & set(source_counts["test"])),
    }

    summary = {
        "split_strategy": compact_manifest.get("split_strategy"),
        "compact_counts": {split: compact_manifest["splits"][split]["count"] for split in ("train", "val", "test")},
        "graph_counts": {split: graph_manifest["splits"][split]["count"] for split in ("train", "val", "test")},
        "duplicate_compact_rows": duplicate_compact,
        "duplicate_graph_hashes": duplicate_graphs,
        "near_duplicate_graph_fingerprints": near_duplicate_graphs,
        "leaked_identity_features": leaked_features,
        "scalers_fit_on_train_only": scaler_fit_source == expected_scalers,
    }
    results = {
        "summary": summary,
        "class_counts": class_counts,
        "source_overlap": source_overlap,
        "scaler_fit_source": scaler_fit_source,
        "identity_feature_check": {
            "identity_columns_checked": sorted(IDENTITY_COLUMNS),
            "leaked_features": leaked_features,
        },
    }

    assert all(value == 0 for value in duplicate_compact.values()), "Cross-split duplicate compact rows detected."
    assert all(value == 0 for value in duplicate_graphs.values()), "Cross-split duplicate graph hashes detected."
    assert not leaked_features, f"Identity columns leaked into model features: {leaked_features}"
    assert scaler_fit_source == expected_scalers, "Scalers were not recorded as fit on train only."
    write_report(args.report, results)
    return results


def main() -> None:
    args = parse_args()
    results = audit(args)
    print(json.dumps({"report": str(args.report), "summary": results["summary"]}, indent=2))


if __name__ == "__main__":
    main()
