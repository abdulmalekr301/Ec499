from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch

from secureedge import config
from secureedge.utils import write_context, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check whether packet node payload features contain non-zero bytes.")
    parser.add_argument("--source", choices=("graphs", "shards"), default="graphs")
    parser.add_argument("--split", choices=("train", "test"), default="train")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--per-class", action="store_true", help="Add per-class payload statistics.")
    return parser.parse_args()


def graph_paths(split: str, limit: int) -> list[Path]:
    graph_dir = config.GRAPH_TRAIN_DIR if split == "train" else config.GRAPH_TEST_DIR
    return sorted(graph_dir.glob("*.pt"))[:limit]


def shard_paths(split: str, limit: int) -> list[Path]:
    shard_dir = config.GRAPH_TRAIN_SHARD_DIR if split == "train" else config.GRAPH_TEST_SHARD_DIR
    return sorted(shard_dir.glob("shard_*.pt"))[:limit]


def packet_stats(graph) -> tuple[float, float, float]:
    packet_x = graph["packet"].x
    if packet_x.numel() == 0:
        return 0.0, 0.0, 0.0
    packet_x = packet_x.float()
    nonzero = packet_x != 0
    packet_rows_with_payload = nonzero.any(dim=1).float().mean().item()
    return float(packet_x.mean().item()), float(nonzero.float().mean().item()), float(packet_rows_with_payload)


def diagnose_graphs(split: str, limit: int) -> dict[str, object]:
    paths = graph_paths(split, limit)
    means = []
    nonzero_fracs = []
    row_nonzero_fracs = []
    class_values: dict[str, dict[str, list[float]]] = {
        class_name: {"means": [], "nonzero_fracs": [], "row_nonzero_fracs": []}
        for class_name in config.CLASS_NAMES
    }
    for path in paths:
        graph = torch.load(path, map_location="cpu", weights_only=False)
        mean_value, nonzero_frac, row_nonzero_frac = packet_stats(graph)
        means.append(mean_value)
        nonzero_fracs.append(nonzero_frac)
        row_nonzero_fracs.append(row_nonzero_frac)
        class_name = graph_class_name(graph)
        class_values[class_name]["means"].append(mean_value)
        class_values[class_name]["nonzero_fracs"].append(nonzero_frac)
        class_values[class_name]["row_nonzero_fracs"].append(row_nonzero_frac)
    return summarize(
        means,
        nonzero_fracs,
        row_nonzero_fracs,
        source="graphs",
        split=split,
        files_examined=len(paths),
        per_class=class_values,
    )


def diagnose_shards(split: str, limit: int) -> dict[str, object]:
    paths = shard_paths(split, limit)
    means = []
    nonzero_fracs = []
    row_nonzero_fracs = []
    class_values: dict[str, dict[str, list[float]]] = {
        class_name: {"means": [], "nonzero_fracs": [], "row_nonzero_fracs": []}
        for class_name in config.CLASS_NAMES
    }
    graph_count = 0
    for path in paths:
        graphs = torch.load(path, map_location="cpu", weights_only=False)
        for graph in graphs:
            mean_value, nonzero_frac, row_nonzero_frac = packet_stats(graph)
            means.append(mean_value)
            nonzero_fracs.append(nonzero_frac)
            row_nonzero_fracs.append(row_nonzero_frac)
            class_name = graph_class_name(graph)
            class_values[class_name]["means"].append(mean_value)
            class_values[class_name]["nonzero_fracs"].append(nonzero_frac)
            class_values[class_name]["row_nonzero_fracs"].append(row_nonzero_frac)
            graph_count += 1
    return summarize(
        means,
        nonzero_fracs,
        row_nonzero_fracs,
        source="shards",
        split=split,
        files_examined=len(paths),
        graph_count=graph_count,
        per_class=class_values,
    )


def summarize(
    means: list[float],
    nonzero_fracs: list[float],
    row_nonzero_fracs: list[float],
    source: str,
    split: str,
    files_examined: int,
    graph_count: int | None = None,
    per_class: dict[str, dict[str, list[float]]] | None = None,
) -> dict[str, object]:
    if not means:
        raise ValueError(f"No graphs found for source={source}, split={split}")
    values = np.asarray(means, dtype=np.float64)
    nonzero_values = np.asarray(nonzero_fracs, dtype=np.float64)
    row_nonzero_values = np.asarray(row_nonzero_fracs, dtype=np.float64)
    result = {
        "source": source,
        "split": split,
        "files_examined": files_examined,
        "graphs_examined": int(graph_count if graph_count is not None else len(means)),
        "mean_packet_node_feature_value": float(values.mean()),
        "min_packet_node_feature_value": float(values.min()),
        "max_packet_node_feature_value": float(values.max()),
        "mean_nonzero_fraction": float(nonzero_values.mean()),
        "min_nonzero_fraction": float(nonzero_values.min()),
        "max_nonzero_fraction": float(nonzero_values.max()),
        "mean_packet_rows_with_any_payload_fraction": float(row_nonzero_values.mean()),
        "min_packet_rows_with_any_payload_fraction": float(row_nonzero_values.min()),
        "max_packet_rows_with_any_payload_fraction": float(row_nonzero_values.max()),
        "zero_mean_graphs": int(np.sum(values == 0.0)),
        "nonzero_mean_graphs": int(np.sum(values > 0.0)),
        "graphs_with_any_payload": int(np.sum(row_nonzero_values > 0.0)),
        "graphs_without_any_payload": int(np.sum(row_nonzero_values == 0.0)),
    }
    if result["mean_nonzero_fraction"] < 0.10:
        result["interpretation"] = "payloads appear to be all or nearly all zeros; fix PacketCapture before retraining"
    elif result["mean_nonzero_fraction"] < 0.80:
        result["interpretation"] = "packet features are non-zero but sparse; inspect payload extraction quality before assuming payloads are fully informative"
    else:
        result["interpretation"] = "packet node features are dense and non-zero; payloads appear informative"
    if per_class is not None:
        result["per_class"] = summarize_per_class(per_class)
    return result


def graph_class_name(graph) -> str:
    class_name = str(getattr(graph, "class_name", ""))
    if class_name:
        return class_name
    return config.CLASS_NAMES[int(graph.y.view(-1)[0].item())]


def summarize_per_class(per_class: dict[str, dict[str, list[float]]]) -> dict[str, dict[str, float | int | str]]:
    summary: dict[str, dict[str, float | int | str]] = {}
    for class_name in config.CLASS_NAMES:
        values = per_class[class_name]
        means = np.asarray(values["means"], dtype=np.float64)
        nonzero = np.asarray(values["nonzero_fracs"], dtype=np.float64)
        rows = np.asarray(values["row_nonzero_fracs"], dtype=np.float64)
        if means.size == 0:
            summary[class_name] = {
                "graphs_examined": 0,
                "mean_packet_node_feature_value": 0.0,
                "mean_nonzero_fraction": 0.0,
                "mean_packet_rows_with_any_payload_fraction": 0.0,
                "payload_gate": "no samples examined",
            }
            continue
        payload_gate = "adequate for payload-heavy class"
        if class_name in {"WebBased", "BruteForce"} and float(means.mean()) < 0.10:
            payload_gate = "below 0.10 payload-heavy class gate; inspect PacketCapture before round-4 training"
        summary[class_name] = {
            "graphs_examined": int(means.size),
            "mean_packet_node_feature_value": float(means.mean()),
            "mean_nonzero_fraction": float(nonzero.mean()),
            "mean_packet_rows_with_any_payload_fraction": float(rows.mean()),
            "zero_mean_graphs": int(np.sum(means == 0.0)),
            "payload_gate": payload_gate,
        }
    return summary


def main() -> None:
    args = parse_args()
    result = diagnose_shards(args.split, args.limit) if args.source == "shards" else diagnose_graphs(args.split, args.limit)
    if not args.per_class:
        result.pop("per_class", None)
    output_path = config.ARTIFACTS_DIR / f"payload_diagnostic_{args.source}_{args.split}.json"
    write_json(output_path, result)
    write_context(
        f"payload-diagnostic-{args.source}-{args.split}.md",
        "Payload Quality Diagnostic",
        [
            "## Result",
            "```json",
            json.dumps(result, indent=2),
            "```",
            "",
            f"- Saved machine-readable output to `{output_path}`.",
        ],
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
