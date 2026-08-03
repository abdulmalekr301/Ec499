from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch

from secureedge import config as root_config
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import make_loader_kwargs, require_pyg_dataloader, training_device
from secureedge.office.final_training_manifest import DEFAULT_OUTPUT_PATH as DEFAULT_FINAL_MANIFEST_PATH
from secureedge.training.engine import (
    class_metrics,
    load_graph_dataset_from_manifest,
    load_json,
    manifest_class_names,
    maybe_mask_temporal_dataset,
    metadata_from_batches,
    predict_loader,
    subtype_recall_metrics,
    temporal_feature_indices_from_manifest,
)


DEFAULT_JSON_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_final_sanity_checks.json"
DEFAULT_REPORT_PATH = root_config.CONTEXT_DIR / "121_office_final_sanity_checks.md"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def tensor_hash(tensor: torch.Tensor) -> str:
    array = tensor.detach().cpu().contiguous().numpy()
    return hashlib.sha256(array.tobytes()).hexdigest()


def graph_flow_hash(graph: Any) -> str:
    flow_id_hash = str(getattr(graph, "flow_id_hash", "") or "")
    if flow_id_hash:
        return flow_id_hash
    return tensor_hash(graph["flow"].x)


def split_graph_records(manifest: dict[str, Any], split: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    metadata_by_path = manifest["splits"][split].get("metadata_by_path", {})
    for class_name, paths in manifest["splits"][split]["paths"].items():
        for path in paths:
            graph = torch.load(path, map_location="cpu", weights_only=False)
            metadata = metadata_by_path.get(path, {})
            records.append(
                {
                    "path": str(path),
                    "class_name": str(class_name),
                    "manifest_subtype": str(metadata.get("subtype", "")),
                    "graph_subtype": str(getattr(graph, "subtype_label", "")),
                    "manifest_candidate_identity": str(metadata.get("candidate_identity", "")),
                    "graph_candidate_identity": str(getattr(graph, "office_candidate_identity", "")),
                    "graph_id": str(getattr(graph, "graph_id", "")),
                    "flow_hash": graph_flow_hash(graph),
                    "group_key": str(metadata.get("group_key", "")),
                    "manifest_day": str(metadata.get("day", "")),
                    "graph_day": str(getattr(graph, "day", "")),
                    "manifest_source_file": str(metadata.get("pcap", "")),
                    "graph_source_file": str(getattr(graph, "source_file", "")),
                }
            )
    return records


def overlap_count(left: list[dict[str, str]], right: list[dict[str, str]], key: str) -> int:
    left_values = {row[key] for row in left if row.get(key)}
    right_values = {row[key] for row in right if row.get(key)}
    return len(left_values & right_values)


def overlap_audit(manifest: dict[str, Any]) -> dict[str, Any]:
    split_records = {split: split_graph_records(manifest, split) for split in ("train", "val", "test")}
    pairs = {
        "train_val": ("train", "val"),
        "train_test": ("train", "test"),
        "val_test": ("val", "test"),
    }
    pair_results: dict[str, dict[str, int]] = {}
    for pair_name, (left, right) in pairs.items():
        pair_results[pair_name] = {
            "graph_id_overlap": overlap_count(split_records[left], split_records[right], "graph_id"),
            "candidate_identity_overlap": overlap_count(
                split_records[left],
                split_records[right],
                "graph_candidate_identity",
            ),
            "flow_hash_overlap": overlap_count(split_records[left], split_records[right], "flow_hash"),
            "group_key_overlap": overlap_count(split_records[left], split_records[right], "group_key"),
        }
    metadata_mismatches = [
        {
            "split": split,
            "path": row["path"],
            "manifest_subtype": row["manifest_subtype"],
            "graph_subtype": row["graph_subtype"],
            "manifest_candidate_identity": row["manifest_candidate_identity"],
            "graph_candidate_identity": row["graph_candidate_identity"],
            "manifest_day": row["manifest_day"],
            "graph_day": row["graph_day"],
            "manifest_source_file": row["manifest_source_file"],
            "graph_source_file": row["graph_source_file"],
        }
        for split, rows in split_records.items()
        for row in rows
        if row["manifest_subtype"] != row["graph_subtype"]
        or row["manifest_candidate_identity"] != row["graph_candidate_identity"]
        or row["manifest_day"] != row["graph_day"]
    ]
    return {
        "split_counts": {split: len(rows) for split, rows in split_records.items()},
        "pairs": pair_results,
        "metadata_mismatch_count": len(metadata_mismatches),
        "metadata_mismatch_examples": metadata_mismatches[:20],
        "flow_hash_source": "graph.flow_id_hash with tensor content hash fallback",
    }


def untrained_validation_audit(manifest: dict[str, Any]) -> dict[str, Any]:
    class_names = manifest_class_names(manifest)
    DataLoader = require_pyg_dataloader()
    device = training_device()
    dataset = load_graph_dataset_from_manifest(manifest, "val", class_names)
    temporal_feature_indices = temporal_feature_indices_from_manifest(manifest)
    dataset = maybe_mask_temporal_dataset(dataset, manifest)
    loader = DataLoader(
        dataset,
        batch_size=root_config.EVAL_BATCH_SIZE,
        shuffle=False,
        **make_loader_kwargs(device),
    )
    torch.manual_seed(42)
    np.random.seed(42)
    model = SecureEdgeHGNN(num_classes=len(class_names)).to(device)
    predictions, targets, batches = predict_loader(model, loader, device)
    metadata = metadata_from_batches(batches)
    metrics = class_metrics(predictions, targets, class_names)
    return {
        "train_steps": 0,
        "epoch": 0,
        "device": str(device),
        "validation_count": int(targets.shape[0]),
        "temporal_features_masked": bool(temporal_feature_indices),
        "temporal_feature_count": len(temporal_feature_indices),
        "accuracy": float(metrics["accuracy"]),
        "macro_f1": float(metrics["macro_f1"]),
        "weighted_f1": float(metrics["weighted_f1"]),
        "per_class": metrics["per_class"],
        "per_subtype_recall": subtype_recall_metrics(predictions, targets, metadata, class_names),
        "prediction_counts": dict(Counter(class_names[int(index)] for index in predictions)),
    }


def ddos_trace(manifest: dict[str, Any]) -> dict[str, Any]:
    traces: list[dict[str, Any]] = []
    for path in manifest["splits"]["val"]["paths"].get("DDoS", [])[:12]:
        metadata = manifest["splits"]["val"]["metadata_by_path"][path]
        graph = torch.load(path, map_location="cpu", weights_only=False)
        traces.append(
            {
                "path": path,
                "manifest": {
                    "class_name": metadata.get("class_name"),
                    "subtype": metadata.get("subtype"),
                    "day": metadata.get("day"),
                    "source_file": metadata.get("pcap"),
                    "candidate_identity": metadata.get("candidate_identity"),
                },
                "graph": {
                    "class_name": str(getattr(graph, "class_name", "")),
                    "subtype": str(getattr(graph, "subtype_label", "")),
                    "day": str(getattr(graph, "day", "")),
                    "source_file": str(getattr(graph, "source_file", "")),
                    "candidate_identity": str(getattr(graph, "office_candidate_identity", "")),
                    "graph_id": str(getattr(graph, "graph_id", "")),
                },
            }
        )
    split_counts = {}
    for split in ("train", "val", "test"):
        split_counts[split] = dict(
            Counter(
                row["subtype"]
                for row in manifest["splits"][split].get("metadata_by_path", {}).values()
                if row.get("class_name") == "DDoS"
            )
        )
    return {
        "validation_ddos_trace_count": len(traces),
        "ddos_subtype_counts_by_split": split_counts,
        "trace_examples": traces,
    }


def markdown_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return lines


def write_report(path: Path, report: dict[str, Any]) -> None:
    untrained = report["untrained_validation"]
    overlap = report["final_manifest_overlap"]
    trace = report["ddos_metadata_trace"]
    lines = [
        "# Office Final Sanity Checks",
        "",
        f"Date: {report['generated_at']}",
        "",
        f"- Final manifest: `{report['final_manifest_path']}`",
        f"- Manifest hash: `{report['final_manifest_hash']}`",
        "",
        "## Epoch 0 Untrained Validation",
        "",
        f"- Train steps: `{untrained['train_steps']}`",
        f"- Validation graphs: `{untrained['validation_count']}`",
        f"- Accuracy: `{untrained['accuracy']:.6f}`",
        f"- Macro F1: `{untrained['macro_f1']:.6f}`",
        f"- Weighted F1: `{untrained['weighted_f1']:.6f}`",
        f"- Temporal features masked: `{untrained['temporal_features_masked']}`",
        "",
        "## Final Manifest Overlap",
        "",
    ]
    rows = []
    for pair_name, values in overlap["pairs"].items():
        rows.append(
            [
                pair_name.replace("_", " <-> "),
                values["graph_id_overlap"],
                values["candidate_identity_overlap"],
                values["flow_hash_overlap"],
                values["group_key_overlap"],
            ]
        )
    lines.extend(markdown_table(["Pair", "Graph ID", "Candidate Identity", "Flow Hash", "Group Key"], rows))
    lines.extend(
        [
            "",
            f"- Metadata mismatch count: `{overlap['metadata_mismatch_count']}`",
            f"- Flow hash source: `{overlap['flow_hash_source']}`",
            "",
            "## DDoS Metadata Trace",
            "",
        ]
    )
    lines.extend(["| Split | DDoS subtype | Count |", "| --- | --- | ---: |"])
    for split, counts in trace["ddos_subtype_counts_by_split"].items():
        for subtype, count in sorted(counts.items()):
            lines.append(f"| {split} | {subtype} | {count} |")
    lines.extend(["", "### Validation Trace Examples", ""])
    lines.extend(["| Manifest subtype | Graph subtype | Manifest day | Graph day | Identity match |", "| --- | --- | --- | --- | --- |"])
    for item in trace["trace_examples"]:
        manifest_item = item["manifest"]
        graph_item = item["graph"]
        lines.append(
            f"| {manifest_item['subtype']} | {graph_item['subtype']} | "
            f"{manifest_item['day']} | {graph_item['day']} | "
            f"{manifest_item['candidate_identity'] == graph_item['candidate_identity']} |"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_final_sanity_checks(
    *,
    final_manifest_path: Path = DEFAULT_FINAL_MANIFEST_PATH,
    json_path: Path = DEFAULT_JSON_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
) -> dict[str, Any]:
    manifest = load_json(final_manifest_path)
    report = {
        "pipeline": "office_final_sanity_checks",
        "generated_at": utc_now(),
        "final_manifest_path": str(final_manifest_path),
        "final_manifest_hash": manifest.get("manifest_hash"),
        "untrained_validation": untrained_validation_audit(manifest),
        "final_manifest_overlap": overlap_audit(manifest),
        "ddos_metadata_trace": ddos_trace(manifest),
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(report_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run mandatory final sanity checks for the Office robust manifest.")
    parser.add_argument("--final-manifest", type=Path, default=DEFAULT_FINAL_MANIFEST_PATH)
    parser.add_argument("--json-path", type=Path, default=DEFAULT_JSON_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_final_sanity_checks(
        final_manifest_path=args.final_manifest,
        json_path=args.json_path,
        report_path=args.report_path,
    )
    print(
        json.dumps(
            {
                "report": str(args.report_path),
                "json": str(args.json_path),
                "epoch0_macro_f1": report["untrained_validation"]["macro_f1"],
                "metadata_mismatch_count": report["final_manifest_overlap"]["metadata_mismatch_count"],
                "overlap_pairs": report["final_manifest_overlap"]["pairs"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
