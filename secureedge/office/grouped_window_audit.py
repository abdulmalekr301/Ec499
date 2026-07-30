from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch

from secureedge import config as root_config
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import make_loader_kwargs, require_pyg_dataloader, training_device
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.train import DEFAULT_OFFICE_CHECKPOINT_PATH
from secureedge.training.engine import (
    class_metrics,
    load_graph_dataset_from_manifest,
    load_json,
    manifest_class_names,
    predict_loader,
)


DEFAULT_SPLIT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "final_candidate_splits"
DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "grouped_window"


def candidate_identity(candidate: dict[str, Any]) -> str:
    source_dataset = str(candidate.get("source_dataset", candidate.get("source", "")))
    return f"{source_dataset}|{candidate.get('day', '')}|{candidate.get('flow_hash', '')}"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def load_split_candidates(split_dir: Path) -> dict[str, dict[str, Any]]:
    records_by_identity: dict[str, dict[str, Any]] = {}
    for split in ("train_real", "val", "test"):
        path = split_dir / f"{split}.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"Candidate split file not found: {path}")
        for candidate in read_jsonl(path):
            identity = candidate_identity(candidate)
            item = dict(candidate)
            item["candidate_identity"] = identity
            records_by_identity.setdefault(identity, item)
    return records_by_identity


def group_key(candidate: dict[str, Any]) -> str:
    source_dataset = str(candidate.get("source_dataset", candidate.get("source", "unknown")) or "unknown")
    day = str(candidate.get("day", "unknown") or "unknown")
    class_name = str(candidate.get("class_name", "unknown") or "unknown")
    subtype = str(candidate.get("gt_subtype") or candidate.get("label") or "no_subtype")
    window_start = str(candidate.get("gt_window_start") or "")
    window_finish = str(candidate.get("gt_window_finish") or "")
    if not window_start and not window_finish:
        subtype = "no_attack_window"
        window_start = "none"
        window_finish = "none"
    return "|".join([source_dataset, day, class_name, subtype, window_start, window_finish])


def group_label_from_key(key: str) -> dict[str, str]:
    source_dataset, day, class_name, subtype, window_start, window_finish = key.split("|", maxsplit=5)
    return {
        "source_dataset": source_dataset,
        "day": day,
        "class_name": class_name,
        "subtype": subtype,
        "window_start": window_start,
        "window_finish": window_finish,
    }


def graph_identity_from_path(path: str | Path) -> str:
    graph = torch.load(path, map_location="cpu", weights_only=False)
    return str(getattr(graph, "office_candidate_identity", ""))


def split_group_counts(
    manifest: dict[str, Any],
    class_names: list[str],
    candidate_by_identity: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, int]], list[dict[str, str]]]:
    counts: dict[str, Counter[str]] = {split: Counter() for split in ("train", "val", "test")}
    missing: list[dict[str, str]] = []
    for split in ("train", "val", "test"):
        paths_by_class = manifest["splits"][split]["paths"]
        for class_name in class_names:
            for path in paths_by_class.get(class_name, []):
                identity = graph_identity_from_path(path)
                candidate = candidate_by_identity.get(identity)
                if candidate is None:
                    missing.append({"split": split, "class_name": class_name, "path": str(path), "candidate_identity": identity})
                    continue
                counts[split][group_key(candidate)] += 1
    return {split: dict(sorted(counter.items())) for split, counter in counts.items()}, missing


def metadata_from_batches(
    batches: list[Any],
    candidate_by_identity: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for batch in batches:
        count = int(batch.y.view(-1).shape[0])
        identities = getattr(batch, "office_candidate_identity", [""] * count)
        if not isinstance(identities, list | tuple):
            identities = [identities for _ in range(count)]
        for identity in identities:
            identity_text = str(identity)
            candidate = candidate_by_identity.get(identity_text)
            if candidate is None:
                rows.append({"candidate_identity": identity_text, "group_key": "missing|missing|missing|missing|missing|missing"})
            else:
                rows.append({"candidate_identity": identity_text, "group_key": group_key(candidate), **candidate})
    return rows


def metrics_by_group(
    predictions: np.ndarray,
    targets: np.ndarray,
    metadata: list[dict[str, Any]],
    class_names: list[str],
) -> dict[str, dict[str, Any]]:
    by_group: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(metadata):
        by_group[str(row["group_key"])].append(index)
    output: dict[str, dict[str, Any]] = {}
    for key, indices in sorted(by_group.items()):
        index_array = np.asarray(indices, dtype=np.int64)
        group_metrics = class_metrics(predictions[index_array], targets[index_array], class_names)
        label = group_label_from_key(key)
        output[key] = {
            **label,
            "support": int(len(indices)),
            "accuracy": float(group_metrics["accuracy"]),
            "macro_f1": float(group_metrics["macro_f1"]),
            "weighted_f1": float(group_metrics["weighted_f1"]),
            "per_class": group_metrics["per_class"],
            "confusion_matrix": group_metrics["confusion_matrix"],
        }
    return output


def write_group_csv(path: Path, group_metrics: dict[str, dict[str, Any]], split_counts: dict[str, dict[str, int]]) -> None:
    fieldnames = [
        "group_key",
        "source_dataset",
        "day",
        "class_name",
        "subtype",
        "window_start",
        "window_finish",
        "train_count",
        "val_count",
        "test_count",
        "validation_support",
        "validation_accuracy",
        "validation_macro_f1",
        "validation_weighted_f1",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for key, metrics in group_metrics.items():
            writer.writerow(
                {
                    "group_key": key,
                    "source_dataset": metrics["source_dataset"],
                    "day": metrics["day"],
                    "class_name": metrics["class_name"],
                    "subtype": metrics["subtype"],
                    "window_start": metrics["window_start"],
                    "window_finish": metrics["window_finish"],
                    "train_count": split_counts["train"].get(key, 0),
                    "val_count": split_counts["val"].get(key, 0),
                    "test_count": split_counts["test"].get(key, 0),
                    "validation_support": metrics["support"],
                    "validation_accuracy": metrics["accuracy"],
                    "validation_macro_f1": metrics["macro_f1"],
                    "validation_weighted_f1": metrics["weighted_f1"],
                }
            )


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    group_metrics = report["validation_metrics_by_group"]
    split_counts = report["split_group_counts"]
    rows = []
    for key, metrics in sorted(group_metrics.items(), key=lambda item: (-item[1]["support"], item[0])):
        rows.append(
            [
                metrics["class_name"],
                metrics["day"],
                metrics["subtype"],
                metrics["window_start"],
                split_counts["train"].get(key, 0),
                split_counts["val"].get(key, 0),
                split_counts["test"].get(key, 0),
                metrics["support"],
                f"{metrics['accuracy']:.6f}",
                f"{metrics['macro_f1']:.6f}",
                f"{metrics['weighted_f1']:.6f}",
            ]
        )
    lines = [
        "# Office Grouped Validation By Attack Window",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Validation groups evaluated: `{len(group_metrics)}`.",
        f"- Validation groups also present in train: `{report['overlap_summary']['val_groups_present_in_train']}`.",
        f"- Validation groups absent from train: `{report['overlap_summary']['val_groups_absent_from_train']}`.",
        f"- Candidate metadata misses: `{len(report['missing_candidate_metadata'])}`.",
        f"- Overall validation macro-F1: `{report['overall_validation_metrics']['macro_f1']:.6f}`.",
        f"- Overall validation weighted-F1: `{report['overall_validation_metrics']['weighted_f1']:.6f}`.",
        "",
        "## Grouped Results",
        "",
        "| Class | Day | Window/Subtype | Window start | Train | Val | Test | Val support | Val accuracy | Val macro-F1 | Val weighted-F1 |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(value) for value in row) + " |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This audit is not a leave-one-window-out experiment. It evaluates the current trained checkpoint and reports whether validation windows are also represented in train.",
            "",
            "If most validation groups are present in train, the current validation score is not a strict window-held-out generalization estimate.",
            "",
            "Per-group macro-F1 is computed on the labels present or predicted inside that isolated group, so a single cross-class error in a one-class group can reduce macro-F1 to roughly 0.5. Use the group accuracy, weighted-F1, and confusion details for the clearest per-window read.",
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


def run_grouped_window_audit(
    *,
    checkpoint_path: Path = DEFAULT_OFFICE_CHECKPOINT_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    split_dir: Path = DEFAULT_SPLIT_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(manifest)
    candidate_by_identity = load_split_candidates(split_dir)
    split_counts, missing = split_group_counts(manifest, class_names, candidate_by_identity)

    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    checkpoint_classes = [str(item) for item in checkpoint["class_names"]]
    if checkpoint_classes != class_names:
        raise ValueError(f"Checkpoint class order does not match manifest: {checkpoint_classes} != {class_names}")

    DataLoader = require_pyg_dataloader()
    device = training_device()
    dataset = load_graph_dataset_from_manifest(manifest, "val", class_names, limit_per_class=root_config.EVAL_LIMIT_PER_CLASS)
    loader = DataLoader(dataset, batch_size=root_config.EVAL_BATCH_SIZE, shuffle=False, **make_loader_kwargs(device))
    model = SecureEdgeHGNN(num_classes=len(class_names)).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    predictions, targets, batches = predict_loader(model, loader, device)
    metadata = metadata_from_batches(batches, candidate_by_identity)
    overall_metrics = class_metrics(predictions, targets, class_names)
    grouped_metrics = metrics_by_group(predictions, targets, metadata, class_names)

    val_groups = set(split_counts["val"])
    train_groups = set(split_counts["train"])
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "grouped_validation_by_attack_window.json"
    csv_path = output_dir / "grouped_validation_by_attack_window.csv"
    markdown_path = output_dir / "grouped_validation_by_attack_window.md"
    report = {
        "pipeline": "office_grouped_validation_by_attack_window",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checkpoint_path": str(checkpoint_path),
        "checkpoint_epoch": checkpoint.get("epoch"),
        "checkpoint_best_validation_macro_f1": checkpoint.get("best_validation_macro_f1"),
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "candidate_split_dir": str(split_dir),
        "class_names": class_names,
        "split_group_counts": split_counts,
        "missing_candidate_metadata": missing,
        "overlap_summary": {
            "train_group_count": len(train_groups),
            "val_group_count": len(val_groups),
            "test_group_count": len(set(split_counts["test"])),
            "val_groups_present_in_train": len(val_groups & train_groups),
            "val_groups_absent_from_train": len(val_groups - train_groups),
            "val_groups_absent_from_train_keys": sorted(val_groups - train_groups),
        },
        "overall_validation_metrics": {
            "accuracy": float(overall_metrics["accuracy"]),
            "macro_f1": float(overall_metrics["macro_f1"]),
            "weighted_f1": float(overall_metrics["weighted_f1"]),
            "total": int(overall_metrics["total"]),
            "per_class": overall_metrics["per_class"],
            "confusion_matrix": overall_metrics["confusion_matrix"],
        },
        "validation_metrics_by_group": grouped_metrics,
        "artifact_paths": {
            "json": str(json_path),
            "csv": str(csv_path),
            "markdown": str(markdown_path),
        },
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_group_csv(csv_path, grouped_metrics, split_counts)
    write_markdown(markdown_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit office validation metrics grouped by attack window.")
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_OFFICE_CHECKPOINT_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--split-dir", type=Path, default=DEFAULT_SPLIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_grouped_window_audit(
        checkpoint_path=args.checkpoint,
        graph_manifest_path=args.graph_manifest,
        split_dir=args.split_dir,
        output_dir=args.output_dir,
    )
    print(
        json.dumps(
            {
                "pipeline": report["pipeline"],
                "generated_at": report["generated_at"],
                "checkpoint_epoch": report["checkpoint_epoch"],
                "overall_validation_metrics": {
                    "accuracy": report["overall_validation_metrics"]["accuracy"],
                    "macro_f1": report["overall_validation_metrics"]["macro_f1"],
                    "weighted_f1": report["overall_validation_metrics"]["weighted_f1"],
                    "total": report["overall_validation_metrics"]["total"],
                },
                "overlap_summary": report["overlap_summary"],
                "missing_candidate_metadata_count": len(report["missing_candidate_metadata"]),
                "artifact_paths": report["artifact_paths"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
