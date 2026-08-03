from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
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
    maybe_mask_temporal_dataset,
    metadata_from_batches,
    predict_loader,
    subtype_recall_metrics,
    temporal_feature_indices_from_manifest,
)


DEFAULT_OFFICE_METRICS_PATH = root_config.ARTIFACTS_DIR / "office_model" / "metrics.json"
DEFAULT_OFFICE_CLASSIFICATION_REPORT_PATH = root_config.ARTIFACTS_DIR / "office_model" / "classification_report.json"
DEFAULT_OFFICE_CONFUSION_MATRIX_PATH = root_config.ARTIFACTS_DIR / "office_model" / "confusion_matrix.csv"
DEFAULT_OFFICE_EVALUATION_REPORT_PATH = root_config.ARTIFACTS_DIR / "office_model" / "evaluation_report.md"


def source_stratified_webbased_metrics(
    predictions: np.ndarray,
    targets: np.ndarray,
    metadata: list[dict[str, str]],
    class_names: list[str],
) -> dict[str, dict[str, float | int]]:
    if "WebBased" not in class_names:
        return {}
    web_index = class_names.index("WebBased")
    by_source: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(metadata):
        if row.get("class_name") == "WebBased" or int(predictions[index]) == web_index:
            by_source[row.get("source_dataset", "unknown")].append(index)
    result: dict[str, dict[str, float | int]] = {}
    for source, indices in sorted(by_source.items()):
        true_positive = sum(1 for index in indices if int(targets[index]) == web_index and int(predictions[index]) == web_index)
        false_negative = sum(1 for index in indices if int(targets[index]) == web_index and int(predictions[index]) != web_index)
        false_positive = sum(1 for index in indices if int(targets[index]) != web_index and int(predictions[index]) == web_index)
        precision = true_positive / max(true_positive + false_positive, 1)
        recall = true_positive / max(true_positive + false_negative, 1)
        f1 = (2.0 * precision * recall / max(precision + recall, 1e-12)) if precision + recall else 0.0
        result[source] = {
            "support_or_predicted_webbased": len(indices),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "tp": int(true_positive),
            "fp": int(false_positive),
            "fn": int(false_negative),
        }
    return result


def bootstrap_macro_f1_ci(
    predictions: np.ndarray,
    targets: np.ndarray,
    class_names: list[str],
    *,
    samples: int,
    seed: int = 42,
) -> dict[str, float] | None:
    if samples <= 0 or targets.shape[0] < 2:
        return None
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(samples):
        indices = rng.integers(0, targets.shape[0], size=targets.shape[0])
        values.append(float(class_metrics(predictions[indices], targets[indices], class_names)["macro_f1"]))
    return {
        "samples": float(samples),
        "p025": float(np.percentile(values, 2.5)),
        "p500": float(np.percentile(values, 50.0)),
        "p975": float(np.percentile(values, 97.5)),
    }


def write_confusion_matrix(path: Path, class_names: list[str], matrix: list[list[int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["true\\predicted", *class_names])
        for class_name, row in zip(class_names, matrix, strict=True):
            writer.writerow([class_name, *row])


def write_evaluation_markdown(path: Path, metrics: dict[str, Any]) -> None:
    lines = [
        "# Office Model Evaluation",
        "",
        f"- Split: `{metrics['split']}`",
        f"- Accuracy: `{metrics['accuracy']:.6f}`",
        f"- Macro F1: `{metrics['macro_f1']:.6f}`",
        f"- Weighted F1: `{metrics['weighted_f1']:.6f}`",
        f"- Temporal features masked: `{metrics['temporal_features_masked']}`",
        f"- Checkpoint: `{metrics['checkpoint_path']}`",
        f"- Graph manifest: `{metrics['graph_manifest_path']}`",
        "",
        "## Class Order",
        "",
        "```json",
        json.dumps(metrics["class_names"], indent=2),
        "```",
        "",
        "## Per-Class Metrics",
        "",
        "| Class | Precision | Recall | F1 | Support | FP Rate | FN Rate |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for class_name, item in metrics["per_class"].items():
        lines.append(
            f"| {class_name} | {item['precision']:.6f} | {item['recall']:.6f} | "
            f"{item['f1']:.6f} | {item['support']} | {item['false_positive_rate']:.6f} | "
            f"{item['false_negative_rate']:.6f} |"
        )
    subtype_recall = metrics.get("per_subtype_recall", {})
    if isinstance(subtype_recall, dict) and subtype_recall:
        lines.extend(
            [
                "",
                "## Per-Subtype Broad-Class Recall",
                "",
                "| Class | Subtype | Support | Correct | Recall |",
                "| --- | --- | ---: | ---: | ---: |",
            ]
        )
        for item in subtype_recall.values():
            lines.append(
                f"| {item['class_name']} | {item['subtype']} | {item['support']} | "
                f"{item['correct_broad_class']} | {item['recall']:.6f} |"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate_office_model(
    *,
    checkpoint_path: Path = DEFAULT_OFFICE_CHECKPOINT_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    split: str = "test",
    metrics_path: Path = DEFAULT_OFFICE_METRICS_PATH,
    classification_report_path: Path = DEFAULT_OFFICE_CLASSIFICATION_REPORT_PATH,
    confusion_matrix_path: Path = DEFAULT_OFFICE_CONFUSION_MATRIX_PATH,
    evaluation_report_path: Path = DEFAULT_OFFICE_EVALUATION_REPORT_PATH,
    bootstrap_samples: int = 200,
) -> dict[str, Any]:
    if split not in {"train", "val", "test"}:
        raise ValueError("split must be one of: train, val, test")
    manifest = load_json(graph_manifest_path)
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    class_names = [str(item) for item in checkpoint["class_names"]]
    manifest_names = manifest_class_names(manifest)
    if class_names != manifest_names:
        raise ValueError(f"Checkpoint class order does not match graph manifest: {class_names} != {manifest_names}")

    DataLoader = require_pyg_dataloader()
    device = training_device()
    dataset = load_graph_dataset_from_manifest(
        manifest,
        split,
        class_names,
        limit_per_class=root_config.EVAL_LIMIT_PER_CLASS,
    )
    temporal_feature_indices = temporal_feature_indices_from_manifest(manifest)
    dataset = maybe_mask_temporal_dataset(dataset, manifest)
    loader = DataLoader(
        dataset,
        batch_size=root_config.EVAL_BATCH_SIZE,
        shuffle=False,
        **make_loader_kwargs(device),
    )
    model = SecureEdgeHGNN(num_classes=len(class_names)).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    predictions, targets, batches = predict_loader(model, loader, device)
    metadata = metadata_from_batches(batches)
    metrics = class_metrics(predictions, targets, class_names)
    metrics.update(
        {
            "split": split,
            "checkpoint_path": str(checkpoint_path),
            "graph_manifest_path": str(graph_manifest_path),
            "graph_manifest_hash": manifest.get("manifest_hash"),
            "checkpoint_graph_manifest_hash": checkpoint.get("graph_manifest_hash"),
            "model_attention_conv": checkpoint.get("model_attention_conv", getattr(model, "attention_conv", "unknown")),
            "temporal_features_masked": bool(temporal_feature_indices),
            "temporal_feature_indices": temporal_feature_indices,
            "per_subtype_recall": subtype_recall_metrics(predictions, targets, metadata, class_names),
            "source_stratified_webbased": source_stratified_webbased_metrics(predictions, targets, metadata, class_names),
            "bootstrap_macro_f1_ci": bootstrap_macro_f1_ci(
                predictions,
                targets,
                class_names,
                samples=bootstrap_samples,
            ),
            "unique_graph_count": len({row["graph_id"] for row in metadata if row.get("graph_id")}),
            "unique_candidate_count": len({row["candidate_identity"] for row in metadata if row.get("candidate_identity")}),
            "source_dataset_counts": dict(Counter(row["source_dataset"] for row in metadata)),
        }
    )
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    classification_report_path.parent.mkdir(parents=True, exist_ok=True)
    classification_report_path.write_text(
        json.dumps(metrics["classification_report"], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_confusion_matrix(confusion_matrix_path, class_names, metrics["confusion_matrix"])
    write_evaluation_markdown(evaluation_report_path, metrics)
    return metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate an office HGNN checkpoint with manifest-defined class labels.")
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_OFFICE_CHECKPOINT_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--split", choices=("train", "val", "test"), default="test")
    parser.add_argument("--metrics-path", type=Path, default=DEFAULT_OFFICE_METRICS_PATH)
    parser.add_argument("--classification-report-path", type=Path, default=DEFAULT_OFFICE_CLASSIFICATION_REPORT_PATH)
    parser.add_argument("--confusion-matrix-path", type=Path, default=DEFAULT_OFFICE_CONFUSION_MATRIX_PATH)
    parser.add_argument("--evaluation-report-path", type=Path, default=DEFAULT_OFFICE_EVALUATION_REPORT_PATH)
    parser.add_argument("--bootstrap-samples", type=int, default=200)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metrics = evaluate_office_model(
        checkpoint_path=args.checkpoint,
        graph_manifest_path=args.graph_manifest,
        split=args.split,
        metrics_path=args.metrics_path,
        classification_report_path=args.classification_report_path,
        confusion_matrix_path=args.confusion_matrix_path,
        evaluation_report_path=args.evaluation_report_path,
        bootstrap_samples=args.bootstrap_samples,
    )
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
