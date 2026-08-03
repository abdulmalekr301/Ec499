from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_recall_fscore_support

from secureedge.data.dataset import GraphFileDataset


@dataclass(frozen=True)
class TrainingContext:
    graph_manifest_path: Path
    shard_manifest_path: Path | None
    class_names: list[str]
    graph_dirs: dict[str, Path]
    feature_dimensions: dict[str, int]
    checkpoint_path: Path
    metrics_path: Path
    config_hash: str
    manifest_hash: str
    materialization_incomplete: bool


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_class_names(manifest: dict[str, Any]) -> list[str]:
    class_names = manifest.get("class_names")
    if not isinstance(class_names, list) or not class_names:
        raise ValueError("Graph manifest must contain a non-empty class_names list.")
    return [str(item) for item in class_names]


def split_paths_from_manifest(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    limit_per_class: int = 0,
) -> list[str]:
    if split not in {"train", "val", "test"}:
        raise ValueError("split must be one of: train, val, test")
    paths_by_class = manifest["splits"][split]["paths"]
    paths: list[str] = []
    for class_name in class_names:
        class_paths = list(paths_by_class.get(class_name, []))
        if limit_per_class > 0:
            class_paths = class_paths[:limit_per_class]
        paths.extend(str(path) for path in class_paths)
    return paths


def load_graph_dataset_from_manifest(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    limit_per_class: int = 0,
) -> GraphFileDataset:
    return GraphFileDataset(split_paths_from_manifest(manifest, split, class_names, limit_per_class=limit_per_class))


class TemporalMaskedGraphDataset(torch.utils.data.Dataset):
    def __init__(self, dataset: torch.utils.data.Dataset, temporal_feature_indices: list[int]) -> None:
        self.dataset = dataset
        self.temporal_feature_indices = [int(index) for index in temporal_feature_indices]

    def __len__(self) -> int:
        return len(self.dataset)

    def __getitem__(self, index: int):
        graph = self.dataset[index].clone()
        if self.temporal_feature_indices:
            graph["flow"].x[:, self.temporal_feature_indices] = 0.0
        graph.temporal_features_masked = bool(self.temporal_feature_indices)
        return graph


def temporal_feature_indices_from_manifest(manifest: dict[str, Any]) -> list[int]:
    policy = dict(manifest.get("final_training_policy", {}))
    if not bool(policy.get("mask_temporal_features", False)):
        return []
    configured = policy.get("temporal_feature_indices")
    if isinstance(configured, list):
        return [int(index) for index in configured]
    names = list(manifest.get("flow_feature_names", []))
    return [
        index
        for index, name in enumerate(names)
        if str(name).startswith("Rolling_") or str(name) == "Unique_Ports_In_SourceDestination"
    ]


def maybe_mask_temporal_dataset(dataset: torch.utils.data.Dataset, manifest: dict[str, Any]) -> torch.utils.data.Dataset:
    temporal_indices = temporal_feature_indices_from_manifest(manifest)
    if not temporal_indices:
        return dataset
    return TemporalMaskedGraphDataset(dataset, temporal_indices)


def validate_training_context(
    context: TrainingContext,
    manifest: dict[str, Any],
    expected_class_names: list[str],
    *,
    allow_incomplete: bool = False,
) -> None:
    if context.class_names != expected_class_names:
        raise ValueError(
            "Office graph manifest class order does not match the YAML config. "
            f"manifest={context.class_names} yaml={expected_class_names}"
        )
    if context.materialization_incomplete and not allow_incomplete:
        raise ValueError(
            "Office graph manifest is marked materialization_incomplete. "
            "Use --allow-incomplete-development-run only for explicit development smoke runs."
        )
    for split in ("train", "val", "test"):
        if int(manifest["splits"].get(split, {}).get("count", 0)) <= 0:
            raise ValueError(f"Office graph manifest has no {split} graphs.")
    for split in ("train", "val"):
        per_class = manifest["splits"][split].get("per_class", {})
        missing = [class_name for class_name in context.class_names if int(per_class.get(class_name, 0)) <= 0]
        if missing:
            raise ValueError(f"Office {split} split is missing classes: {missing}")


def label_set_is_valid(labels: np.ndarray, class_names: list[str]) -> bool:
    if labels.size == 0:
        return False
    return bool(np.all((labels >= 0) & (labels < len(class_names))))


def class_metrics(
    predictions: np.ndarray,
    targets: np.ndarray,
    class_names: list[str],
) -> dict[str, Any]:
    labels = list(range(len(class_names)))
    if not label_set_is_valid(targets, class_names):
        raise ValueError("Targets contain labels outside the manifest class range.")
    if not label_set_is_valid(predictions, class_names):
        raise ValueError("Predictions contain labels outside the manifest class range.")
    matrix = confusion_matrix(targets, predictions, labels=labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        targets,
        predictions,
        labels=labels,
        zero_division=0,
    )
    per_class: dict[str, dict[str, float | int]] = {}
    total = int(matrix.sum())
    for index, class_name in enumerate(class_names):
        tp = int(matrix[index, index])
        fn = int(matrix[index, :].sum() - tp)
        fp = int(matrix[:, index].sum() - tp)
        tn = int(total - tp - fn - fp)
        per_class[class_name] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "false_positive_rate": float(fp / max(fp + tn, 1)),
            "false_negative_rate": float(fn / max(fn + tp, 1)),
        }
    return {
        "accuracy": float(np.mean(predictions == targets)),
        "macro_f1": float(f1_score(targets, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(targets, predictions, average="weighted", zero_division=0)),
        "classification_report": classification_report(
            targets,
            predictions,
            labels=labels,
            target_names=class_names,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": matrix.tolist(),
        "class_names": list(class_names),
        "per_class": per_class,
        "total": int(targets.shape[0]),
        "correct": int(np.sum(predictions == targets)),
        "incorrect": int(np.sum(predictions != targets)),
    }


def predict_loader(model, loader, device: torch.device) -> tuple[np.ndarray, np.ndarray, list[Any]]:
    model.eval()
    predictions: list[np.ndarray] = []
    targets: list[np.ndarray] = []
    batches: list[Any] = []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device, non_blocking=True)
            logits = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
            predictions.append(torch.argmax(logits, dim=1).cpu().numpy())
            targets.append(batch.y.view(-1).cpu().numpy())
            batches.append(batch.cpu())
    return np.concatenate(predictions), np.concatenate(targets), batches


def _as_list(value: object, length: int) -> list[object]:
    if isinstance(value, list | tuple):
        return list(value)
    return [value for _ in range(length)]


def metadata_from_batches(batches: list[Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for batch in batches:
        count = int(batch.y.view(-1).shape[0])
        class_names = _as_list(getattr(batch, "class_name", ""), count)
        subtypes = _as_list(getattr(batch, "subtype_label", "no_subtype"), count)
        days = _as_list(getattr(batch, "day", "unknown"), count)
        sources = _as_list(getattr(batch, "source_dataset", "unknown"), count)
        candidate_ids = _as_list(getattr(batch, "office_candidate_identity", ""), count)
        graph_ids = _as_list(getattr(batch, "graph_id", ""), count)
        for class_name, subtype, day, source, candidate_id, graph_id in zip(
            class_names,
            subtypes,
            days,
            sources,
            candidate_ids,
            graph_ids,
            strict=False,
        ):
            rows.append(
                {
                    "class_name": str(class_name),
                    "subtype": str(subtype),
                    "day": str(day),
                    "source_dataset": str(source),
                    "candidate_identity": str(candidate_id),
                    "graph_id": str(graph_id),
                }
            )
    return rows


def subtype_recall_metrics(
    predictions: np.ndarray,
    targets: np.ndarray,
    metadata: list[dict[str, str]],
    class_names: list[str],
) -> dict[str, dict[str, float | int | str]]:
    rows: dict[str, list[int]] = {}
    for index, row in enumerate(metadata):
        class_name = row.get("class_name", "")
        subtype = row.get("subtype", "no_subtype")
        key = f"{class_name}|{subtype}"
        rows.setdefault(key, []).append(index)
    output: dict[str, dict[str, float | int | str]] = {}
    for key, indices in sorted(rows.items()):
        class_name, subtype = key.split("|", maxsplit=1)
        if class_name not in class_names:
            continue
        class_index = class_names.index(class_name)
        index_array = np.asarray(indices, dtype=np.int64)
        support = int(index_array.shape[0])
        correct = int(np.sum(predictions[index_array] == class_index))
        output[key] = {
            "class_name": class_name,
            "subtype": subtype,
            "support": support,
            "correct_broad_class": correct,
            "recall": float(correct / max(support, 1)),
        }
    return output
