from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from secureedge import config as root_config
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, OfficeConfig, load_office_config
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_IMBALANCE_REPORT_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_imbalance_policy.json"


def split_class_counts_from_manifest(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    limit_per_class: int = 0,
) -> dict[str, int]:
    paths_by_class = manifest["splits"][split]["paths"]
    counts: dict[str, int] = {}
    for class_name in class_names:
        count = len(paths_by_class.get(class_name, []))
        if limit_per_class > 0:
            count = min(count, limit_per_class)
        counts[class_name] = int(count)
    return counts


def labels_from_class_counts(counts: dict[str, int], class_names: list[str]) -> list[int]:
    labels: list[int] = []
    for index, class_name in enumerate(class_names):
        labels.extend([index] * int(counts.get(class_name, 0)))
    return labels


def calculate_class_weights(
    counts: dict[str, int],
    class_names: list[str],
    imbalance_policy: dict[str, Any],
) -> tuple[list[float] | None, dict[str, Any]]:
    loss_policy = dict(imbalance_policy.get("loss", {}))
    loss_name = str(loss_policy.get("name", "plain_cross_entropy"))
    weighting = dict(loss_policy.get("class_weighting", {}))
    method = str(weighting.get("method", "none"))
    count_values = np.asarray([int(counts.get(class_name, 0)) for class_name in class_names], dtype=np.float64)
    if np.any(count_values <= 0):
        missing = [class_names[index] for index, value in enumerate(count_values) if value <= 0]
        raise ValueError(f"Cannot calculate office class weights with empty train classes: {missing}")

    summary: dict[str, Any] = {
        "loss": loss_name,
        "method": method,
        "count_source": "train_split_only",
        "train_class_counts": {class_name: int(counts[class_name]) for class_name in class_names},
    }
    if loss_name in {"plain_cross_entropy", "cross_entropy"} or method == "none":
        summary["weights_by_class"] = None
        return None, summary
    if loss_name != "weighted_cross_entropy":
        raise ValueError(f"Unsupported office loss for class weights: {loss_name!r}")

    if method == "inverse_frequency":
        weights = count_values.sum() / (len(class_names) * count_values)
    elif method == "effective_number":
        beta = float(weighting.get("beta", 0.9999))
        if not 0.0 <= beta < 1.0:
            raise ValueError("effective_number beta must be in [0.0, 1.0).")
        if beta == 0.0:
            weights = np.ones_like(count_values)
        else:
            weights = (1.0 - beta) / (1.0 - np.power(beta, count_values))
        summary["beta"] = beta
    else:
        raise ValueError(f"Unsupported office class weighting method: {method!r}")

    if bool(weighting.get("normalize_mean_to_one", True)):
        weights = weights / float(weights.mean())
        summary["normalize_mean_to_one"] = True
    else:
        summary["normalize_mean_to_one"] = False

    max_weight = weighting.get("max_weight")
    if max_weight is not None:
        max_weight_float = float(max_weight)
        if max_weight_float <= 0:
            raise ValueError("max_weight must be positive when configured.")
        weights = np.minimum(weights, max_weight_float)
        summary["max_weight"] = max_weight_float

    rounded = [float(round(value, 6)) for value in weights.tolist()]
    summary["weights_by_class"] = dict(zip(class_names, rounded, strict=True))
    return rounded, summary


def balanced_sampler_summary(
    counts: dict[str, int],
    class_names: list[str],
    imbalance_policy: dict[str, Any],
) -> dict[str, Any]:
    policy = dict(imbalance_policy.get("balanced_batches", {}))
    enabled = bool(policy.get("enabled", False))
    method = str(policy.get("method", "none"))
    summary: dict[str, Any] = {
        "enabled": enabled,
        "method": method,
        "count_source": "train_split_only",
    }
    if not enabled:
        return summary
    if method != "weighted_random_sampler":
        raise ValueError(f"Unsupported office balanced batch method: {method!r}")
    if any(int(counts.get(class_name, 0)) <= 0 for class_name in class_names):
        raise ValueError("Balanced sampling requires every train class to have at least one graph.")
    total = sum(int(counts[class_name]) for class_name in class_names)
    class_probability = 1.0 / len(class_names)
    summary.update(
        {
            "replacement": bool(policy.get("replacement", True)),
            "num_samples_per_epoch": int(total),
            "sample_weighting": str(policy.get("sample_weighting", "inverse_class_frequency")),
            "expected_class_probability_per_draw": {
                class_name: round(class_probability, 6) for class_name in class_names
            },
        }
    )
    return summary


def sample_weights_from_class_counts(
    counts: dict[str, int],
    class_names: list[str],
    imbalance_policy: dict[str, Any],
) -> tuple[list[float] | None, dict[str, Any]]:
    summary = balanced_sampler_summary(counts, class_names, imbalance_policy)
    if not summary["enabled"]:
        return None, summary
    sample_weights: list[float] = []
    for class_name in class_names:
        class_count = int(counts[class_name])
        sample_weights.extend([1.0 / class_count] * class_count)
    return sample_weights, summary


def build_imbalance_report(
    *,
    office_config: OfficeConfig,
    graph_manifest_path: Path,
    train_limit_per_class: int = 0,
) -> dict[str, Any]:
    manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(manifest)
    split_counts = {
        split: split_class_counts_from_manifest(manifest, split, class_names)
        for split in ("train", "val", "test")
    }
    effective_train_counts = split_class_counts_from_manifest(
        manifest,
        "train",
        class_names,
        limit_per_class=train_limit_per_class,
    )
    weights, weight_summary = calculate_class_weights(effective_train_counts, class_names, office_config.imbalance_policy)
    _, sampler = sample_weights_from_class_counts(effective_train_counts, class_names, office_config.imbalance_policy)
    split_targets = office_config.split_targets
    return {
        "pipeline": "office_imbalance_policy",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config_path": str(office_config.path),
        "config_hash": office_config.config_hash,
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "class_names": class_names,
        "train_limit_per_class": int(train_limit_per_class),
        "split_counts": split_counts,
        "webbased_policy": {
            **dict(office_config.imbalance_policy.get("webbased_policy", {})),
            "configured_native_train": split_targets.webbased_native_train,
            "configured_cicids2017_train_only": split_targets.webbased_cicids2017_train_only,
            "configured_train_real": split_targets.webbased_train_real,
            "configured_train_target": split_targets.webbased_train_target,
            "configured_val": split_targets.webbased_val,
            "configured_test": split_targets.webbased_test,
            "materialized_train": split_counts["train"].get("WebBased", 0),
            "materialized_val": split_counts["val"].get("WebBased", 0),
            "materialized_test": split_counts["test"].get("WebBased", 0),
            "materialized_cicids2017_train_only_shortfall": max(
                0,
                split_targets.webbased_train_real - split_counts["train"].get("WebBased", 0),
            ),
        },
        "class_weight_summary": weight_summary,
        "class_weights": weights,
        "balanced_batches": sampler,
        "metric_policy": {
            "checkpoint_selection_metric": "validation_macro_f1",
            "test_split_loaded_during_training": False,
            "report_macro_metrics": True,
            "report_webbased_confidence": True,
        },
    }


def write_imbalance_report(
    *,
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    output_path: Path = DEFAULT_IMBALANCE_REPORT_PATH,
    train_limit_per_class: int = 0,
) -> dict[str, Any]:
    office_config = load_office_config(config_path)
    report = build_imbalance_report(
        office_config=office_config,
        graph_manifest_path=graph_manifest_path,
        train_limit_per_class=train_limit_per_class,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write the CIC-IDS-2018 office imbalance policy report.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_IMBALANCE_REPORT_PATH)
    parser.add_argument("--train-limit-per-class", type=int, default=0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = write_imbalance_report(
        config_path=args.config,
        graph_manifest_path=args.graph_manifest,
        output_path=args.output,
        train_limit_per_class=args.train_limit_per_class,
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
