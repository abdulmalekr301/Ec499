from __future__ import annotations

import argparse
import csv
import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.utils.data import WeightedRandomSampler

from secureedge import config as root_config
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import (
    amp_disabled_reason,
    amp_is_enabled,
    bool_label,
    cosine_cycle,
    current_lr,
    make_loader_kwargs,
    require_pyg_dataloader,
    training_device,
)
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, load_office_config
from secureedge.office.imbalance import (
    calculate_class_weights,
    sample_weights_from_class_counts,
    split_class_counts_from_manifest,
)
from secureedge.office.manifests import stable_json_hash
from secureedge.training.engine import (
    TrainingContext,
    class_metrics,
    load_graph_dataset_from_manifest,
    load_json,
    manifest_class_names,
    maybe_mask_temporal_dataset,
    metadata_from_batches,
    predict_loader,
    split_paths_from_manifest,
    subtype_recall_metrics,
    temporal_feature_indices_from_manifest,
    validate_training_context,
)


DEFAULT_OFFICE_CHECKPOINT_PATH = root_config.ARTIFACTS_DIR / "office_model" / "best_office_hgnn.pt"
DEFAULT_OFFICE_HISTORY_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_training_history.json"
DEFAULT_OFFICE_TRAINING_RUNS_DIR = root_config.ARTIFACTS_DIR / "office_model" / "training_runs"


def next_office_training_run_id() -> int:
    pattern = re.compile(r"office_run_(\d+)_history\.json$")
    run_ids: list[int] = []
    for path in DEFAULT_OFFICE_TRAINING_RUNS_DIR.glob("office_run_*_history.json"):
        match = pattern.match(path.name)
        if match:
            run_ids.append(int(match.group(1)))
    return max(run_ids, default=0) + 1


def markdown_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return lines


def write_office_training_history_csv(path: Path, history: list[dict[str, object]]) -> None:
    fieldnames = [
        "run",
        "epoch",
        "train_loss",
        "validation_accuracy",
        "validation_macro_f1",
        "validation_weighted_f1",
        "learning_rate",
        "batch_size",
        "grad_accum_steps",
        "effective_batch_size",
        "use_amp",
        "scheduler",
        "scheduler_monitor",
        "scheduler_metric",
        "stale_epochs",
        "best_validation_macro_f1",
        "is_best",
        "epoch_duration_seconds",
        "correct",
        "incorrect",
        "total",
        "diagnostic_warning_count",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in history:
            writer.writerow({field: row.get(field) for field in fieldnames})


def diagnostic_warnings(row: dict[str, object], *, epoch: int) -> list[str]:
    warnings: list[str] = []
    validation_macro_f1 = float(row["validation_macro_f1"])
    train_loss = float(row["train_loss"])
    if epoch == 1 and validation_macro_f1 >= 0.98:
        warnings.append(
            "first_epoch_validation_macro_f1_ge_0.98; inspect split similarity, feature leakage, and duplicated/easy session patterns"
        )
    if train_loss <= 0.1 and validation_macro_f1 >= 0.99:
        warnings.append("very_low_train_loss_with_near_perfect_validation_macro_f1")
    per_class = row.get("per_class", {})
    if isinstance(per_class, dict):
        webbased = per_class.get("WebBased")
        if isinstance(webbased, dict) and int(webbased.get("support", 0)) <= 103:
            warnings.append("webbased_validation_support_is_low; treat WebBased metrics as high_variance")
    return warnings


def group_aware_sample_weights_from_manifest(
    manifest: dict[str, object],
    class_names: list[str],
    *,
    limit_per_class: int = 0,
) -> tuple[list[float] | None, dict[str, object] | None]:
    policy = dict(manifest.get("final_training_policy", {}))
    if policy.get("sampler") != "class_subtype_group_graph_weighted_random_sampler":
        return None, None
    train_split = dict(manifest["splits"]["train"])
    metadata_by_path = dict(train_split.get("metadata_by_path", {}))
    paths = split_paths_from_manifest(manifest, "train", class_names, limit_per_class=limit_per_class)
    if not paths:
        return None, None

    class_to_paths: dict[str, list[str]] = {class_name: [] for class_name in class_names}
    subtype_to_paths: dict[tuple[str, str], list[str]] = {}
    group_to_paths: dict[tuple[str, str, str], list[str]] = {}
    metadata_rows: dict[str, dict[str, object]] = {}
    for path in paths:
        meta = dict(metadata_by_path.get(path, {}))
        class_name = str(meta.get("class_name", ""))
        if class_name not in class_names:
            raise ValueError(f"Missing or invalid class metadata for training path: {path}")
        subtype = str(meta.get("subtype", "no_subtype"))
        group_key = str(meta.get("group_key", f"{class_name}|{subtype}|missing_group"))
        metadata_rows[path] = meta
        class_to_paths[class_name].append(path)
        subtype_to_paths.setdefault((class_name, subtype), []).append(path)
        group_to_paths.setdefault((class_name, subtype, group_key), []).append(path)

    class_count = len([class_name for class_name, values in class_to_paths.items() if values])
    if class_count != len(class_names):
        missing = [class_name for class_name, values in class_to_paths.items() if not values]
        raise ValueError(f"Group-aware sampler requires all train classes: missing={missing}")

    subtype_counts_by_class = Counter(class_name for class_name, _ in subtype_to_paths)
    group_counts_by_subtype = Counter((class_name, subtype) for class_name, subtype, _ in group_to_paths)
    weights: list[float] = []
    for path in paths:
        meta = metadata_rows[path]
        class_name = str(meta["class_name"])
        subtype = str(meta.get("subtype", "no_subtype"))
        group_key = str(meta.get("group_key", f"{class_name}|{subtype}|missing_group"))
        group_size = len(group_to_paths[(class_name, subtype, group_key)])
        weight = 1.0 / (
            class_count
            * max(int(subtype_counts_by_class[class_name]), 1)
            * max(int(group_counts_by_subtype[(class_name, subtype)]), 1)
            * max(group_size, 1)
        )
        weights.append(weight)
    summary = {
        "enabled": True,
        "method": "class_subtype_group_graph_weighted_random_sampler",
        "replacement": True,
        "num_samples_per_epoch": len(paths),
        "class_count": class_count,
        "subtype_counts_by_class": dict(sorted(subtype_counts_by_class.items())),
        "group_count": len(group_to_paths),
        "group_counts_by_subtype": {
            f"{class_name}|{subtype}": int(count)
            for (class_name, subtype), count in sorted(group_counts_by_subtype.items())
        },
    }
    return weights, summary


def write_office_run_markdown(
    path: Path,
    *,
    run_id: int,
    run_started_at: str,
    run_config: dict[str, object],
    history: list[dict[str, object]],
    best_epoch: int | None,
    best_validation_macro_f1: float,
    stopped_reason: str,
) -> None:
    latest = history[-1] if history else {}
    class_names = list(run_config["class_names"])
    lines = [
        f"# Office HGNN Training Run {run_id}",
        "",
        f"> Run started: `{run_started_at}`",
        f"> Last updated: `{datetime.now(timezone.utc).isoformat(timespec='seconds')}`",
        "",
        "## Configuration",
        "",
        "```text",
        f"device={run_config['device']}",
        f"model_attention_conv={run_config['model_attention_conv']}",
        f"batch_size={run_config['batch_size']}",
        f"grad_accum_steps={run_config['grad_accum_steps']}",
        f"effective_batch_size={run_config['effective_batch_size']}",
        f"eval_batch_size={run_config['eval_batch_size']}",
        f"use_amp={bool_label(bool(run_config['use_amp']))}",
        f"amp_disabled_reason={run_config['amp_disabled_reason']}",
        f"checkpoint_selection_split={run_config['checkpoint_selection_split']}",
        f"test_split_loaded_during_training={run_config['test_split_loaded_during_training']}",
        f"lr_start={run_config['lr_start']}",
        f"lr_target={run_config['lr_target']}",
        f"lr_min={run_config['lr_min']}",
        f"scheduler={run_config['scheduler']}",
        f"plateau_monitor={run_config['plateau_monitor']}",
        f"cosine_t0={run_config['cosine_t0']}",
        f"cosine_t_mult={run_config['cosine_t_mult']}",
        f"weight_decay={run_config['weight_decay']}",
        f"grad_clip_max_norm={run_config['grad_clip_max_norm']}",
        f"max_epochs={run_config['max_epochs']}",
        f"early_stopping_patience={run_config['early_stopping_patience']}",
        f"print_class_every={run_config['print_class_every']}",
        f"label_smoothing={run_config['label_smoothing']}",
        f"temporal_features_masked={run_config['temporal_features_masked']}",
        f"temporal_feature_indices={run_config['temporal_feature_indices']}",
        "```",
        "",
        "## Dataset",
        "",
    ]
    lines.extend(
        markdown_table(
            ["Class", "Train"],
            [[class_name, run_config["train_class_counts"][class_name]] for class_name in class_names],
        )
    )
    lines.extend(
        [
            "",
            "## Imbalance Handling",
            "",
            f"- Loss: `{run_config['class_weight_summary']['loss']}`.",
            f"- Weight method: `{run_config['class_weight_summary']['method']}`.",
            f"- Count source: `{run_config['class_weight_summary']['count_source']}`.",
            f"- Balanced sampler: `{run_config['balanced_batches']['enabled']}`.",
            f"- Sampler method: `{run_config['balanced_batches']['method']}`.",
            "",
            "## Current Status",
            "",
            f"- Stopped reason: `{stopped_reason}`.",
            f"- Epochs completed: `{len(history)}`.",
            f"- Best epoch: `{best_epoch}`.",
            f"- Best validation macro F1: `{best_validation_macro_f1:.6f}`.",
        ]
    )
    if latest:
        lines.extend(
            [
                f"- Latest validation accuracy: `{float(latest['validation_accuracy']):.6f}`.",
                f"- Latest validation macro F1: `{float(latest['validation_macro_f1']):.6f}`.",
                f"- Latest validation weighted F1: `{float(latest['validation_weighted_f1']):.6f}`.",
                f"- Latest train loss: `{float(latest['train_loss']):.6f}`.",
                f"- Latest learning rate: `{float(latest['learning_rate']):.8g}`.",
                "",
                "## Diagnostic Warnings",
                "",
            ]
        )
        warnings = latest.get("diagnostic_warnings", [])
        if warnings:
            lines.extend(f"- `{warning}`" for warning in warnings)
        else:
            lines.append("- None.")
        lines.extend(["", "## Per-Epoch Summary", ""])
        rows = [
            [
                row["epoch"],
                f"{float(row['train_loss']):.6f}",
                f"{float(row['validation_accuracy']):.6f}",
                f"{float(row['validation_macro_f1']):.6f}",
                f"{float(row['validation_weighted_f1']):.6f}",
                f"{float(row['learning_rate']):.8g}",
                row["stale_epochs"],
                f"{float(row['best_validation_macro_f1']):.6f}",
                row["cosine_cycle"],
                f"{float(row['epoch_duration_seconds']):.2f}",
                row["diagnostic_warning_count"],
                "yes" if row["is_best"] else "no",
            ]
            for row in history
        ]
        lines.extend(
            markdown_table(
                [
                    "Epoch",
                    "Train Loss",
                    "Val Acc",
                    "Val Macro F1",
                    "Val Weighted F1",
                    "LR",
                    "Stale",
                    "Best Val F1",
                    "Cycle",
                    "Seconds",
                    "Warnings",
                    "Best",
                ],
                rows,
            )
        )
        lines.extend(["", "## Latest Validation Per-Class Metrics", ""])
        per_class = latest.get("per_class", {})
        class_rows = []
        for class_name in class_names:
            item = per_class[class_name]
            class_rows.append(
                [
                    class_name,
                    item["support"],
                    item["tp"],
                    item["fp"],
                    item["fn"],
                    f"{float(item['precision']):.6f}",
                    f"{float(item['recall']):.6f}",
                    f"{float(item['f1']):.6f}",
                    f"{float(item['false_positive_rate']):.6f}",
                    f"{float(item['false_negative_rate']):.6f}",
                ]
            )
        lines.extend(
            markdown_table(
                ["Class", "Support", "TP", "FP", "FN", "Precision", "Recall", "F1", "FP Rate", "FN Rate"],
                class_rows,
            )
        )
        subtype_recall = latest.get("per_subtype_recall", {})
        if isinstance(subtype_recall, dict) and subtype_recall:
            lines.extend(["", "## Latest Validation Per-Subtype Recall", ""])
            rows = []
            for key, item in subtype_recall.items():
                rows.append(
                    [
                        item["class_name"],
                        item["subtype"],
                        item["support"],
                        item["correct_broad_class"],
                        f"{float(item['recall']):.6f}",
                    ]
                )
            lines.extend(markdown_table(["Class", "Subtype", "Support", "Correct", "Recall"], rows))
        lines.extend(
            [
                "",
                "## Artifact Paths",
                "",
                f"- Latest history JSON: `{run_config['latest_history_json_path']}`",
                f"- Run history JSON: `{run_config['run_history_json_path']}`",
                f"- Run history CSV: `{run_config['run_history_csv_path']}`",
                f"- Run config JSON: `{run_config['run_config_path']}`",
                f"- Run checkpoint: `{run_config['run_checkpoint_path']}`",
                f"- Global office checkpoint: `{run_config['checkpoint_path']}`",
            ]
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_training_context(
    *,
    config_path: Path,
    graph_manifest_path: Path,
    checkpoint_path: Path,
    history_path: Path,
) -> tuple[TrainingContext, dict[str, object], list[str]]:
    office_config = load_office_config(config_path)
    manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(manifest)
    graph_dirs = {split: Path(str(path)) for split, path in manifest.get("graph_dirs", {}).items()}
    context = TrainingContext(
        graph_manifest_path=graph_manifest_path,
        shard_manifest_path=None,
        class_names=class_names,
        graph_dirs=graph_dirs,
        feature_dimensions={str(key): int(value) for key, value in manifest["feature_dimensions"].items()},
        checkpoint_path=checkpoint_path,
        metrics_path=history_path,
        config_hash=office_config.config_hash,
        manifest_hash=str(manifest.get("manifest_hash", "")),
        materialization_incomplete=bool(manifest.get("materialization_incomplete", False)),
    )
    return context, manifest, office_config.class_names


def train_office_model(
    *,
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    checkpoint_path: Path = DEFAULT_OFFICE_CHECKPOINT_PATH,
    history_path: Path = DEFAULT_OFFICE_HISTORY_PATH,
    allow_incomplete_development_run: bool = False,
) -> dict[str, object]:
    context, manifest, expected_class_names = build_training_context(
        config_path=config_path,
        graph_manifest_path=graph_manifest_path,
        checkpoint_path=checkpoint_path,
        history_path=history_path,
    )
    validate_training_context(
        context,
        manifest,
        expected_class_names,
        allow_incomplete=allow_incomplete_development_run,
    )
    if root_config.GRAD_ACCUM_STEPS < 1:
        raise ValueError("SECUREEDGE_GRAD_ACCUM_STEPS must be >= 1.")
    if root_config.LR_SCHEDULER not in {"cosine", "plateau", "none"}:
        raise ValueError("SECUREEDGE_SCHEDULER must be one of: cosine, plateau, none")
    if root_config.PLATEAU_MONITOR != "val_macro_f1":
        raise ValueError("Office training currently supports SECUREEDGE_PLATEAU_MONITOR=val_macro_f1.")
    device = training_device()
    DataLoader = require_pyg_dataloader()
    office_config = load_office_config(config_path)
    run_id = next_office_training_run_id()
    run_started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_history_json_path = DEFAULT_OFFICE_TRAINING_RUNS_DIR / f"office_run_{run_id:02d}_history.json"
    run_history_csv_path = DEFAULT_OFFICE_TRAINING_RUNS_DIR / f"office_run_{run_id:02d}_history.csv"
    run_config_path = DEFAULT_OFFICE_TRAINING_RUNS_DIR / f"office_run_{run_id:02d}_config.json"
    run_checkpoint_path = DEFAULT_OFFICE_TRAINING_RUNS_DIR / f"office_run_{run_id:02d}_best_office_hgnn.pt"
    run_log_path = root_config.CONTEXT_DIR / f"office-training-logs-{run_id:02d}.md"
    train_class_counts = split_class_counts_from_manifest(
        manifest,
        "train",
        context.class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    class_weights, class_weight_summary = calculate_class_weights(
        train_class_counts,
        context.class_names,
        office_config.imbalance_policy,
    )
    sample_weights, balanced_sampler = group_aware_sample_weights_from_manifest(
        manifest,
        context.class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    if sample_weights is None:
        sample_weights, balanced_sampler = sample_weights_from_class_counts(
            train_class_counts,
            context.class_names,
            office_config.imbalance_policy,
        )
    else:
        class_weight_summary["sampler_note"] = "Using manifest-provided group-aware sampler instead of YAML class sampler."
    if balanced_sampler is None:
        _, balanced_sampler = sample_weights_from_class_counts(
            train_class_counts,
            context.class_names,
            office_config.imbalance_policy,
        )
    train_sampler = None
    if sample_weights is not None:
        train_sampler = WeightedRandomSampler(
            torch.as_tensor(sample_weights, dtype=torch.double),
            num_samples=len(sample_weights),
            replacement=bool(balanced_sampler.get("replacement", True)),
        )
    train_dataset = load_graph_dataset_from_manifest(
        manifest,
        "train",
        context.class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    val_dataset = load_graph_dataset_from_manifest(
        manifest,
        "val",
        context.class_names,
        limit_per_class=root_config.EVAL_LIMIT_PER_CLASS,
    )
    temporal_feature_indices = temporal_feature_indices_from_manifest(manifest)
    train_dataset = maybe_mask_temporal_dataset(train_dataset, manifest)
    val_dataset = maybe_mask_temporal_dataset(val_dataset, manifest)
    train_loader = DataLoader(
        train_dataset,
        batch_size=root_config.BATCH_SIZE,
        shuffle=train_sampler is None,
        sampler=train_sampler,
        **make_loader_kwargs(device),
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=root_config.EVAL_BATCH_SIZE,
        shuffle=False,
        **make_loader_kwargs(device),
    )

    model = SecureEdgeHGNN(num_classes=len(context.class_names)).to(device)
    class_weight_tensor = None
    if class_weights is not None:
        class_weight_tensor = torch.tensor(class_weights, dtype=torch.float32, device=device)
    criterion = nn.CrossEntropyLoss(weight=class_weight_tensor, label_smoothing=root_config.LABEL_SMOOTHING)
    optimizer = torch.optim.Adam(model.parameters(), lr=root_config.LEARNING_RATE, weight_decay=root_config.WEIGHT_DECAY)
    use_amp = amp_is_enabled(device)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    if root_config.WARMUP_EPOCHS > 0:
        for group in optimizer.param_groups:
            group["lr"] = root_config.WARMUP_START_LR
    if root_config.LR_SCHEDULER == "cosine":
        scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
            optimizer,
            T_0=root_config.COSINE_T0,
            T_mult=root_config.COSINE_T_MULT,
            eta_min=root_config.MIN_LEARNING_RATE,
        )
    elif root_config.LR_SCHEDULER == "plateau":
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer,
            mode="max",
            factor=0.5,
            patience=root_config.LR_SCHEDULER_PATIENCE,
            threshold=root_config.PLATEAU_THRESHOLD,
            min_lr=root_config.MIN_LEARNING_RATE,
        )
    else:
        scheduler = None
    best_validation_macro_f1 = -1.0
    best_epoch: int | None = None
    stale_epochs = 0
    history: list[dict[str, object]] = []
    run_config = {
        "run": run_id,
        "pipeline": "office_model_training",
        "started_at": run_started_at,
        "config_path": str(config_path),
        "config_hash": context.config_hash,
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": context.manifest_hash,
        "class_names": context.class_names,
        "model_attention_conv": office_config.architecture_policy["current_attention_conv"],
        "checkpoint_selection_split": "val",
        "test_split_loaded_during_training": False,
        "batch_size": root_config.BATCH_SIZE,
        "grad_accum_steps": root_config.GRAD_ACCUM_STEPS,
        "effective_batch_size": root_config.BATCH_SIZE * root_config.GRAD_ACCUM_STEPS,
        "eval_batch_size": root_config.EVAL_BATCH_SIZE,
        "max_epochs": root_config.MAX_EPOCHS,
        "early_stopping_patience": root_config.EARLY_STOPPING_PATIENCE,
        "learning_rate": root_config.LEARNING_RATE,
        "lr_start": root_config.WARMUP_START_LR,
        "lr_target": root_config.LEARNING_RATE,
        "lr_min": root_config.MIN_LEARNING_RATE,
        "warmup_epochs": root_config.WARMUP_EPOCHS,
        "scheduler": root_config.LR_SCHEDULER,
        "plateau_monitor": root_config.PLATEAU_MONITOR,
        "plateau_threshold": root_config.PLATEAU_THRESHOLD,
        "lr_scheduler_patience": root_config.LR_SCHEDULER_PATIENCE,
        "cosine_t0": root_config.COSINE_T0,
        "cosine_t_mult": root_config.COSINE_T_MULT,
        "weight_decay": root_config.WEIGHT_DECAY,
        "label_smoothing": root_config.LABEL_SMOOTHING,
        "grad_clip_max_norm": root_config.GRAD_CLIP_MAX_NORM,
        "print_class_every": root_config.PRINT_CLASS_EVERY,
        "n_batches_per_epoch": len(train_loader),
        "n_train": len(train_dataset),
        "n_val": len(val_dataset),
        "n_test": int(manifest["splits"]["test"]["count"]),
        "train_limit_per_class": root_config.TRAIN_LIMIT_PER_CLASS,
        "eval_limit_per_class": root_config.EVAL_LIMIT_PER_CLASS,
        "num_workers": root_config.NUM_WORKERS,
        "prefetch_factor": root_config.PREFETCH_FACTOR,
        "device": str(device),
        "torch_cuda_available": bool(torch.cuda.is_available()),
        "torch_cuda_version": torch.version.cuda,
        "cuda_device_count": int(torch.cuda.device_count()),
        "cuda_device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "use_amp": use_amp,
        "amp_disabled_reason": amp_disabled_reason(device),
        "allow_incomplete_development_run": allow_incomplete_development_run,
        "imbalance_policy": office_config.imbalance_policy,
        "train_class_counts": train_class_counts,
        "class_weight_summary": class_weight_summary,
        "balanced_batches": balanced_sampler,
        "temporal_features_masked": bool(temporal_feature_indices),
        "temporal_feature_indices": temporal_feature_indices,
        "temporal_feature_count": len(temporal_feature_indices),
        "latest_history_json_path": str(history_path),
        "run_history_json_path": str(run_history_json_path),
        "run_history_csv_path": str(run_history_csv_path),
        "run_config_path": str(run_config_path),
        "run_checkpoint_path": str(run_checkpoint_path),
        "run_log_path": str(run_log_path),
        "checkpoint_path": str(checkpoint_path),
    }
    training_config_hash = stable_json_hash(run_config)
    run_config["training_config_hash"] = training_config_hash
    run_config_path.parent.mkdir(parents=True, exist_ok=True)
    run_config_path.write_text(json.dumps(run_config, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "run": run_id,
                "run_log": str(run_log_path),
                "run_config": str(run_config_path),
                "history_json": str(run_history_json_path),
                "history_csv": str(run_history_csv_path),
                "checkpoint_path": str(checkpoint_path),
                "run_checkpoint_path": str(run_checkpoint_path),
                "device": str(device),
                "torch_cuda_available": bool(torch.cuda.is_available()),
                "cuda_device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
                "model_attention_conv": run_config["model_attention_conv"],
                "batch_size": root_config.BATCH_SIZE,
                "grad_accum_steps": root_config.GRAD_ACCUM_STEPS,
                "effective_batch_size": root_config.BATCH_SIZE * root_config.GRAD_ACCUM_STEPS,
                "eval_batch_size": root_config.EVAL_BATCH_SIZE,
                "use_amp": use_amp,
                "amp_disabled_reason": amp_disabled_reason(device),
                "scheduler": root_config.LR_SCHEDULER,
                "warmup_epochs": root_config.WARMUP_EPOCHS,
                "lr_start": root_config.WARMUP_START_LR,
                "lr_target": root_config.LEARNING_RATE,
                "lr_min": root_config.MIN_LEARNING_RATE,
                "n_train": len(train_dataset),
                "n_val": len(val_dataset),
                "n_test": int(manifest["splits"]["test"]["count"]),
                "train_class_counts": train_class_counts,
                "class_weights": class_weight_summary.get("weights_by_class"),
                "balanced_batches": balanced_sampler,
                "label_smoothing": root_config.LABEL_SMOOTHING,
                "temporal_features_masked": bool(temporal_feature_indices),
                "temporal_feature_count": len(temporal_feature_indices),
                "training_config_hash": training_config_hash,
            },
            indent=2,
            sort_keys=True,
        )
    )
    stopped_reason = "max_epochs_reached"
    write_office_run_markdown(
        run_log_path,
        run_id=run_id,
        run_started_at=run_started_at,
        run_config=run_config,
        history=history,
        best_epoch=best_epoch,
        best_validation_macro_f1=best_validation_macro_f1,
        stopped_reason="running",
    )

    for epoch in range(1, root_config.MAX_EPOCHS + 1):
        started = time.perf_counter()
        if epoch <= root_config.WARMUP_EPOCHS:
            ratio = epoch / max(root_config.WARMUP_EPOCHS, 1)
            warmup_lr = root_config.WARMUP_START_LR + ratio * (root_config.LEARNING_RATE - root_config.WARMUP_START_LR)
            for group in optimizer.param_groups:
                group["lr"] = warmup_lr
        model.train()
        losses: list[float] = []
        optimizer.zero_grad(set_to_none=True)
        for batch_index, batch in enumerate(train_loader, start=1):
            batch = batch.to(device, non_blocking=True)
            labels = batch.y.view(-1)
            with torch.amp.autocast("cuda", enabled=use_amp):
                logits = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
                if not torch.isfinite(logits).all():
                    raise FloatingPointError(f"Non-finite logits detected during epoch {epoch}, batch {batch_index}.")
                loss = criterion(logits, labels)
            if not torch.isfinite(loss):
                raise FloatingPointError(
                    f"Non-finite loss detected during epoch {epoch}, batch {batch_index}: {float(loss.detach().cpu())}"
                )
            losses.append(float(loss.item()))
            scaled_loss = loss / root_config.GRAD_ACCUM_STEPS
            scaler.scale(scaled_loss).backward()
            if batch_index % root_config.GRAD_ACCUM_STEPS == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), root_config.GRAD_CLIP_MAX_NORM)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
                if scheduler is not None and root_config.LR_SCHEDULER == "cosine" and epoch > root_config.WARMUP_EPOCHS:
                    cosine_position = (epoch - root_config.WARMUP_EPOCHS - 1) + (
                        batch_index / max(len(train_loader), 1)
                    )
                    scheduler.step(cosine_position)
        if len(train_loader) % root_config.GRAD_ACCUM_STEPS != 0:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), root_config.GRAD_CLIP_MAX_NORM)
            scaler.step(optimizer)
            scaler.update()
            optimizer.zero_grad(set_to_none=True)
            if scheduler is not None and root_config.LR_SCHEDULER == "cosine" and epoch > root_config.WARMUP_EPOCHS:
                scheduler.step(epoch - root_config.WARMUP_EPOCHS)

        predictions, targets, batches = predict_loader(model, val_loader, device)
        metrics = class_metrics(predictions, targets, context.class_names)
        metadata = metadata_from_batches(batches)
        per_subtype_recall = subtype_recall_metrics(predictions, targets, metadata, context.class_names)
        validation_macro_f1 = float(metrics["macro_f1"])
        scheduler_monitor = root_config.PLATEAU_MONITOR if root_config.LR_SCHEDULER == "plateau" else root_config.LR_SCHEDULER
        scheduler_metric = validation_macro_f1
        if scheduler is not None and root_config.LR_SCHEDULER == "plateau" and epoch > root_config.WARMUP_EPOCHS:
            scheduler.step(scheduler_metric)
        learning_rate = current_lr(optimizer)
        is_best = validation_macro_f1 > best_validation_macro_f1
        if is_best:
            best_validation_macro_f1 = validation_macro_f1
            best_epoch = epoch
            stale_epochs = 0
        else:
            stale_epochs += 1
        row = {
            "run": run_id,
            "epoch": epoch,
            "train_loss": float(np.mean(losses)) if losses else float("nan"),
            "validation_accuracy": float(metrics["accuracy"]),
            "validation_macro_f1": validation_macro_f1,
            "validation_weighted_f1": float(metrics["weighted_f1"]),
            "learning_rate": learning_rate,
            "batch_size": root_config.BATCH_SIZE,
            "grad_accum_steps": root_config.GRAD_ACCUM_STEPS,
            "effective_batch_size": root_config.BATCH_SIZE * root_config.GRAD_ACCUM_STEPS,
            "eval_batch_size": root_config.EVAL_BATCH_SIZE,
            "use_amp": use_amp,
            "scheduler": root_config.LR_SCHEDULER,
            "scheduler_monitor": scheduler_monitor,
            "scheduler_metric": scheduler_metric,
            "best_validation_macro_f1": best_validation_macro_f1,
            "is_best": is_best,
            "stale_epochs": stale_epochs,
            "epoch_duration_seconds": time.perf_counter() - started,
            "cosine_cycle": cosine_cycle(epoch - root_config.WARMUP_EPOCHS - 1)
            if root_config.LR_SCHEDULER == "cosine"
            else 0,
            "correct": int(metrics["correct"]),
            "incorrect": int(metrics["incorrect"]),
            "total": int(metrics["total"]),
            "per_class": metrics["per_class"],
            "per_subtype_recall": per_subtype_recall,
            "confusion_matrix": metrics["confusion_matrix"],
        }
        warnings = diagnostic_warnings(row, epoch=epoch)
        row["diagnostic_warnings"] = warnings
        row["diagnostic_warning_count"] = len(warnings)
        history.append(row)
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text(json.dumps({"run_config": run_config, "history": history}, indent=2), encoding="utf-8")
        run_history_json_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
        write_office_training_history_csv(run_history_csv_path, history)
        write_office_run_markdown(
            run_log_path,
            run_id=run_id,
            run_started_at=run_started_at,
            run_config=run_config,
            history=history,
            best_epoch=best_epoch,
            best_validation_macro_f1=best_validation_macro_f1,
            stopped_reason="running",
        )
        suffix = " | BEST" if is_best else ""
        warning_suffix = f" | warnings={len(warnings)}" if warnings else ""
        print(
            f"Epoch {epoch:03d}/{root_config.MAX_EPOCHS} | "
            f"loss={row['train_loss']:.4f} | "
            f"val_acc={float(metrics['accuracy']):.4f} | "
            f"val_macro_f1={validation_macro_f1:.4f} | "
            f"val_weighted_f1={float(metrics['weighted_f1']):.4f} | "
            f"lr={learning_rate:.3g} | stale={stale_epochs}{suffix}{warning_suffix}"
        )
        if warnings:
            for warning in warnings:
                print(f"  warning: {warning}")
        if root_config.PRINT_CLASS_EVERY > 0 and epoch % root_config.PRINT_CLASS_EVERY == 0:
            per_class_line = "  " + "  ".join(
                f"{name}: {float(metrics['per_class'][name]['f1']):.3f}" for name in context.class_names
            )
            print(per_class_line)
        if is_best:
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "optimizer_state": optimizer.state_dict(),
                "scheduler_state": scheduler.state_dict() if scheduler is not None else None,
                "class_names": context.class_names,
                "best_validation_macro_f1": best_validation_macro_f1,
                "best_validation_epoch": best_epoch,
                "validation_accuracy": float(metrics["accuracy"]),
                "validation_weighted_f1": float(metrics["weighted_f1"]),
                "validation_confusion_matrix": metrics["confusion_matrix"],
                "graph_manifest_path": str(graph_manifest_path),
                "graph_manifest_hash": context.manifest_hash,
                "training_config_hash": training_config_hash,
                "config_hash": context.config_hash,
                "feature_dimensions": context.feature_dimensions,
                "checkpoint_selection_split": "val",
                "test_split_loaded_during_training": False,
                "epoch": epoch,
                "run": run_id,
                "model": "SecureEdgeHGNN",
                "model_attention_conv": office_config.architecture_policy["current_attention_conv"],
                "num_classes": len(context.class_names),
                "run_config_path": str(run_config_path),
                "run_history_json_path": str(run_history_json_path),
                "run_history_csv_path": str(run_history_csv_path),
                "run_log_path": str(run_log_path),
                "run_checkpoint_path": str(run_checkpoint_path),
                "class_weight_summary": class_weight_summary,
                "balanced_batches": balanced_sampler,
                "label_smoothing": root_config.LABEL_SMOOTHING,
                "temporal_features_masked": bool(temporal_feature_indices),
                "temporal_feature_indices": temporal_feature_indices,
                "per_subtype_recall": per_subtype_recall,
            }
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(checkpoint, checkpoint_path)
            torch.save(checkpoint, run_checkpoint_path)
        if stale_epochs >= root_config.EARLY_STOPPING_PATIENCE:
            stopped_reason = "early_stopping"
            break

    write_office_run_markdown(
        run_log_path,
        run_id=run_id,
        run_started_at=run_started_at,
        run_config=run_config,
        history=history,
        best_epoch=best_epoch,
        best_validation_macro_f1=best_validation_macro_f1,
        stopped_reason=stopped_reason,
    )

    return {
        "checkpoint_path": str(checkpoint_path),
        "history_path": str(history_path),
        "run_log_path": str(run_log_path),
        "run_history_json_path": str(run_history_json_path),
        "run_history_csv_path": str(run_history_csv_path),
        "run_checkpoint_path": str(run_checkpoint_path),
        "best_validation_macro_f1": best_validation_macro_f1,
        "best_validation_epoch": best_epoch,
        "class_names": context.class_names,
        "test_split_loaded_during_training": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the CIC-IDS-2018 office HGNN without loading the test split.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--checkpoint-path", type=Path, default=DEFAULT_OFFICE_CHECKPOINT_PATH)
    parser.add_argument("--history-path", type=Path, default=DEFAULT_OFFICE_HISTORY_PATH)
    parser.add_argument("--allow-incomplete-development-run", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = train_office_model(
        config_path=args.config,
        graph_manifest_path=args.graph_manifest,
        checkpoint_path=args.checkpoint_path,
        history_path=args.history_path,
        allow_incomplete_development_run=args.allow_incomplete_development_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
