from __future__ import annotations

import argparse
import json
import time
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
    predict_loader,
    validate_training_context,
)


DEFAULT_OFFICE_CHECKPOINT_PATH = root_config.ARTIFACTS_DIR / "office_model" / "best_office_hgnn.pt"
DEFAULT_OFFICE_HISTORY_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_training_history.json"


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
    device = training_device()
    DataLoader = require_pyg_dataloader()
    office_config = load_office_config(config_path)
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
    sample_weights, balanced_sampler = sample_weights_from_class_counts(
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
    criterion = nn.CrossEntropyLoss(weight=class_weight_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=root_config.LEARNING_RATE, weight_decay=root_config.WEIGHT_DECAY)
    use_amp = amp_is_enabled(device)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    best_validation_macro_f1 = -1.0
    best_epoch: int | None = None
    stale_epochs = 0
    history: list[dict[str, object]] = []
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_config = {
        "pipeline": "office_model_training",
        "started_at": started_at,
        "config_path": str(config_path),
        "config_hash": context.config_hash,
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": context.manifest_hash,
        "class_names": context.class_names,
        "checkpoint_selection_split": "val",
        "test_split_loaded_during_training": False,
        "batch_size": root_config.BATCH_SIZE,
        "eval_batch_size": root_config.EVAL_BATCH_SIZE,
        "max_epochs": root_config.MAX_EPOCHS,
        "early_stopping_patience": root_config.EARLY_STOPPING_PATIENCE,
        "device": str(device),
        "use_amp": use_amp,
        "amp_disabled_reason": amp_disabled_reason(device),
        "allow_incomplete_development_run": allow_incomplete_development_run,
        "imbalance_policy": office_config.imbalance_policy,
        "train_class_counts": train_class_counts,
        "class_weight_summary": class_weight_summary,
        "balanced_batches": balanced_sampler,
    }
    training_config_hash = stable_json_hash(run_config)

    for epoch in range(1, root_config.MAX_EPOCHS + 1):
        started = time.perf_counter()
        model.train()
        losses: list[float] = []
        optimizer.zero_grad(set_to_none=True)
        for batch_index, batch in enumerate(train_loader, start=1):
            batch = batch.to(device, non_blocking=True)
            labels = batch.y.view(-1)
            with torch.amp.autocast("cuda", enabled=use_amp):
                logits = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
                loss = criterion(logits, labels)
            losses.append(float(loss.item()))
            scaler.scale(loss).backward()
            if batch_index % root_config.GRAD_ACCUM_STEPS == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), root_config.GRAD_CLIP_MAX_NORM)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
        if len(train_loader) % root_config.GRAD_ACCUM_STEPS != 0:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), root_config.GRAD_CLIP_MAX_NORM)
            scaler.step(optimizer)
            scaler.update()
            optimizer.zero_grad(set_to_none=True)

        predictions, targets, _ = predict_loader(model, val_loader, device)
        metrics = class_metrics(predictions, targets, context.class_names)
        validation_macro_f1 = float(metrics["macro_f1"])
        is_best = validation_macro_f1 > best_validation_macro_f1
        if is_best:
            best_validation_macro_f1 = validation_macro_f1
            best_epoch = epoch
            stale_epochs = 0
        else:
            stale_epochs += 1
        row = {
            "epoch": epoch,
            "train_loss": float(np.mean(losses)) if losses else float("nan"),
            "validation_accuracy": float(metrics["accuracy"]),
            "validation_macro_f1": validation_macro_f1,
            "validation_weighted_f1": float(metrics["weighted_f1"]),
            "best_validation_macro_f1": best_validation_macro_f1,
            "is_best": is_best,
            "stale_epochs": stale_epochs,
            "epoch_duration_seconds": time.perf_counter() - started,
        }
        history.append(row)
        history_path.parent.mkdir(parents=True, exist_ok=True)
        history_path.write_text(json.dumps({"run_config": run_config, "history": history}, indent=2), encoding="utf-8")
        print(
            f"Epoch {epoch:03d}/{root_config.MAX_EPOCHS} | "
            f"loss={row['train_loss']:.4f} | validation_macro_f1={validation_macro_f1:.4f}"
        )
        if is_best:
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "optimizer_state": optimizer.state_dict(),
                "class_names": context.class_names,
                "best_validation_macro_f1": best_validation_macro_f1,
                "best_validation_epoch": best_epoch,
                "validation_confusion_matrix": metrics["confusion_matrix"],
                "graph_manifest_path": str(graph_manifest_path),
                "graph_manifest_hash": context.manifest_hash,
                "training_config_hash": training_config_hash,
                "config_hash": context.config_hash,
                "feature_dimensions": context.feature_dimensions,
                "checkpoint_selection_split": "val",
                "test_split_loaded_during_training": False,
                "epoch": epoch,
                "model": "SecureEdgeHGNN",
                "num_classes": len(context.class_names),
            }
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            torch.save(checkpoint, checkpoint_path)
        if stale_epochs >= root_config.EARLY_STOPPING_PATIENCE:
            break

    return {
        "checkpoint_path": str(checkpoint_path),
        "history_path": str(history_path),
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
