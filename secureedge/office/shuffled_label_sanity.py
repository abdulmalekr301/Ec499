from __future__ import annotations

import argparse
import csv
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import Dataset, WeightedRandomSampler

from secureedge import config as root_config
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import (
    amp_disabled_reason,
    amp_is_enabled,
    current_lr,
    make_loader_kwargs,
    require_pyg_dataloader,
    training_device,
)
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, load_office_config
from secureedge.office.imbalance import calculate_class_weights, split_class_counts_from_manifest
from secureedge.office.manifests import stable_json_hash
from secureedge.training.engine import (
    class_metrics,
    load_graph_dataset_from_manifest,
    load_json,
    manifest_class_names,
    predict_loader,
)


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "sanity" / "shuffled_labels"


class ShuffledLabelDataset(Dataset):
    def __init__(self, dataset: Dataset, shuffled_labels: list[int]) -> None:
        if len(dataset) != len(shuffled_labels):
            raise ValueError("Dataset length and shuffled label count must match.")
        self.dataset = dataset
        self.shuffled_labels = list(shuffled_labels)

    def __len__(self) -> int:
        return len(self.dataset)

    def __getitem__(self, index: int):
        graph = self.dataset[index].clone()
        graph.y = torch.tensor([self.shuffled_labels[index]], dtype=torch.long)
        return graph


def split_labels_from_manifest(
    manifest: dict[str, Any],
    split: str,
    class_names: list[str],
    *,
    limit_per_class: int = 0,
) -> list[int]:
    labels: list[int] = []
    paths_by_class = manifest["splits"][split]["paths"]
    for class_index, class_name in enumerate(class_names):
        count = len(paths_by_class.get(class_name, []))
        if limit_per_class > 0:
            count = min(count, limit_per_class)
        labels.extend([class_index] * count)
    return labels


def shuffle_labels_preserving_distribution(labels: list[int], *, seed: int) -> list[int]:
    shuffled = np.asarray(labels, dtype=np.int64).copy()
    rng = np.random.default_rng(seed)
    rng.shuffle(shuffled)
    return [int(value) for value in shuffled.tolist()]


def class_counts_from_labels(labels: list[int], class_names: list[str]) -> dict[str, int]:
    counts = Counter(labels)
    return {class_name: int(counts.get(index, 0)) for index, class_name in enumerate(class_names)}


def sample_weights_from_labels(labels: list[int], class_names: list[str]) -> list[float]:
    counts = class_counts_from_labels(labels, class_names)
    return [1.0 / counts[class_names[label]] for label in labels]


def write_history_csv(path: Path, history: list[dict[str, object]]) -> None:
    fieldnames = [
        "epoch",
        "train_loss",
        "validation_accuracy",
        "validation_macro_f1",
        "validation_weighted_f1",
        "learning_rate",
        "epoch_duration_seconds",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in history:
            writer.writerow({field: row.get(field) for field in fieldnames})


def write_markdown_report(path: Path, result: dict[str, Any]) -> None:
    config = result["run_config"]
    latest = result["history"][-1] if result["history"] else {}
    lines = [
        "# Office Shuffled-Label Sanity Test",
        "",
        f"Date: {result['completed_at']}",
        "",
        "## Purpose",
        "",
        "Train the office model with randomly shuffled training labels while evaluating on real validation labels.",
        "Validation performance should collapse toward chance. High validation performance would indicate a serious leakage or evaluation bug.",
        "",
        "## Configuration",
        "",
        "```text",
        f"seed={config['seed']}",
        f"epochs={config['epochs']}",
        f"device={config['device']}",
        f"model_attention_conv={config['model_attention_conv']}",
        f"batch_size={config['batch_size']}",
        f"grad_accum_steps={config['grad_accum_steps']}",
        f"use_amp={config['use_amp']}",
        f"train_label_agreement_rate={config['train_label_agreement_rate']:.6f}",
        f"train_label_agreement_count={config['train_label_agreement_count']}",
        f"train_count={config['train_count']}",
        f"validation_count={config['validation_count']}",
        "```",
        "",
        "## Per-Epoch Results",
        "",
        "| Epoch | Train loss | Val accuracy | Val macro-F1 | Val weighted-F1 | LR | Seconds |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in result["history"]:
        lines.append(
            "| "
            f"{row['epoch']} | "
            f"{float(row['train_loss']):.6f} | "
            f"{float(row['validation_accuracy']):.6f} | "
            f"{float(row['validation_macro_f1']):.6f} | "
            f"{float(row['validation_weighted_f1']):.6f} | "
            f"{float(row['learning_rate']):.8g} | "
            f"{float(row['epoch_duration_seconds']):.2f} |"
        )
    if latest:
        lines.extend(
            [
                "",
                "## Final Validation Per-Class Metrics",
                "",
                "| Class | Support | Precision | Recall | F1 | TP | FP | FN |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for class_name in config["class_names"]:
            item = latest["per_class"][class_name]
            lines.append(
                "| "
                f"{class_name} | "
                f"{item['support']} | "
                f"{float(item['precision']):.6f} | "
                f"{float(item['recall']):.6f} | "
                f"{float(item['f1']):.6f} | "
                f"{item['tp']} | "
                f"{item['fp']} | "
                f"{item['fn']} |"
            )
    lines.extend(
        [
            "",
            "## Interpretation Rule",
            "",
            "- Expected result: validation macro-F1 stays low because train labels are random.",
            "- Concerning result: validation macro-F1 remains high despite shuffled train labels.",
            "",
            "## Artifact Paths",
            "",
            f"- JSON: `{config['result_json_path']}`",
            f"- CSV: `{config['history_csv_path']}`",
            f"- Markdown: `{config['report_md_path']}`",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_shuffled_label_sanity(
    *,
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    epochs: int = 3,
    seed: int = 42,
) -> dict[str, Any]:
    if epochs < 1:
        raise ValueError("epochs must be >= 1.")
    manifest = load_json(graph_manifest_path)
    office_config = load_office_config(config_path)
    class_names = manifest_class_names(manifest)
    if class_names != office_config.class_names:
        raise ValueError(f"Manifest class names do not match config: {class_names} != {office_config.class_names}")
    if bool(manifest.get("materialization_incomplete", False)):
        raise ValueError("Refusing shuffled-label sanity test on an incomplete office graph manifest.")
    if root_config.GRAD_ACCUM_STEPS < 1:
        raise ValueError("SECUREEDGE_GRAD_ACCUM_STEPS must be >= 1.")

    device = training_device()
    DataLoader = require_pyg_dataloader()
    train_dataset = load_graph_dataset_from_manifest(
        manifest,
        "train",
        class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    val_dataset = load_graph_dataset_from_manifest(
        manifest,
        "val",
        class_names,
        limit_per_class=root_config.EVAL_LIMIT_PER_CLASS,
    )
    original_train_labels = split_labels_from_manifest(
        manifest,
        "train",
        class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    shuffled_train_labels = shuffle_labels_preserving_distribution(original_train_labels, seed=seed)
    train_label_agreement_count = sum(
        1 for original, shuffled in zip(original_train_labels, shuffled_train_labels, strict=True) if original == shuffled
    )
    shuffled_train_dataset = ShuffledLabelDataset(train_dataset, shuffled_train_labels)
    shuffled_train_counts = class_counts_from_labels(shuffled_train_labels, class_names)
    expected_train_counts = split_class_counts_from_manifest(
        manifest,
        "train",
        class_names,
        limit_per_class=root_config.TRAIN_LIMIT_PER_CLASS,
    )
    if shuffled_train_counts != expected_train_counts:
        raise ValueError("Shuffled labels must preserve the original training class distribution.")

    class_weights, class_weight_summary = calculate_class_weights(
        shuffled_train_counts,
        class_names,
        office_config.imbalance_policy,
    )
    train_sampler = WeightedRandomSampler(
        torch.as_tensor(sample_weights_from_labels(shuffled_train_labels, class_names), dtype=torch.double),
        num_samples=len(shuffled_train_labels),
        replacement=True,
    )
    train_loader = DataLoader(
        shuffled_train_dataset,
        batch_size=root_config.BATCH_SIZE,
        sampler=train_sampler,
        shuffle=False,
        **make_loader_kwargs(device),
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=root_config.EVAL_BATCH_SIZE,
        shuffle=False,
        **make_loader_kwargs(device),
    )

    model = SecureEdgeHGNN(num_classes=len(class_names)).to(device)
    class_weight_tensor = torch.tensor(class_weights, dtype=torch.float32, device=device) if class_weights else None
    criterion = nn.CrossEntropyLoss(weight=class_weight_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=root_config.LEARNING_RATE, weight_decay=root_config.WEIGHT_DECAY)
    use_amp = amp_is_enabled(device)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    if root_config.WARMUP_EPOCHS > 0:
        for group in optimizer.param_groups:
            group["lr"] = root_config.WARMUP_START_LR
    history: list[dict[str, Any]] = []
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    output_dir.mkdir(parents=True, exist_ok=True)
    result_json_path = output_dir / "shuffled_label_sanity_result.json"
    history_csv_path = output_dir / "shuffled_label_sanity_history.csv"
    report_md_path = output_dir / "shuffled_label_sanity_report.md"
    run_config = {
        "pipeline": "office_shuffled_label_sanity",
        "started_at": started_at,
        "seed": seed,
        "epochs": epochs,
        "config_path": str(config_path),
        "config_hash": office_config.config_hash,
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "class_names": class_names,
        "model_attention_conv": office_config.architecture_policy["current_attention_conv"],
        "device": str(device),
        "use_amp": use_amp,
        "amp_disabled_reason": amp_disabled_reason(device),
        "batch_size": root_config.BATCH_SIZE,
        "grad_accum_steps": root_config.GRAD_ACCUM_STEPS,
        "effective_batch_size": root_config.BATCH_SIZE * root_config.GRAD_ACCUM_STEPS,
        "eval_batch_size": root_config.EVAL_BATCH_SIZE,
        "learning_rate": root_config.LEARNING_RATE,
        "lr_start": root_config.WARMUP_START_LR,
        "lr_target": root_config.LEARNING_RATE,
        "lr_min": root_config.MIN_LEARNING_RATE,
        "warmup_epochs": root_config.WARMUP_EPOCHS,
        "weight_decay": root_config.WEIGHT_DECAY,
        "train_count": len(train_dataset),
        "validation_count": len(val_dataset),
        "train_class_counts": expected_train_counts,
        "shuffled_train_class_counts": shuffled_train_counts,
        "train_label_agreement_count": train_label_agreement_count,
        "train_label_agreement_rate": train_label_agreement_count / max(len(original_train_labels), 1),
        "class_weight_summary": class_weight_summary,
        "result_json_path": str(result_json_path),
        "history_csv_path": str(history_csv_path),
        "report_md_path": str(report_md_path),
    }
    run_config["run_config_hash"] = stable_json_hash(run_config)
    print(json.dumps(run_config, indent=2, sort_keys=True))

    for epoch in range(1, epochs + 1):
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
            scaler.scale(loss / root_config.GRAD_ACCUM_STEPS).backward()
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
        metrics = class_metrics(predictions, targets, class_names)
        row = {
            "epoch": epoch,
            "train_loss": float(np.mean(losses)) if losses else float("nan"),
            "validation_accuracy": float(metrics["accuracy"]),
            "validation_macro_f1": float(metrics["macro_f1"]),
            "validation_weighted_f1": float(metrics["weighted_f1"]),
            "learning_rate": current_lr(optimizer),
            "epoch_duration_seconds": time.perf_counter() - started,
            "per_class": metrics["per_class"],
            "confusion_matrix": metrics["confusion_matrix"],
        }
        history.append(row)
        result = {
            "run_config": run_config,
            "history": history,
            "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        result_json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        write_history_csv(history_csv_path, history)
        write_markdown_report(report_md_path, result)
        print(
            f"Epoch {epoch:03d}/{epochs:03d} | "
            f"loss={row['train_loss']:.4f} | "
            f"val_acc={row['validation_accuracy']:.4f} | "
            f"val_macro_f1={row['validation_macro_f1']:.4f} | "
            f"val_weighted_f1={row['validation_weighted_f1']:.4f}"
        )

    return {
        "run_config": run_config,
        "history": history,
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an office shuffled-label sanity training test.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--seed", type=int, default=root_config.RANDOM_SEED)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = run_shuffled_label_sanity(
        config_path=args.config,
        graph_manifest_path=args.graph_manifest,
        output_dir=args.output_dir,
        epochs=args.epochs,
        seed=args.seed,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
