from __future__ import annotations

import csv
import json
import math
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import confusion_matrix, f1_score
from torch import nn

from secureedge import config
from secureedge.data.dataset import load_graph_dataset, load_graph_manifest
from secureedge.models.hgnn import SecureEdgeHGNN, document_architecture
from secureedge.utils import ensure_directories, write_context


def require_pyg_dataloader():
    try:
        from torch_geometric.loader import DataLoader
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "PyTorch Geometric is required for graph training. Install torch-geometric "
            "and its matching sparse dependencies before running training."
        ) from exc
    return DataLoader


def move_batch(batch, device: torch.device):
    return batch.to(device, non_blocking=True)


def logits_for_batch(model: SecureEdgeHGNN, batch) -> torch.Tensor:
    return model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)


def bool_label(value: bool) -> str:
    return "yes" if value else "no"


def training_device() -> torch.device:
    if config.DEVICE == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    if config.DEVICE == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("SECUREEDGE_DEVICE=cuda was requested, but CUDA is not available to PyTorch.")
    if config.DEVICE not in {"cpu", "cuda"}:
        raise ValueError("SECUREEDGE_DEVICE must be one of: auto, cpu, cuda")
    return torch.device(config.DEVICE)


def amp_disabled_reason(device: torch.device) -> str | None:
    if not config.USE_AMP:
        return "SECUREEDGE_USE_AMP=0"
    if device.type != "cuda":
        return "device_is_not_cuda"
    if config.GRAPH_VALUE_MODE == "raw":
        return "raw_graph_values_can_exceed_fp16_range"
    return None


def amp_is_enabled(device: torch.device) -> bool:
    return amp_disabled_reason(device) is None


def make_loader_kwargs(device: torch.device, num_workers: int | None = None) -> dict[str, object]:
    workers = config.NUM_WORKERS if num_workers is None else num_workers
    kwargs: dict[str, object] = {
        "num_workers": workers,
        "pin_memory": device.type == "cuda",
    }
    if workers > 0:
        kwargs["persistent_workers"] = True
        kwargs["prefetch_factor"] = config.PREFETCH_FACTOR
    return kwargs


def next_training_run_id() -> int:
    pattern = re.compile(r"logs-(\d+)\.md$")
    run_ids = []
    for path in config.CONTEXT_DIR.glob("logs-*.md"):
        match = pattern.match(path.name)
        if match:
            run_ids.append(int(match.group(1)))
    return max(run_ids, default=0) + 1


def load_shard_manifest() -> dict[str, object]:
    if not config.GRAPH_SHARD_MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Graph shard manifest not found: {config.GRAPH_SHARD_MANIFEST_PATH}. "
            "Run `.venv/bin/python -m secureedge.data.create_shards --overwrite` before training, "
            "or set SECUREEDGE_USE_GRAPH_SHARDS=0 to use the slower individual graph files."
        )
    return json.loads(config.GRAPH_SHARD_MANIFEST_PATH.read_text(encoding="utf-8"))


def shard_entries(manifest: dict[str, object], split: str) -> list[dict[str, object]]:
    entries = list(manifest["splits"][split]["shards"])
    missing = [entry["path"] for entry in entries if not Path(str(entry["path"])).exists()]
    if missing:
        raise FileNotFoundError(f"Shard manifest references missing {split} shard files: {missing[:10]}")
    return entries


def load_shard_graphs(path: str | Path) -> list:
    graphs = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(graphs, list):
        raise TypeError(f"Expected shard {path} to contain a list of graphs, found {type(graphs)!r}")
    return graphs


def epoch_batch_count_from_shards(entries: list[dict[str, object]]) -> int:
    return sum(math.ceil(int(entry["count"]) / config.BATCH_SIZE) for entry in entries)


def compute_class_metrics(predictions: np.ndarray, targets: np.ndarray) -> dict[str, dict[str, float | int]]:
    labels = list(range(len(config.CLASS_NAMES)))
    cm = confusion_matrix(targets, predictions, labels=labels)
    total = int(cm.sum())
    metrics: dict[str, dict[str, float | int]] = {}
    for index, class_name in enumerate(config.CLASS_NAMES):
        tp = int(cm[index, index])
        fn = int(cm[index, :].sum() - tp)
        fp = int(cm[:, index].sum() - tp)
        tn = int(total - tp - fn - fp)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = (2.0 * precision * recall / max(precision + recall, 1e-12)) if (precision + recall) else 0.0
        metrics[class_name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "support": int(cm[index, :].sum()),
            "predicted_as_class": int(cm[:, index].sum()),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "false_positive_rate": float(fp / max(fp + tn, 1)),
            "false_negative_rate": float(fn / max(fn + tp, 1)),
        }
    return metrics


def evaluate_metrics_on_loader(model: SecureEdgeHGNN, loader, device: torch.device) -> tuple[list[np.ndarray], list[np.ndarray]]:
    predictions: list[np.ndarray] = []
    targets: list[np.ndarray] = []
    with torch.no_grad():
        for batch in loader:
            batch = move_batch(batch, device)
            logits = logits_for_batch(model, batch)
            predictions.append(torch.argmax(logits, dim=1).cpu().numpy())
            targets.append(batch.y.view(-1).cpu().numpy())
    return predictions, targets


def evaluate_metrics(model: SecureEdgeHGNN, eval_source, DataLoader, device: torch.device, use_shards: bool) -> dict[str, object]:
    model.eval()
    predictions: list[np.ndarray] = []
    targets: list[np.ndarray] = []
    if use_shards:
        for entry in eval_source:
            graphs = load_shard_graphs(entry["path"])
            loader = DataLoader(
                graphs,
                batch_size=config.EVAL_BATCH_SIZE,
                shuffle=False,
                **make_loader_kwargs(device, num_workers=0),
            )
            shard_predictions, shard_targets = evaluate_metrics_on_loader(model, loader, device)
            predictions.extend(shard_predictions)
            targets.extend(shard_targets)
            del graphs
    else:
        predictions, targets = evaluate_metrics_on_loader(model, eval_source, device)

    y_pred = np.concatenate(predictions)
    y_true = np.concatenate(targets)
    class_metrics = compute_class_metrics(y_pred, y_true)
    accuracy = float(np.mean(y_pred == y_true))
    return {
        "accuracy": accuracy,
        "correct": int(np.sum(y_pred == y_true)),
        "incorrect": int(np.sum(y_pred != y_true)),
        "total": int(y_true.shape[0]),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "per_class": class_metrics,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=list(range(len(config.CLASS_NAMES)))).tolist(),
    }


def evaluate_macro_f1(model: SecureEdgeHGNN, loader, device: torch.device) -> float:
    metrics = evaluate_metrics(model, loader, None, device, use_shards=False)
    return float(metrics["macro_f1"])


def current_lr(optimizer: torch.optim.Optimizer) -> float:
    return float(optimizer.param_groups[0]["lr"])


def model_signature() -> dict[str, object]:
    return {
        "model": "SecureEdgeHGNN",
        "flow_node": config.N_FLOW_NODE_FEATURES,
        "packet_node": config.N_PACKET_FEATURES,
        "contain_edge": config.N_CONTAIN_EDGE_FEATS,
        "link_edge": config.N_LINK_EDGE_FEATS,
        "hidden_size": config.HGNN_HIDDEN_SIZE,
        "attn_size": config.HGNN_ATTN_SIZE,
        "heads": 2,
        "batchnorm_eps": config.HGNN_BATCHNORM_EPS,
        "readout_mode": config.HGNN_READOUT_MODE,
        "use_payload_encoder": config.USE_PAYLOAD_ENCODER,
    }


def checkpoint_signature_compatible(checkpoint: dict[str, object]) -> bool:
    return checkpoint.get("model_signature") == model_signature()


def checkpoint_macro_f1(path: Path) -> float | None:
    if not path.exists():
        return None
    checkpoint = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(checkpoint, dict):
        return None
    if not checkpoint_signature_compatible(checkpoint):
        return None
    value = checkpoint.get("best_macro_f1", checkpoint.get("macro_f1"))
    if value is None:
        return None
    return float(value)


def cosine_cycle(epoch_index_after_warmup: float) -> int:
    if epoch_index_after_warmup < 0:
        return 0
    cycle = 1
    cycle_len = config.COSINE_T0
    remaining = epoch_index_after_warmup
    while remaining >= cycle_len:
        remaining -= cycle_len
        cycle += 1
        cycle_len *= config.COSINE_T_MULT
    return cycle


def write_training_history_csv(path: Path, history: list[dict[str, object]]) -> None:
    fieldnames = [
        "run",
        "epoch",
        "train_loss",
        "accuracy",
        "macro_f1",
        "learning_rate",
        "batch_size",
        "grad_accum_steps",
        "effective_batch_size",
        "use_amp",
        "heads",
        "scheduler",
        "scheduler_monitor",
        "scheduler_metric",
        "stale_epochs",
        "best_f1_so_far",
        "is_best",
        "epoch_duration_seconds",
        "seconds",
        "cosine_cycle",
        "correct",
        "incorrect",
        "total",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in history:
            writer.writerow({field: row.get(field) for field in fieldnames})


def load_resume_state(
    model: SecureEdgeHGNN,
    optimizer: torch.optim.Optimizer,
    scheduler,
    device: torch.device,
) -> dict[str, object]:
    if not config.RESUME_CHECKPOINT_PATH.exists():
        raise FileNotFoundError(f"Resume checkpoint not found: {config.RESUME_CHECKPOINT_PATH}")
    checkpoint = torch.load(config.RESUME_CHECKPOINT_PATH, map_location=device, weights_only=False)
    if not isinstance(checkpoint, dict):
        raise TypeError(f"Expected checkpoint dictionary, found {type(checkpoint)!r}")
    if not checkpoint_signature_compatible(checkpoint):
        raise ValueError(
            f"Checkpoint {config.RESUME_CHECKPOINT_PATH} was saved with an incompatible model architecture. "
            "Start from scratch for this architecture, or set the current architecture env vars to match the checkpoint."
        )
    model.load_state_dict(checkpoint["model_state_dict"])
    if config.RESUME_LOAD_OPTIMIZER and "optimizer_state" in checkpoint:
        optimizer.load_state_dict(checkpoint["optimizer_state"])
    scheduler_state = checkpoint.get("scheduler_state")
    if config.RESUME_LOAD_SCHEDULER and scheduler is not None and scheduler_state is not None:
        scheduler.load_state_dict(scheduler_state)
    checkpoint_epoch = int(checkpoint.get("epoch", 0))
    if checkpoint_epoch < 1:
        raise ValueError(f"Checkpoint {config.RESUME_CHECKPOINT_PATH} does not contain a valid epoch number.")
    return {
        "path": str(config.RESUME_CHECKPOINT_PATH),
        "source_run_id": checkpoint.get("run_id"),
        "checkpoint_epoch": checkpoint_epoch,
        "best_macro_f1": float(checkpoint.get("best_macro_f1", checkpoint.get("macro_f1", -1.0))),
        "optimizer_loaded": bool(config.RESUME_LOAD_OPTIMIZER and "optimizer_state" in checkpoint),
        "scheduler_loaded": bool(config.RESUME_LOAD_SCHEDULER and scheduler is not None and scheduler_state is not None),
    }


def markdown_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
    return lines


def write_run_markdown(
    path: Path,
    run_id: int,
    run_started_at: str,
    device: torch.device,
    history: list[dict[str, object]],
    best_epoch: int | None,
    best_f1: float,
    stopped_reason: str,
    resume_info: dict[str, object] | None = None,
) -> None:
    latest = history[-1] if history else {}
    lines = [
        f"# SecureEdge Training Run {run_id}",
        "",
        f"> Run started: `{run_started_at}`",
        f"> Last updated: `{datetime.now(timezone.utc).isoformat(timespec='seconds')}`",
        "",
        "## Configuration",
        "",
        "```text",
        f"device={device}",
        f"batch_size={config.BATCH_SIZE}",
        f"grad_accum_steps={config.GRAD_ACCUM_STEPS}",
        f"effective_batch_size={config.BATCH_SIZE * config.GRAD_ACCUM_STEPS}",
        f"eval_batch_size={config.EVAL_BATCH_SIZE}",
        f"use_amp={bool_label(amp_is_enabled(device))}",
        f"amp_disabled_reason={amp_disabled_reason(device)}",
        f"use_graph_shards={bool_label(config.USE_GRAPH_SHARDS)}",
        "checkpoint_selection_split=val",
        f"num_workers={config.NUM_WORKERS}",
        f"prefetch_factor={config.PREFETCH_FACTOR}",
        f"lr_start={config.WARMUP_START_LR}",
        f"lr_target={config.LEARNING_RATE}",
        f"lr_min={config.MIN_LEARNING_RATE}",
        f"scheduler={config.LR_SCHEDULER}",
        f"plateau_monitor={config.PLATEAU_MONITOR}",
        f"plateau_threshold={config.PLATEAU_THRESHOLD}",
        f"cosine_t0={config.COSINE_T0}",
        f"cosine_t_mult={config.COSINE_T_MULT}",
        f"label_smoothing={config.LABEL_SMOOTHING}",
        f"max_epochs={config.MAX_EPOCHS}",
        f"early_stop_patience={config.EARLY_STOPPING_PATIENCE}",
        f"print_class_every={config.PRINT_CLASS_EVERY}",
        "```",
        "",
        "## Current Status",
        "",
        f"- Stopped reason: `{stopped_reason}`.",
        f"- Epochs completed: `{len(history)}`.",
        f"- Best epoch: `{best_epoch}`.",
        f"- Best validation macro F1: `{best_f1:.6f}`.",
    ]
    if resume_info:
        lines.extend(
            [
                "",
                "## Resume Source",
                "",
                f"- Checkpoint: `{resume_info['path']}`.",
                f"- Source run: `{resume_info['source_run_id']}`.",
                f"- Source best epoch: `{resume_info['checkpoint_epoch']}`.",
                f"- Source best macro F1: `{float(resume_info['best_macro_f1']):.6f}`.",
                f"- Optimizer state loaded: `{bool_label(bool(resume_info['optimizer_loaded']))}`.",
                f"- Scheduler state loaded: `{bool_label(bool(resume_info['scheduler_loaded']))}`.",
            ]
        )
    if latest:
        lines.extend(
            [
                f"- Latest validation accuracy: `{float(latest['accuracy']):.6f}`.",
                f"- Latest validation macro F1: `{float(latest['macro_f1']):.6f}`.",
                f"- Latest train loss: `{float(latest['train_loss']):.6f}`.",
                f"- Latest learning rate: `{float(latest['learning_rate']):.8g}`.",
                "",
                "## Per-Epoch Summary",
                "",
            ]
        )
        rows = [
            [
                row["epoch"],
                f"{float(row['train_loss']):.6f}",
                f"{float(row['accuracy']):.6f}",
                f"{float(row['macro_f1']):.6f}",
                f"{float(row['learning_rate']):.8g}",
                f"{float(row.get('scheduler_metric', 0.0)):.6f}",
                row["stale_epochs"],
                f"{float(row['best_f1_so_far']):.6f}",
                row["cosine_cycle"],
                f"{float(row['epoch_duration_seconds']):.2f}",
                "yes" if row["is_best"] else "no",
            ]
            for row in history
        ]
        lines.extend(
            markdown_table(
                [
                    "Epoch",
                    "Train Loss",
                    "Val Accuracy",
                    "Val Macro F1",
                    "LR",
                    "Scheduler Metric",
                    "Stale",
                    "Best Val F1",
                    "Cycle",
                    "Seconds",
                    "Best",
                ],
                rows,
            )
        )
        lines.extend(["", "## Latest Validation Per-Class FP/FN Rates", ""])
        per_class = latest.get("per_class", {})
        class_rows = []
        for class_name in config.CLASS_NAMES:
            item = per_class[class_name]
            class_rows.append(
                [
                    class_name,
                    item["tp"],
                    item["fp"],
                    item["fn"],
                    item["tn"],
                    f"{float(item['f1']):.6f}",
                    f"{float(item['false_positive_rate']):.6f}",
                    f"{float(item['false_negative_rate']):.6f}",
                ]
            )
        lines.extend(markdown_table(["Class", "TP", "FP", "FN", "TN", "F1", "FP Rate", "FN Rate"], class_rows))
        lines.extend(
            [
                "",
                "## Full Machine-Readable History",
                "",
                f"- JSON: `artifacts/training_runs/run_{run_id:02d}_history.json`",
                f"- CSV: `artifacts/training_runs/run_{run_id:02d}_history.csv`",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def train() -> None:
    ensure_directories()
    manifest = load_graph_manifest()
    expected_train = config.TRAIN_SAMPLES_PER_CLASS * len(config.CLASS_NAMES)
    if int(manifest["splits"]["train"]["count"]) != expected_train:
        raise ValueError("Run full graph preprocessing before training; the current graph manifest is not the final train split.")
    if int(manifest["splits"].get("val", {}).get("count", 0)) <= 0:
        raise ValueError("Run graph preprocessing with validation enabled before training; the current graph manifest has no val split.")
    if int(manifest["splits"]["test"]["count"]) <= 0:
        raise ValueError("Run full graph preprocessing before training; the current graph manifest has no test split.")
    device = training_device()
    run_id = next_training_run_id()
    run_started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_history_json_path = config.TRAINING_RUNS_DIR / f"run_{run_id:02d}_history.json"
    run_history_csv_path = config.TRAINING_RUNS_DIR / f"run_{run_id:02d}_history.csv"
    run_config_path = config.TRAINING_RUNS_DIR / f"run_{run_id:02d}_config.json"
    run_checkpoint_path = config.TRAINING_RUNS_DIR / f"run_{run_id:02d}_best_hgnn.pt"
    run_log_path = config.CONTEXT_DIR / f"logs-{run_id}.md"
    print(
        json.dumps(
            {
                "run_id": run_id,
                "run_log": str(run_log_path),
                "device": str(device),
                "torch_cuda_available": bool(torch.cuda.is_available()),
                "torch_cuda_version": torch.version.cuda,
                "cuda_device_count": int(torch.cuda.device_count()),
                "cuda_device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
                "batch_size": config.BATCH_SIZE,
                "grad_accum_steps": config.GRAD_ACCUM_STEPS,
                "effective_batch_size": config.BATCH_SIZE * config.GRAD_ACCUM_STEPS,
                "eval_batch_size": config.EVAL_BATCH_SIZE,
                "use_amp": amp_is_enabled(device),
                "amp_disabled_reason": amp_disabled_reason(device),
                "use_graph_shards": config.USE_GRAPH_SHARDS,
                "train_limit_per_class": config.TRAIN_LIMIT_PER_CLASS,
                "validation_limit_per_class": config.EVAL_LIMIT_PER_CLASS,
                "eval_limit_per_class": config.EVAL_LIMIT_PER_CLASS,
                "max_epochs": config.MAX_EPOCHS,
                "scheduler": config.LR_SCHEDULER,
                "plateau_monitor": config.PLATEAU_MONITOR,
                "plateau_threshold": config.PLATEAU_THRESHOLD,
                "label_smoothing": config.LABEL_SMOOTHING,
                "resume_from_checkpoint": config.RESUME_FROM_CHECKPOINT,
                "resume_checkpoint_path": str(config.RESUME_CHECKPOINT_PATH) if config.RESUME_FROM_CHECKPOINT else None,
            },
            indent=2,
        )
    )

    DataLoader = require_pyg_dataloader()
    if config.USE_GRAPH_SHARDS:
        shard_manifest = load_shard_manifest()
        train_source = shard_entries(shard_manifest, "train")
        eval_source = shard_entries(shard_manifest, "val")
        n_batches_per_epoch = epoch_batch_count_from_shards(train_source)
    else:
        shard_manifest = None
        train_dataset = load_graph_dataset("train", limit_per_class=config.TRAIN_LIMIT_PER_CLASS)
        val_dataset = load_graph_dataset("val", limit_per_class=config.EVAL_LIMIT_PER_CLASS)
        train_source = DataLoader(
            train_dataset,
            batch_size=config.BATCH_SIZE,
            shuffle=True,
            **make_loader_kwargs(device),
        )
        eval_source = DataLoader(
            val_dataset,
            batch_size=config.EVAL_BATCH_SIZE,
            shuffle=False,
            **make_loader_kwargs(device),
        )
        n_batches_per_epoch = len(train_source)

    run_config = {
        "run_id": run_id,
        "started_at": run_started_at,
        "device": str(device),
        "cuda_available": bool(torch.cuda.is_available()),
        "cuda_device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "batch_size": config.BATCH_SIZE,
        "grad_accum_steps": config.GRAD_ACCUM_STEPS,
        "effective_batch_size": config.BATCH_SIZE * config.GRAD_ACCUM_STEPS,
        "eval_batch_size": config.EVAL_BATCH_SIZE,
        "use_amp": amp_is_enabled(device),
        "amp_disabled_reason": amp_disabled_reason(device),
        "use_graph_shards": config.USE_GRAPH_SHARDS,
        "validation_split": "val",
        "num_workers": config.NUM_WORKERS,
        "prefetch_factor": config.PREFETCH_FACTOR,
        "lr_start": config.WARMUP_START_LR,
        "lr_target": config.LEARNING_RATE,
        "lr_min": config.MIN_LEARNING_RATE,
        "scheduler": config.LR_SCHEDULER,
        "plateau_monitor": config.PLATEAU_MONITOR,
        "plateau_threshold": config.PLATEAU_THRESHOLD,
        "cosine_t0": config.COSINE_T0,
        "cosine_t_mult": config.COSINE_T_MULT,
        "label_smoothing": config.LABEL_SMOOTHING,
        "max_epochs": config.MAX_EPOCHS,
        "early_stopping_patience": config.EARLY_STOPPING_PATIENCE,
        "n_batches_per_epoch": n_batches_per_epoch,
        "n_train": int(manifest["splits"]["train"]["count"]),
        "n_val": int(manifest["splits"]["val"]["count"]),
        "n_test": int(manifest["splits"]["test"]["count"]),
        "print_class_every": config.PRINT_CLASS_EVERY,
        "run_checkpoint_path": str(run_checkpoint_path),
        "global_checkpoint_path": str(config.HGNN_CHECKPOINT_PATH),
        "resume_from_checkpoint": config.RESUME_FROM_CHECKPOINT,
        "resume_checkpoint_path": str(config.RESUME_CHECKPOINT_PATH) if config.RESUME_FROM_CHECKPOINT else None,
        "resume_load_optimizer": config.RESUME_LOAD_OPTIMIZER,
        "resume_load_scheduler": config.RESUME_LOAD_SCHEDULER,
    }

    model = SecureEdgeHGNN().to(device)
    document_architecture()
    if config.LABEL_SMOOTHING != 0.0:
        raise ValueError("XG-NID oversampling training expects SECUREEDGE_LABEL_SMOOTHING=0.0.")
    if config.GRAD_ACCUM_STEPS < 1:
        raise ValueError("SECUREEDGE_GRAD_ACCUM_STEPS must be >= 1.")
    if config.PLATEAU_MONITOR not in {"val_macro_f1", "train_accuracy"}:
        raise ValueError("SECUREEDGE_PLATEAU_MONITOR must be one of: val_macro_f1, train_accuracy")
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=config.LEARNING_RATE, weight_decay=config.WEIGHT_DECAY)
    use_amp = amp_is_enabled(device)
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    if config.WARMUP_EPOCHS > 0:
        for group in optimizer.param_groups:
            group["lr"] = config.WARMUP_START_LR
    if config.LR_SCHEDULER == "cosine":
        scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
            optimizer,
            T_0=config.COSINE_T0,
            T_mult=config.COSINE_T_MULT,
            eta_min=config.MIN_LEARNING_RATE,
        )
    elif config.LR_SCHEDULER == "plateau":
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer,
            mode="max",
            factor=0.5,
            patience=config.LR_SCHEDULER_PATIENCE,
            threshold=config.PLATEAU_THRESHOLD,
            min_lr=config.MIN_LEARNING_RATE,
        )
    elif config.LR_SCHEDULER == "none":
        scheduler = None
    else:
        raise ValueError("SECUREEDGE_SCHEDULER must be one of: cosine, plateau, none")

    resume_info = None
    start_epoch = 1
    best_f1 = -1.0
    best_epoch: int | None = None
    stale_epochs = 0
    if config.RESUME_FROM_CHECKPOINT:
        resume_info = load_resume_state(model, optimizer, scheduler, device)
        checkpoint_epoch = int(resume_info["checkpoint_epoch"])
        if config.MAX_EPOCHS <= checkpoint_epoch:
            raise ValueError(
                "SECUREEDGE_MAX_EPOCHS must be greater than the checkpoint epoch when resuming. "
                f"Checkpoint epoch is {checkpoint_epoch}, but SECUREEDGE_MAX_EPOCHS is {config.MAX_EPOCHS}."
            )
        start_epoch = checkpoint_epoch + 1
        best_epoch = checkpoint_epoch
        best_f1 = float(resume_info["best_macro_f1"])
        run_config["resume_source"] = resume_info
    run_config["start_epoch"] = start_epoch
    run_config_path.write_text(json.dumps(run_config, indent=2), encoding="utf-8")

    history: list[dict[str, float]] = []
    stopped_reason = "max_epochs_reached"
    write_run_markdown(run_log_path, run_id, run_started_at, device, history, best_epoch, best_f1, "running", resume_info)
    for epoch in range(start_epoch, config.MAX_EPOCHS + 1):
        epoch_started = time.perf_counter()
        if epoch <= config.WARMUP_EPOCHS:
            ratio = epoch / max(config.WARMUP_EPOCHS, 1)
            warmup_lr = config.WARMUP_START_LR + ratio * (config.LEARNING_RATE - config.WARMUP_START_LR)
            for group in optimizer.param_groups:
                group["lr"] = warmup_lr

        model.train()
        losses: list[float] = []
        batch_index = 0
        optimizer.zero_grad(set_to_none=True)

        def train_batch(batch) -> None:
            nonlocal batch_index
            batch = move_batch(batch, device)
            labels = batch.y.view(-1)
            with torch.amp.autocast("cuda", enabled=use_amp):
                logits = logits_for_batch(model, batch)
                if not torch.isfinite(logits).all():
                    raise FloatingPointError(
                        f"Non-finite logits detected during epoch {epoch}, batch {batch_index + 1}."
                    )
                loss = criterion(logits, labels)
            if not torch.isfinite(loss):
                raise FloatingPointError(
                    f"Non-finite loss detected during epoch {epoch}, batch {batch_index + 1}: {float(loss.detach().cpu())}"
                )
            losses.append(float(loss.item()))
            scaled_loss = loss / config.GRAD_ACCUM_STEPS
            scaler.scale(scaled_loss).backward()
            batch_index += 1
            if batch_index % config.GRAD_ACCUM_STEPS == 0:
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), config.GRAD_CLIP_MAX_NORM)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
                if scheduler is not None and config.LR_SCHEDULER == "cosine" and epoch > config.WARMUP_EPOCHS:
                    cosine_position = (epoch - config.WARMUP_EPOCHS - 1) + (batch_index / max(n_batches_per_epoch, 1))
                    scheduler.step(cosine_position)

        if config.USE_GRAPH_SHARDS:
            epoch_shards = list(train_source)
            random.Random(config.RANDOM_SEED + epoch).shuffle(epoch_shards)
            for entry in epoch_shards:
                graphs = load_shard_graphs(entry["path"])
                random.Random(config.RANDOM_SEED + epoch + batch_index).shuffle(graphs)
                shard_loader = DataLoader(
                    graphs,
                    batch_size=config.BATCH_SIZE,
                    shuffle=False,
                    **make_loader_kwargs(device, num_workers=0),
                )
                for batch in shard_loader:
                    train_batch(batch)
                del graphs
        else:
            for batch in train_source:
                train_batch(batch)
        if batch_index % config.GRAD_ACCUM_STEPS != 0:
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), config.GRAD_CLIP_MAX_NORM)
            scaler.step(optimizer)
            scaler.update()
            optimizer.zero_grad(set_to_none=True)
            if scheduler is not None and config.LR_SCHEDULER == "cosine" and epoch > config.WARMUP_EPOCHS:
                cosine_position = epoch - config.WARMUP_EPOCHS
                scheduler.step(cosine_position)

        metrics = evaluate_metrics(model, eval_source, DataLoader, device, use_shards=config.USE_GRAPH_SHARDS)
        macro_f1 = float(metrics["macro_f1"])
        scheduler_monitor = config.PLATEAU_MONITOR if config.LR_SCHEDULER == "plateau" else config.LR_SCHEDULER
        scheduler_metric = macro_f1
        if scheduler is not None and config.LR_SCHEDULER == "plateau" and epoch > config.WARMUP_EPOCHS:
            if config.PLATEAU_MONITOR == "train_accuracy":
                train_metrics = evaluate_metrics(model, train_source, DataLoader, device, use_shards=config.USE_GRAPH_SHARDS)
                scheduler_metric = float(train_metrics["accuracy"])
            scheduler.step(scheduler_metric)
        learning_rate = current_lr(optimizer)
        train_loss = float(np.mean(losses)) if losses else float("nan")
        previous_best = best_f1
        is_best = macro_f1 > best_f1
        if is_best:
            best_f1 = macro_f1
            best_epoch = epoch
            stale_epochs = 0
        else:
            stale_epochs += 1
        epoch_duration = time.perf_counter() - epoch_started
        row = {
            "run": run_id,
            "epoch": epoch,
            "train_loss": train_loss,
            "accuracy": float(metrics["accuracy"]),
            "macro_f1": macro_f1,
            "learning_rate": learning_rate,
            "batch_size": config.BATCH_SIZE,
            "grad_accum_steps": config.GRAD_ACCUM_STEPS,
            "effective_batch_size": config.BATCH_SIZE * config.GRAD_ACCUM_STEPS,
            "eval_batch_size": config.EVAL_BATCH_SIZE,
            "use_amp": use_amp,
            "heads": 2,
            "scheduler": config.LR_SCHEDULER,
            "scheduler_monitor": scheduler_monitor,
            "scheduler_metric": scheduler_metric,
            "stale_epochs": stale_epochs,
            "best_f1_so_far": best_f1,
            "is_best": is_best,
            "epoch_duration_seconds": epoch_duration,
            "seconds": epoch_duration,
            "cosine_cycle": cosine_cycle(epoch - config.WARMUP_EPOCHS - 1) if config.LR_SCHEDULER == "cosine" else 0,
            "correct": int(metrics["correct"]),
            "incorrect": int(metrics["incorrect"]),
            "total": int(metrics["total"]),
            "per_class": metrics["per_class"],
            "confusion_matrix": metrics["confusion_matrix"],
        }
        history.append(row)
        run_history_json_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
        write_training_history_csv(run_history_csv_path, history)
        write_run_markdown(run_log_path, run_id, run_started_at, device, history, best_epoch, best_f1, "running", resume_info)
        suffix = " | BEST" if is_best else ""
        print(
            f"Epoch {epoch:03d}/{config.MAX_EPOCHS} | Loss: {train_loss:.4f} | "
            f"Acc: {float(metrics['accuracy']):.4f} | F1: {macro_f1:.4f} | "
            f"LR: {learning_rate:.3g} | Stale: {stale_epochs}{suffix}"
        )
        if config.PRINT_CLASS_EVERY > 0 and epoch % config.PRINT_CLASS_EVERY == 0:
            per_class_line = "  " + "  ".join(
                f"{name}: {float(metrics['per_class'][name]['f1']):.3f}" for name in config.CLASS_NAMES
            )
            print(per_class_line)

        if is_best:
            checkpoint = {
                "model_state_dict": model.state_dict(),
                "optimizer_state": optimizer.state_dict(),
                "scheduler_state": scheduler.state_dict() if scheduler is not None else None,
                "class_names": config.CLASS_NAMES,
                "best_macro_f1": best_f1,
                "macro_f1": macro_f1,
                "epoch": epoch,
                "graph_manifest": str(config.GRAPH_MANIFEST_PATH),
                "shard_manifest": str(config.GRAPH_SHARD_MANIFEST_PATH) if config.USE_GRAPH_SHARDS else None,
                "feature_dimensions": manifest["feature_dimensions"],
                "model": "SecureEdgeHGNN",
                "model_signature": model_signature(),
                "train_limit_per_class": config.TRAIN_LIMIT_PER_CLASS,
                "eval_limit_per_class": config.EVAL_LIMIT_PER_CLASS,
                "checkpoint_selection_split": "val",
                "device": str(device),
                "run_id": run_id,
                "history_json": str(run_history_json_path),
                "history_csv": str(run_history_csv_path),
                "run_checkpoint": str(run_checkpoint_path),
                "global_checkpoint": str(config.HGNN_CHECKPOINT_PATH),
                "resumed_from": resume_info,
                "config": {
                    "flow_node": config.N_FLOW_NODE_FEATURES,
                    "packet_node": config.N_PACKET_FEATURES,
                    "contain_edge": config.N_CONTAIN_EDGE_FEATS,
                    "link_edge": config.N_LINK_EDGE_FEATS,
                    "label_smoothing": config.LABEL_SMOOTHING,
                    "lr_target": config.LEARNING_RATE,
                    "lr_min": config.MIN_LEARNING_RATE,
                    "scheduler": config.LR_SCHEDULER,
                    "plateau_monitor": config.PLATEAU_MONITOR,
                    "plateau_threshold": config.PLATEAU_THRESHOLD,
                    "batch_size": config.BATCH_SIZE,
                    "grad_accum_steps": config.GRAD_ACCUM_STEPS,
                    "effective_batch_size": config.BATCH_SIZE * config.GRAD_ACCUM_STEPS,
                    "use_amp": use_amp,
                    "amp_disabled_reason": amp_disabled_reason(device),
                    "readout_mode": config.HGNN_READOUT_MODE,
                    "use_payload_encoder": config.USE_PAYLOAD_ENCODER,
                    "batchnorm_eps": config.HGNN_BATCHNORM_EPS,
                    "graph_value_mode": manifest.get("graph_value_mode", "scaled"),
                },
            }
            torch.save(checkpoint, run_checkpoint_path)
            incumbent_global_f1 = checkpoint_macro_f1(config.HGNN_CHECKPOINT_PATH)
            promoted_to_global = incumbent_global_f1 is None or best_f1 > incumbent_global_f1
            if promoted_to_global:
                checkpoint["global_best_replaced_macro_f1"] = incumbent_global_f1
                torch.save(checkpoint, config.HGNN_CHECKPOINT_PATH)
            else:
                checkpoint["global_best_replaced_macro_f1"] = None
                checkpoint["global_best_retained_macro_f1"] = incumbent_global_f1
                torch.save(checkpoint, run_checkpoint_path)
        if stale_epochs >= config.EARLY_STOPPING_PATIENCE:
            stopped_reason = "early_stopping"
            break

    write_run_markdown(run_log_path, run_id, run_started_at, device, history, best_epoch, best_f1, stopped_reason, resume_info)

    write_context(
        "05_training.md",
        "HGNN Training",
        [
            "## Action",
            f"- Trained `SecureEdgeHGNN` on graph files from `{config.GRAPH_TRAIN_DIR}`.",
            f"- Evaluated each epoch on validation graph files from `{config.GRAPH_VAL_DIR}`.",
            f"- Reserved test graph files under `{config.GRAPH_TEST_DIR}` for final evaluation.",
            f"- Best validation macro F1: `{best_f1:.6f}`.",
            f"- Batch size: `{config.BATCH_SIZE}` graph objects.",
            f"- Gradient accumulation steps: `{config.GRAD_ACCUM_STEPS}`.",
            f"- Effective batch size: `{config.BATCH_SIZE * config.GRAD_ACCUM_STEPS}` graph objects.",
            f"- Evaluation batch size: `{config.EVAL_BATCH_SIZE}` graph objects.",
            f"- AMP enabled: `{use_amp}`.",
            f"- Device: `{device}`.",
            f"- Run log: `{run_log_path}`.",
            f"- History JSON: `{run_history_json_path}`.",
            f"- History CSV: `{run_history_csv_path}`.",
            f"- Training limit per class: `{config.TRAIN_LIMIT_PER_CLASS or 'full split'}`.",
            f"- Validation limit per class: `{config.EVAL_LIMIT_PER_CLASS or 'full split'}`.",
            f"- Warmup: `{config.WARMUP_EPOCHS}` epochs from `{config.WARMUP_START_LR}` to `{config.LEARNING_RATE}`.",
            f"- Weight decay: `{config.WEIGHT_DECAY}`.",
            f"- Scheduler: `{config.LR_SCHEDULER}`, min LR `{config.MIN_LEARNING_RATE}`.",
            f"- Label smoothing: `{config.LABEL_SMOOTHING}`.",
            f"- Resume from checkpoint: `{config.RESUME_FROM_CHECKPOINT}`.",
            f"- Resume checkpoint path: `{config.RESUME_CHECKPOINT_PATH if config.RESUME_FROM_CHECKPOINT else 'not used'}`.",
            "- Loss: plain `CrossEntropyLoss()` with no class weights and no label smoothing.",
            f"- Saved this run's best checkpoint to `{run_checkpoint_path}`.",
            f"- Promoted to global checkpoint `{config.HGNN_CHECKPOINT_PATH}` only if this run beat the existing global macro F1.",
            "",
            "## Last Epoch",
            "```json",
            json.dumps(history[-1] if history else {}, indent=2),
            "```",
        ],
    )


def main() -> None:
    train()


if __name__ == "__main__":
    main()
