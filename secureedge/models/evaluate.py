from __future__ import annotations

import json
from collections import defaultdict

import numpy as np
import torch
from sklearn.metrics import classification_report, f1_score

from secureedge import config
from secureedge.data.dataset import load_graph_dataset
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import require_pyg_dataloader, training_device
from secureedge.utils import ensure_directories, write_context, write_json


def load_checkpoint() -> dict:
    if not config.HGNN_CHECKPOINT_PATH.exists():
        raise FileNotFoundError("Run `python -m secureedge.models.train` before evaluation.")
    return torch.load(config.HGNN_CHECKPOINT_PATH, map_location="cpu", weights_only=False)


def as_list(value: object, length: int) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value for _ in range(length)]


def predict(model: SecureEdgeHGNN, loader, device: torch.device) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    model.eval()
    predictions: list[np.ndarray] = []
    targets: list[np.ndarray] = []
    subtypes: list[str] = []
    classes: list[str] = []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device, non_blocking=True)
            logits = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
            batch_predictions = torch.argmax(logits, dim=1).cpu().numpy()
            batch_targets = batch.y.view(-1).cpu().numpy()
            predictions.append(batch_predictions)
            targets.append(batch_targets)
            subtypes.extend(str(item) for item in as_list(getattr(batch, "subtype_label", ""), len(batch_targets)))
            classes.extend(str(item) for item in as_list(getattr(batch, "class_name", ""), len(batch_targets)))
    return np.concatenate(predictions), np.concatenate(targets), subtypes, classes


def ddos_subtype_distribution(predictions: np.ndarray, subtypes: list[str], classes: list[str]) -> dict[str, dict[str, int]]:
    distribution: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for pred_index, subtype, class_name in zip(predictions, subtypes, classes, strict=False):
        if class_name != "DDoS":
            continue
        distribution[subtype][config.CLASS_NAMES[int(pred_index)]] += 1
    return {subtype: dict(counts) for subtype, counts in sorted(distribution.items())}


def evaluate() -> dict:
    ensure_directories()
    checkpoint = load_checkpoint()
    DataLoader = require_pyg_dataloader()
    test_dataset = load_graph_dataset("test", limit_per_class=config.EVAL_LIMIT_PER_CLASS)
    device = training_device()
    loader_kwargs = {
        "num_workers": config.NUM_WORKERS,
        "pin_memory": device.type == "cuda",
    }
    if config.NUM_WORKERS > 0:
        loader_kwargs["persistent_workers"] = True
        loader_kwargs["prefetch_factor"] = config.PREFETCH_FACTOR
    test_loader = DataLoader(
        test_dataset,
        batch_size=config.BATCH_SIZE,
        shuffle=False,
        **loader_kwargs,
    )

    model = SecureEdgeHGNN().to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    predictions, targets, subtypes, classes = predict(model, test_loader, device)

    report = classification_report(
        targets,
        predictions,
        labels=list(range(len(config.CLASS_NAMES))),
        target_names=config.CLASS_NAMES,
        output_dict=True,
        zero_division=0,
    )
    ddos_distribution = ddos_subtype_distribution(predictions, subtypes, classes)
    ddos_recall = {
        subtype: (counts.get("DDoS", 0) / max(sum(counts.values()), 1)) for subtype, counts in ddos_distribution.items()
    }
    metrics = {
        "macro_f1": float(f1_score(targets, predictions, average="macro", zero_division=0)),
        "classification_report": report,
        "ddos_subtype_prediction_distribution": ddos_distribution,
        "ddos_subtype_ddos_recall": ddos_recall,
        "checkpoint": str(config.HGNN_CHECKPOINT_PATH),
        "target_macro_f1": 0.97,
    }
    write_json(config.METRICS_PATH, metrics)
    write_context(
        "06_evaluation.md",
        "HGNN Evaluation",
        [
            "## Action",
            f"- Evaluated checkpoint `{config.HGNN_CHECKPOINT_PATH}` on graph test files.",
            f"- Saved metrics to `{config.METRICS_PATH}`.",
            f"- Macro F1: `{metrics['macro_f1']:.6f}`.",
            "",
            "## Target",
            "- Final methodology target is macro F1 >= 0.97.",
            "- Each DDoS subtype should be predicted as DDoS at a rate >= 0.90.",
            "",
            "## DDoS Subtype DDoS Recall",
            "```json",
            json.dumps(ddos_recall, indent=2),
            "```",
        ],
    )
    return metrics


def main() -> None:
    metrics = evaluate()
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
