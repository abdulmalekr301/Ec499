from __future__ import annotations

import json

import numpy as np
import torch

from secureedge import config
from secureedge.data.dataset import load_graph_dataset
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import require_pyg_dataloader
from secureedge.utils import ensure_directories, write_context, write_json


def calibrate_threshold() -> float:
    ensure_directories()
    if not config.HGNN_CHECKPOINT_PATH.exists():
        raise FileNotFoundError("Run `python -m secureedge.models.train` before OOD calibration.")
    checkpoint = torch.load(config.HGNN_CHECKPOINT_PATH, map_location="cpu", weights_only=False)
    DataLoader = require_pyg_dataloader()
    train_dataset = load_graph_dataset("train")
    train_loader = DataLoader(
        train_dataset,
        batch_size=config.BATCH_SIZE,
        shuffle=False,
        num_workers=config.NUM_WORKERS,
        pin_memory=torch.cuda.is_available(),
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = SecureEdgeHGNN().to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    confidences: list[np.ndarray] = []
    correctness: list[np.ndarray] = []
    with torch.no_grad():
        for batch in train_loader:
            batch = batch.to(device)
            probabilities = torch.softmax(model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict), dim=1).cpu()
            labels = batch.y.view(-1).cpu()
            max_conf, preds = probabilities.max(dim=1)
            confidences.append(max_conf.numpy())
            correctness.append((preds == labels).numpy())

    conf = np.concatenate(confidences)
    correct = np.concatenate(correctness).astype(bool)
    if not correct.any():
        raise ValueError("Cannot calibrate OOD threshold because no training graphs were classified correctly.")
    threshold = float(np.percentile(conf[correct], 5))
    write_json(
        config.OOD_THRESHOLD_PATH,
        {
            "method": "maximum_softmax_probability",
            "calibration_split": "train",
            "percentile": 5,
            "threshold": threshold,
            "correct_samples": int(correct.sum()),
        },
    )
    write_context(
        "07_ood_detection.md",
        "OOD Detection",
        [
            "## Action",
            "- Calibrated maximum-softmax-probability threshold on correctly classified training graphs.",
            f"- Threshold: `{threshold:.8f}`.",
            f"- Saved threshold to `{config.OOD_THRESHOLD_PATH}`.",
            "- Inference rule: if max softmax probability is below this value, emit `Unknown Attack`.",
        ],
    )
    return threshold


def main() -> None:
    threshold = calibrate_threshold()
    print(json.dumps({"threshold": threshold}, indent=2))


if __name__ == "__main__":
    main()
