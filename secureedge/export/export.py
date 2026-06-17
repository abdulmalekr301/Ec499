from __future__ import annotations

import torch

from secureedge import config
from secureedge.data.dataset import GraphFileDataset, split_paths
from secureedge.models.hgnn import SecureEdgeHGNN
from secureedge.models.train import require_pyg_dataloader
from secureedge.utils import ensure_directories, write_context


class TraceableHGNN(torch.nn.Module):
    def __init__(self, model: SecureEdgeHGNN) -> None:
        super().__init__()
        self.model = model

    def forward(self, x_dict, edge_index_dict, edge_attr_dict, batch_dict):
        return self.model(x_dict, edge_index_dict, edge_attr_dict, batch_dict)


def export_torchscript() -> None:
    ensure_directories()
    if not config.HGNN_CHECKPOINT_PATH.exists():
        raise FileNotFoundError("Run `python -m secureedge.models.train` before export.")
    checkpoint = torch.load(config.HGNN_CHECKPOINT_PATH, map_location="cpu", weights_only=False)
    DataLoader = require_pyg_dataloader()
    test_paths = split_paths("test")
    if not test_paths:
        raise FileNotFoundError("No test graph files were found in the graph manifest.")
    sample_loader = DataLoader(GraphFileDataset(test_paths[:1]), batch_size=1, shuffle=False)
    sample_batch = next(iter(sample_loader))

    model = SecureEdgeHGNN()
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    traceable = TraceableHGNN(model).eval()
    example = (
        sample_batch.x_dict,
        sample_batch.edge_index_dict,
        sample_batch.edge_attr_dict,
        sample_batch.batch_dict,
    )

    with torch.no_grad():
        expected = traceable(*example)
    traced = torch.jit.trace(traceable, example, strict=False)
    with torch.no_grad():
        actual = traced(*example)
    if not torch.allclose(expected, actual, atol=1e-5):
        raise ValueError("TorchScript verification failed: traced logits differ from PyTorch logits.")

    traced.save(str(config.HGNN_TORCHSCRIPT_PATH))
    write_context(
        "08_export.md",
        "HGNN TorchScript Export",
        [
            "## Action",
            f"- Exported checkpoint `{config.HGNN_CHECKPOINT_PATH}` to `{config.HGNN_TORCHSCRIPT_PATH}`.",
            "- Traced a one-graph PyG batch using the model's dictionary inputs.",
            "- Verified traced logits match PyTorch logits within `1e-5` absolute tolerance on the sample batch.",
            "",
            "## Note",
            "- The final methodology requires verification on 100 random test graphs after the target macro F1 is reached.",
        ],
    )


def main() -> None:
    export_torchscript()
    print(f"Wrote {config.HGNN_TORCHSCRIPT_PATH}")


if __name__ == "__main__":
    main()
