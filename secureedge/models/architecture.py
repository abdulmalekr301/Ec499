from __future__ import annotations

import torch
from torch import nn

from secureedge import config
from secureedge.utils import write_context


class SecureEdgeMLP(nn.Module):
    def __init__(
        self,
        input_dim: int = config.INPUT_DIM,
        num_classes: int = len(config.CLASS_NAMES),
        hidden_dims: tuple[int, ...] = config.MLP_HIDDEN_DIMS,
        dropout: float = config.DROPOUT_RATE,
    ) -> None:
        super().__init__()
        layers: list[nn.Module] = []
        previous = input_dim
        for width in hidden_dims:
            layers.extend(
                [
                    nn.Linear(previous, width),
                    nn.BatchNorm1d(width),
                    nn.ReLU(),
                    nn.Dropout(dropout),
                ]
            )
            previous = width
        layers.append(nn.Linear(previous, num_classes))
        self.network = nn.Sequential(*layers)
        self.net = self.network

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.network(features)


def document_architecture(input_dim: int) -> None:
    write_context(
        "04_model_architecture.md",
        "Model Architecture",
        [
            "## Architecture",
            f"- Input dimension: `{input_dim}`.",
            f"- Hidden layers: `{config.MLP_HIDDEN_DIMS}`.",
            f"- Dropout: `{config.DROPOUT_RATE}`.",
            f"- Output classes: `{len(config.CLASS_NAMES)}`.",
            "",
            "## Notes",
            "- The forward pass returns raw logits; softmax is applied only for metrics and OOD scoring.",
        ],
    )
