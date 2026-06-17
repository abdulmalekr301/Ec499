from __future__ import annotations

import torch
from torch import nn

from secureedge import config
from secureedge.utils import write_context


def require_pyg_layers():
    try:
        from torch_geometric.nn import GATConv, HeteroConv, global_mean_pool
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "PyTorch Geometric is required for SecureEdgeHGNN. Install torch-geometric "
            "and the matching torch-scatter/torch-sparse/torch-cluster wheels for the "
            "active Torch build."
        ) from exc
    return GATConv, HeteroConv, global_mean_pool


class SecureEdgeHGNN(nn.Module):
    def __init__(
        self,
        hidden_size: int = config.HGNN_HIDDEN_SIZE,
        num_classes: int = config.N_CLASSES,
        leaky_relu_slope: float = config.HGNN_LEAKY_RELU_SLOPE,
    ) -> None:
        super().__init__()
        GATConv, HeteroConv, global_mean_pool = require_pyg_layers()
        self.global_mean_pool = global_mean_pool
        self.conv1 = HeteroConv(
            {
                ("flow", "contains", "packet"): GATConv(
                    (-1, -1), hidden_size, edge_dim=config.N_CONTAIN_EDGE_FEATS, add_self_loops=False
                ),
                ("packet", "rev_contains", "flow"): GATConv(
                    (-1, -1), hidden_size, edge_dim=config.N_CONTAIN_EDGE_FEATS, add_self_loops=False
                ),
                ("packet", "linked_to", "packet"): GATConv(
                    (-1, -1), hidden_size, edge_dim=config.N_LINK_EDGE_FEATS, add_self_loops=False
                ),
            },
            aggr="sum",
        )
        self.bn_flow_1 = nn.BatchNorm1d(hidden_size)
        self.bn_packet_1 = nn.BatchNorm1d(hidden_size)
        self.conv2 = HeteroConv(
            {
                ("flow", "contains", "packet"): GATConv((-1, -1), hidden_size, add_self_loops=False),
                ("packet", "rev_contains", "flow"): GATConv((-1, -1), hidden_size, add_self_loops=False),
                ("packet", "linked_to", "packet"): GATConv((-1, -1), hidden_size, add_self_loops=False),
            },
            aggr="sum",
        )
        self.bn_flow_2 = nn.BatchNorm1d(hidden_size)
        self.bn_packet_2 = nn.BatchNorm1d(hidden_size)
        self.activation = nn.LeakyReLU(negative_slope=leaky_relu_slope)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, num_classes),
        )

    def forward(
        self,
        x_dict: dict[str, torch.Tensor],
        edge_index_dict: dict[tuple[str, str, str], torch.Tensor],
        edge_attr_dict: dict[tuple[str, str, str], torch.Tensor],
        batch_dict: dict[str, torch.Tensor],
    ) -> torch.Tensor:
        x_dict = self.conv1(x_dict, edge_index_dict, edge_attr_dict)
        x_dict["flow"] = self.activation(self.bn_flow_1(x_dict["flow"]))
        x_dict["packet"] = self.activation(self.bn_packet_1(x_dict["packet"]))

        x_dict = self.conv2(x_dict, edge_index_dict)
        x_dict["flow"] = self.activation(self.bn_flow_2(x_dict["flow"]))
        x_dict["packet"] = self.activation(self.bn_packet_2(x_dict["packet"]))

        flow_pooled = self.global_mean_pool(x_dict["flow"], batch_dict["flow"])
        packet_pooled = self.global_mean_pool(x_dict["packet"], batch_dict["packet"])
        graph_embedding = (flow_pooled + packet_pooled) / 2.0
        return self.classifier(graph_embedding)

    def forward_batch(self, batch) -> torch.Tensor:
        return self(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)


def document_architecture() -> None:
    write_context(
        "04_model_architecture.md",
        "HGNN Architecture",
        [
            "## Action",
            "- Deprecated the flat MLP path and added `secureedge.models.hgnn.SecureEdgeHGNN`.",
            "- Implemented two heterogeneous GAT layers with flow-to-packet, packet-to-flow, and packet-to-packet edge types.",
            f"- Flow node input dimension: `{config.N_FLOW_NODE_FEATURES}`.",
            f"- Packet node input dimension: `{config.N_PACKET_FEATURES}`.",
            f"- Hidden size: `{config.HGNN_HIDDEN_SIZE}`.",
            "- Graph embeddings are produced by mean-pooling flow and packet node embeddings and averaging the two pooled vectors.",
            "- The classifier head is `Linear(64, 32) -> ReLU -> Linear(32, 16) -> ReLU -> Linear(16, 8)`.",
        ],
    )
