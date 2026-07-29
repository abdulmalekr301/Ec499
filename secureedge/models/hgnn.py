from __future__ import annotations

import torch
from torch import nn

from secureedge import config
from secureedge.utils import write_context


def require_pyg_layers():
    try:
        from torch_geometric.nn import GATv2Conv, HeteroConv, global_mean_pool
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "PyTorch Geometric is required for SecureEdgeHGNN. Install torch-geometric "
            "and the matching torch-scatter/torch-sparse/torch-cluster wheels for the "
            "active Torch build."
        ) from exc
    return GATv2Conv, HeteroConv, global_mean_pool


class SecureEdgeHGNN(nn.Module):
    def __init__(
        self,
        hidden_size: int = config.HGNN_HIDDEN_SIZE,
        num_classes: int = config.N_CLASSES,
        leaky_relu_slope: float = config.HGNN_LEAKY_RELU_SLOPE,
    ) -> None:
        super().__init__()
        GATv2Conv, HeteroConv, global_mean_pool = require_pyg_layers()
        self.attention_conv = "GATv2Conv"
        self.global_mean_pool = global_mean_pool
        self.use_payload_encoder = config.USE_PAYLOAD_ENCODER
        self.packet_encoder = (
            nn.Sequential(
                nn.Conv1d(
                    1,
                    config.PAYLOAD_ENCODER_CHANNELS,
                    kernel_size=config.PAYLOAD_ENCODER_KERNEL_SIZE,
                    padding=config.PAYLOAD_ENCODER_KERNEL_SIZE // 2,
                ),
                nn.BatchNorm1d(config.PAYLOAD_ENCODER_CHANNELS, eps=config.HGNN_BATCHNORM_EPS),
                nn.ReLU(),
                nn.Conv1d(config.PAYLOAD_ENCODER_CHANNELS, config.PAYLOAD_ENCODER_CHANNELS, kernel_size=5, padding=2),
                nn.BatchNorm1d(config.PAYLOAD_ENCODER_CHANNELS, eps=config.HGNN_BATCHNORM_EPS),
                nn.ReLU(),
                nn.AdaptiveMaxPool1d(1),
                nn.Flatten(),
                nn.Dropout(config.PAYLOAD_ENCODER_DROPOUT),
                nn.Linear(config.PAYLOAD_ENCODER_CHANNELS, hidden_size),
                nn.ReLU(),
            )
            if self.use_payload_encoder
            else nn.Identity()
        )
        self.conv1 = HeteroConv(
            {
                ("flow", "contains", "packet"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_CONTAIN_EDGE_FEATS,
                    add_self_loops=False,
                ),
                ("packet", "rev_contains", "flow"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_CONTAIN_EDGE_FEATS,
                    add_self_loops=False,
                ),
                ("packet", "linked_to", "packet"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_LINK_EDGE_FEATS,
                    add_self_loops=False,
                ),
            },
            aggr="sum",
        )
        self.bn_flow_1 = nn.BatchNorm1d(hidden_size, eps=config.HGNN_BATCHNORM_EPS)
        self.bn_packet_1 = nn.BatchNorm1d(hidden_size, eps=config.HGNN_BATCHNORM_EPS)
        self.conv2 = HeteroConv(
            {
                ("flow", "contains", "packet"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_CONTAIN_EDGE_FEATS,
                    add_self_loops=False,
                ),
                ("packet", "rev_contains", "flow"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_CONTAIN_EDGE_FEATS,
                    add_self_loops=False,
                ),
                ("packet", "linked_to", "packet"): GATv2Conv(
                    (-1, -1),
                    config.HGNN_ATTN_SIZE,
                    heads=2,
                    concat=True,
                    edge_dim=config.N_LINK_EDGE_FEATS,
                    add_self_loops=False,
                ),
            },
            aggr="sum",
        )
        self.bn_flow_2 = nn.BatchNorm1d(hidden_size, eps=config.HGNN_BATCHNORM_EPS)
        self.bn_packet_2 = nn.BatchNorm1d(hidden_size, eps=config.HGNN_BATCHNORM_EPS)
        self.activation = nn.LeakyReLU(negative_slope=leaky_relu_slope)
        if config.HGNN_READOUT_MODE not in {"concat", "average"}:
            raise ValueError("SECUREEDGE_HGNN_READOUT_MODE must be one of: concat, average")
        classifier_input_dim = hidden_size * 2 if config.HGNN_READOUT_MODE == "concat" else hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(classifier_input_dim, 64 if config.HGNN_READOUT_MODE == "concat" else 32),
            nn.ReLU(),
            nn.Linear(64 if config.HGNN_READOUT_MODE == "concat" else 32, 32 if config.HGNN_READOUT_MODE == "concat" else 16),
            nn.ReLU(),
            nn.Linear(32 if config.HGNN_READOUT_MODE == "concat" else 16, num_classes),
        )

    def forward(
        self,
        x_dict: dict[str, torch.Tensor],
        edge_index_dict: dict[tuple[str, str, str], torch.Tensor],
        edge_attr_dict: dict[tuple[str, str, str], torch.Tensor],
        batch_dict: dict[str, torch.Tensor],
    ) -> torch.Tensor:
        x_dict = dict(x_dict)
        if self.use_payload_encoder:
            x_dict["packet"] = self.packet_encoder(x_dict["packet"].unsqueeze(1))
        x_dict = self.conv1(x_dict, edge_index_dict, edge_attr_dict)
        x_dict["flow"] = self.activation(self.bn_flow_1(x_dict["flow"]))
        x_dict["packet"] = self.activation(self.bn_packet_1(x_dict["packet"]))

        x_dict = self.conv2(x_dict, edge_index_dict, edge_attr_dict)
        x_dict["flow"] = self.activation(self.bn_flow_2(x_dict["flow"]))
        x_dict["packet"] = self.activation(self.bn_packet_2(x_dict["packet"]))

        flow_pooled = self.global_mean_pool(x_dict["flow"], batch_dict["flow"])
        packet_pooled = self.global_mean_pool(x_dict["packet"], batch_dict["packet"])
        if config.HGNN_READOUT_MODE == "concat":
            graph_embedding = torch.cat([flow_pooled, packet_pooled], dim=1)
        else:
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
            "- Implemented two heterogeneous GATv2 layers with flow-to-packet, packet-to-flow, and packet-to-packet edge types.",
            f"- Flow node input dimension: `{config.N_FLOW_NODE_FEATURES}`.",
            f"- Packet node input dimension: `{config.N_PACKET_FEATURES}`.",
            f"- Optional packet payload CNN encoder enabled: `{config.USE_PAYLOAD_ENCODER}`.",
            f"- Hidden size: `{config.HGNN_HIDDEN_SIZE}`.",
            f"- BatchNorm epsilon: `{config.HGNN_BATCHNORM_EPS}`.",
            f"- GATv2 attention: `heads=2`, `attention size={config.HGNN_ATTN_SIZE}`, concatenated output `{config.HGNN_ATTN_SIZE * 2}`.",
            "- Note: multi-head GATv2 remains a SecureEdge enhancement; the XG-NID repo comparison showed `attn_size` is dead code in the upstream model.",
            "- Both HGNN layers receive edge attributes for contain, reverse-contain, and packet-link relations.",
            f"- Graph readout mode: `{config.HGNN_READOUT_MODE}`.",
            "- With concat readout, the classifier head receives a 128-dimensional flow+packet embedding.",
        ],
    )
