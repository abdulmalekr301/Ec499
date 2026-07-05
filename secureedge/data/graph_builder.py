from __future__ import annotations

import json
import hashlib
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler

from secureedge import config


def safe_divide(numerator: float, denominator: float) -> float:
    numerator = float(numerator or 0.0)
    denominator = float(denominator or 0.0)
    if not np.isfinite(denominator) or denominator == 0.0:
        return 0.0
    value = numerator / denominator
    return float(value) if np.isfinite(value) else 0.0


def compute_derived_features(flow_features: dict[str, float]) -> dict[str, float]:
    bidi_duration_s = float(flow_features.get("bidirectional_duration_ms", 0.0) or 0.0) / 1000.0
    src_duration_s = float(flow_features.get("src2dst_duration_ms", 0.0) or 0.0) / 1000.0
    dst_duration_s = float(flow_features.get("dst2src_duration_ms", 0.0) or 0.0) / 1000.0
    return {
        "bidirectional_bytes_per_second": safe_divide(flow_features.get("bidirectional_bytes", 0.0), bidi_duration_s),
        "bidirectional_packets_per_second": safe_divide(flow_features.get("bidirectional_packets", 0.0), bidi_duration_s),
        "src2dst_bytes_per_second": safe_divide(flow_features.get("src2dst_bytes", 0.0), src_duration_s),
        "src2dst_packets_per_second": safe_divide(flow_features.get("src2dst_packets", 0.0), src_duration_s),
        "dst2src_bytes_per_second": safe_divide(flow_features.get("dst2src_bytes", 0.0), dst_duration_s),
        "dst2src_packets_per_second": safe_divide(flow_features.get("dst2src_packets", 0.0), dst_duration_s),
        "down_up_bytes_ratio": safe_divide(flow_features.get("dst2src_bytes", 0.0), flow_features.get("src2dst_bytes", 0.0)),
        "average_packet_size": safe_divide(flow_features.get("bidirectional_bytes", 0.0), flow_features.get("bidirectional_packets", 0.0)),
    }


def require_pyg() -> tuple[type, type]:
    try:
        from torch_geometric.data import HeteroData
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            "PyTorch Geometric is required for the final XG-NID graph pipeline. "
            "Install torch-geometric and its torch-scatter/torch-sparse/torch-cluster "
            "dependencies for the active Torch build before running this phase."
        ) from exc
    return HeteroData, object


def ordered_flow_vector(flow_features: dict[str, float], temporal_features: dict[str, float]) -> tuple[list[str], list[float]]:
    derived_features = compute_derived_features(flow_features)
    complete_features = {**flow_features, **derived_features}
    names = list(config.FLOW_FEATURE_ORDER) + list(config.TEMPORAL_FEATURES)
    values = [float(complete_features.get(name, 0.0) or 0.0) for name in config.FLOW_FEATURE_ORDER]
    values.extend(float(temporal_features.get(name, 0.0) or 0.0) for name in config.TEMPORAL_FEATURES)
    return names, values


def build_compact_graph_record(
    flow_features: dict[str, float],
    temporal_features: dict[str, float],
    packet_records: list[dict[str, object]],
    label: int,
    subtype_label: str,
    class_name: str,
    source_file: str,
    source_order: int,
) -> dict[str, object] | None:
    if not packet_records:
        return None

    feature_names, flow_values = ordered_flow_vector(flow_features, temporal_features)

    packet_rows: list[list[int]] = []
    contain_edge_rows: list[list[float]] = []
    timestamps: list[float] = []
    for packet in packet_records[: config.FLOW_PACKET_LIMIT]:
        payload = packet.get("payload", [])
        payload_values = [int(byte) & 0xFF for byte in payload]
        if len(payload_values) < config.N_PACKET_FEATURES:
            payload_values.extend([0] * (config.N_PACKET_FEATURES - len(payload_values)))
        packet_rows.append(payload_values[: config.N_PACKET_FEATURES])
        contain_edge_rows.append(
            [
                float(packet.get("direction", 0) or 0),
                float(packet.get("ip_size", 0) or 0),
                float(packet.get("transport_size", 0) or 0),
                float(packet.get("payload_size", 0) or 0),
            ]
        )
        timestamps.append(float(packet.get("timestamp_ms", 0) or 0))

    n_packets = len(packet_rows)
    if n_packets == 0:
        return None

    link_deltas = []
    if n_packets > 1:
        link_deltas = [max(0.0, timestamps[index + 1] - timestamps[index]) for index in range(n_packets - 1)]

    return {
        "compact_graph": True,
        "flow_x": np.asarray(flow_values, dtype=np.float32),
        "packet_x_uint8": np.asarray(packet_rows, dtype=np.uint8),
        "contain_edge_attr": np.asarray(contain_edge_rows, dtype=np.float32),
        "link_edge_attr": np.asarray(link_deltas, dtype=np.float32).reshape(-1, 1),
        "label": int(label),
        "subtype_label": subtype_label,
        "class_name": class_name,
        "source_file": source_file,
        "source_order": int(source_order),
        "flow_feature_names": feature_names,
        "flow_feature_order": list(config.FLOW_FEATURE_ORDER),
        "flow_feature_version": "xgnid_76_plus_temporal_16",
    }


def compact_to_hetero_graph(compact: dict[str, object]):
    import torch

    HeteroData, _ = require_pyg()
    packet_rows = np.asarray(compact["packet_x_uint8"], dtype=np.uint8)
    n_packets = int(packet_rows.shape[0])
    if n_packets == 0:
        return None

    data = HeteroData()
    data["flow"].x = torch.tensor(np.asarray(compact["flow_x"], dtype=np.float32), dtype=torch.float32).unsqueeze(0)
    data["packet"].x = torch.tensor(packet_rows.astype(np.float32) / 255.0, dtype=torch.float32)
    contains_index = torch.tensor([[0] * n_packets, list(range(n_packets))], dtype=torch.long)
    contains_attr = torch.tensor(np.asarray(compact["contain_edge_attr"], dtype=np.float32), dtype=torch.float32)
    data["flow", "contains", "packet"].edge_index = contains_index
    data["flow", "contains", "packet"].edge_attr = contains_attr
    data["packet", "rev_contains", "flow"].edge_index = contains_index.flip(0)
    data["packet", "rev_contains", "flow"].edge_attr = contains_attr.clone()

    link_deltas = np.asarray(compact["link_edge_attr"], dtype=np.float32).reshape(-1, 1)
    if n_packets > 1:
        src = list(range(n_packets - 1))
        dst = list(range(1, n_packets))
        data["packet", "linked_to", "packet"].edge_index = torch.tensor([src, dst], dtype=torch.long)
        data["packet", "linked_to", "packet"].edge_attr = torch.tensor(link_deltas, dtype=torch.float32)

    data.y = torch.tensor([int(compact["label"])], dtype=torch.long)
    data.class_name = str(compact["class_name"])
    data.subtype_label = str(compact["subtype_label"])
    data.source_file = str(compact["source_file"])
    data.source_order = int(compact["source_order"])
    data.flow_feature_names = list(compact["flow_feature_names"])
    data.flow_feature_order = list(compact.get("flow_feature_order", config.FLOW_FEATURE_ORDER))
    return data


def build_hetero_graph(
    flow_features: dict[str, float],
    temporal_features: dict[str, float],
    packet_records: list[dict[str, object]],
    label: int,
    subtype_label: str,
    class_name: str,
    source_file: str,
    source_order: int,
):
    compact = build_compact_graph_record(
        flow_features,
        temporal_features,
        packet_records,
        label,
        subtype_label,
        class_name,
        source_file,
        source_order,
    )
    if compact is None:
        return None
    return compact_to_hetero_graph(compact)


GraphRef = object | Path | str


def load_graph_ref(graph_ref: GraphRef):
    if isinstance(graph_ref, Path | str):
        path = Path(graph_ref)
        if path.suffix == ".pkl":
            with path.open("rb") as handle:
                return pickle.load(handle)
        import torch

        return torch.load(path, map_location="cpu", weights_only=False)
    return graph_ref


def is_compact_graph(graph: object) -> bool:
    return isinstance(graph, dict) and bool(graph.get("compact_graph"))


def graph_class_name(graph_ref: GraphRef) -> str:
    graph = load_graph_ref(graph_ref)
    if is_compact_graph(graph):
        return str(graph["class_name"])
    return str(graph.class_name)


def graph_flow_matrix(graphs: Iterable[GraphRef]) -> np.ndarray:
    rows = []
    for graph_ref in graphs:
        graph = load_graph_ref(graph_ref)
        if is_compact_graph(graph):
            rows.append(np.asarray(graph["flow_x"], dtype=np.float32))
        else:
            rows.append(graph["flow"].x.squeeze(0).cpu().numpy())
    return np.vstack(rows).astype(np.float32)


def graph_contain_edge_matrix(graphs: Iterable[GraphRef]) -> np.ndarray:
    rows = []
    for graph_ref in graphs:
        graph = load_graph_ref(graph_ref)
        if is_compact_graph(graph):
            rows.append(np.asarray(graph["contain_edge_attr"], dtype=np.float32))
        else:
            rows.append(graph["flow", "contains", "packet"].edge_attr.cpu().numpy())
    return np.vstack(rows).astype(np.float32)


def graph_link_delta_vector(graphs: Iterable[GraphRef]) -> np.ndarray:
    rows = []
    for graph_ref in graphs:
        graph = load_graph_ref(graph_ref)
        if is_compact_graph(graph):
            deltas = np.asarray(graph["link_edge_attr"], dtype=np.float32).reshape(-1)
            if deltas.size:
                rows.append(deltas)
        else:
            edge_type = ("packet", "linked_to", "packet")
            if edge_type in graph.edge_types:
                rows.append(graph[edge_type].edge_attr.cpu().numpy().reshape(-1))
    if not rows:
        return np.array([1.0], dtype=np.float32)
    return np.concatenate(rows).astype(np.float32)


def normalize_graph(
    graph,
    flow_scaler: StandardScaler,
    contain_scaler: StandardScaler,
    link_norm_value: float,
) -> object:
    link_norm_value = max(float(link_norm_value), 1.0)
    if is_compact_graph(graph):
        compact = dict(graph)
        compact["flow_x"] = flow_scaler.transform(np.asarray(compact["flow_x"], dtype=np.float32).reshape(1, -1)).squeeze(0)
        compact["contain_edge_attr"] = contain_scaler.transform(np.asarray(compact["contain_edge_attr"], dtype=np.float32))
        link_edges = np.asarray(compact["link_edge_attr"], dtype=np.float32)
        if link_edges.size:
            compact["link_edge_attr"] = link_edges / link_norm_value
        return compact_to_hetero_graph(compact)

    import torch

    flow = graph["flow"].x.cpu().numpy()
    graph["flow"].x = torch.tensor(flow_scaler.transform(flow), dtype=torch.float32)

    contain = graph["flow", "contains", "packet"].edge_attr.cpu().numpy()
    contain_scaled = torch.tensor(contain_scaler.transform(contain), dtype=torch.float32)
    graph["flow", "contains", "packet"].edge_attr = contain_scaled
    graph["packet", "rev_contains", "flow"].edge_attr = contain_scaled.clone()

    edge_type = ("packet", "linked_to", "packet")
    if edge_type in graph.edge_types:
        graph[edge_type].edge_attr = graph[edge_type].edge_attr / link_norm_value
    return graph


def fit_graph_normalizers(train_graphs: list[GraphRef]) -> tuple[StandardScaler, StandardScaler, float]:
    flow_scaler = StandardScaler()
    flow_scaler.fit(graph_flow_matrix(train_graphs))

    contain_scaler = StandardScaler()
    contain_scaler.fit(graph_contain_edge_matrix(train_graphs))

    link_deltas = graph_link_delta_vector(train_graphs)
    link_norm_value = float(np.percentile(link_deltas, 99))
    if not np.isfinite(link_norm_value) or link_norm_value <= 0:
        link_norm_value = 1.0

    joblib.dump(flow_scaler, config.FLOW_NODE_SCALER_PATH)
    joblib.dump(contain_scaler, config.CONTAIN_EDGE_SCALER_PATH)
    config.LINK_EDGE_NORM_PATH.write_text(
        json.dumps({"method": "p99_training_link_delta_ms", "p99_ms": link_norm_value}, indent=2),
        encoding="utf-8",
    )
    return flow_scaler, contain_scaler, link_norm_value


def clear_pt_files(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for path in directory.glob("*.pt"):
        path.unlink()


def save_graph_split(
    graphs: list[GraphRef],
    split_dir: Path,
    split_name: str,
    flow_scaler: StandardScaler,
    contain_scaler: StandardScaler,
    link_norm_value: float,
) -> dict[str, list[str]]:
    clear_pt_files(split_dir)
    counters: Counter[str] = Counter()
    paths_by_class: dict[str, list[str]] = defaultdict(list)
    for graph_ref in graphs:
        graph = normalize_graph(load_graph_ref(graph_ref), flow_scaler, contain_scaler, link_norm_value)
        class_name = str(graph.class_name)
        counters[class_name] += 1
        source_file = str(getattr(graph, "source_file", ""))
        source_order = int(getattr(graph, "source_order", -1))
        graph_id_payload = f"{split_name}|{class_name}|{graph.subtype_label}|{source_file}|{source_order}"
        graph.graph_id = hashlib.sha256(graph_id_payload.encode("utf-8")).hexdigest()
        graph.split = split_name
        graph.used_attacker_mac_filter = bool(config.ENABLE_ATTACKER_MAC_FILTER)
        graph.num_packets = int(graph["packet"].x.shape[0])
        graph.flow_id_hash = hashlib.sha256(f"{source_file}|{source_order}".encode("utf-8")).hexdigest()
        path = split_dir / f"{class_name}_{counters[class_name]:06d}.pt"
        import torch

        torch.save(graph, path)
        paths_by_class[class_name].append(str(path))
    return {class_name: paths_by_class.get(class_name, []) for class_name in config.CLASS_NAMES}


def save_graph_dataset(train_graphs: list[GraphRef], val_graphs: list[GraphRef], test_graphs: list[GraphRef]) -> dict[str, object]:
    if not train_graphs or not val_graphs or not test_graphs:
        raise ValueError("Train, validation, and test graph splits must all contain at least one graph.")
    flow_scaler, contain_scaler, link_norm_value = fit_graph_normalizers(train_graphs)
    config.FLOW_FEATURE_ORDER_PATH.write_text(json.dumps(list(config.FLOW_FEATURE_ORDER), indent=2), encoding="utf-8")
    train_paths = save_graph_split(train_graphs, config.GRAPH_TRAIN_DIR, "train", flow_scaler, contain_scaler, link_norm_value)
    val_paths = save_graph_split(val_graphs, config.GRAPH_VAL_DIR, "val", flow_scaler, contain_scaler, link_norm_value)
    test_paths = save_graph_split(test_graphs, config.GRAPH_TEST_DIR, "test", flow_scaler, contain_scaler, link_norm_value)
    first_graph = load_graph_ref(train_graphs[0])
    if is_compact_graph(first_graph):
        feature_names = list(first_graph["flow_feature_names"])
        flow_node_dim = int(np.asarray(first_graph["flow_x"]).shape[0])
    else:
        feature_names = list(getattr(first_graph, "flow_feature_names", []))
        flow_node_dim = int(first_graph["flow"].x.shape[1])
    manifest = {
        "n_train": len(train_graphs),
        "n_val": len(val_graphs),
        "n_test": len(test_graphs),
        "n_flow_features": max(0, flow_node_dim - config.N_TEMPORAL_FEATURES),
        "n_temporal_feats": config.N_TEMPORAL_FEATURES,
        "n_flow_node_feats": flow_node_dim,
        "n_packet_feats": config.N_PACKET_FEATURES,
        "n_contain_edge_feats": config.N_CONTAIN_EDGE_FEATS,
        "n_link_edge_feats": config.N_LINK_EDGE_FEATS,
        "class_counts_train": {class_name: len(train_paths[class_name]) for class_name in config.CLASS_NAMES},
        "class_counts_val": {class_name: len(val_paths[class_name]) for class_name in config.CLASS_NAMES},
        "class_counts_test": {class_name: len(test_paths[class_name]) for class_name in config.CLASS_NAMES},
        "train_files": [path for class_name in config.CLASS_NAMES for path in train_paths[class_name]],
        "val_files": [path for class_name in config.CLASS_NAMES for path in val_paths[class_name]],
        "test_files": [path for class_name in config.CLASS_NAMES for path in test_paths[class_name]],
        "total_graph_count": len(train_graphs) + len(val_graphs) + len(test_graphs),
        "splits": {
            "train": {
                "count": len(train_graphs),
                "per_class": {class_name: len(train_paths[class_name]) for class_name in config.CLASS_NAMES},
                "paths": train_paths,
            },
            "val": {
                "count": len(val_graphs),
                "per_class": {class_name: len(val_paths[class_name]) for class_name in config.CLASS_NAMES},
                "paths": val_paths,
            },
            "test": {
                "count": len(test_graphs),
                "per_class": {class_name: len(test_paths[class_name]) for class_name in config.CLASS_NAMES},
                "paths": test_paths,
            },
        },
        "feature_dimensions": {
            "flow_node": flow_node_dim,
            "packet_node": config.N_PACKET_FEATURES,
            "contain_edge": config.N_CONTAIN_EDGE_FEATS,
            "link_edge": config.N_LINK_EDGE_FEATS,
        },
        "flow_feature_names": feature_names,
        "link_edge_norm_value": link_norm_value,
        "scalers": {
            "flow_node": str(config.FLOW_NODE_SCALER_PATH),
            "contain_edge": str(config.CONTAIN_EDGE_SCALER_PATH),
            "link_edge": str(config.LINK_EDGE_NORM_PATH),
        },
        "scaler_fit_source": {
            "flow_scaler_fit_split": "train",
            "contain_edge_scaler_fit_split": "train",
            "link_delta_normalizer_fit_split": "train",
        },
        "flow_feature_order_path": str(config.FLOW_FEATURE_ORDER_PATH),
    }
    config.GRAPH_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
