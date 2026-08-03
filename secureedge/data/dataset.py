from __future__ import annotations

import json
from pathlib import Path

import torch
from torch.utils.data import Dataset

from secureedge import config


class GraphFileDataset(Dataset):
    def __init__(self, paths: list[str | Path]) -> None:
        self.paths = [Path(path) for path in paths]

    def __len__(self) -> int:
        return len(self.paths)

    def __getitem__(self, index: int):
        graph = torch.load(self.paths[index], map_location="cpu", weights_only=False)
        if hasattr(graph, "office_candidate_identity"):
            for key in (
                "candidate_split",
                "endpoint_selection",
                "flow_hash",
                "source",
                "source_order",
            ):
                if not hasattr(graph, key):
                    setattr(graph, key, "")
        return graph


def load_graph_manifest(path: str | Path = config.GRAPH_MANIFEST_PATH) -> dict:
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Graph manifest not found: {manifest_path}. Run graph preprocessing before loading graph datasets.")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def split_paths(split: str, limit_per_class: int = 0) -> list[str]:
    manifest = load_graph_manifest()
    paths_by_class = manifest["splits"][split]["paths"]
    paths: list[str] = []
    for class_name in config.CLASS_NAMES:
        class_paths = paths_by_class.get(class_name, [])
        if limit_per_class > 0:
            class_paths = class_paths[:limit_per_class]
        paths.extend(class_paths)
    return paths


def load_graph_dataset(split: str, limit_per_class: int = 0) -> GraphFileDataset:
    if split not in {"train", "val", "test"}:
        raise ValueError("split must be one of: 'train', 'val', 'test'")
    return GraphFileDataset(split_paths(split, limit_per_class=limit_per_class))
