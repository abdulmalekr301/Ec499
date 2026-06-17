from __future__ import annotations

import json
import pickle
from pathlib import Path

from secureedge import config
from secureedge.data.graph_builder import save_graph_dataset
from secureedge.utils import ensure_directories, write_context


def load_compact_manifest() -> dict[str, object]:
    if not config.COMPACT_RESERVOIR_MANIFEST_PATH.exists():
        raise FileNotFoundError(
            f"Compact reservoir manifest not found: {config.COMPACT_RESERVOIR_MANIFEST_PATH}. "
            "Run `python -m secureedge.data.preprocess` first."
        )
    return json.loads(config.COMPACT_RESERVOIR_MANIFEST_PATH.read_text(encoding="utf-8"))


def paths_from_manifest(manifest: dict[str, object], split: str) -> list[Path]:
    split_info = manifest.get("splits", {}).get(split, {})
    paths = [Path(item) for item in split_info.get("paths", [])]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Compact manifest references missing {split} records: {missing[:10]}")
    return paths


def validate_compact_feature_version(paths: list[Path]) -> None:
    if not paths:
        raise ValueError("Compact manifest split is empty.")
    with paths[0].open("rb") as handle:
        record = pickle.load(handle)
    version = record.get("flow_feature_version")
    flow_dim = int(record.get("flow_x").shape[0])
    if version != "xgnid_76_plus_temporal_16" or flow_dim != config.N_FLOW_NODE_FEATURES:
        raise ValueError(
            "Compact records are stale and do not contain the 92-dimensional flow node features. "
            f"Found version={version!r}, flow_dim={flow_dim}; expected "
            f"version='xgnid_76_plus_temporal_16', flow_dim={config.N_FLOW_NODE_FEATURES}. "
            "Delete/regenerate `data/graphs/_reservoir` by rerunning `python -m secureedge.data.preprocess`."
        )


def build_graphs() -> dict[str, object]:
    ensure_directories()
    manifest = load_compact_manifest()
    train_records = paths_from_manifest(manifest, "train")
    test_records = paths_from_manifest(manifest, "test")
    validate_compact_feature_version(train_records)
    validate_compact_feature_version(test_records)
    graph_manifest = save_graph_dataset(train_records, test_records)

    write_context(
        "17_build_graphs.md",
        "Graph Construction From Compact Records",
        [
            "## Action",
            f"- Loaded compact records from `{config.COMPACT_RESERVOIR_MANIFEST_PATH}`.",
            "- Fitted flow-node and contain-edge `StandardScaler` objects on training records only.",
            "- Fitted link-edge p99 normalization on training link deltas only.",
            "- Converted compact pickle records into PyG `HeteroData` graph objects.",
            f"- Saved training graphs under `{config.GRAPH_TRAIN_DIR}`.",
            f"- Saved test graphs under `{config.GRAPH_TEST_DIR}`.",
            f"- Saved graph manifest to `{config.GRAPH_MANIFEST_PATH}`.",
            "",
            "## Counts",
            "```json",
            json.dumps(
                {
                    "n_train": graph_manifest["n_train"],
                    "n_test": graph_manifest["n_test"],
                    "class_counts_train": graph_manifest["class_counts_train"],
                    "class_counts_test": graph_manifest["class_counts_test"],
                    "feature_dimensions": graph_manifest["feature_dimensions"],
                    "scalers": graph_manifest["scalers"],
                },
                indent=2,
            ),
            "```",
        ],
    )
    return graph_manifest


def main() -> None:
    manifest = build_graphs()
    print(
        json.dumps(
            {
                "graph_manifest": str(config.GRAPH_MANIFEST_PATH),
                "n_train": manifest["n_train"],
                "n_test": manifest["n_test"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
