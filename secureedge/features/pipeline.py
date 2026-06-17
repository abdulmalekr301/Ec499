from __future__ import annotations

import json

from secureedge import config
from secureedge.data.dataset import load_graph_manifest
from secureedge.utils import ensure_directories, write_context


def validate_graph_features() -> dict:
    ensure_directories()
    manifest = load_graph_manifest()
    dims = manifest["feature_dimensions"]
    expected = {
        "flow_node": config.N_FLOW_NODE_FEATURES,
        "packet_node": config.N_PACKET_FEATURES,
        "contain_edge": config.N_CONTAIN_EDGE_FEATS,
        "link_edge": config.N_LINK_EDGE_FEATS,
    }
    mismatches = {name: {"expected": expected[name], "actual": dims.get(name)} for name in expected if dims.get(name) != expected[name]}
    if mismatches:
        raise ValueError(f"Graph feature dimensions do not match config: {mismatches}")

    for path in (config.FLOW_NODE_SCALER_PATH, config.CONTAIN_EDGE_SCALER_PATH, config.LINK_EDGE_NORM_PATH):
        if not path.exists():
            raise FileNotFoundError(f"Missing graph normalizer artifact: {path}")
    expected_train = config.TRAIN_SAMPLES_PER_CLASS * len(config.CLASS_NAMES)
    expected_test = config.TEST_SAMPLES_PER_CLASS * len(config.CLASS_NAMES)
    actual_train = int(manifest["splits"]["train"]["count"])
    actual_test = int(manifest["splits"]["test"]["count"])
    if actual_train != expected_train or actual_test != expected_test:
        raise ValueError(
            "Graph manifest does not contain the required final dataset split. "
            f"Expected train/test {expected_train}/{expected_test}, found {actual_train}/{actual_test}. "
            "Run `python -m secureedge.data.preprocess` on the full PCAP dataset."
        )

    write_context(
        "03_feature_engineering.md",
        "Graph Feature Engineering",
        [
            "## Action",
            "- Validated the final XG-NID graph feature artifacts.",
            "- Flow node features are the NFStream numeric feature vector plus the 16 temporal features.",
            "- Packet node features are 1,500 normalized payload-byte values per packet.",
            "- Contain edge features are standardized direction, IP size, transport size, and payload size.",
            "- Link edge features are packet-to-packet time deltas normalized by the 99th percentile from training graphs.",
            "",
            "## Manifest",
            "```json",
            json.dumps(
                {
                    "train_count": manifest["splits"]["train"]["count"],
                    "test_count": manifest["splits"]["test"]["count"],
                    "feature_dimensions": manifest["feature_dimensions"],
                    "scalers": manifest["scalers"],
                },
                indent=2,
            ),
            "```",
        ],
    )
    return manifest


def main() -> None:
    manifest = validate_graph_features()
    print(json.dumps({"graph_manifest": str(config.GRAPH_MANIFEST_PATH), "total_graph_count": manifest["total_graph_count"]}, indent=2))


if __name__ == "__main__":
    main()
