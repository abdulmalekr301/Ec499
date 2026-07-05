from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import numpy as np

from secureedge import config
from secureedge.utils import ensure_directories, write_context


def compact_paths(limit: int) -> list[Path]:
    grouped = [
        sorted(directory.glob("*.pkl"))
        for directory in sorted(config.GRAPH_RESERVOIR_DIR.iterdir())
        if directory.is_dir()
    ]
    paths = [path for group in grouped for path in group]
    if limit <= 0 or len(paths) <= limit:
        return paths
    selected: list[Path] = []
    group_index = 0
    while len(selected) < limit and any(grouped):
        group = grouped[group_index % len(grouped)]
        if group:
            selected.append(group.pop(0))
        group_index += 1
    return selected


def inspect_compact(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        compact = pickle.load(handle)
    flow_values = np.asarray(compact["flow_x"], dtype=np.float32)
    packet_rows = np.asarray(compact["packet_x_uint8"], dtype=np.uint8)
    feature_names = list(compact.get("flow_feature_names", []))
    try:
        packet_feature_index = feature_names.index("bidirectional_packets")
        flow_packet_count = float(flow_values[packet_feature_index])
    except ValueError:
        packet_feature_index = None
        flow_packet_count = None
    packet_node_count = int(packet_rows.shape[0])
    mismatch = bool(flow_packet_count is not None and flow_packet_count > config.FLOW_PACKET_LIMIT and packet_node_count <= config.FLOW_PACKET_LIMIT)
    return {
        "path": str(path),
        "class_name": compact.get("class_name"),
        "subtype_label": compact.get("subtype_label"),
        "flow_bidirectional_packets": flow_packet_count,
        "packet_node_count": packet_node_count,
        "packet_feature_index": packet_feature_index,
        "mismatch": mismatch,
    }


def verify(limit: int) -> dict[str, object]:
    ensure_directories()
    paths = compact_paths(limit)
    if not paths:
        raise FileNotFoundError(f"No compact reservoir records found under {config.GRAPH_RESERVOIR_DIR}")
    samples = [inspect_compact(path) for path in paths]
    mismatches = [item for item in samples if item["mismatch"]]
    packet_counts = [
        float(item["flow_bidirectional_packets"])
        for item in samples
        if item["flow_bidirectional_packets"] is not None
    ]
    result = {
        "records_examined": len(samples),
        "flow_packet_limit": config.FLOW_PACKET_LIMIT,
        "mismatch_count": len(mismatches),
        "mismatch_fraction": len(mismatches) / max(len(samples), 1),
        "max_flow_bidirectional_packets": max(packet_counts) if packet_counts else None,
        "max_packet_node_count": max(int(item["packet_node_count"]) for item in samples),
        "sample_mismatches": mismatches[:20],
        "sample_records": samples[:20],
        "conclusion": (
            "mismatch_confirmed_rebuild_needed"
            if mismatches
            else "no_mismatch_observed_flowcapper_consistent"
        ),
    }
    output_path = config.ARTIFACTS_DIR / "flow_window_consistency.json"
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    write_context(
        "41_flow_window_consistency.md",
        "Flow Window Consistency",
        [
            "## Action",
            f"- Examined `{len(samples)}` compact reservoir records under `{config.GRAPH_RESERVOIR_DIR}`.",
            f"- Saved machine-readable output to `{output_path}`.",
            "",
            "## Result",
            "```json",
            json.dumps(
                {
                    "records_examined": result["records_examined"],
                    "flow_packet_limit": result["flow_packet_limit"],
                    "mismatch_count": result["mismatch_count"],
                    "mismatch_fraction": result["mismatch_fraction"],
                    "max_flow_bidirectional_packets": result["max_flow_bidirectional_packets"],
                    "max_packet_node_count": result["max_packet_node_count"],
                    "conclusion": result["conclusion"],
                },
                indent=2,
            ),
            "```",
        ],
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify flow statistics and packet nodes use the same <=20 packet window.")
    parser.add_argument("--limit", type=int, default=5000, help="Maximum compact records to inspect; use 0 for all records.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(verify(args.limit), indent=2))


if __name__ == "__main__":
    main()
