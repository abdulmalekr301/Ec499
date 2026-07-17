from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from secureedge import config as root_config
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, load_office_config
from secureedge.office.manifests import (
    DEFAULT_CUMULATIVE_PATH,
    atomic_write_text,
    load_compact_record,
    stable_json_hash,
)


DEFAULT_GATE_REPORT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "gate_reports"
DEFAULT_GATE5_PATH = DEFAULT_GATE_REPORT_DIR / "gate5_compact_features.json"
DEFAULT_GATE6_PATH = DEFAULT_GATE_REPORT_DIR / "gate6_graph_structure.json"
DEFAULT_OFFICE_GRAPH_MANIFEST_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_graph_dataset_manifest.json"

ADDRESS_IDENTITY_PATTERNS = (
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "ip_src",
    "ip_dst",
    "mac",
    "hwaddr",
)
TUPLE_CONTEXT_FEATURES = {"src_port", "dst_port", "protocol"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def limited_append(items: list[dict[str, Any]], item: dict[str, Any], limit: int) -> None:
    if len(items) < limit:
        items.append(item)


def _shape(value: Any) -> tuple[int, ...] | None:
    shape = getattr(value, "shape", None)
    if shape is None:
        return None
    return tuple(int(part) for part in shape)


def _is_finite_array(value: Any) -> bool:
    try:
        array = np.asarray(value)
        return bool(np.isfinite(array).all())
    except Exception:
        return False


def _dtype_name(value: Any) -> str:
    dtype = getattr(value, "dtype", None)
    return str(dtype) if dtype is not None else "unknown"


def _record_failure(
    failures: list[dict[str, Any]],
    path: str,
    reason: str,
    detail: Any,
    limit: int,
) -> None:
    limited_append(failures, {"path": path, "reason": reason, "detail": detail}, limit)


def validate_compact_pool(
    cumulative_path: Path = DEFAULT_CUMULATIVE_PATH,
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    output_path: Path = DEFAULT_GATE5_PATH,
    sample_limit: int = 200,
) -> dict[str, Any]:
    office_config = load_office_config(config_path)
    manifest = json.loads(cumulative_path.read_text(encoding="utf-8"))
    compact_root = Path(str(manifest["compact_root"]))
    expected_classes = office_config.class_names
    expected_class_to_label = {name: index for index, name in enumerate(expected_classes)}
    graph_cfg = office_config.data["graph"]
    expected_flow_dim = int(graph_cfg["flow_features"])
    expected_packet_dim = int(graph_cfg["packet_bytes"])
    expected_packet_limit = int(graph_cfg["flow_packet_limit"])
    expected_feature_version = str(graph_cfg["compact_feature_version"])

    hard_failures: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    per_class: Counter[str] = Counter()
    per_label: Counter[str] = Counter()
    packet_count_histogram: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    day_counts: Counter[str] = Counter()
    feature_versions: Counter[str] = Counter()
    dtype_counts = {
        "flow_x": Counter(),
        "packet_x_uint8": Counter(),
        "contain_edge_attr": Counter(),
        "link_edge_attr": Counter(),
    }
    dimension_counts = {
        "flow_dim": Counter(),
        "packet_dim": Counter(),
        "contain_edge_dim": Counter(),
        "link_edge_dim": Counter(),
    }
    candidate_identities: set[str] = set()
    duplicate_candidate_identities: list[str] = []
    flow_feature_name_sets: Counter[str] = Counter()
    observed_feature_names: set[str] = set()

    records = manifest.get("records", [])
    for entry in records:
        rel_path = str(entry.get("path", ""))
        path = compact_root / rel_path
        if not path.exists():
            _record_failure(hard_failures, rel_path, "missing_compact_file", "", sample_limit)
            continue
        try:
            record = load_compact_record(path)
        except Exception as exc:  # noqa: BLE001 - validation reports all compact load failures.
            _record_failure(hard_failures, rel_path, "load_error", f"{type(exc).__name__}: {exc}", sample_limit)
            continue

        class_name = str(record.get("class_name", ""))
        label = record.get("label")
        candidate_identity = str(record.get("candidate_identity", ""))
        feature_version = str(record.get("flow_feature_version", ""))
        source_dataset = str(record.get("source_dataset", "unknown"))
        day = str(record.get("day", "unknown"))
        per_class.update([class_name])
        per_label.update([str(label)])
        source_counts.update([source_dataset])
        day_counts.update([day])
        feature_versions.update([feature_version])

        if not candidate_identity:
            _record_failure(hard_failures, rel_path, "missing_candidate_identity", "", sample_limit)
        elif candidate_identity in candidate_identities:
            duplicate_candidate_identities.append(candidate_identity)
            _record_failure(hard_failures, rel_path, "duplicate_candidate_identity", candidate_identity, sample_limit)
        else:
            candidate_identities.add(candidate_identity)

        if class_name not in expected_class_to_label:
            _record_failure(hard_failures, rel_path, "unknown_class_name", class_name, sample_limit)
        elif int(label) != expected_class_to_label[class_name]:
            _record_failure(
                hard_failures,
                rel_path,
                "label_class_mismatch",
                {"class_name": class_name, "label": label, "expected": expected_class_to_label[class_name]},
                sample_limit,
            )

        if feature_version != expected_feature_version:
            _record_failure(
                hard_failures,
                rel_path,
                "feature_version_mismatch",
                {"actual": feature_version, "expected": expected_feature_version},
                sample_limit,
            )

        flow_x = record.get("flow_x")
        packet_x = record.get("packet_x_uint8")
        contain_edge_attr = record.get("contain_edge_attr")
        link_edge_attr = record.get("link_edge_attr")
        flow_shape = _shape(flow_x)
        packet_shape = _shape(packet_x)
        contain_shape = _shape(contain_edge_attr)
        link_shape = _shape(link_edge_attr)

        dtype_counts["flow_x"].update([_dtype_name(flow_x)])
        dtype_counts["packet_x_uint8"].update([_dtype_name(packet_x)])
        dtype_counts["contain_edge_attr"].update([_dtype_name(contain_edge_attr)])
        dtype_counts["link_edge_attr"].update([_dtype_name(link_edge_attr)])

        flow_dim = flow_shape[0] if flow_shape and len(flow_shape) == 1 else None
        packet_count = packet_shape[0] if packet_shape and len(packet_shape) == 2 else None
        packet_dim = packet_shape[1] if packet_shape and len(packet_shape) == 2 else None
        contain_rows = contain_shape[0] if contain_shape and len(contain_shape) == 2 else None
        contain_dim = contain_shape[1] if contain_shape and len(contain_shape) == 2 else None
        link_rows = link_shape[0] if link_shape and len(link_shape) == 2 else None
        link_dim = link_shape[1] if link_shape and len(link_shape) == 2 else None
        dimension_counts["flow_dim"].update([str(flow_dim)])
        dimension_counts["packet_dim"].update([str(packet_dim)])
        dimension_counts["contain_edge_dim"].update([str(contain_dim)])
        dimension_counts["link_edge_dim"].update([str(link_dim)])
        packet_count_histogram.update([str(packet_count)])

        if flow_dim != expected_flow_dim:
            _record_failure(hard_failures, rel_path, "flow_dim_mismatch", {"actual": flow_shape, "expected": expected_flow_dim}, sample_limit)
        if packet_count is None or packet_count < 1 or packet_count > expected_packet_limit:
            _record_failure(
                hard_failures,
                rel_path,
                "packet_count_out_of_range",
                {"actual": packet_count, "expected_min": 1, "expected_max": expected_packet_limit},
                sample_limit,
            )
        if packet_dim != expected_packet_dim:
            _record_failure(hard_failures, rel_path, "packet_dim_mismatch", {"actual": packet_shape, "expected": expected_packet_dim}, sample_limit)
        if _dtype_name(packet_x) != "uint8":
            _record_failure(hard_failures, rel_path, "packet_dtype_mismatch", _dtype_name(packet_x), sample_limit)
        if contain_rows != packet_count or contain_dim != root_config.N_CONTAIN_EDGE_FEATS:
            _record_failure(
                hard_failures,
                rel_path,
                "contain_edge_shape_mismatch",
                {"actual": contain_shape, "expected_rows": packet_count, "expected_dim": root_config.N_CONTAIN_EDGE_FEATS},
                sample_limit,
            )
        expected_link_rows = max(0, int(packet_count or 0) - 1)
        if link_rows != expected_link_rows or link_dim != root_config.N_LINK_EDGE_FEATS:
            _record_failure(
                hard_failures,
                rel_path,
                "link_edge_shape_mismatch",
                {"actual": link_shape, "expected_rows": expected_link_rows, "expected_dim": root_config.N_LINK_EDGE_FEATS},
                sample_limit,
            )
        if not _is_finite_array(flow_x):
            _record_failure(hard_failures, rel_path, "flow_nonfinite", "", sample_limit)
        if not _is_finite_array(contain_edge_attr):
            _record_failure(hard_failures, rel_path, "contain_edge_nonfinite", "", sample_limit)
        if not _is_finite_array(link_edge_attr):
            _record_failure(hard_failures, rel_path, "link_edge_nonfinite", "", sample_limit)

        feature_names = tuple(str(name) for name in record.get("flow_feature_names", []))
        observed_feature_names.update(feature_names)
        flow_feature_name_sets.update([stable_json_hash(feature_names)])
        if len(feature_names) != expected_flow_dim:
            _record_failure(
                hard_failures,
                rel_path,
                "flow_feature_name_count_mismatch",
                {"actual": len(feature_names), "expected": expected_flow_dim},
                sample_limit,
            )

    manifest_per_class = {str(key): int(value) for key, value in manifest.get("per_class", {}).items()}
    actual_per_class = dict(sorted(per_class.items()))
    if actual_per_class != manifest_per_class:
        _record_failure(
            hard_failures,
            str(cumulative_path),
            "manifest_class_count_mismatch",
            {"actual": actual_per_class, "manifest": manifest_per_class},
            sample_limit,
        )
    if len(records) != sum(per_class.values()):
        _record_failure(
            hard_failures,
            str(cumulative_path),
            "manifest_record_count_mismatch",
            {"records": len(records), "validated": sum(per_class.values())},
            sample_limit,
        )

    lower_feature_names = {name.lower() for name in observed_feature_names}
    address_identity_features = sorted(
        name for name in observed_feature_names if any(pattern in name.lower() for pattern in ADDRESS_IDENTITY_PATTERNS)
    )
    tuple_context_features = sorted(name for name in observed_feature_names if name.lower() in TUPLE_CONTEXT_FEATURES)
    if address_identity_features:
        _record_failure(
            hard_failures,
            "flow_feature_names",
            "address_identity_feature_names_present",
            address_identity_features,
            sample_limit,
        )
    if tuple_context_features:
        limited_append(
            warnings,
            {
                "path": "flow_feature_names",
                "reason": "tuple_context_features_present",
                "detail": tuple_context_features,
            },
            sample_limit,
        )
    if "src_ip" not in lower_feature_names and "dst_ip" not in lower_feature_names:
        limited_append(
            warnings,
            {
                "path": "flow_feature_names",
                "reason": "address_identity_features_absent",
                "detail": "No raw IP/MAC feature names were found.",
            },
            sample_limit,
        )

    report = {
        "schema_version": 1,
        "gate": "G5_COMPACT_FEATURES",
        "generated_at": utc_now(),
        **office_config.provenance(),
        "status": "pass" if not hard_failures else "fail",
        "hard_failure_count": len(hard_failures),
        "warning_count": len(warnings),
        "hard_failures": hard_failures,
        "warnings": warnings,
        "cumulative_manifest_path": str(cumulative_path.resolve()),
        "compact_root": str(compact_root.resolve()),
        "record_count": len(records),
        "validated_record_count": sum(per_class.values()),
        "manifest_hash": manifest.get("manifest_hash"),
        "per_class": actual_per_class,
        "per_label": dict(sorted(per_label.items())),
        "per_source_dataset": dict(sorted(source_counts.items())),
        "per_day": dict(sorted(day_counts.items())),
        "feature_versions": dict(sorted(feature_versions.items())),
        "dimension_counts": {key: dict(sorted(counter.items())) for key, counter in dimension_counts.items()},
        "dtype_counts": {key: dict(sorted(counter.items())) for key, counter in dtype_counts.items()},
        "packet_count_histogram": dict(sorted(packet_count_histogram.items(), key=lambda item: int(item[0]) if item[0].isdigit() else -1)),
        "duplicate_candidate_identity_count": len(duplicate_candidate_identities),
        "flow_feature_name_set_count": len(flow_feature_name_sets),
        "flow_feature_name_set_hashes": dict(sorted(flow_feature_name_sets.items())),
        "identity_leakage_audit": {
            "address_identity_patterns": list(ADDRESS_IDENTITY_PATTERNS),
            "address_identity_features": address_identity_features,
            "tuple_context_features": tuple_context_features,
        },
    }
    report["report_hash"] = stable_json_hash({key: value for key, value in report.items() if key != "report_hash"})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(output_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def _edge_pairs(edge_index: Any) -> list[tuple[int, int]]:
    array = edge_index.detach().cpu().numpy()
    if array.shape[0] != 2:
        return []
    return [(int(src), int(dst)) for src, dst in array.T]


def _tensor_is_finite(value: Any) -> bool:
    try:
        import torch

        return bool(torch.isfinite(value).all().item())
    except Exception:
        return False


def validate_graph_dataset(
    graph_manifest_path: Path = DEFAULT_OFFICE_GRAPH_MANIFEST_PATH,
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    output_path: Path = DEFAULT_GATE6_PATH,
    sample_limit: int = 200,
) -> dict[str, Any]:
    import torch

    office_config = load_office_config(config_path)
    graph_manifest = json.loads(graph_manifest_path.read_text(encoding="utf-8"))
    class_names = list(graph_manifest.get("class_names") or office_config.class_names)
    class_to_label = {name: index for index, name in enumerate(class_names)}
    dims = graph_manifest["feature_dimensions"]
    expected_flow_dim = int(dims["flow_node"])
    expected_packet_dim = int(dims["packet_node"])
    expected_contain_dim = int(dims["contain_edge"])
    expected_link_dim = int(dims["link_edge"])

    hard_failures: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    per_split: Counter[str] = Counter()
    per_class: Counter[str] = Counter()
    per_split_class: dict[str, Counter[str]] = {split: Counter() for split in ("train", "val", "test")}
    packet_count_histogram: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    day_counts: Counter[str] = Counter()
    graph_ids: set[str] = set()
    duplicate_graph_ids: list[str] = []

    all_files: list[tuple[str, str]] = []
    for split in ("train", "val", "test"):
        split_info = graph_manifest["splits"][split]
        files = list(split_info.get("files", []))
        expected_count = int(split_info["count"])
        if len(files) != expected_count:
            _record_failure(
                hard_failures,
                split,
                "manifest_file_count_mismatch",
                {"files": len(files), "expected": expected_count},
                sample_limit,
            )
        all_files.extend((split, path) for path in files)
        for class_name in class_names:
            if int(split_info["per_class"].get(class_name, 0)) == 0:
                limited_append(
                    warnings,
                    {
                        "path": split,
                        "reason": "class_missing_from_split",
                        "detail": class_name,
                    },
                    sample_limit,
                )

    for split, path_text in all_files:
        path = Path(path_text)
        if not path.exists():
            _record_failure(hard_failures, path_text, "missing_graph_file", "", sample_limit)
            continue
        try:
            graph = torch.load(path, map_location="cpu", weights_only=False)
        except Exception as exc:  # noqa: BLE001 - validation reports all graph load failures.
            _record_failure(hard_failures, path_text, "graph_load_error", f"{type(exc).__name__}: {exc}", sample_limit)
            continue

        graph_id = str(getattr(graph, "graph_id", ""))
        if not graph_id:
            _record_failure(hard_failures, path_text, "missing_graph_id", "", sample_limit)
        elif graph_id in graph_ids:
            duplicate_graph_ids.append(graph_id)
            _record_failure(hard_failures, path_text, "duplicate_graph_id", graph_id, sample_limit)
        else:
            graph_ids.add(graph_id)

        class_name = str(getattr(graph, "class_name", ""))
        per_split.update([split])
        per_class.update([class_name])
        per_split_class[split].update([class_name])
        source_counts.update([str(getattr(graph, "source_dataset", "unknown"))])
        day_counts.update([str(getattr(graph, "day", "unknown"))])

        if class_name not in class_to_label:
            _record_failure(hard_failures, path_text, "unknown_class_name", class_name, sample_limit)
        y_value = int(graph.y.item()) if hasattr(graph, "y") else None
        if class_name in class_to_label and y_value != class_to_label[class_name]:
            _record_failure(
                hard_failures,
                path_text,
                "label_class_mismatch",
                {"class_name": class_name, "label": y_value, "expected": class_to_label.get(class_name)},
                sample_limit,
            )

        if set(graph.node_types) != {"flow", "packet"}:
            _record_failure(hard_failures, path_text, "node_type_mismatch", list(graph.node_types), sample_limit)
        expected_edge_types = {
            ("flow", "contains", "packet"),
            ("packet", "rev_contains", "flow"),
        }
        n_packets = int(graph["packet"].x.shape[0]) if "packet" in graph.node_types else 0
        if n_packets > 1:
            expected_edge_types.add(("packet", "linked_to", "packet"))
        if not expected_edge_types.issubset(set(graph.edge_types)):
            _record_failure(
                hard_failures,
                path_text,
                "edge_type_missing",
                {"actual": [list(edge_type) for edge_type in graph.edge_types], "expected": [list(edge_type) for edge_type in expected_edge_types]},
                sample_limit,
            )

        if tuple(graph["flow"].x.shape) != (1, expected_flow_dim):
            _record_failure(
                hard_failures,
                path_text,
                "flow_x_shape_mismatch",
                {"actual": tuple(graph["flow"].x.shape), "expected": (1, expected_flow_dim)},
                sample_limit,
            )
        if n_packets < 1 or int(graph["packet"].x.shape[1]) != expected_packet_dim:
            _record_failure(
                hard_failures,
                path_text,
                "packet_x_shape_mismatch",
                {"actual": tuple(graph["packet"].x.shape), "expected_dim": expected_packet_dim},
                sample_limit,
            )
        packet_count_histogram.update([str(n_packets)])
        if not _tensor_is_finite(graph["flow"].x):
            _record_failure(hard_failures, path_text, "flow_x_nonfinite", "", sample_limit)
        if not _tensor_is_finite(graph["packet"].x):
            _record_failure(hard_failures, path_text, "packet_x_nonfinite", "", sample_limit)

        contains = graph["flow", "contains", "packet"]
        rev_contains = graph["packet", "rev_contains", "flow"]
        if tuple(contains.edge_index.shape) != (2, n_packets):
            _record_failure(hard_failures, path_text, "contains_edge_index_shape_mismatch", tuple(contains.edge_index.shape), sample_limit)
        if tuple(contains.edge_attr.shape) != (n_packets, expected_contain_dim):
            _record_failure(hard_failures, path_text, "contains_edge_attr_shape_mismatch", tuple(contains.edge_attr.shape), sample_limit)
        if tuple(rev_contains.edge_index.shape) != (2, n_packets):
            _record_failure(hard_failures, path_text, "rev_contains_edge_index_shape_mismatch", tuple(rev_contains.edge_index.shape), sample_limit)
        if tuple(rev_contains.edge_attr.shape) != (n_packets, expected_contain_dim):
            _record_failure(hard_failures, path_text, "rev_contains_edge_attr_shape_mismatch", tuple(rev_contains.edge_attr.shape), sample_limit)
        if not _tensor_is_finite(contains.edge_attr):
            _record_failure(hard_failures, path_text, "contains_edge_attr_nonfinite", "", sample_limit)
        if not _tensor_is_finite(rev_contains.edge_attr):
            _record_failure(hard_failures, path_text, "rev_contains_edge_attr_nonfinite", "", sample_limit)
        contains_pairs = _edge_pairs(contains.edge_index)
        if len(contains_pairs) != len(set(contains_pairs)):
            _record_failure(hard_failures, path_text, "duplicate_contains_edges", "", sample_limit)

        link_type = ("packet", "linked_to", "packet")
        if n_packets > 1:
            link = graph[link_type]
            expected_link_rows = n_packets - 1
            if tuple(link.edge_index.shape) != (2, expected_link_rows):
                _record_failure(hard_failures, path_text, "link_edge_index_shape_mismatch", tuple(link.edge_index.shape), sample_limit)
            if tuple(link.edge_attr.shape) != (expected_link_rows, expected_link_dim):
                _record_failure(hard_failures, path_text, "link_edge_attr_shape_mismatch", tuple(link.edge_attr.shape), sample_limit)
            if not _tensor_is_finite(link.edge_attr):
                _record_failure(hard_failures, path_text, "link_edge_attr_nonfinite", "", sample_limit)
            link_pairs = _edge_pairs(link.edge_index)
            if len(link_pairs) != len(set(link_pairs)):
                _record_failure(hard_failures, path_text, "duplicate_link_edges", "", sample_limit)
            if any(src == dst for src, dst in link_pairs):
                _record_failure(hard_failures, path_text, "link_self_loop", "", sample_limit)

    manifest_counts = {
        split: int(graph_manifest["splits"][split]["count"])
        for split in ("train", "val", "test")
    }
    if dict(per_split) != manifest_counts:
        _record_failure(
            hard_failures,
            str(graph_manifest_path),
            "split_count_mismatch",
            {"actual": dict(per_split), "manifest": manifest_counts},
            sample_limit,
        )

    report = {
        "schema_version": 1,
        "gate": "G6_GRAPH_STRUCTURE",
        "generated_at": utc_now(),
        **office_config.provenance(),
        "status": "pass" if not hard_failures else "fail",
        "hard_failure_count": len(hard_failures),
        "warning_count": len(warnings),
        "hard_failures": hard_failures,
        "warnings": warnings,
        "graph_manifest_path": str(graph_manifest_path.resolve()),
        "graph_manifest_hash": graph_manifest.get("manifest_hash"),
        "graph_value_mode": graph_manifest.get("graph_value_mode"),
        "record_count": len(all_files),
        "validated_graph_count": sum(per_split.values()),
        "per_split": dict(sorted(per_split.items())),
        "per_class": dict(sorted(per_class.items())),
        "per_split_class": {
            split: {class_name: per_split_class[split].get(class_name, 0) for class_name in class_names}
            for split in ("train", "val", "test")
        },
        "per_source_dataset": dict(sorted(source_counts.items())),
        "per_day": dict(sorted(day_counts.items())),
        "packet_count_histogram": dict(sorted(packet_count_histogram.items(), key=lambda item: int(item[0]) if item[0].isdigit() else -1)),
        "duplicate_graph_id_count": len(duplicate_graph_ids),
        "materialization_incomplete": bool(graph_manifest.get("materialization_incomplete", False)),
    }
    report["report_hash"] = stable_json_hash({key: value for key, value in report.items() if key != "report_hash"})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(output_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run office validation gates.")
    parser.add_argument("--gate", choices=("5", "g5", "G5", "6", "g6", "G6"), required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--cumulative-manifest", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_OFFICE_GRAPH_MANIFEST_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_GATE5_PATH)
    parser.add_argument("--sample-limit", type=int, default=200)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gate = args.gate.lower()
    if gate in {"5", "g5"}:
        output_path = args.output if args.output != DEFAULT_GATE5_PATH else DEFAULT_GATE5_PATH
        report = validate_compact_pool(
            cumulative_path=args.cumulative_manifest,
            config_path=args.config,
            output_path=output_path,
            sample_limit=args.sample_limit,
        )
    else:
        output_path = args.output if args.output != DEFAULT_GATE5_PATH else DEFAULT_GATE6_PATH
        report = validate_graph_dataset(
            graph_manifest_path=args.graph_manifest,
            config_path=args.config,
            output_path=output_path,
            sample_limit=args.sample_limit,
        )
    print(
        json.dumps(
            {
                "gate": report["gate"],
                "status": report["status"],
                "hard_failure_count": report["hard_failure_count"],
                "warning_count": report["warning_count"],
                "record_count": report["record_count"],
                "validated_record_count": report.get("validated_record_count", report.get("validated_graph_count")),
                "output": str(output_path),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
