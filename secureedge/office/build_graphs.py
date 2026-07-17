from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import torch
from sklearn.preprocessing import StandardScaler

from secureedge import config as root_config
from secureedge.data.graph_builder import compact_to_hetero_graph, graph_value_mode
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, load_office_config
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, atomic_write_text, load_compact_record, stable_json_hash


DEFAULT_OFFICE_GRAPH_ROOT = root_config.GRAPH_DIR
DEFAULT_TRAIN_DIR = DEFAULT_OFFICE_GRAPH_ROOT / "office_train"
DEFAULT_VAL_DIR = DEFAULT_OFFICE_GRAPH_ROOT / "office_val"
DEFAULT_TEST_DIR = DEFAULT_OFFICE_GRAPH_ROOT / "office_test"
DEFAULT_MANIFEST_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_graph_dataset_manifest.json"
DEFAULT_FLOW_SCALER_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_flow_node_scaler.joblib"
DEFAULT_CONTAIN_SCALER_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_contain_edge_scaler.joblib"
DEFAULT_LINK_NORM_PATH = root_config.ARTIFACTS_DIR / "office_model" / "office_link_edge_norm_p99.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def clear_pt_files(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for path in directory.glob("*.pt"):
        path.unlink()


def split_compact_records(cumulative_manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    splits: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    for record in cumulative_manifest.get("records", []):
        split = str(record.get("split", ""))
        if split in splits:
            splits[split].append(record)
    return splits


def compact_path(compact_root: Path, record: dict[str, Any]) -> Path:
    return compact_root / str(record["path"])


def fit_office_normalizers(
    train_records: list[dict[str, Any]],
    compact_root: Path,
    flow_scaler_path: Path,
    contain_scaler_path: Path,
    link_norm_path: Path,
) -> tuple[StandardScaler | None, StandardScaler | None, float]:
    if graph_value_mode() == "raw":
        atomic_write_text(
            link_norm_path,
            json.dumps({"method": "raw_unscaled", "p99_ms": None}, indent=2, sort_keys=True) + "\n",
        )
        return None, None, 1.0

    flow_rows: list[np.ndarray] = []
    contain_rows: list[np.ndarray] = []
    link_rows: list[np.ndarray] = []
    for record in train_records:
        compact = load_compact_record(compact_path(compact_root, record))
        flow_rows.append(np.asarray(compact["flow_x"], dtype=np.float32).reshape(1, -1))
        contain_rows.append(np.asarray(compact["contain_edge_attr"], dtype=np.float32))
        link_values = np.asarray(compact["link_edge_attr"], dtype=np.float32).reshape(-1)
        if link_values.size:
            link_rows.append(link_values)

    flow_scaler = StandardScaler()
    flow_scaler.fit(np.vstack(flow_rows).astype(np.float32))
    contain_scaler = StandardScaler()
    contain_scaler.fit(np.vstack(contain_rows).astype(np.float32))
    if link_rows:
        link_norm_value = float(np.percentile(np.concatenate(link_rows).astype(np.float32), 99))
    else:
        link_norm_value = 1.0
    if not np.isfinite(link_norm_value) or link_norm_value <= 0:
        link_norm_value = 1.0

    flow_scaler_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(flow_scaler, flow_scaler_path)
    joblib.dump(contain_scaler, contain_scaler_path)
    atomic_write_text(
        link_norm_path,
        json.dumps({"method": "p99_training_link_delta_ms", "p99_ms": link_norm_value}, indent=2, sort_keys=True) + "\n",
    )
    return flow_scaler, contain_scaler, link_norm_value


def normalize_compact_for_office(
    compact: dict[str, Any],
    flow_scaler: StandardScaler | None,
    contain_scaler: StandardScaler | None,
    link_norm_value: float,
) -> dict[str, Any]:
    if graph_value_mode() == "raw":
        return compact
    normalized = dict(compact)
    normalized["flow_x"] = flow_scaler.transform(
        np.asarray(compact["flow_x"], dtype=np.float32).reshape(1, -1)
    ).squeeze(0)
    normalized["contain_edge_attr"] = contain_scaler.transform(
        np.asarray(compact["contain_edge_attr"], dtype=np.float32)
    )
    link_edges = np.asarray(compact["link_edge_attr"], dtype=np.float32)
    if link_edges.size:
        normalized["link_edge_attr"] = link_edges / max(float(link_norm_value), 1.0)
    return normalized


def save_office_split(
    records: list[dict[str, Any]],
    split_name: str,
    split_dir: Path,
    compact_root: Path,
    class_names: list[str],
    flow_scaler: StandardScaler | None,
    contain_scaler: StandardScaler | None,
    link_norm_value: float,
    overwrite: bool,
) -> dict[str, Any]:
    if overwrite:
        clear_pt_files(split_dir)
    split_dir.mkdir(parents=True, exist_ok=True)
    counters: Counter[str] = Counter()
    paths_by_class: dict[str, list[str]] = defaultdict(list)
    graph_files: list[str] = []
    skipped_existing = 0
    for record in records:
        class_name = str(record["class_name"])
        counters[class_name] += 1
        candidate_identity = str(record["candidate_identity"])
        graph_id = stable_json_hash({"split": split_name, "candidate_identity": candidate_identity})
        out_path = split_dir / f"{class_name}_{counters[class_name]:06d}_{graph_id[:12]}.pt"
        if out_path.exists() and not overwrite:
            skipped_existing += 1
            paths_by_class[class_name].append(str(out_path))
            graph_files.append(str(out_path))
            continue
        compact = load_compact_record(compact_path(compact_root, record))
        graph = compact_to_hetero_graph(normalize_compact_for_office(compact, flow_scaler, contain_scaler, link_norm_value))
        if graph is None:
            raise ValueError(f"Compact record produced an empty graph: {record['path']}")
        graph.graph_id = graph_id
        graph.split = split_name
        graph.office_candidate_identity = candidate_identity
        graph.office_compact_path = str(compact_path(compact_root, record))
        graph.num_packets = int(graph["packet"].x.shape[0])
        graph.flow_id_hash = str(record.get("flow_hash") or "")
        torch.save(graph, out_path)
        paths_by_class[class_name].append(str(out_path))
        graph_files.append(str(out_path))
    return {
        "count": len(records),
        "skipped_existing": skipped_existing,
        "per_class": {class_name: len(paths_by_class.get(class_name, [])) for class_name in class_names},
        "paths": {class_name: paths_by_class.get(class_name, []) for class_name in class_names},
        "files": graph_files,
    }


def build_office_graphs(
    config_path: Path = DEFAULT_OFFICE_CONFIG_PATH,
    cumulative_manifest_path: Path = DEFAULT_CUMULATIVE_PATH,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    train_dir: Path = DEFAULT_TRAIN_DIR,
    val_dir: Path = DEFAULT_VAL_DIR,
    test_dir: Path = DEFAULT_TEST_DIR,
    flow_scaler_path: Path = DEFAULT_FLOW_SCALER_PATH,
    contain_scaler_path: Path = DEFAULT_CONTAIN_SCALER_PATH,
    link_norm_path: Path = DEFAULT_LINK_NORM_PATH,
    overwrite: bool = False,
) -> dict[str, Any]:
    office_config = load_office_config(config_path)
    cumulative_manifest = json.loads(cumulative_manifest_path.read_text(encoding="utf-8"))
    compact_root = Path(str(cumulative_manifest["compact_root"]))
    splits = split_compact_records(cumulative_manifest)
    if not splits["train"] or not splits["val"] or not splits["test"]:
        raise ValueError(
            "Office graph conversion requires non-empty train, val, and test compact splits. "
            f"Got train={len(splits['train'])}, val={len(splits['val'])}, test={len(splits['test'])}."
        )

    flow_scaler, contain_scaler, link_norm_value = fit_office_normalizers(
        splits["train"],
        compact_root,
        flow_scaler_path,
        contain_scaler_path,
        link_norm_path,
    )
    class_names = office_config.class_names
    split_outputs = {
        "train": save_office_split(
            splits["train"],
            "train",
            train_dir,
            compact_root,
            class_names,
            flow_scaler,
            contain_scaler,
            link_norm_value,
            overwrite=overwrite,
        ),
        "val": save_office_split(
            splits["val"],
            "val",
            val_dir,
            compact_root,
            class_names,
            flow_scaler,
            contain_scaler,
            link_norm_value,
            overwrite=overwrite,
        ),
        "test": save_office_split(
            splits["test"],
            "test",
            test_dir,
            compact_root,
            class_names,
            flow_scaler,
            contain_scaler,
            link_norm_value,
            overwrite=overwrite,
        ),
    }
    train_files = split_outputs["train"]["files"]
    first_compact = load_compact_record(compact_path(compact_root, splits["train"][0]))
    manifest = {
        "schema_version": 1,
        "pipeline": "office_compact_to_pyg_graphs",
        "generated_at": utc_now(),
        **office_config.provenance(),
        "cumulative_manifest_path": str(cumulative_manifest_path.resolve()),
        "cumulative_manifest_hash": cumulative_manifest.get("manifest_hash"),
        "graph_value_mode": graph_value_mode(),
        "raw_derived_flow_transform": root_config.RAW_DERIVED_FLOW_TRANSFORM if graph_value_mode() == "raw" else "not_applicable_scaled_mode",
        "class_names": class_names,
        "n_train": split_outputs["train"]["count"],
        "n_val": split_outputs["val"]["count"],
        "n_test": split_outputs["test"]["count"],
        "total_graph_count": sum(split_outputs[split]["count"] for split in ("train", "val", "test")),
        "splits": split_outputs,
        "graph_dirs": {
            "train": str(train_dir.resolve()),
            "val": str(val_dir.resolve()),
            "test": str(test_dir.resolve()),
        },
        "feature_dimensions": {
            "flow_node": int(np.asarray(first_compact["flow_x"]).shape[0]),
            "packet_node": int(office_config.data["graph"]["packet_bytes"]),
            "contain_edge": root_config.N_CONTAIN_EDGE_FEATS,
            "link_edge": root_config.N_LINK_EDGE_FEATS,
        },
        "flow_feature_names": list(first_compact.get("flow_feature_names", [])),
        "scalers": {
            "flow_node": str(flow_scaler_path.resolve()) if graph_value_mode() == "scaled" else None,
            "contain_edge": str(contain_scaler_path.resolve()) if graph_value_mode() == "scaled" else None,
            "link_edge": str(link_norm_path.resolve()),
        },
        "scaler_fit_source": (
            {
                "flow_scaler_fit_split": "train",
                "contain_edge_scaler_fit_split": "train",
                "link_delta_normalizer_fit_split": "train",
            }
            if graph_value_mode() == "scaled"
            else {
                "flow_scaler_fit_split": "disabled_raw_mode",
                "contain_edge_scaler_fit_split": "disabled_raw_mode",
                "link_delta_normalizer_fit_split": "disabled_raw_mode",
            }
        ),
        "link_edge_norm_value": link_norm_value,
        "materialization_incomplete": any(
            split_outputs[split]["per_class"].get(class_name, 0) == 0
            for split in ("train", "val", "test")
            for class_name in class_names
        ),
    }
    manifest["manifest_hash"] = stable_json_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    atomic_write_text(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert office compact graph records to PyG HeteroData graph files.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--cumulative-manifest", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--manifest-path", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--train-dir", type=Path, default=DEFAULT_TRAIN_DIR)
    parser.add_argument("--val-dir", type=Path, default=DEFAULT_VAL_DIR)
    parser.add_argument("--test-dir", type=Path, default=DEFAULT_TEST_DIR)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = build_office_graphs(
        config_path=args.config,
        cumulative_manifest_path=args.cumulative_manifest,
        manifest_path=args.manifest_path,
        train_dir=args.train_dir,
        val_dir=args.val_dir,
        test_dir=args.test_dir,
        overwrite=args.overwrite,
    )
    print(
        json.dumps(
            {
                "manifest": str(args.manifest_path),
                "n_train": manifest["n_train"],
                "n_val": manifest["n_val"],
                "n_test": manifest["n_test"],
                "total_graph_count": manifest["total_graph_count"],
                "materialization_incomplete": manifest["materialization_incomplete"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
