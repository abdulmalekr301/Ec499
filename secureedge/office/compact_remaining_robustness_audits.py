from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from secureedge import config as root_config
from secureedge.office.compact_group_holdout_nn_audit import (
    class_distribution,
    endpoint_service_key,
    infiltration_window_id,
    make_fold_specs,
    pcap_name,
    row_from_record,
    run_fold,
    stable_take,
    subtype_name,
    window_key,
)
from secureedge.office.compact_nearest_neighbor_similarity_audit import compact_vector
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, load_compact_record, stable_json_hash
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "remaining_audits"
DEFAULT_COMPACT_MANIFEST_PATH = (
    root_config.ARTIFACTS_DIR
    / "office_model"
    / "office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json"
)

TARGET_RETRAIN_FOLDS = {
    "infiltration_holdout_early_13_14h",
    "infiltration_holdout_late_18_19h",
    "ddos_holdout_hoic",
    "ddos_holdout_loic-udp",
    "dos_holdout_hulk",
    "dos_holdout_goldeneye",
    "bruteforce_holdout_ftp",
}
ABLATION_FOLDS = {
    "infiltration_holdout_early_13_14h",
    "infiltration_holdout_late_18_19h",
    "ddos_holdout_loic-udp",
    "dos_holdout_hulk",
    "bruteforce_holdout_ftp",
}
TEMPORAL_NAME_PREFIXES = ("Rolling_", "Unique_Ports_In_SourceDestination")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compact_path(root: Path, record: dict[str, Any]) -> Path:
    return root / Path(str(record["path"]))


def load_compact_rows_and_vectors(manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], np.ndarray, list[dict[str, Any]]]:
    manifest = load_json(manifest_path)
    root = Path(str(manifest["compact_root"]))
    rows: list[dict[str, Any]] = []
    vectors: list[np.ndarray] = []
    compacts: list[dict[str, Any]] = []
    for record in manifest.get("records", []):
        path = compact_path(root, record)
        compact = load_compact_record(path)
        row = row_from_record(record, compact, path)
        row["compact_rel_path"] = str(record["path"])
        rows.append(row)
        compacts.append(compact)
        vectors.append(compact_vector(compact))
    return manifest, rows, np.vstack(vectors).astype(np.float32), compacts


def graph_path_map(compact_manifest: dict[str, Any], graph_manifest: dict[str, Any]) -> dict[str, str]:
    class_names = manifest_class_names(graph_manifest)
    compact_by_split_class: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in compact_manifest.get("records", []):
        compact_by_split_class[(str(record.get("split")), str(record.get("class_name")))].append(record)

    output: dict[str, str] = {}
    errors: list[str] = []
    for split in ("train", "val", "test"):
        paths_by_class = graph_manifest["splits"][split]["paths"]
        for class_name in class_names:
            compact_records = compact_by_split_class[(split, class_name)]
            graph_paths = list(paths_by_class.get(class_name, []))
            if len(compact_records) != len(graph_paths):
                errors.append(
                    f"{split}/{class_name}: compact={len(compact_records)} graph={len(graph_paths)}"
                )
                continue
            for record, graph_path in zip(compact_records, graph_paths, strict=True):
                output[str(record["path"])] = str(graph_path)
    if errors:
        raise ValueError("Compact/PyG manifest split counts do not align: " + "; ".join(errors))
    return output


def paths_by_class(rows: list[dict[str, Any]], graph_paths: dict[str, str], class_names: list[str]) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {class_name: [] for class_name in class_names}
    for row in rows:
        output[str(row["class_name"])].append(graph_paths[str(row["compact_rel_path"])])
    return output


def split_payload(rows: list[dict[str, Any]], graph_paths: dict[str, str], class_names: list[str]) -> dict[str, Any]:
    paths = paths_by_class(rows, graph_paths, class_names)
    return {
        "count": len(rows),
        "per_class": {class_name: len(paths.get(class_name, [])) for class_name in class_names},
        "paths": paths,
        "files": [path for class_name in class_names for path in paths.get(class_name, [])],
    }


def write_robust_graph_manifest(
    *,
    base_graph_manifest: dict[str, Any],
    class_names: list[str],
    fold_id: str,
    fold_kind: str,
    heldout_rows: list[dict[str, Any]],
    graph_paths: dict[str, str],
    all_rows: list[dict[str, Any]],
    output_dir: Path,
) -> dict[str, Any]:
    heldout_ids = {str(row["compact_rel_path"]) for row in heldout_rows}
    train_rows = [
        row
        for row in all_rows
        if str(row["split"]) == "train" and str(row["compact_rel_path"]) not in heldout_ids
    ]
    val_rows = [
        row
        for row in all_rows
        if str(row["split"]) == "val" and str(row["compact_rel_path"]) not in heldout_ids
    ]
    if not val_rows:
        val_rows = stable_take(train_rows, min(2000, len(train_rows)), seed=42, salt=f"{fold_id}|fallback_val")
    test_rows = heldout_rows
    manifest = {
        **{key: value for key, value in base_graph_manifest.items() if key not in {"splits", "manifest_hash"}},
        "schema_version": 2,
        "pipeline": "office_robust_group_holdout_graph_manifest",
        "generated_at": utc_now(),
        "base_graph_manifest_hash": base_graph_manifest.get("manifest_hash", ""),
        "fold_id": fold_id,
        "fold_kind": fold_kind,
        "class_names": class_names,
        "n_train": len(train_rows),
        "n_val": len(val_rows),
        "n_test": len(test_rows),
        "total_graph_count": len(train_rows) + len(val_rows) + len(test_rows),
        "splits": {
            "train": split_payload(train_rows, graph_paths, class_names),
            "val": split_payload(val_rows, graph_paths, class_names),
            "test": split_payload(test_rows, graph_paths, class_names),
        },
        "robustness_fold": {
            "fold_id": fold_id,
            "fold_kind": fold_kind,
            "heldout_count": len(test_rows),
            "heldout_class_counts": class_distribution(test_rows),
            "train_class_counts": class_distribution(train_rows),
            "val_class_counts": class_distribution(val_rows),
            "test_class_counts": class_distribution(test_rows),
            "training_command_template": (
                "SECUREEDGE_DEVICE=cuda SECUREEDGE_MAX_EPOCHS=300 "
                f".venv/bin/python -m secureedge.office.train --graph-manifest {{manifest_path}} "
                f"--checkpoint-path artifacts/office_model/robustness/training/{fold_id}_best_office_hgnn.pt "
                f"--history-path artifacts/office_model/robustness/training/{fold_id}_history.json"
            ),
        },
    }
    manifest["materialization_incomplete"] = any(
        manifest["splits"][split]["per_class"].get(class_name, 0) <= 0
        for split in ("train", "val")
        for class_name in class_names
    )
    manifest["manifest_hash"] = stable_json_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    path = output_dir / f"{fold_id}_graph_manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "fold_id": fold_id,
        "fold_kind": fold_kind,
        "manifest_path": str(path),
        "heldout_count": len(test_rows),
        "train_class_counts": manifest["robustness_fold"]["train_class_counts"],
        "val_class_counts": manifest["robustness_fold"]["val_class_counts"],
        "test_class_counts": manifest["robustness_fold"]["test_class_counts"],
        "materialization_incomplete": manifest["materialization_incomplete"],
        "training_command": manifest["robustness_fold"]["training_command_template"].format(manifest_path=str(path)),
    }


def make_targeted_retraining_manifests(
    *,
    rows: list[dict[str, Any]],
    compact_manifest: dict[str, Any],
    graph_manifest: dict[str, Any],
    output_dir: Path,
) -> list[dict[str, Any]]:
    class_names = manifest_class_names(graph_manifest)
    graph_paths = graph_path_map(compact_manifest, graph_manifest)
    summaries: list[dict[str, Any]] = []
    for spec in make_fold_specs():
        if spec["fold_id"] not in TARGET_RETRAIN_FOLDS:
            continue
        heldout_rows = [row for row in rows if spec["predicate"](row)]
        summaries.append(
            write_robust_graph_manifest(
                base_graph_manifest=graph_manifest,
                class_names=class_names,
                fold_id=spec["fold_id"],
                fold_kind=str(spec["audit_scope"]),
                heldout_rows=heldout_rows,
                graph_paths=graph_paths,
                all_rows=rows,
                output_dir=output_dir / "robust_pyg_manifests",
            )
        )
    return summaries


def pcap_fold_key(row: dict[str, Any]) -> str:
    return "|".join([str(row.get("class_name")), str(row.get("day", "unknown")), str(row.get("pcap", "missing_pcap"))])


def make_pcap_holdout_manifests(
    *,
    rows: list[dict[str, Any]],
    compact_manifest: dict[str, Any],
    graph_manifest: dict[str, Any],
    output_dir: Path,
    max_folds: int = 5,
) -> list[dict[str, Any]]:
    class_names = manifest_class_names(graph_manifest)
    graph_paths = graph_path_map(compact_manifest, graph_manifest)
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row.get("class_name") == "WebBased":
            continue
        by_key[pcap_fold_key(row)].append(row)
    total_counts = Counter(str(row.get("class_name")) for row in rows)
    candidates = []
    for key, group_rows in by_key.items():
        heldout_counts = Counter(str(row.get("class_name")) for row in group_rows)
        remaining = {class_name: total_counts[class_name] - heldout_counts[class_name] for class_name in class_names}
        if any(value <= 0 for value in remaining.values()):
            continue
        if len(group_rows) < 1000:
            continue
        candidates.append((len(group_rows), key, group_rows))
    selected = sorted(candidates, key=lambda item: (-item[0], item[1]))[:max_folds]
    summaries: list[dict[str, Any]] = []
    for _, key, heldout_rows in selected:
        class_name, day, pcap = key.split("|", maxsplit=2)
        fold_id = "pcap_holdout_" + stable_json_hash({"key": key})[:12]
        summary = write_robust_graph_manifest(
            base_graph_manifest=graph_manifest,
            class_names=class_names,
            fold_id=fold_id,
            fold_kind="Whole-PCAP holdout",
            heldout_rows=heldout_rows,
            graph_paths=graph_paths,
            all_rows=rows,
            output_dir=output_dir / "robust_pyg_manifests",
        )
        summary.update({"heldout_class": class_name, "heldout_day": day, "heldout_pcap": pcap})
        summaries.append(summary)
    return summaries


def endpoint_service_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_class: dict[str, dict[str, Any]] = {}
    for class_name in sorted({str(row.get("class_name")) for row in rows}):
        class_rows = [row for row in rows if str(row.get("class_name")) == class_name]
        keys = [endpoint_service_key(row) for row in class_rows]
        unknown = [key for key in keys if "unknown" in key]
        by_class[class_name] = {
            "count": len(class_rows),
            "endpoint_service_groups": len(set(keys)),
            "unknown_key_count": len(unknown),
            "unknown_key_rate": len(unknown) / max(len(class_rows), 1),
            "top_groups": dict(Counter(keys).most_common(8)),
            "status": "usable" if len(unknown) == 0 and len(set(keys)) >= 3 else "blocked_or_weak_metadata",
        }
    return {"by_class": by_class}


def temporal_context_audit(compacts: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    feature_names = list(compacts[0].get("flow_feature_names", [])) if compacts else []
    temporal_indices = [
        index
        for index, name in enumerate(feature_names)
        if str(name).startswith(TEMPORAL_NAME_PREFIXES)
    ]
    statuses = Counter(str(compact.get("temporal_context_status", "missing")) for compact in compacts)
    by_class = {}
    for class_name in sorted({str(row.get("class_name")) for row in rows}):
        indices = [index for index, row in enumerate(rows) if str(row.get("class_name")) == class_name]
        by_class[class_name] = dict(Counter(str(compacts[index].get("temporal_context_status", "missing")) for index in indices))
    return {
        "flow_feature_count": len(feature_names),
        "temporal_feature_count": len(temporal_indices),
        "temporal_feature_indices": temporal_indices,
        "temporal_feature_names": [feature_names[index] for index in temporal_indices],
        "temporal_context_status_counts": dict(statuses),
        "temporal_context_status_by_class": by_class,
        "has_temporal_index_path": any(compact.get("temporal_index_path") for compact in compacts),
        "status": "metadata_complete_but_temporal_index_not_provenanced"
        if temporal_indices and not any(compact.get("temporal_index_path") for compact in compacts)
        else "complete",
    }


def compact_for_ablation(compact: dict[str, Any], variant: str) -> dict[str, Any]:
    item = dict(compact)
    flow_x = np.asarray(item.get("flow_x", []), dtype=np.float32).copy()
    packet_x = np.asarray(item.get("packet_x_uint8", []), dtype=np.float32).copy()
    contain = np.asarray(item.get("contain_edge_attr", []), dtype=np.float32).copy()
    link = np.asarray(item.get("link_edge_attr", []), dtype=np.float32).copy()
    feature_names = list(item.get("flow_feature_names", []))
    temporal_indices = [
        index for index, name in enumerate(feature_names) if str(name).startswith(TEMPORAL_NAME_PREFIXES)
    ]
    port_indices = [index for index, name in enumerate(feature_names) if str(name) in {"src_port", "dst_port"}]
    protocol_indices = [index for index, name in enumerate(feature_names) if str(name) == "protocol"]
    if variant == "no_temporal":
        flow_x[temporal_indices] = 0.0
    elif variant == "temporal_only":
        keep = np.zeros_like(flow_x)
        keep[temporal_indices] = flow_x[temporal_indices]
        flow_x = keep
        packet_x[:] = 0.0
        contain[:] = 0.0
        link[:] = 0.0
    elif variant == "flow_only":
        packet_x[:] = 0.0
        contain[:] = 0.0
        link[:] = 0.0
    elif variant == "no_ports":
        flow_x[port_indices] = 0.0
    elif variant == "no_protocol":
        flow_x[protocol_indices] = 0.0
    elif variant == "no_packet_payload":
        packet_x[:] = 0.0
    elif variant == "packet_only":
        flow_x[:] = 0.0
        contain[:] = 0.0
        link[:] = 0.0
    elif variant != "full":
        raise ValueError(f"Unknown ablation variant: {variant}")
    item["flow_x"] = flow_x
    item["packet_x_uint8"] = packet_x
    item["contain_edge_attr"] = contain
    item["link_edge_attr"] = link
    return item


def feature_ablation_nn_audit(
    *,
    rows: list[dict[str, Any]],
    compacts: list[dict[str, Any]],
    output_dir: Path,
    query_cap: int,
    reference_per_class: int,
    seed: int,
) -> dict[str, Any]:
    variants = [
        "full",
        "no_temporal",
        "temporal_only",
        "flow_only",
        "no_ports",
        "no_protocol",
        "no_packet_payload",
        "packet_only",
    ]
    fold_specs = [spec for spec in make_fold_specs() if spec["fold_id"] in ABLATION_FOLDS]
    results: list[dict[str, Any]] = []
    for variant in variants:
        vectors = np.vstack([compact_vector(compact_for_ablation(compact, variant)) for compact in compacts]).astype(np.float32)
        for spec in fold_specs:
            result = run_fold(
                spec=spec,
                vectors=vectors,
                rows=rows,
                query_cap=query_cap,
                reference_per_class=reference_per_class,
                seed=seed,
                n_neighbors=10,
            )
            result["ablation_variant"] = variant
            results.append(result)
    summary = {
        "variants": variants,
        "fold_ids": [spec["fold_id"] for spec in fold_specs],
        "query_cap": query_cap,
        "reference_per_class": reference_per_class,
        "rows": results,
    }
    path = output_dir / "feature_ablation_compact_nn_audit.json"
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return {**summary, "artifact_path": str(path)}


def group_key_for_balance(row: dict[str, Any]) -> str:
    return "|".join([str(row.get("class_name")), str(row.get("subtype")), str(row.get("window_key"))])


def round_robin_groups(groups: dict[str, list[dict[str, Any]]], target: int) -> list[dict[str, Any]]:
    buckets = [(key, list(values)) for key, values in sorted(groups.items())]
    output: list[dict[str, Any]] = []
    while len(output) < target:
        progressed = False
        for _, values in buckets:
            if not values:
                continue
            output.append(values.pop(0))
            progressed = True
            if len(output) >= target:
                break
        if not progressed:
            break
    return output


def group_balance_and_campaign_cap_audit(rows: list[dict[str, Any]], output_dir: Path, *, cap_per_group: int = 1000) -> dict[str, Any]:
    train_rows = [row for row in rows if str(row.get("split")) == "train"]
    class_names = sorted({str(row.get("class_name")) for row in train_rows})
    by_class: dict[str, dict[str, Any]] = {}
    capped_rows: list[dict[str, Any]] = []
    balanced_rows: list[dict[str, Any]] = []
    for class_name in class_names:
        class_rows = [row for row in train_rows if str(row.get("class_name")) == class_name]
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in class_rows:
            groups[group_key_for_balance(row)].append(row)
        target = len(class_rows)
        balanced = round_robin_groups(groups, target)
        balanced_rows.extend(balanced)
        class_capped: list[dict[str, Any]] = []
        for key, group_rows in sorted(groups.items()):
            class_capped.extend(stable_take(group_rows, cap_per_group, seed=42, salt=f"cap|{key}"))
        capped_rows.extend(class_capped)
        largest = Counter(group_key_for_balance(row) for row in class_rows).most_common(1)[0]
        by_class[class_name] = {
            "train_count": len(class_rows),
            "group_count": len(groups),
            "largest_group": largest[0],
            "largest_group_count": largest[1],
            "largest_group_share": largest[1] / max(len(class_rows), 1),
            "subtype_counts": dict(Counter(str(row.get("subtype")) for row in class_rows)),
            "group_balanced_available_count": len(balanced),
            "group_balanced_subtype_counts": dict(Counter(str(row.get("subtype")) for row in balanced)),
            "campaign_cap_per_group": cap_per_group,
            "campaign_capped_count": len(class_capped),
            "campaign_capped_subtype_counts": dict(Counter(str(row.get("subtype")) for row in class_capped)),
        }
    capped_manifest = {
        "schema_version": 1,
        "pipeline": "office_campaign_capped_compact_manifest",
        "generated_at": utc_now(),
        "cap_per_class_subtype_window_group": cap_per_group,
        "records": [
            {key: row.get(key) for key in ("path", "candidate_identity", "class_name", "label", "split", "source_dataset", "day", "subtype_label")}
            for row in capped_rows
        ],
        "per_class_counts": dict(Counter(str(row.get("class_name")) for row in capped_rows)),
    }
    capped_manifest["manifest_hash"] = stable_json_hash({key: value for key, value in capped_manifest.items() if key != "manifest_hash"})
    capped_path = output_dir / "campaign_capped_train_compact_manifest.json"
    capped_path.write_text(json.dumps(capped_manifest, indent=2, sort_keys=True), encoding="utf-8")
    result = {
        "by_class": by_class,
        "group_balanced_total_available": len(balanced_rows),
        "campaign_capped_total": len(capped_rows),
        "campaign_capped_manifest_path": str(capped_path),
    }
    path = output_dir / "group_balance_campaign_cap_audit.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return {**result, "artifact_path": str(path)}


def external_data_audit(dataset_root: Path) -> dict[str, Any]:
    pcap_files = sorted(str(path) for path in dataset_root.glob("**/*") if path.suffix.lower() in {".pcap", ".pcapng"})
    csv_files = sorted(str(path) for path in dataset_root.glob("**/*") if path.suffix.lower() == ".csv")
    independent_candidates = [
        path for path in pcap_files + csv_files if "cic_ids_2018" not in path.lower() and "cicids2017" not in path.lower()
    ]
    return {
        "dataset_root": str(dataset_root),
        "pcap_file_count": len(pcap_files),
        "csv_file_count": len(csv_files),
        "pcap_files": pcap_files,
        "independent_external_candidate_count": len(independent_candidates),
        "independent_external_candidates": independent_candidates,
        "status": "blocked_no_independent_external_dataset"
        if not independent_candidates
        else "external_candidates_available",
    }


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Office Remaining Robustness Audits",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Audit 5 - Targeted Retraining Manifests",
        "",
        "| Fold | Held out | Train classes | Test classes | Manifest |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for item in report["targeted_retraining_manifests"]:
        lines.append(
            f"| {item['fold_id']} | {item['heldout_count']} | "
            f"{item['train_class_counts']} | {item['test_class_counts']} | `{item['manifest_path']}` |"
        )
    lines.extend(
        [
            "",
            "Status: fold manifests and exact training commands were generated. Full HGNN retraining was not run in this CPU-only session.",
            "",
            "## Audit 6 - Whole-PCAP Holdout Manifests",
            "",
            "| Fold | Class | Day | Held out | PCAP | Manifest |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for item in report["pcap_holdout_manifests"]:
        lines.append(
            f"| {item['fold_id']} | {item['heldout_class']} | {item['heldout_day']} | "
            f"{item['heldout_count']} | `{item['heldout_pcap']}` | `{item['manifest_path']}` |"
        )
    lines.extend(
        [
            "",
            "## Audit 7 - Endpoint/Service Feasibility",
            "",
            "| Class | Graphs | Groups | Unknown-key rate | Status |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for class_name, item in report["endpoint_service_audit"]["by_class"].items():
        lines.append(
            f"| {class_name} | {item['count']} | {item['endpoint_service_groups']} | "
            f"{item['unknown_key_rate']:.6f} | {item['status']} |"
        )
    temporal = report["temporal_context_audit"]
    lines.extend(
        [
            "",
            "## Audit 8 - Temporal Context",
            "",
            f"- Flow feature count: `{temporal['flow_feature_count']}`.",
            f"- Temporal feature count: `{temporal['temporal_feature_count']}`.",
            f"- Temporal context status counts: `{temporal['temporal_context_status_counts']}`.",
            f"- Has temporal index path provenance: `{temporal['has_temporal_index_path']}`.",
            f"- Status: `{temporal['status']}`.",
            "",
            "## Audit 9 - Feature Ablation NN",
            "",
            f"- Artifact: `{report['feature_ablation_nn_audit']['artifact_path']}`.",
            f"- Variants: `{', '.join(report['feature_ablation_nn_audit']['variants'])}`.",
            f"- Folds: `{', '.join(report['feature_ablation_nn_audit']['fold_ids'])}`.",
            "",
            "## Audits 10 and 11 - Group Balance and Campaign Cap",
            "",
            "| Class | Train | Groups | Largest group share | Capped train |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    balance = report["group_balance_campaign_cap_audit"]
    for class_name, item in balance["by_class"].items():
        lines.append(
            f"| {class_name} | {item['train_count']} | {item['group_count']} | "
            f"{item['largest_group_share']:.6f} | {item['campaign_capped_count']} |"
        )
    external = report["external_data_audit"]
    lines.extend(
        [
            "",
            "## Audit 12 - External Data Availability",
            "",
            f"- Dataset root: `{external['dataset_root']}`.",
            f"- Local PCAP files found: `{external['pcap_file_count']}`.",
            f"- Local CSV files found: `{external['csv_file_count']}`.",
            f"- Independent external candidates found: `{external['independent_external_candidate_count']}`.",
            f"- Status: `{external['status']}`.",
            "",
            "## Artifact Paths",
            "",
            f"- JSON: `{report['artifact_paths']['json']}`",
            f"- Markdown: `{report['artifact_paths']['markdown']}`",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_remaining_audits(
    *,
    compact_manifest_path: Path = DEFAULT_COMPACT_MANIFEST_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    dataset_root: Path = root_config.ROOT_DIR / "datasets",
    query_cap: int = 500,
    reference_per_class: int = 2500,
    seed: int = 42,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    compact_manifest, rows, _, compacts = load_compact_rows_and_vectors(compact_manifest_path)
    graph_manifest = load_json(graph_manifest_path)
    report = {
        "generated_at": utc_now(),
        "compact_manifest_path": str(compact_manifest_path),
        "graph_manifest_path": str(graph_manifest_path),
        "targeted_retraining_manifests": make_targeted_retraining_manifests(
            rows=rows,
            compact_manifest=compact_manifest,
            graph_manifest=graph_manifest,
            output_dir=output_dir,
        ),
        "pcap_holdout_manifests": make_pcap_holdout_manifests(
            rows=rows,
            compact_manifest=compact_manifest,
            graph_manifest=graph_manifest,
            output_dir=output_dir,
        ),
        "endpoint_service_audit": endpoint_service_audit(rows),
        "temporal_context_audit": temporal_context_audit(compacts, rows),
        "feature_ablation_nn_audit": feature_ablation_nn_audit(
            rows=rows,
            compacts=compacts,
            output_dir=output_dir,
            query_cap=query_cap,
            reference_per_class=reference_per_class,
            seed=seed,
        ),
        "group_balance_campaign_cap_audit": group_balance_and_campaign_cap_audit(rows, output_dir),
        "external_data_audit": external_data_audit(dataset_root),
        "artifact_paths": {
            "json": str(output_dir / "remaining_robustness_audits.json"),
            "markdown": str(output_dir / "remaining_robustness_audits.md"),
        },
    }
    (output_dir / "remaining_robustness_audits.json").write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_markdown(output_dir / "remaining_robustness_audits.md", report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Complete local Office robustness audit artifacts for audits 5-12.")
    parser.add_argument("--compact-manifest", type=Path, default=DEFAULT_COMPACT_MANIFEST_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dataset-root", type=Path, default=root_config.ROOT_DIR / "datasets")
    parser.add_argument("--query-cap", type=int, default=500)
    parser.add_argument("--reference-per-class", type=int, default=2500)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_remaining_audits(
        compact_manifest_path=args.compact_manifest,
        graph_manifest_path=args.graph_manifest,
        output_dir=args.output_dir,
        dataset_root=args.dataset_root,
        query_cap=args.query_cap,
        reference_per_class=args.reference_per_class,
        seed=args.seed,
    )
    print(json.dumps(report["artifact_paths"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
