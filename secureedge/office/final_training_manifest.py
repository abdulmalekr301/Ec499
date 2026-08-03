from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import torch

from secureedge import config as root_config
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.compact_group_holdout_nn_audit import pcap_name, row_from_record, stable_take, subtype_name, window_key
from secureedge.office.manifests import load_compact_record, stable_json_hash
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_COMPACT_MANIFEST_PATH = (
    root_config.ARTIFACTS_DIR
    / "office_model"
    / "office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json"
)
DEFAULT_OUTPUT_PATH = (
    root_config.ARTIFACTS_DIR
    / "office_model"
    / "office_final_robust_training_manifest.json"
)
DEFAULT_REPORT_PATH = root_config.CONTEXT_DIR / "120_office_final_robust_training_manifest.md"

QUESTIONABLE_SUBTYPES = {
    ("BruteForce", "FTP-BruteForce"): "ftp_bruteforce_attempted_stress_set",
    ("DoS", "DoS-SlowHTTPTest"): "dos_slowhttptest_attempted_stress_set",
}
TEMPORAL_NAME_PREFIXES = ("Rolling_", "Unique_Ports_In_SourceDestination")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compact_path(root: Path, record: dict[str, Any]) -> Path:
    return root / Path(str(record["path"]))


def stable_even_take(rows: list[dict[str, Any]], target: int, *, seed: int, salt: str) -> list[dict[str, Any]]:
    if target <= 0 or len(rows) <= target:
        return list(rows)
    ordered = sorted(
        rows,
        key=lambda row: (
            str(row.get("candidate_timestamp") or ""),
            int(row.get("source_order") or 0),
            stable_take([row], 1, seed=seed, salt=salt)[0].get("compact_rel_path", ""),
        ),
    )
    if target == 1:
        return [ordered[len(ordered) // 2]]
    positions = [round(index * (len(ordered) - 1) / (target - 1)) for index in range(target)]
    return [ordered[int(position)] for position in positions]


def load_rows(compact_manifest_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = load_json(compact_manifest_path)
    root = Path(str(manifest["compact_root"]))
    rows: list[dict[str, Any]] = []
    for record in manifest.get("records", []):
        path = compact_path(root, record)
        compact = load_compact_record(path)
        row = row_from_record(record, compact, path)
        row["compact_rel_path"] = str(record["path"])
        row["source_order"] = int(record.get("source_order") or compact.get("source_order") or 0)
        row["candidate_timestamp"] = str(row.get("candidate_timestamp") or compact.get("candidate_timestamp") or "")
        row["flow_feature_names"] = list(compact.get("flow_feature_names", []))
        rows.append(row)
    return manifest, rows


def graph_path_map(rows: list[dict[str, Any]], graph_manifest: dict[str, Any]) -> dict[str, str]:
    class_names = manifest_class_names(graph_manifest)
    graph_by_candidate: dict[str, str] = {}
    duplicate_candidates: dict[str, list[str]] = defaultdict(list)
    for split in ("train", "val", "test"):
        paths_by_class = graph_manifest["splits"][split]["paths"]
        for class_name in class_names:
            graph_paths = list(paths_by_class.get(class_name, []))
            for graph_path in graph_paths:
                graph = torch.load(graph_path, map_location="cpu", weights_only=False)
                candidate_identity = str(getattr(graph, "office_candidate_identity", ""))
                if not candidate_identity:
                    raise ValueError(f"PyG graph is missing office_candidate_identity: {graph_path}")
                if candidate_identity in graph_by_candidate:
                    duplicate_candidates[candidate_identity].extend([graph_by_candidate[candidate_identity], str(graph_path)])
                else:
                    graph_by_candidate[candidate_identity] = str(graph_path)
    if duplicate_candidates:
        examples = {
            candidate: paths[:4]
            for candidate, paths in list(sorted(duplicate_candidates.items()))[:5]
        }
        raise ValueError(f"Duplicate PyG office_candidate_identity values prevent stable joining: {examples}")

    output: dict[str, str] = {}
    missing: list[str] = []
    for row in rows:
        candidate_identity = str(row.get("candidate_identity") or "")
        graph_path = graph_by_candidate.get(candidate_identity)
        if graph_path is None:
            missing.append(candidate_identity or str(row.get("compact_rel_path", "")))
            continue
        output[str(row["compact_rel_path"])] = graph_path
    if missing:
        raise ValueError(
            "Compact rows without matching PyG office_candidate_identity: "
            + "; ".join(missing[:10])
            + (f"; ... {len(missing) - 10} more" if len(missing) > 10 else "")
        )
    return output


def group_key(row: dict[str, Any]) -> str:
    return "|".join(
        [
            str(row.get("source_dataset") or "unknown"),
            str(row.get("class_name") or "unknown"),
            subtype_name(row),
            str(row.get("day") or "unknown"),
            window_key(row),
            pcap_name(row),
        ]
    )


def group_rows(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[group_key(row)].append(row)
    return groups


def split_groups(groups: dict[str, list[dict[str, Any]]], *, seed: int, salt: str) -> dict[str, list[str]]:
    keys = sorted(groups)
    if not keys:
        return {"train": [], "val": [], "test": []}
    if len(keys) == 1:
        return {"train": keys, "val": [], "test": []}
    if len(keys) == 2:
        by_size = sorted(keys, key=lambda key: (len(groups[key]), stable_json_hash({"seed": seed, "group_key": key})))
        holdout_split = "test" if int(stable_json_hash({"seed": seed, "salt": salt})[:8], 16) % 2 == 0 else "val"
        output = {"train": [by_size[1]], "val": [], "test": []}
        output[holdout_split].append(by_size[0])
        return output

    def take_holdout(
        available: list[str],
        *,
        target: int,
        split_name: str,
        min_remaining_groups: int,
    ) -> list[str]:
        ordered = sorted(
            available,
            key=lambda key: (len(groups[key]), stable_json_hash({"seed": seed, "salt": salt, "split": split_name, "group_key": key})),
        )
        selected: list[str] = []
        total = 0
        for key in ordered:
            if len(available) - len(selected) <= min_remaining_groups:
                break
            if selected and total >= target:
                break
            selected.append(key)
            total += len(groups[key])
        return selected

    total = sum(len(groups[key]) for key in keys)
    test_keys = take_holdout(
        keys,
        target=max(1, round(total * 0.10)),
        split_name="test",
        min_remaining_groups=2,
    )
    remaining = [key for key in keys if key not in set(test_keys)]
    val_keys = take_holdout(
        remaining,
        target=max(1, round(total * 0.10)),
        split_name="val",
        min_remaining_groups=1,
    )
    train_keys = [key for key in keys if key not in set(test_keys) and key not in set(val_keys)]
    if not train_keys:
        smallest_val = min(val_keys, key=lambda key: (len(groups[key]), key))
        val_keys.remove(smallest_val)
        train_keys.append(smallest_val)
    return {
        "test": test_keys,
        "val": val_keys,
        "train": train_keys,
    }


def path_payload(rows: list[dict[str, Any]], graph_paths: dict[str, str], class_names: list[str]) -> dict[str, Any]:
    by_class: dict[str, list[str]] = {class_name: [] for class_name in class_names}
    metadata_by_path: dict[str, dict[str, Any]] = {}
    for row in rows:
        graph_path = graph_paths[str(row["compact_rel_path"])]
        class_name = str(row["class_name"])
        by_class[class_name].append(graph_path)
        metadata_by_path[graph_path] = {
            "class_name": class_name,
            "subtype": subtype_name(row),
            "day": str(row.get("day") or "unknown"),
            "source_dataset": str(row.get("source_dataset") or "unknown"),
            "pcap": pcap_name(row),
            "group_key": group_key(row),
            "candidate_identity": str(row.get("candidate_identity") or ""),
        }
    return {
        "count": len(rows),
        "per_class": {class_name: len(by_class[class_name]) for class_name in class_names},
        "paths": by_class,
        "files": [path for class_name in class_names for path in by_class[class_name]],
        "metadata_by_path": metadata_by_path,
    }


def temporal_indices(rows: list[dict[str, Any]]) -> tuple[list[int], list[str]]:
    names: list[str] = []
    for row in rows:
        names = list(row.get("flow_feature_names") or [])
        if names:
            break
    indices = [
        index
        for index, name in enumerate(names)
        if str(name).startswith(TEMPORAL_NAME_PREFIXES)
    ]
    return indices, [names[index] for index in indices]


def build_final_training_manifest(
    *,
    compact_manifest_path: Path = DEFAULT_COMPACT_MANIFEST_PATH,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
    train_group_cap: int = 1000,
    seed: int = 42,
) -> dict[str, Any]:
    compact_manifest, rows = load_rows(compact_manifest_path)
    graph_manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(graph_manifest)
    graph_paths = graph_path_map(rows, graph_manifest)

    stress_sets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    eligible_rows: list[dict[str, Any]] = []
    for row in rows:
        stress_name = QUESTIONABLE_SUBTYPES.get((str(row.get("class_name")), subtype_name(row)))
        if stress_name:
            stress_sets[stress_name].append(row)
        else:
            eligible_rows.append(row)

    by_class_subtype: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    for key, grouped_rows in group_rows(eligible_rows).items():
        first = grouped_rows[0]
        by_class_subtype[(str(first["class_name"]), subtype_name(first))][key] = grouped_rows

    split_rows: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    for class_subtype, groups in sorted(by_class_subtype.items()):
        split_keys = split_groups(groups, seed=seed, salt="|".join(class_subtype))
        for split_name, keys in split_keys.items():
            for key in keys:
                group = groups[key]
                if split_name == "train":
                    group = stable_even_take(group, train_group_cap, seed=seed, salt=key)
                split_rows[split_name].extend(group)

    temporal_feature_indices, temporal_feature_names = temporal_indices(rows)
    split_payloads = {
        split: path_payload(split_rows[split], graph_paths, class_names)
        for split in ("train", "val", "test")
    }
    stress_payloads = {
        name: path_payload(stress_rows, graph_paths, class_names)
        for name, stress_rows in sorted(stress_sets.items())
    }
    manifest = {
        **{key: value for key, value in graph_manifest.items() if key not in {"splits", "manifest_hash"}},
        "schema_version": 2,
        "pipeline": "office_final_robust_training_manifest",
        "generated_at": utc_now(),
        "base_graph_manifest_path": str(graph_manifest_path),
        "base_graph_manifest_hash": graph_manifest.get("manifest_hash", ""),
        "compact_manifest_path": str(compact_manifest_path),
        "compact_manifest_hash": compact_manifest.get("manifest_hash", ""),
        "class_names": class_names,
        "n_train": split_payloads["train"]["count"],
        "n_val": split_payloads["val"]["count"],
        "n_test": split_payloads["test"]["count"],
        "total_graph_count": sum(split_payloads[split]["count"] for split in ("train", "val", "test")),
        "splits": split_payloads,
        "stress_sets": stress_payloads,
        "final_training_policy": {
            "questionable_subtypes_excluded_from_main_training": {
                f"{class_name}|{subtype}": stress_name
                for (class_name, subtype), stress_name in QUESTIONABLE_SUBTYPES.items()
            },
            "split_unit": "source_dataset|class|subtype|day|window_key|pcap",
            "group_overlap_allowed": False,
            "train_group_cap": train_group_cap,
            "train_group_cap_sampling": "stable_even_window_sampling",
            "sampler": "class_subtype_group_graph_weighted_random_sampler",
            "mask_temporal_features": True,
            "temporal_feature_indices": temporal_feature_indices,
            "temporal_feature_names": temporal_feature_names,
            "loss": "weighted_cross_entropy",
            "class_weighting": "inverse_sqrt_normalized_mean_one_capped_5",
            "label_smoothing": 0.05,
        },
        "split_group_counts": {
            split: len({group_key(row) for row in split_rows[split]})
            for split in ("train", "val", "test")
        },
        "subtype_counts": {
            split: dict(sorted(Counter(f"{row['class_name']}|{subtype_name(row)}" for row in split_rows[split]).items()))
            for split in ("train", "val", "test")
        },
        "stress_set_counts": {
            name: dict(sorted(Counter(f"{row['class_name']}|{subtype_name(row)}" for row in stress_rows).items()))
            for name, stress_rows in sorted(stress_sets.items())
        },
    }
    manifest["materialization_incomplete"] = any(
        split_payloads[split]["per_class"].get(class_name, 0) <= 0
        for split in ("train", "val", "test")
        for class_name in class_names
    )
    manifest["manifest_hash"] = stable_json_hash({key: value for key, value in manifest.items() if key != "manifest_hash"})
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(report_path, manifest, output_path)
    return manifest


def write_report(path: Path, manifest: dict[str, Any], manifest_path: Path) -> None:
    lines = [
        "# Office Final Robust Training Manifest",
        "",
        f"Date: {manifest['generated_at']}",
        "",
        f"- Manifest: `{manifest_path}`",
        f"- Train graphs: `{manifest['n_train']}`",
        f"- Validation graphs: `{manifest['n_val']}`",
        f"- Test graphs: `{manifest['n_test']}`",
        f"- Train groups: `{manifest['split_group_counts']['train']}`",
        f"- Validation groups: `{manifest['split_group_counts']['val']}`",
        f"- Test groups: `{manifest['split_group_counts']['test']}`",
        f"- Temporal features masked: `{manifest['final_training_policy']['mask_temporal_features']}`",
        f"- Train cap per group: `{manifest['final_training_policy']['train_group_cap']}`",
        "",
        "## Split Counts",
        "",
        "| Class | Train | Val | Test |",
        "| --- | ---: | ---: | ---: |",
    ]
    for class_name in manifest["class_names"]:
        lines.append(
            f"| {class_name} | {manifest['splits']['train']['per_class'][class_name]} | "
            f"{manifest['splits']['val']['per_class'][class_name]} | "
            f"{manifest['splits']['test']['per_class'][class_name]} |"
        )
    lines.extend(["", "## Subtype Counts", ""])
    for split in ("train", "val", "test"):
        lines.extend([f"### {split.title()}", "", "| Subtype | Graphs |", "| --- | ---: |"])
        for subtype, count in manifest["subtype_counts"][split].items():
            lines.append(f"| {subtype} | {count} |")
        lines.append("")
    lines.extend(["## Stress Sets", "", "| Stress set | Graphs | Counts |", "| --- | ---: | --- |"])
    for name, payload in manifest["stress_sets"].items():
        lines.append(f"| {name} | {payload['count']} | `{manifest['stress_set_counts'][name]}` |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Office final robust training PyG manifest.")
    parser.add_argument("--compact-manifest", type=Path, default=DEFAULT_COMPACT_MANIFEST_PATH)
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--train-group-cap", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = build_final_training_manifest(
        compact_manifest_path=args.compact_manifest,
        graph_manifest_path=args.graph_manifest,
        output_path=args.output,
        report_path=args.report,
        train_group_cap=args.train_group_cap,
        seed=args.seed,
    )
    print(
        json.dumps(
            {
                "manifest": str(args.output),
                "report": str(args.report),
                "n_train": manifest["n_train"],
                "n_val": manifest["n_val"],
                "n_test": manifest["n_test"],
                "materialization_incomplete": manifest["materialization_incomplete"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
