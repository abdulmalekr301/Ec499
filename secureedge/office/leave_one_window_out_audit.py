from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureedge import config as root_config
from secureedge.office.build_graphs import DEFAULT_MANIFEST_PATH
from secureedge.office.grouped_window_audit import (
    DEFAULT_SPLIT_DIR,
    candidate_identity,
    graph_identity_from_path,
    group_key,
    group_label_from_key,
    load_split_candidates,
)
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "leave_one_window_out"


def graph_records_by_group(
    manifest: dict[str, Any],
    class_names: list[str],
    candidate_by_identity: dict[str, dict[str, Any]],
) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, str]]]:
    by_group: dict[str, list[dict[str, str]]] = {}
    missing: list[dict[str, str]] = []
    for split in ("train", "val", "test"):
        paths_by_class = manifest["splits"][split]["paths"]
        for class_name in class_names:
            for path in paths_by_class.get(class_name, []):
                identity = graph_identity_from_path(path)
                candidate = candidate_by_identity.get(identity)
                if candidate is None:
                    missing.append(
                        {
                            "split": split,
                            "class_name": class_name,
                            "path": str(path),
                            "candidate_identity": identity,
                        }
                    )
                    continue
                key = group_key(candidate)
                by_group.setdefault(key, []).append(
                    {
                        "split": split,
                        "class_name": class_name,
                        "path": str(path),
                        "candidate_identity": identity,
                    }
                )
    return by_group, missing


def class_counts(records: list[dict[str, str]], class_names: list[str]) -> dict[str, int]:
    counts = Counter(record["class_name"] for record in records)
    return {class_name: int(counts.get(class_name, 0)) for class_name in class_names}


def status_for_fold(
    *,
    heldout_count: int,
    remaining_counts: dict[str, int],
    heldout_class: str,
    min_train_per_class: int,
    min_eval_support: int,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    zero_train = [class_name for class_name, count in remaining_counts.items() if count <= 0]
    if zero_train:
        reasons.append(f"zero training support after holdout: {', '.join(zero_train)}")
    if heldout_count < min_eval_support:
        reasons.append(f"held-out support {heldout_count} below minimum eval support {min_eval_support}")
    heldout_class_train = int(remaining_counts.get(heldout_class, 0))
    if 0 < heldout_class_train < min_train_per_class:
        reasons.append(
            f"remaining {heldout_class} training support {heldout_class_train} below minimum {min_train_per_class}"
        )
    if zero_train:
        return "invalid_zero_shot_class", reasons
    if reasons:
        return "weak_support_fold", reasons
    return "runnable_candidate", reasons


def build_fold_rows(
    *,
    by_group: dict[str, list[dict[str, str]]],
    class_names: list[str],
    min_train_per_class: int,
    min_eval_support: int,
) -> list[dict[str, Any]]:
    all_records = [record for records in by_group.values() for record in records]
    total_counts = class_counts(all_records, class_names)
    rows: list[dict[str, Any]] = []
    for key, heldout_records in sorted(by_group.items()):
        label = group_label_from_key(key)
        heldout_counts = class_counts(heldout_records, class_names)
        heldout_count = len(heldout_records)
        remaining_counts = {
            class_name: int(total_counts[class_name] - heldout_counts[class_name]) for class_name in class_names
        }
        status, reasons = status_for_fold(
            heldout_count=heldout_count,
            remaining_counts=remaining_counts,
            heldout_class=label["class_name"],
            min_train_per_class=min_train_per_class,
            min_eval_support=min_eval_support,
        )
        rows.append(
            {
                "group_key": key,
                **label,
                "heldout_count": int(heldout_count),
                "heldout_train_count": int(sum(1 for record in heldout_records if record["split"] == "train")),
                "heldout_val_count": int(sum(1 for record in heldout_records if record["split"] == "val")),
                "heldout_test_count": int(sum(1 for record in heldout_records if record["split"] == "test")),
                "remaining_train_count_total": int(sum(remaining_counts.values())),
                "remaining_train_count_for_heldout_class": int(remaining_counts[label["class_name"]]),
                "remaining_class_counts": remaining_counts,
                "status": status,
                "reasons": reasons,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]], class_names: list[str]) -> None:
    fieldnames = [
        "group_key",
        "source_dataset",
        "day",
        "class_name",
        "subtype",
        "window_start",
        "window_finish",
        "heldout_count",
        "heldout_train_count",
        "heldout_val_count",
        "heldout_test_count",
        "remaining_train_count_total",
        "remaining_train_count_for_heldout_class",
        "status",
        "reasons",
        *[f"remaining_{class_name}" for class_name in class_names],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            output = {field: row.get(field) for field in fieldnames}
            output["reasons"] = "; ".join(row["reasons"])
            for class_name in class_names:
                output[f"remaining_{class_name}"] = row["remaining_class_counts"][class_name]
            writer.writerow(output)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    rows = report["folds"]
    lines = [
        "# Office Leave-One-Window-Out Audit",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Summary",
        "",
        f"- Total materialized graph groups: `{report['summary']['total_groups']}`.",
        f"- Runnable candidate folds: `{report['summary']['runnable_candidate']}`.",
        f"- Weak-support folds: `{report['summary']['weak_support_fold']}`.",
        f"- Invalid zero-shot folds: `{report['summary']['invalid_zero_shot_class']}`.",
        f"- Minimum remaining train support per class threshold: `{report['min_train_per_class']}`.",
        f"- Minimum held-out eval support threshold: `{report['min_eval_support']}`.",
        f"- Candidate metadata misses: `{len(report['missing_candidate_metadata'])}`.",
        "",
        "## Fold Inventory",
        "",
        "| Class | Day | Window/Subtype | Held out | Remaining same class | Status | Reason |",
        "| --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        reason = "; ".join(row["reasons"]) if row["reasons"] else "ok"
        lines.append(
            "| "
            + " | ".join(
                [
                    str(row["class_name"]),
                    str(row["day"]),
                    str(row["subtype"]),
                    str(row["heldout_count"]),
                    str(row["remaining_train_count_for_heldout_class"]),
                    str(row["status"]),
                    reason,
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A strict leave-one-window-out evaluation is not uniformly valid for this office dataset as currently materialized.",
            "",
            "For classes with only one attack window, holding that window out removes every training example of that class. Those folds become zero-shot class tests, not ordinary robustness folds.",
            "",
            "The meaningful next training runs should be limited to folds with enough remaining same-class support, or the grouping level should be changed to day/session/PCAP depending on the question being tested.",
            "",
            "## Artifact Paths",
            "",
            f"- JSON: `{report['artifact_paths']['json']}`",
            f"- CSV: `{report['artifact_paths']['csv']}`",
            f"- Markdown: `{report['artifact_paths']['markdown']}`",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_leave_one_window_out_audit(
    *,
    graph_manifest_path: Path = DEFAULT_MANIFEST_PATH,
    split_dir: Path = DEFAULT_SPLIT_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    min_train_per_class: int = 1000,
    min_eval_support: int = 100,
) -> dict[str, Any]:
    manifest = load_json(graph_manifest_path)
    class_names = manifest_class_names(manifest)
    candidate_by_identity = load_split_candidates(split_dir)
    by_group, missing = graph_records_by_group(manifest, class_names, candidate_by_identity)
    rows = build_fold_rows(
        by_group=by_group,
        class_names=class_names,
        min_train_per_class=min_train_per_class,
        min_eval_support=min_eval_support,
    )
    status_counts = Counter(row["status"] for row in rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "leave_one_window_out_audit.json"
    csv_path = output_dir / "leave_one_window_out_audit.csv"
    markdown_path = output_dir / "leave_one_window_out_audit.md"
    report = {
        "pipeline": "office_leave_one_window_out_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "candidate_split_dir": str(split_dir),
        "class_names": class_names,
        "min_train_per_class": int(min_train_per_class),
        "min_eval_support": int(min_eval_support),
        "summary": {
            "total_groups": len(rows),
            "runnable_candidate": int(status_counts.get("runnable_candidate", 0)),
            "weak_support_fold": int(status_counts.get("weak_support_fold", 0)),
            "invalid_zero_shot_class": int(status_counts.get("invalid_zero_shot_class", 0)),
        },
        "folds": rows,
        "missing_candidate_metadata": missing,
        "artifact_paths": {
            "json": str(json_path),
            "csv": str(csv_path),
            "markdown": str(markdown_path),
        },
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_csv(csv_path, rows, class_names)
    write_markdown(markdown_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit feasibility of office leave-one-window-out folds.")
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--split-dir", type=Path, default=DEFAULT_SPLIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--min-train-per-class", type=int, default=1000)
    parser.add_argument("--min-eval-support", type=int, default=100)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_leave_one_window_out_audit(
        graph_manifest_path=args.graph_manifest,
        split_dir=args.split_dir,
        output_dir=args.output_dir,
        min_train_per_class=args.min_train_per_class,
        min_eval_support=args.min_eval_support,
    )
    print(
        json.dumps(
            {
                "pipeline": report["pipeline"],
                "generated_at": report["generated_at"],
                "summary": report["summary"],
                "missing_candidate_metadata_count": len(report["missing_candidate_metadata"]),
                "artifact_paths": report["artifact_paths"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
