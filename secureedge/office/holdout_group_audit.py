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
    graph_identity_from_path,
    load_split_candidates,
)
from secureedge.training.engine import load_json, manifest_class_names


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "holdout_groups"
SCOPES = ("day", "pcap", "endpoint_service")


def graph_records(
    manifest: dict[str, Any],
    class_names: list[str],
    candidate_by_identity: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    records: list[dict[str, Any]] = []
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
                records.append(
                    {
                        "split": split,
                        "class_name": class_name,
                        "path": str(path),
                        "candidate_identity": identity,
                        **candidate,
                    }
                )
    return records, missing


def pcap_name(value: object) -> str:
    text = str(value or "")
    return Path(text).name if text else "missing_pcap"


def scope_key(record: dict[str, Any], scope: str) -> str:
    source_dataset = str(record.get("source_dataset", record.get("source", "unknown")) or "unknown")
    day = str(record.get("day", "unknown") or "unknown")
    if scope == "day":
        return "|".join([source_dataset, day])
    if scope == "pcap":
        return "|".join([source_dataset, day, pcap_name(record.get("endpoint_pcap"))])
    if scope == "endpoint_service":
        return "|".join(
            [
                source_dataset,
                day,
                str(record.get("src_ip", "unknown") or "unknown"),
                str(record.get("dst_ip", "unknown") or "unknown"),
                str(record.get("dst_port", "unknown") or "unknown"),
                str(record.get("protocol", "unknown") or "unknown"),
            ]
        )
    raise ValueError(f"Unsupported scope: {scope}")


def scope_label(key: str, scope: str) -> dict[str, str]:
    parts = key.split("|")
    if scope == "day":
        return {"source_dataset": parts[0], "day": parts[1], "group": parts[1]}
    if scope == "pcap":
        return {"source_dataset": parts[0], "day": parts[1], "group": parts[2]}
    if scope == "endpoint_service":
        return {
            "source_dataset": parts[0],
            "day": parts[1],
            "group": f"{parts[2]} -> {parts[3]}:{parts[4]}/{parts[5]}",
        }
    raise ValueError(f"Unsupported scope: {scope}")


def class_counts(records: list[dict[str, Any]], class_names: list[str]) -> dict[str, int]:
    counts = Counter(str(record["class_name"]) for record in records)
    return {class_name: int(counts.get(class_name, 0)) for class_name in class_names}


def status_for_group(
    *,
    heldout_count: int,
    heldout_counts: dict[str, int],
    remaining_counts: dict[str, int],
    min_train_per_class: int,
    min_eval_support: int,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    zero_train = [class_name for class_name, count in remaining_counts.items() if count <= 0]
    if zero_train:
        reasons.append(f"zero training support after holdout: {', '.join(zero_train)}")
    if heldout_count < min_eval_support:
        reasons.append(f"held-out support {heldout_count} below minimum eval support {min_eval_support}")
    weak_classes = [
        class_name
        for class_name, heldout_class_count in heldout_counts.items()
        if heldout_class_count > 0 and 0 < remaining_counts[class_name] < min_train_per_class
    ]
    if weak_classes:
        details = ", ".join(f"{class_name}={remaining_counts[class_name]}" for class_name in weak_classes)
        reasons.append(f"remaining held-out class support below minimum {min_train_per_class}: {details}")
    if zero_train:
        return "invalid_zero_shot_class", reasons
    if reasons:
        return "weak_support_group", reasons
    return "runnable_candidate", reasons


def build_scope_rows(
    *,
    records: list[dict[str, Any]],
    class_names: list[str],
    scope: str,
    min_train_per_class: int,
    min_eval_support: int,
) -> list[dict[str, Any]]:
    by_key: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_key.setdefault(scope_key(record, scope), []).append(record)
    total_counts = class_counts(records, class_names)
    rows: list[dict[str, Any]] = []
    for key, heldout_records in sorted(by_key.items()):
        heldout_counts = class_counts(heldout_records, class_names)
        remaining_counts = {
            class_name: int(total_counts[class_name] - heldout_counts[class_name]) for class_name in class_names
        }
        status, reasons = status_for_group(
            heldout_count=len(heldout_records),
            heldout_counts=heldout_counts,
            remaining_counts=remaining_counts,
            min_train_per_class=min_train_per_class,
            min_eval_support=min_eval_support,
        )
        rows.append(
            {
                "scope": scope,
                "group_key": key,
                **scope_label(key, scope),
                "heldout_count": int(len(heldout_records)),
                "heldout_class_counts": heldout_counts,
                "remaining_class_counts": remaining_counts,
                "status": status,
                "reasons": reasons,
            }
        )
    return rows


def summarize_rows(rows_by_scope: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for scope, rows in rows_by_scope.items():
        statuses = Counter(row["status"] for row in rows)
        summary[scope] = {
            "total_groups": len(rows),
            "runnable_candidate": int(statuses.get("runnable_candidate", 0)),
            "weak_support_group": int(statuses.get("weak_support_group", 0)),
            "invalid_zero_shot_class": int(statuses.get("invalid_zero_shot_class", 0)),
        }
    return summary


def write_csv(path: Path, rows_by_scope: dict[str, list[dict[str, Any]]], class_names: list[str]) -> None:
    fieldnames = [
        "scope",
        "group_key",
        "source_dataset",
        "day",
        "group",
        "heldout_count",
        "status",
        "reasons",
        *[f"heldout_{class_name}" for class_name in class_names],
        *[f"remaining_{class_name}" for class_name in class_names],
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for scope in SCOPES:
            for row in rows_by_scope[scope]:
                output = {field: row.get(field) for field in fieldnames}
                output["reasons"] = "; ".join(row["reasons"])
                for class_name in class_names:
                    output[f"heldout_{class_name}"] = row["heldout_class_counts"][class_name]
                    output[f"remaining_{class_name}"] = row["remaining_class_counts"][class_name]
                writer.writerow(output)


def top_problem_rows(rows: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    bad_rows = [row for row in rows if row["status"] != "runnable_candidate"]
    return sorted(bad_rows, key=lambda row: (-int(row["heldout_count"]), row["group_key"]))[:limit]


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    rows_by_scope = report["rows_by_scope"]
    lines = [
        "# Office Whole-Group Holdout Audit",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Summary",
        "",
        "| Scope | Groups | Runnable | Weak support | Invalid zero-shot |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for scope in SCOPES:
        item = summary[scope]
        lines.append(
            f"| {scope} | {item['total_groups']} | {item['runnable_candidate']} | "
            f"{item['weak_support_group']} | {item['invalid_zero_shot_class']} |"
        )
    lines.extend(
        [
            "",
            "## Largest Problem Groups",
            "",
            "| Scope | Day | Group | Held out | Status | Reason |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    for scope in SCOPES:
        for row in top_problem_rows(rows_by_scope[scope]):
            reason = "; ".join(row["reasons"]) if row["reasons"] else "ok"
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(scope),
                        str(row["day"]),
                        str(row["group"]),
                        str(row["heldout_count"]),
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
            "Whole-day holdout is a harsh test for this dataset because several attack classes occur on only one day. Holding out those days removes all training support for the corresponding classes.",
            "",
            "PCAP-level and endpoint/service-level holdouts are more often runnable, but weak-support groups remain where rare classes are concentrated in a small number of sources.",
            "",
            "The endpoint/service scope groups by source dataset, day, source IP, destination IP, destination port, and protocol. It intentionally excludes source port because source port is usually ephemeral and would collapse toward per-flow grouping.",
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


def run_holdout_group_audit(
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
    records, missing = graph_records(manifest, class_names, candidate_by_identity)
    rows_by_scope = {
        scope: build_scope_rows(
            records=records,
            class_names=class_names,
            scope=scope,
            min_train_per_class=min_train_per_class,
            min_eval_support=min_eval_support,
        )
        for scope in SCOPES
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "holdout_group_audit.json"
    csv_path = output_dir / "holdout_group_audit.csv"
    markdown_path = output_dir / "holdout_group_audit.md"
    report = {
        "pipeline": "office_whole_group_holdout_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "graph_manifest_path": str(graph_manifest_path),
        "graph_manifest_hash": str(manifest.get("manifest_hash", "")),
        "candidate_split_dir": str(split_dir),
        "class_names": class_names,
        "min_train_per_class": int(min_train_per_class),
        "min_eval_support": int(min_eval_support),
        "summary": summarize_rows(rows_by_scope),
        "rows_by_scope": rows_by_scope,
        "missing_candidate_metadata": missing,
        "artifact_paths": {
            "json": str(json_path),
            "csv": str(csv_path),
            "markdown": str(markdown_path),
        },
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_csv(csv_path, rows_by_scope, class_names)
    write_markdown(markdown_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit office whole-day, PCAP, and endpoint/service holdout groups.")
    parser.add_argument("--graph-manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    parser.add_argument("--split-dir", type=Path, default=DEFAULT_SPLIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--min-train-per-class", type=int, default=1000)
    parser.add_argument("--min-eval-support", type=int, default=100)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_holdout_group_audit(
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
