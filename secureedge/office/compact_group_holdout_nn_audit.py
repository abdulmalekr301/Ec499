from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from secureedge import config as root_config
from secureedge.office.compact_nearest_neighbor_similarity_audit import (
    compact_manifest_class_names,
    compact_root,
    compact_vector,
    endpoint_service_key,
    load_json,
    pcap_name,
    subtype_name,
    window_key,
)
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, load_compact_record


DEFAULT_OUTPUT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "robustness" / "compact_group_holdout_nn"

FoldPredicate = Callable[[dict[str, Any]], bool]


SUBTYPE_DISPLAY_NAMES = {
    "SSH-Bruteforce": "SSH",
    "FTP-BruteForce": "FTP",
    "DoS-Hulk": "Hulk",
    "DoS-GoldenEye": "GoldenEye",
    "DoS-Slowloris": "Slowloris",
    "DoS-SlowHTTPTest": "SlowHTTPTest",
    "DDOS-HOIC": "HOIC",
    "DDOS-LOIC-HTTP": "LOIC-HTTP",
    "DDOS-LOIC-UDP": "LOIC-UDP",
    "Brute Force-Web": "BF-Web",
    "Brute Force-XSS": "BF-XSS",
    "SQL Injection": "SQLi",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stable_score(text: str, seed: int) -> str:
    payload = f"{seed}|{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def stable_take(records: list[dict[str, Any]], cap: int, *, seed: int, salt: str) -> list[dict[str, Any]]:
    if cap <= 0 or len(records) <= cap:
        return list(records)
    return sorted(
        records,
        key=lambda row: stable_score(
            "|".join([salt, str(row.get("path", "")), str(row.get("candidate_identity", ""))]),
            seed,
        ),
    )[:cap]


def parse_candidate_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def infiltration_window_id(row: dict[str, Any]) -> str:
    if str(row.get("class_name")) != "Infiltration":
        return "not_infiltration"
    ts = parse_candidate_timestamp(row.get("candidate_timestamp") or row.get("csv_start_ts"))
    if ts is None:
        return "missing_timestamp"
    return "early_13_14h" if ts.hour < 16 else "late_18_19h"


def row_from_record(record: dict[str, Any], compact: dict[str, Any], abs_path: Path) -> dict[str, Any]:
    row = {**record}
    for key in (
        "candidate_identity",
        "candidate_timestamp",
        "csv_start_ts",
        "class_name",
        "day",
        "source_dataset",
        "source_file",
        "subtype_label",
        "gt_subtype",
        "label",
        "gt_window_start",
        "gt_window_finish",
        "endpoint_pcap",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "attacker_public_ip",
        "attacker_private_ip",
        "victim_private_ip",
        "victim_public_ip",
    ):
        if row.get(key) in (None, "") and compact.get(key) not in (None, ""):
            row[key] = compact.get(key)
    row["abs_path"] = str(abs_path)
    row["subtype"] = subtype_name(row)
    row["pcap"] = pcap_name(row)
    row["window_key"] = window_key(row)
    row["endpoint_service_key"] = endpoint_service_key(row)
    row["infiltration_window"] = infiltration_window_id(row)
    return row


def load_records_and_vectors(manifest_path: Path) -> tuple[dict[str, Any], np.ndarray, list[dict[str, Any]], list[str]]:
    manifest = load_json(manifest_path)
    root = compact_root(manifest)
    vectors: list[np.ndarray] = []
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    for record in manifest.get("records", []):
        path = root / Path(str(record["path"]))
        if not path.exists():
            missing.append(str(path))
            continue
        compact = load_compact_record(path)
        vectors.append(compact_vector(compact))
        rows.append(row_from_record(record, compact, path))
    if not vectors:
        raise ValueError(f"No compact graph records could be loaded from {manifest_path}")
    return manifest, np.vstack(vectors).astype(np.float32), rows, missing


def class_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get("class_name", "")) for row in rows).items()))


def subtype_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(f"{row.get('class_name')}|{row.get('subtype')}" for row in rows).items()))


def summarize_selected_manifest(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_class: dict[str, dict[str, Any]] = {}
    for class_name in sorted({str(row.get("class_name")) for row in rows}):
        class_rows = [row for row in rows if str(row.get("class_name")) == class_name]
        by_class[class_name] = {
            "count": len(class_rows),
            "subtypes": dict(sorted(Counter(str(row.get("subtype")) for row in class_rows).items())),
            "days": dict(sorted(Counter(str(row.get("day", "unknown")) for row in class_rows).items())),
            "pcap_group_count": len({str(row.get("pcap")) for row in class_rows}),
            "window_group_count": len({str(row.get("window_key")) for row in class_rows}),
            "endpoint_service_group_count": len({str(row.get("endpoint_service_key")) for row in class_rows}),
        }
    return {"by_class": by_class}


def make_fold_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for subtype in ("DDOS-LOIC-HTTP", "DDOS-LOIC-UDP", "DDOS-HOIC"):
        specs.append(
            {
                "fold_id": f"ddos_holdout_{SUBTYPE_DISPLAY_NAMES[subtype].lower()}",
                "audit_scope": "DDoS subtype holdout",
                "heldout_class": "DDoS",
                "heldout_group": subtype,
                "heldout_display": SUBTYPE_DISPLAY_NAMES[subtype],
                "predicate": lambda row, subtype=subtype: row.get("class_name") == "DDoS"
                and row.get("subtype") == subtype,
            }
        )
    for subtype in ("DoS-GoldenEye", "DoS-Slowloris", "DoS-SlowHTTPTest", "DoS-Hulk"):
        specs.append(
            {
                "fold_id": f"dos_holdout_{SUBTYPE_DISPLAY_NAMES[subtype].lower()}",
                "audit_scope": "DoS subtype holdout",
                "heldout_class": "DoS",
                "heldout_group": subtype,
                "heldout_display": SUBTYPE_DISPLAY_NAMES[subtype],
                "predicate": lambda row, subtype=subtype: row.get("class_name") == "DoS" and row.get("subtype") == subtype,
            }
        )
    for subtype in ("FTP-BruteForce", "SSH-Bruteforce"):
        specs.append(
            {
                "fold_id": f"bruteforce_holdout_{SUBTYPE_DISPLAY_NAMES[subtype].lower()}",
                "audit_scope": "BruteForce subtype holdout",
                "heldout_class": "BruteForce",
                "heldout_group": subtype,
                "heldout_display": SUBTYPE_DISPLAY_NAMES[subtype],
                "predicate": lambda row, subtype=subtype: row.get("class_name") == "BruteForce"
                and row.get("subtype") == subtype,
            }
        )
    for window_id, display in (("early_13_14h", "early 13-14h"), ("late_18_19h", "late 18-19h")):
        specs.append(
            {
                "fold_id": f"infiltration_holdout_{window_id}",
                "audit_scope": "Infiltration window holdout",
                "heldout_class": "Infiltration",
                "heldout_group": window_id,
                "heldout_display": display,
                "predicate": lambda row, window_id=window_id: row.get("class_name") == "Infiltration"
                and row.get("infiltration_window") == window_id,
            }
        )
    for subtype in ("Brute Force-Web", "Brute Force-XSS", "SQL Injection"):
        specs.append(
            {
                "fold_id": f"webbased_holdout_{SUBTYPE_DISPLAY_NAMES[subtype].lower()}",
                "audit_scope": "WebBased subtype holdout",
                "heldout_class": "WebBased",
                "heldout_group": subtype,
                "heldout_display": SUBTYPE_DISPLAY_NAMES[subtype],
                "predicate": lambda row, subtype=subtype: row.get("class_name") == "WebBased"
                and row.get("subtype") == subtype,
            }
        )
    return specs


def sample_reference_rows(
    rows: list[dict[str, Any]],
    heldout_mask: np.ndarray,
    *,
    per_class_cap: int,
    seed: int,
    salt: str,
) -> list[int]:
    available = [index for index, is_heldout in enumerate(heldout_mask.tolist()) if not is_heldout]
    by_class: dict[str, list[int]] = defaultdict(list)
    for index in available:
        by_class[str(rows[index].get("class_name"))].append(index)
    selected: list[int] = []
    for class_name, indices in sorted(by_class.items()):
        indexed_rows = [{**rows[index], "_index": index} for index in indices]
        sampled = stable_take(indexed_rows, per_class_cap, seed=seed, salt=f"{salt}|{class_name}")
        selected.extend(int(row["_index"]) for row in sampled)
    return selected


def percentile(values: np.ndarray | list[float], q: float) -> float | None:
    if len(values) == 0:
        return None
    return float(np.percentile(np.asarray(values, dtype=np.float64), q))


def metric(value: float | None) -> float | None:
    if value is None:
        return None
    if not np.isfinite(value):
        return None
    return float(value)


def class_nn_distances(
    query_x: np.ndarray,
    ref_x: np.ndarray,
    ref_rows: list[dict[str, Any]],
    target_class: str,
) -> tuple[np.ndarray | None, np.ndarray | None, list[str]]:
    correct_indices = [index for index, row in enumerate(ref_rows) if str(row.get("class_name")) == target_class]
    wrong_indices = [index for index, row in enumerate(ref_rows) if str(row.get("class_name")) != target_class]
    if not correct_indices or not wrong_indices:
        return None, None, []
    correct_nn = NearestNeighbors(n_neighbors=1, metric="cosine")
    wrong_nn = NearestNeighbors(n_neighbors=1, metric="cosine")
    correct_nn.fit(ref_x[correct_indices])
    wrong_nn.fit(ref_x[wrong_indices])
    correct_dist, _ = correct_nn.kneighbors(query_x)
    wrong_dist, wrong_local = wrong_nn.kneighbors(query_x)
    competing_classes = [str(ref_rows[wrong_indices[int(local[0])]].get("class_name")) for local in wrong_local]
    return correct_dist[:, 0], wrong_dist[:, 0], competing_classes


def run_fold(
    *,
    spec: dict[str, Any],
    vectors: np.ndarray,
    rows: list[dict[str, Any]],
    query_cap: int,
    reference_per_class: int,
    seed: int,
    n_neighbors: int,
) -> dict[str, Any]:
    predicate: FoldPredicate = spec["predicate"]
    heldout_mask = np.asarray([bool(predicate(row)) for row in rows], dtype=bool)
    query_indices_all = np.where(heldout_mask)[0].tolist()
    query_rows_all = [{**rows[index], "_index": index} for index in query_indices_all]
    query_rows_sampled = stable_take(query_rows_all, query_cap, seed=seed, salt=f"{spec['fold_id']}|query")
    query_indices = [int(row["_index"]) for row in query_rows_sampled]

    ref_indices = sample_reference_rows(
        rows,
        heldout_mask,
        per_class_cap=reference_per_class,
        seed=seed,
        salt=f"{spec['fold_id']}|reference",
    )
    query_rows = [rows[index] for index in query_indices]
    ref_rows = [rows[index] for index in ref_indices]
    same_class_ref_count = sum(1 for row in ref_rows if str(row.get("class_name")) == spec["heldout_class"])

    status = "complete"
    notes: list[str] = []
    if not query_indices_all:
        status = "invalid_no_query_support"
        notes.append("No selected compact records matched the held-out group.")
    elif same_class_ref_count == 0:
        status = "invalid_zero_same_class_reference"
        notes.append("The reference pool has no same-class examples after holding out this group.")
    elif len(query_indices_all) < 100:
        status = "weak_small_query_support"
        notes.append("Held-out query support is below 100 graphs; percentages are unstable.")

    result: dict[str, Any] = {
        "fold_id": spec["fold_id"],
        "audit_scope": spec["audit_scope"],
        "heldout_class": spec["heldout_class"],
        "heldout_group": spec["heldout_group"],
        "heldout_display": spec["heldout_display"],
        "status": status,
        "notes": notes,
        "query_total": len(query_indices_all),
        "query_sample_count": len(query_indices),
        "reference_sample_count": len(ref_indices),
        "same_class_reference_count": same_class_ref_count,
        "query_class_distribution": class_distribution(query_rows),
        "reference_class_distribution": class_distribution(ref_rows),
        "query_subtype_distribution": subtype_distribution(query_rows),
    }
    if status.startswith("invalid") or not query_indices or not ref_indices:
        return result

    scaler = StandardScaler()
    ref_x = scaler.fit_transform(vectors[ref_indices]).astype(np.float32)
    query_x = scaler.transform(vectors[query_indices]).astype(np.float32)

    neighbor_count = min(n_neighbors, len(ref_indices))
    nn = NearestNeighbors(n_neighbors=neighbor_count, metric="cosine")
    nn.fit(ref_x)
    distances, indices = nn.kneighbors(query_x)
    neighbor_classes = np.asarray([[ref_rows[int(index)].get("class_name") for index in row] for row in indices])
    correct = neighbor_classes == spec["heldout_class"]

    nearest_correct_dist, nearest_wrong_dist, competing_classes = class_nn_distances(
        query_x,
        ref_x,
        ref_rows,
        str(spec["heldout_class"]),
    )
    if nearest_correct_dist is None or nearest_wrong_dist is None:
        result["status"] = "invalid_missing_correct_or_wrong_reference"
        result["notes"].append("Could not compute correct/wrong class margin.")
        return result

    margin = nearest_wrong_dist - nearest_correct_dist
    top1_neighbor_classes = Counter(str(value) for value in neighbor_classes[:, 0].tolist())
    strongest_competing_class = Counter(competing_classes).most_common(1)[0][0] if competing_classes else ""

    def topk_fraction(k: int) -> float:
        use_k = min(k, neighbor_count)
        return float(correct[:, :use_k].sum(axis=1).mean() / use_k)

    result.update(
        {
            "top1_correct_class_rate": float(correct[:, 0].mean()),
            "top3_correct_class_fraction": topk_fraction(3),
            "top5_correct_class_fraction": topk_fraction(5),
            "top10_correct_class_fraction": topk_fraction(10),
            "nearest_correct_distance_median": metric(percentile(nearest_correct_dist, 50)),
            "nearest_correct_distance_mean": float(nearest_correct_dist.mean()),
            "nearest_wrong_distance_median": metric(percentile(nearest_wrong_dist, 50)),
            "nearest_wrong_distance_mean": float(nearest_wrong_dist.mean()),
            "margin_p05": metric(percentile(margin, 5)),
            "margin_median": metric(percentile(margin, 50)),
            "margin_p95": metric(percentile(margin, 95)),
            "margin_positive_rate": float((margin > 0).mean()),
            "margin_near_zero_rate": float((np.abs(margin) <= 0.001).mean()),
            "strongest_competing_class": strongest_competing_class,
            "top1_neighbor_class_distribution": dict(sorted(top1_neighbor_classes.items())),
        }
    )
    return result


def write_csv(path: Path, folds: list[dict[str, Any]]) -> None:
    fields = [
        "fold_id",
        "audit_scope",
        "heldout_class",
        "heldout_display",
        "status",
        "query_total",
        "query_sample_count",
        "reference_sample_count",
        "same_class_reference_count",
        "top1_correct_class_rate",
        "top3_correct_class_fraction",
        "top5_correct_class_fraction",
        "top10_correct_class_fraction",
        "nearest_correct_distance_median",
        "nearest_wrong_distance_median",
        "margin_p05",
        "margin_median",
        "margin_p95",
        "margin_positive_rate",
        "margin_near_zero_rate",
        "strongest_competing_class",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for fold in folds:
            writer.writerow({field: fold.get(field) for field in fields})


def fmt(value: Any) -> str:
    if value is None or value == "":
        return "n/a"
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Office Compact Group-Held-Out Nearest-Neighbor Audit",
        "",
        f"Date: {report['generated_at']}",
        "",
        "## Configuration",
        "",
        f"- Compact manifest: `{report['compact_manifest_path']}`",
        f"- Loaded records: `{report['loaded_record_count']}`",
        f"- Missing compact files: `{len(report['missing_paths'])}`",
        f"- Query cap per fold: `{report['query_cap']}`",
        f"- Reference cap per class: `{report['reference_per_class']}`",
        f"- Neighbors: `{report['n_neighbors']}`",
        f"- Seed: `{report['seed']}`",
        "",
        "## Fold Results",
        "",
        "| Fold | Scope | Query | Status | Query total | Query sampled | Same-class ref | Top-1 correct | Top-3 correct | Top-5 correct | Top-10 correct | Correct dist med | Wrong dist med | Margin med | Positive margin | Near-zero margin | Strongest competitor |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for fold in report["folds"]:
        lines.append(
            f"| {fold['fold_id']} | {fold['audit_scope']} | {fold['heldout_class']} / {fold['heldout_display']} | "
            f"{fold['status']} | {fold['query_total']} | {fold['query_sample_count']} | {fold['same_class_reference_count']} | "
            f"{fmt(fold.get('top1_correct_class_rate'))} | {fmt(fold.get('top3_correct_class_fraction'))} | "
            f"{fmt(fold.get('top5_correct_class_fraction'))} | {fmt(fold.get('top10_correct_class_fraction'))} | "
            f"{fmt(fold.get('nearest_correct_distance_median'))} | {fmt(fold.get('nearest_wrong_distance_median'))} | "
            f"{fmt(fold.get('margin_median'))} | {fmt(fold.get('margin_positive_rate'))} | "
            f"{fmt(fold.get('margin_near_zero_rate'))} | {fold.get('strongest_competing_class', 'n/a')} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
            "- `top-k correct` is the mean fraction of the top-k neighbor list that belongs to the held-out broad class.",
            "- `margin = nearest_wrong_class_distance - nearest_correct_class_distance`; positive values mean the nearest same-class reference is closer than the nearest competing-class reference.",
            "- `weak_small_query_support` folds were computed but should be treated as unstable because fewer than 100 query graphs were available.",
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


def run_group_holdout_nn_audit(
    *,
    compact_manifest_path: Path = DEFAULT_CUMULATIVE_PATH,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    query_cap: int = 1000,
    reference_per_class: int = 5000,
    seed: int = 42,
    n_neighbors: int = 10,
) -> dict[str, Any]:
    manifest, vectors, rows, missing = load_records_and_vectors(compact_manifest_path)
    class_names = compact_manifest_class_names(manifest)
    folds = [
        run_fold(
            spec=spec,
            vectors=vectors,
            rows=rows,
            query_cap=query_cap,
            reference_per_class=reference_per_class,
            seed=seed,
            n_neighbors=n_neighbors,
        )
        for spec in make_fold_specs()
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "compact_group_holdout_nn_audit.json"
    csv_path = output_dir / "compact_group_holdout_nn_audit.csv"
    md_path = output_dir / "compact_group_holdout_nn_audit.md"
    report = {
        "generated_at": utc_now(),
        "compact_manifest_path": str(compact_manifest_path),
        "compact_root": str(compact_root(manifest)),
        "class_names": class_names,
        "loaded_record_count": len(rows),
        "vector_dimension": int(vectors.shape[1]),
        "missing_paths": missing,
        "query_cap": query_cap,
        "reference_per_class": reference_per_class,
        "seed": seed,
        "n_neighbors": n_neighbors,
        "selected_manifest_summary": summarize_selected_manifest(rows),
        "folds": folds,
        "artifact_paths": {
            "json": str(json_path),
            "csv": str(csv_path),
            "markdown": str(md_path),
        },
    }
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_csv(csv_path, folds)
    write_markdown(md_path, report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact-manifest", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--query-cap", type=int, default=1000)
    parser.add_argument("--reference-per-class", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-neighbors", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = run_group_holdout_nn_audit(
        compact_manifest_path=args.compact_manifest,
        output_dir=args.output_dir,
        query_cap=args.query_cap,
        reference_per_class=args.reference_per_class,
        seed=args.seed,
        n_neighbors=args.n_neighbors,
    )
    print(json.dumps({"artifact_paths": report["artifact_paths"], "fold_count": len(report["folds"])}, indent=2))


if __name__ == "__main__":
    main()
