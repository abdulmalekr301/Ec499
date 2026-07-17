from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import torch

from secureedge import config
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, load_office_config


DEFAULT_COMPACT_ROOT = config.GRAPH_DIR / "office_compact"
DEFAULT_ARTIFACT_DIR = config.ARTIFACTS_DIR / "office_model"
DEFAULT_CUMULATIVE_PATH = DEFAULT_ARTIFACT_DIR / "office_compact_cumulative_manifest.json"
DEFAULT_DONE_REGISTRY_PATH = DEFAULT_ARTIFACT_DIR / "done_candidates.jsonl"
DEFAULT_RUNS_DIR = DEFAULT_ARTIFACT_DIR / "runs"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_json_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(text, encoding="utf-8")
    os.replace(tmp_path, path)


def candidate_id(day: str, five_tuple: tuple[Any, ...] | list[Any], csv_start_ts: float | str) -> str:
    """Return a stable ID for a candidate flow.

    The office compact records already carry `candidate_identity`; this helper is for
    future materialization planning where only day, tuple, and timestamp are known.
    The IP/port endpoints are sorted as a bidirectional pair while protocol remains
    part of the key.
    """
    if len(five_tuple) != 5:
        raise ValueError(f"five_tuple must have 5 values, got {len(five_tuple)}")
    src_ip, src_port, dst_ip, dst_port, proto = five_tuple
    endpoint_a = (str(src_ip), str(src_port))
    endpoint_b = (str(dst_ip), str(dst_port))
    ordered = sorted([endpoint_a, endpoint_b])
    payload = {
        "day": day,
        "endpoints": ordered,
        "protocol": str(proto).lower(),
        "csv_start_ts": str(csv_start_ts),
    }
    return hashlib.sha1(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CompactRecordSummary:
    path: str
    candidate_identity: str
    class_name: str
    label: int | None
    split: str | None
    source_dataset: str | None
    day: str | None
    subtype_label: str | None
    flow_hash: str | None
    compact_tensor_hash: str | None
    flow_feature_version: str | None
    flow_dim: int | None
    packet_count: int | None
    packet_dim: int | None
    contain_edge_dim: int | None
    link_edge_dim: int | None
    file_size_bytes: int
    file_mtime_ns: int

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "candidate_identity": self.candidate_identity,
            "class_name": self.class_name,
            "label": self.label,
            "split": self.split,
            "source_dataset": self.source_dataset,
            "day": self.day,
            "subtype_label": self.subtype_label,
            "flow_hash": self.flow_hash,
            "compact_tensor_hash": self.compact_tensor_hash,
            "flow_feature_version": self.flow_feature_version,
            "flow_dim": self.flow_dim,
            "packet_count": self.packet_count,
            "packet_dim": self.packet_dim,
            "contain_edge_dim": self.contain_edge_dim,
            "link_edge_dim": self.link_edge_dim,
            "file_size_bytes": self.file_size_bytes,
            "file_mtime_ns": self.file_mtime_ns,
        }


def load_compact_record(path: Path) -> dict[str, Any]:
    """Load either pickle-written or torch-written compact records."""
    try:
        with path.open("rb") as handle:
            obj = pickle.load(handle)
    except Exception:
        obj = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(obj, dict):
        raise TypeError(f"{path} did not contain a compact graph dict")
    return obj


def _shape_dim(value: Any, index: int) -> int | None:
    shape = getattr(value, "shape", None)
    if shape is None or len(shape) <= index:
        return None
    return int(shape[index])


def summarize_compact_file(path: Path, compact_root: Path) -> CompactRecordSummary:
    record = load_compact_record(path)
    stat = path.stat()
    rel_path = path.relative_to(compact_root).as_posix()
    class_name = str(record.get("class_name") or path.parent.name)
    candidate_identity = str(record.get("candidate_identity") or path.stem)
    split = record.get("candidate_split") or record.get("split")
    packet_x = record.get("packet_x_uint8")
    contain_edge_attr = record.get("contain_edge_attr")
    link_edge_attr = record.get("link_edge_attr")
    flow_x = record.get("flow_x")
    return CompactRecordSummary(
        path=rel_path,
        candidate_identity=candidate_identity,
        class_name=class_name,
        label=int(record["label"]) if record.get("label") is not None else None,
        split=str(split) if split is not None else None,
        source_dataset=str(record["source_dataset"]) if record.get("source_dataset") is not None else None,
        day=str(record["day"]) if record.get("day") is not None else None,
        subtype_label=str(record["subtype_label"]) if record.get("subtype_label") is not None else None,
        flow_hash=str(record["flow_hash"]) if record.get("flow_hash") is not None else None,
        compact_tensor_hash=str(record["compact_tensor_hash"])
        if record.get("compact_tensor_hash") is not None
        else None,
        flow_feature_version=str(record["flow_feature_version"])
        if record.get("flow_feature_version") is not None
        else None,
        flow_dim=_shape_dim(flow_x, 0),
        packet_count=_shape_dim(packet_x, 0),
        packet_dim=_shape_dim(packet_x, 1),
        contain_edge_dim=_shape_dim(contain_edge_attr, 1),
        link_edge_dim=_shape_dim(link_edge_attr, 1),
        file_size_bytes=int(stat.st_size),
        file_mtime_ns=int(stat.st_mtime_ns),
    )


class DoneRegistry:
    """Append-only registry of materialized candidate identities."""

    def __init__(self, path: Path):
        self.path = path
        self._done: set[str] = set()
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    cid = item.get("candidate_identity")
                    if cid:
                        self._done.add(str(cid))

    def __len__(self) -> int:
        return len(self._done)

    def contains(self, cid: str) -> bool:
        return cid in self._done

    def mark_batch(self, records: list[CompactRecordSummary], run_id: str = "manual") -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new_records = [record for record in records if record.candidate_identity not in self._done]
        if not new_records:
            return 0
        with self.path.open("a", encoding="utf-8") as handle:
            for record in new_records:
                event = {
                    "candidate_identity": record.candidate_identity,
                    "class_name": record.class_name,
                    "path": record.path,
                    "source_dataset": record.source_dataset,
                    "day": record.day,
                    "flow_hash": record.flow_hash,
                    "run_id": run_id,
                    "registered_at": utc_now(),
                }
                handle.write(json.dumps(event, sort_keys=True) + "\n")
                self._done.add(record.candidate_identity)
            handle.flush()
            os.fsync(handle.fileno())
        return len(new_records)

    @classmethod
    def backfill(cls, path: Path, records: list[CompactRecordSummary], run_id: str) -> "DoneRegistry":
        registry = cls(path)
        registry.mark_batch(records, run_id=run_id)
        return registry


def build_cumulative_manifest(
    records: list[CompactRecordSummary],
    compact_root: Path,
    run_id: str,
    rejected: list[dict[str, str]],
) -> dict[str, Any]:
    office_config = load_office_config(DEFAULT_OFFICE_CONFIG_PATH)
    per_class = Counter(record.class_name for record in records)
    per_split = Counter(record.split or "unknown" for record in records)
    per_source = Counter(record.source_dataset or "unknown" for record in records)
    per_day = Counter(record.day or "unknown" for record in records)
    feature_versions = Counter(record.flow_feature_version or "unknown" for record in records)
    labels = Counter(str(record.label) if record.label is not None else "unknown" for record in records)
    duplicate_candidates = [
        candidate for candidate, count in Counter(record.candidate_identity for record in records).items() if count > 1
    ]
    dim_counts = {
        "flow_dim": Counter(str(record.flow_dim) for record in records),
        "packet_dim": Counter(str(record.packet_dim) for record in records),
        "contain_edge_dim": Counter(str(record.contain_edge_dim) for record in records),
        "link_edge_dim": Counter(str(record.link_edge_dim) for record in records),
    }
    records_json = [record.to_json() for record in records]
    manifest = {
        "schema_version": 1,
        "pipeline": "office_compact_cumulative_manifest",
        "run_id": run_id,
        "generated_at": utc_now(),
        **office_config.provenance(),
        "compact_root": str(compact_root.resolve()),
        "record_count": len(records),
        "rejected_count": len(rejected),
        "rejected_sample": rejected[:100],
        "per_class": dict(sorted(per_class.items())),
        "per_split": dict(sorted(per_split.items())),
        "per_source_dataset": dict(sorted(per_source.items())),
        "per_day": dict(sorted(per_day.items())),
        "labels": dict(sorted(labels.items())),
        "feature_versions": dict(sorted(feature_versions.items())),
        "dimension_counts": {
            key: dict(sorted(counter.items())) for key, counter in dim_counts.items()
        },
        "duplicate_candidate_identity_count": len(duplicate_candidates),
        "duplicate_candidate_identity_sample": sorted(duplicate_candidates)[:100],
        "records": records_json,
    }
    manifest["manifest_hash"] = stable_json_hash({k: v for k, v in manifest.items() if k != "manifest_hash"})
    return manifest


def reconcile_from_filesystem(
    compact_root: Path = DEFAULT_COMPACT_ROOT,
    cumulative_path: Path = DEFAULT_CUMULATIVE_PATH,
    done_registry_path: Path = DEFAULT_DONE_REGISTRY_PATH,
    runs_dir: Path = DEFAULT_RUNS_DIR,
) -> dict[str, Any]:
    compact_root = compact_root.resolve()
    run_id = f"reconcile_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    records: list[CompactRecordSummary] = []
    rejected: list[dict[str, str]] = []
    for path in sorted(compact_root.glob("*/*.pkl")):
        try:
            records.append(summarize_compact_file(path, compact_root))
        except Exception as exc:  # noqa: BLE001 - all load failures belong in the reconcile report.
            rejected.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})

    manifest = build_cumulative_manifest(records, compact_root, run_id, rejected)
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True)
    atomic_write_text(cumulative_path, manifest_text + "\n")

    runs_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(runs_dir / f"{run_id}.json", manifest_text + "\n")

    registry = DoneRegistry(done_registry_path)
    newly_registered = registry.mark_batch(records, run_id=run_id)
    registry_summary = {
        "path": str(done_registry_path.resolve()),
        "registered_candidate_count": len(registry),
        "newly_registered_from_reconcile": newly_registered,
    }
    manifest["done_registry"] = registry_summary
    manifest["run_manifest_path"] = str((runs_dir / f"{run_id}.json").resolve())
    atomic_write_text(cumulative_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def append_run_manifest(run_manifest: dict[str, Any], runs_dir: Path = DEFAULT_RUNS_DIR) -> Path:
    run_id = str(run_manifest.get("run_id") or f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    runs_dir.mkdir(parents=True, exist_ok=True)
    path = runs_dir / f"{run_id}.json"
    payload = dict(run_manifest)
    payload.setdefault("schema_version", 1)
    payload.setdefault("generated_at", utc_now())
    payload["manifest_hash"] = stable_json_hash({k: v for k, v in payload.items() if k != "manifest_hash"})
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def summarize_manifest(manifest: dict[str, Any]) -> str:
    lines = [
        f"run_id: {manifest['run_id']}",
        f"record_count: {manifest['record_count']}",
        f"rejected_count: {manifest['rejected_count']}",
        "per_class:",
    ]
    for class_name, count in manifest["per_class"].items():
        lines.append(f"  {class_name}: {count}")
    if manifest.get("duplicate_candidate_identity_count"):
        lines.append(f"duplicate_candidate_identity_count: {manifest['duplicate_candidate_identity_count']}")
    if manifest.get("done_registry"):
        lines.append(
            f"done_registry_registered: {manifest['done_registry']['registered_candidate_count']}"
        )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Office compact graph manifest and done-registry utilities.")
    parser.add_argument("--compact-root", type=Path, default=DEFAULT_COMPACT_ROOT)
    parser.add_argument("--cumulative-path", type=Path, default=DEFAULT_CUMULATIVE_PATH)
    parser.add_argument("--done-registry-path", type=Path, default=DEFAULT_DONE_REGISTRY_PATH)
    parser.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR)
    parser.add_argument("--reconcile", action="store_true", help="Rebuild cumulative manifest from compact files.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not args.reconcile:
        raise SystemExit("No action requested. Use --reconcile to rebuild the cumulative manifest.")
    manifest = reconcile_from_filesystem(
        compact_root=args.compact_root,
        cumulative_path=args.cumulative_path,
        done_registry_path=args.done_registry_path,
        runs_dir=args.runs_dir,
    )
    print(summarize_manifest(manifest))


if __name__ == "__main__":
    main()
