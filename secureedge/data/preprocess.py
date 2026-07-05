from __future__ import annotations

import json
import hashlib
import pickle
import os
import re
import resource
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import psutil

from secureedge import config
from secureedge.data.graph_builder import graph_class_name
from secureedge.utils import ensure_directories, write_context

PROCESS = psutil.Process()


def canonical_label(raw: object) -> str | None:
    label = str(raw).strip()
    if label in config.SUBTYPE_TO_CLASS:
        return config.SUBTYPE_TO_CLASS[label]
    if not label or label.lower() == "nan":
        return None
    normalized = label.lower().replace(" ", "").replace("-", "").replace("_", "")

    if normalized in {"benigntraffic", "benign", "benignfinal"}:
        return "Benign"
    if normalized.startswith("ddos"):
        return "DDoS"
    if normalized.startswith("dos"):
        return "DoS"
    if normalized.startswith("mirai"):
        return "Mirai"
    if normalized.startswith("recon") or normalized == "vulnerabilityscan":
        return "Recon"
    if normalized in {"dnsspoofing", "mitmarpspoofing"}:
        return "Spoofing"
    if normalized == "dictionarybruteforce":
        return "BruteForce"

    compact_web = {item.lower().replace(" ", "").replace("-", "").replace("_", "") for item in config.WEB_BASED_LABELS}
    if normalized in compact_web:
        return "WebBased"
    return None


def subtype_from_pcap(path: Path) -> str:
    def normalize_stem(stem: str) -> str:
        while stem and stem[-1].isdigit():
            stem = stem[:-1]
        return stem.rstrip("-_")

    if config.PCAP_CHUNK_DIR in path.parents:
        return normalize_stem(path.parent.name)
    return normalize_stem(path.stem)


def chunk_sort_key(path: Path) -> tuple[int, int | str, str]:
    match = re.search(r"(\d{5})(?=\D|$)", path.name)
    if match:
        return (0, int(match.group(1)), path.name)
    suffix_match = re.search(r"\.pcap(\d+)$", path.name)
    if suffix_match:
        return (1, int(suffix_match.group(1)), path.name)
    return (1, 0, path.name)


def discover_pcap_groups() -> dict[str, list[Path]]:
    if not config.PCAP_DIR.exists():
        raise FileNotFoundError(f"PCAP directory not found: {config.PCAP_DIR}")
    groups: dict[str, list[Path]] = {}
    threshold_bytes = config.PCAP_CHUNK_THRESHOLD_MB * 1024 * 1024

    top_level_pcaps = sorted(path for path in config.PCAP_DIR.glob("*.pcap") if path.is_file())
    for path in top_level_pcaps:
        subtype = subtype_from_pcap(path)
        chunk_dir = config.PCAP_CHUNK_DIR / path.stem
        if not chunk_dir.exists():
            chunk_dir = config.PCAP_CHUNK_DIR / subtype
        if path.stat().st_size > threshold_bytes:
            if config.USE_SPLIT_PCAP_CHUNKS and chunk_dir.exists():
                chunks = sorted(
                    (item for item in chunk_dir.glob("*.pcap*") if item.is_file()),
                    key=chunk_sort_key,
                )
                if chunks:
                    groups[subtype] = chunks
                    continue
            print(
                f"[preprocess] warning: {path.name} is larger than {config.PCAP_CHUNK_THRESHOLD_MB} MB "
                "and has no split chunks; skipping.",
                flush=True,
            )
        else:
            groups[subtype] = [path]
    return groups


def discover_pcap_files() -> list[Path]:
    groups = discover_pcap_groups()
    return [path for paths in groups.values() for path in paths]


def expected_subtypes() -> set[str]:
    expected = set(config.SUBTYPE_TO_CLASS)
    if "BenignTraffic" in expected:
        expected.remove("Benign_Final")
    return expected


def validate_pcap_class_coverage(pcap_files: list[Path]) -> dict[str, list[str]]:
    coverage = {class_name: [] for class_name in config.CLASS_NAMES}
    seen_subtypes: set[str] = set()
    unknown: list[str] = []
    for path in pcap_files:
        subtype = subtype_from_pcap(path)
        class_name = canonical_label(subtype)
        if class_name is None:
            unknown.append(path.name)
            continue
        seen_subtypes.add(subtype)
        coverage[class_name].append(path.name)

    missing = [class_name for class_name, files in coverage.items() if not files]
    missing_subtypes = sorted(expected_subtypes() - seen_subtypes)
    if unknown or missing or missing_subtypes:
        details = []
        if missing:
            details.append(f"missing classes: {', '.join(missing)}")
        if missing_subtypes:
            details.append(f"missing subtypes: {', '.join(missing_subtypes)}")
        if unknown:
            details.append(f"unmapped PCAP files: {', '.join(unknown)}")
        raise ValueError(
            "PCAP dataset does not cover the required eight-class Stage 1 task ("
            + "; ".join(details)
            + "). Add the missing PCAPs or update the class plan before preprocessing."
        )
    return coverage


def subtypes_for_class(class_name: str) -> list[str]:
    return [
        subtype
        for subtype, mapped_class in config.SUBTYPE_TO_CLASS.items()
        if mapped_class == class_name and not (subtype == "Benign_Final" and "BenignTraffic" in config.SUBTYPE_TO_CLASS)
    ]


def per_subtype_target(class_name: str) -> int:
    split_total = config.TRAIN_SAMPLES_PER_CLASS + config.VAL_SAMPLES_PER_CLASS + config.TEST_SAMPLES_PER_CLASS
    return int(np.ceil(split_total / len(subtypes_for_class(class_name))))


def total_requested_graphs() -> int:
    return config.N_CLASSES * (
        config.TRAIN_SAMPLES_PER_CLASS + config.VAL_SAMPLES_PER_CLASS + config.TEST_SAMPLES_PER_CLASS
    )


def assert_full_run_is_allowed(pcap_files: list[Path]) -> None:
    total_bytes = sum(path.stat().st_size for path in pcap_files)
    max_file_bytes = max((path.stat().st_size for path in pcap_files), default=0)
    full_methodology_count = total_requested_graphs() >= 100_000
    large_unsplit_corpus = total_bytes >= 10 * 1024**3 and max_file_bytes > config.PCAP_CHUNK_THRESHOLD_MB * 1024 * 1024
    if config.ALLOW_FULL_PREPROCESS:
        return
    if full_methodology_count or large_unsplit_corpus:
        raise RuntimeError(
            "Refusing to start full PCAP preprocessing without an explicit safety override. "
            f"This request would target {total_requested_graphs():,} graphs from "
            f"{total_bytes / (1024 ** 3):.2f} GiB of PCAP data, which has already exhausted "
            "system memory/swap on this workstation. For a bounded development run, set smaller "
            "sample counts, for example:\n\n"
            "  SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 "
            "python -m secureedge.data.preprocess\n\n"
            "For the full final-methodology run, use a larger machine or a non-interactive batch "
            "environment and set SECUREEDGE_ALLOW_FULL_PREPROCESS=1 only when you are ready."
        )


def clear_reservoir_dir() -> None:
    if config.GRAPH_RESERVOIR_DIR.exists():
        shutil.rmtree(config.GRAPH_RESERVOIR_DIR)
    config.GRAPH_RESERVOIR_DIR.mkdir(parents=True, exist_ok=True)


def save_reservoir_graph(graph: object, subtype: str, seen_count: int) -> Path:
    safe_subtype = subtype.replace("/", "_")
    subtype_dir = config.GRAPH_RESERVOIR_DIR / safe_subtype
    subtype_dir.mkdir(parents=True, exist_ok=True)
    path = subtype_dir / f"{safe_subtype}_{seen_count:08d}.pkl"
    with path.open("wb") as handle:
        pickle.dump(graph, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return path


def update_subtype_reservoir(
    reservoirs: dict[str, list[Path]],
    graph_path: Path,
    subtype: str,
    rng: np.random.Generator,
    reservoir_size: int,
    seen_count: int,
) -> None:
    reservoir = reservoirs.setdefault(subtype, [])
    if len(reservoir) < reservoir_size:
        reservoir.append(graph_path)
        return
    replacement_index = int(rng.integers(0, seen_count))
    if replacement_index < reservoir_size:
        old_path = reservoir[replacement_index]
        if old_path.exists():
            old_path.unlink()
        reservoir[replacement_index] = graph_path
    elif graph_path.exists():
        graph_path.unlink()


def reservoir_is_full(reservoirs: dict[str, list[Path]], subtype: str, reservoir_size: int) -> bool:
    return len(reservoirs.get(subtype, [])) >= reservoir_size


def sample_graphs(graphs: list[Path], size: int, rng: np.random.Generator, replace: bool) -> list[Path]:
    if not graphs:
        raise ValueError("Cannot sample an empty graph pool.")
    indices = rng.choice(np.arange(len(graphs)), size=size, replace=replace)
    return [graphs[int(index)] for index in indices]


def compact_content_hash(path: Path) -> str:
    with path.open("rb") as handle:
        record = pickle.load(handle)
    h = hashlib.sha256()
    for key in ("flow_x", "packet_x_uint8", "contain_edge_attr", "link_edge_attr"):
        h.update(np.asarray(record[key]).tobytes())
    h.update(str(record["label"]).encode("utf-8"))
    return h.hexdigest()


def balance_to_target(records: list[Path], target: int, rng: np.random.Generator) -> tuple[list[Path], dict[str, object]]:
    if not records:
        raise ValueError("Cannot balance an empty graph pool.")
    if len(records) >= target:
        balanced = sample_graphs(records, target, rng, replace=False)
        oversampled_count = 0
    else:
        oversampled_count = target - len(records)
        balanced = list(records) + sample_graphs(records, oversampled_count, rng, replace=True)
    rng.shuffle(balanced)
    unique_count = len(set(balanced))
    metadata = {
        "real_available": len(records),
        "target_total": target,
        "unique_in_balanced_pool": unique_count,
        "oversampled_count": oversampled_count,
        "oversampled_fraction": oversampled_count / max(target, 1),
    }
    return balanced, metadata


def split_without_cross_split_duplicates(
    records: list[Path],
    rng: np.random.Generator,
) -> tuple[list[Path], list[Path], list[Path], dict[str, object]]:
    unique_records = list(dict.fromkeys(records))
    hash_groups: dict[str, list[Path]] = {}
    for path in unique_records:
        hash_groups.setdefault(compact_content_hash(path), []).append(path)
    groups = list(hash_groups.values())
    rng.shuffle(groups)

    requested_test = config.TEST_SAMPLES_PER_CLASS
    requested_val = config.VAL_SAMPLES_PER_CLASS
    train_groups: list[list[Path]] = []
    val_groups: list[list[Path]] = []
    test_groups: list[list[Path]] = []
    train_seed_count = 0
    val_count = 0
    test_count = 0

    for index, group in enumerate(groups):
        remaining_groups_after_this = len(groups) - index - 1
        group_size = len(group)
        if remaining_groups_after_this == 0 and not train_groups:
            train_groups.append(group)
            train_seed_count += group_size
        elif test_count < requested_test and (test_count <= val_count or val_count >= requested_val):
            test_groups.append(group)
            test_count += group_size
        elif val_count < requested_val:
            val_groups.append(group)
            val_count += group_size
        else:
            train_groups.append(group)
            train_seed_count += group_size

    class_test = [path for group in test_groups for path in group]
    class_val = [path for group in val_groups for path in group]
    train_seed = [path for group in train_groups for path in group]
    if not train_seed:
        raise ValueError("Cannot build a train split after reserving validation/test records.")

    class_train, train_summary = balance_to_target(train_seed, config.TRAIN_SAMPLES_PER_CLASS, rng)
    split_overlap = {
        "train_val": len(set(class_train) & set(class_val)),
        "train_test": len(set(class_train) & set(class_test)),
        "val_test": len(set(class_val) & set(class_test)),
    }
    metadata = {
        **train_summary,
        "split_order": "split_first_then_oversample_train_only",
        "raw_unique_available": len(unique_records),
        "content_hash_group_count": len(groups),
        "train_seed_count": len(train_seed),
        "requested_train_count": config.TRAIN_SAMPLES_PER_CLASS,
        "requested_val_count": requested_val,
        "requested_test_count": requested_test,
        "train_count": len(class_train),
        "val_count": len(class_val),
        "test_count": len(class_test),
        "val_shortfall": max(0, requested_val - len(class_val)),
        "test_shortfall": max(0, requested_test - len(class_test)),
        "cross_split_duplicate_reference_counts": split_overlap,
    }
    return class_train, class_val, class_test, metadata


def build_balanced_splits(
    subtype_reservoirs: dict[str, list[Path]],
    rng: np.random.Generator,
) -> tuple[list[Path], list[Path], list[Path], dict[str, dict[str, object]], dict[str, int]]:
    train_graphs: list[Path] = []
    val_graphs: list[Path] = []
    test_graphs: list[Path] = []
    class_pool_counts: dict[str, int] = {}
    oversampling_summary: dict[str, dict[str, object]] = {}
    for class_name in config.CLASS_NAMES:
        class_graphs: list[Path] = []
        for subtype in subtypes_for_class(class_name):
            class_graphs.extend(subtype_reservoirs.get(subtype, []))
        if not class_graphs:
            raise ValueError(f"Class {class_name} has no graph samples after subtype reservoir extraction.")
        class_pool_counts[class_name] = len(class_graphs)
        class_train, class_val, class_test, class_summary = split_without_cross_split_duplicates(class_graphs, rng)
        oversampling_summary[class_name] = class_summary
        train_graphs.extend(class_train)
        val_graphs.extend(class_val)
        test_graphs.extend(class_test)
    rng.shuffle(train_graphs)
    rng.shuffle(val_graphs)
    rng.shuffle(test_graphs)
    return train_graphs, val_graphs, test_graphs, oversampling_summary, class_pool_counts


def load_existing_subtype_reservoirs() -> dict[str, list[Path]]:
    if not config.GRAPH_RESERVOIR_DIR.exists():
        raise FileNotFoundError(f"Compact reservoir directory not found: {config.GRAPH_RESERVOIR_DIR}")
    reservoirs: dict[str, list[Path]] = {}
    for subtype_dir in sorted(path for path in config.GRAPH_RESERVOIR_DIR.iterdir() if path.is_dir()):
        subtype = subtype_dir.name
        paths = sorted(subtype_dir.glob("*.pkl"))
        if paths:
            reservoirs[subtype] = paths
    if not reservoirs:
        raise FileNotFoundError(f"No compact `.pkl` records found under {config.GRAPH_RESERVOIR_DIR}")
    return reservoirs


def compact_manifest_source_from_existing() -> dict[str, object]:
    if config.COMPACT_RESERVOIR_MANIFEST_PATH.exists():
        existing = json.loads(config.COMPACT_RESERVOIR_MANIFEST_PATH.read_text(encoding="utf-8"))
        return dict(existing.get("source", {}))
    return {
        "pcap_dir": str(config.PCAP_DIR),
        "pcap_chunk_dir": str(config.PCAP_CHUNK_DIR),
        "use_split_chunks": config.USE_SPLIT_PCAP_CHUNKS,
        "subtypes": {},
    }


def assert_memory_available(context: str) -> None:
    rss_gb = PROCESS.memory_info().rss / (1024**3)
    if rss_gb > config.MAX_PROCESS_RSS_GB:
        raise MemoryError(
            f"Stopping preprocessing during {context}: process RSS is {rss_gb:.2f} GiB, "
            f"above configured ceiling {config.MAX_PROCESS_RSS_GB:.2f} GiB."
        )
    available_gb = psutil.virtual_memory().available / (1024**3)
    if available_gb < config.MIN_AVAILABLE_MEMORY_GB:
        raise MemoryError(
            f"Stopping preprocessing during {context}: available memory is {available_gb:.2f} GiB, "
            f"below configured floor {config.MIN_AVAILABLE_MEMORY_GB:.2f} GiB."
        )


def worker_limits() -> None:
    if config.ALLOW_UNSAFE_PREPROCESS:
        return
    limit_bytes = int((config.MAX_PROCESS_RSS_GB + 0.75) * 1024**3)
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def output_tag_for_pcap(path: Path) -> str:
    if config.PCAP_CHUNK_DIR in path.parents:
        relative = path.relative_to(config.PCAP_CHUNK_DIR)
        return "_".join(relative.parts).replace("/", "_").replace(".", "_")
    return path.name.replace(".", "_")


def run_extraction_worker(paths: list[Path], subtype: str, class_name: str, class_index: int, target: int) -> dict[str, object]:
    safe_subtype = subtype.replace("/", "_")
    out_dir = config.GRAPH_RESERVOIR_DIR / safe_subtype
    summary_path = config.GRAPH_RESERVOIR_DIR / safe_subtype / f"{safe_subtype}_summary.json"
    command = [
        sys.executable,
        "-m",
        "secureedge.data.extract_worker",
    ]
    for path in paths:
        command.extend(["--pcap", str(path)])
    command.extend([
        "--subtype",
        subtype,
        "--class-name",
        class_name,
        "--class-index",
        str(class_index),
        "--target",
        str(target),
        "--out-dir",
        str(out_dir),
        "--summary-path",
        str(summary_path),
        "--max-rss-gb",
        str(config.MAX_PROCESS_RSS_GB),
        "--min-available-gb",
        str(config.MIN_AVAILABLE_MEMORY_GB),
        "--chunk-threshold-mb",
        str(config.PCAP_CHUNK_THRESHOLD_MB),
        "--chunk-size-mb",
        str(config.PCAP_CHUNK_SIZE_MB),
        "--memory-check-interval",
        str(config.PCAP_MEMORY_CHECK_INTERVAL),
    ])
    env = os.environ.copy()
    env.setdefault("MALLOC_ARENA_MAX", "2")
    env.setdefault("OMP_NUM_THREADS", "1")
    env.setdefault("OPENBLAS_NUM_THREADS", "1")
    env.setdefault("MKL_NUM_THREADS", "1")
    subprocess.run(
        command,
        check=True,
        env=env,
        timeout=config.PCAP_WORKER_TIMEOUT_SECONDS,
        preexec_fn=worker_limits if not config.ALLOW_UNSAFE_PREPROCESS else None,
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert_memory_available(f"after worker for {subtype}")
    return summary


def write_compact_manifest(
    train_graphs: list[Path],
    val_graphs: list[Path],
    test_graphs: list[Path],
    source: dict[str, object],
    seen_counts: dict[str, int],
    stored_counts: dict[str, int],
    class_pool_counts: dict[str, int],
    oversampling_summary: dict[str, dict[str, object]],
    skipped_zero_packet_flows: int,
    skipped_files: list[str],
    mac_filter_summaries: dict[str, object],
    context_action_lines: list[str],
) -> dict[str, object]:
    manifest = {
        "total_compact_count": len(train_graphs) + len(val_graphs) + len(test_graphs),
        "split_strategy": "split_first_then_oversample_train_only",
        "source": source,
        "splits": {
            "train": {
                "count": len(train_graphs),
                "paths": [str(path) for path in train_graphs],
            },
            "val": {
                "count": len(val_graphs),
                "paths": [str(path) for path in val_graphs],
            },
            "test": {
                "count": len(test_graphs),
                "paths": [str(path) for path in test_graphs],
            },
        },
        "counts": {
            "seen_counts": seen_counts,
            "stored_counts": stored_counts,
            "class_pool_counts_before_split": class_pool_counts,
            "oversampling_summary": oversampling_summary,
            "train_per_class": {
                class_name: sum(1 for path in train_graphs if graph_class_name(path) == class_name)
                for class_name in config.CLASS_NAMES
            },
            "val_per_class": {
                class_name: sum(1 for path in val_graphs if graph_class_name(path) == class_name)
                for class_name in config.CLASS_NAMES
            },
            "test_per_class": {
                class_name: sum(1 for path in test_graphs if graph_class_name(path) == class_name)
                for class_name in config.CLASS_NAMES
            },
            "skipped_zero_packet_flows": skipped_zero_packet_flows,
            "mac_filter_enabled": config.ENABLE_ATTACKER_MAC_FILTER,
            "attacker_mac_count": len(config.ATTACKER_MACS),
            "mac_filter_summaries": mac_filter_summaries,
            "skipped_files_after_reservoir_fill_count": len(skipped_files),
            "skipped_files_after_reservoir_fill_sample": skipped_files[:25],
        },
    }
    config.COMPACT_RESERVOIR_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    write_context(
        "02_preprocessing.md",
        "Compact Preprocessing",
        [
            "## Action",
            *context_action_lines,
            "- Applied leakage-safe splitting: reserve validation/test records first, then oversample the train split only.",
            f"- Saved compact reservoir manifest to `{config.COMPACT_RESERVOIR_MANIFEST_PATH}`.",
            "",
            "## Counts",
            "```json",
            json.dumps(manifest["counts"], indent=2),
            "```",
        ],
    )
    return manifest


def resplit_existing_reservoir() -> tuple[Path, Path]:
    ensure_directories()
    assert_memory_available("resplit startup")
    subtype_reservoirs = load_existing_subtype_reservoirs()
    rng = np.random.default_rng(config.RANDOM_SEED)
    train_graphs, val_graphs, test_graphs, oversampling_summary, class_pool_counts = build_balanced_splits(
        subtype_reservoirs, rng
    )
    stored_counts = {subtype: len(paths) for subtype, paths in subtype_reservoirs.items()}
    source = compact_manifest_source_from_existing()
    write_compact_manifest(
        train_graphs,
        val_graphs,
        test_graphs,
        source,
        seen_counts=stored_counts,
        stored_counts=stored_counts,
        class_pool_counts=class_pool_counts,
        oversampling_summary=oversampling_summary,
        skipped_zero_packet_flows=0,
        skipped_files=[],
        mac_filter_summaries={},
        context_action_lines=[
            f"- Reused existing compact reservoir under `{config.GRAPH_RESERVOIR_DIR}`.",
            "- Did not rerun NFStream extraction or modify raw compact records.",
            f"- Loaded `{sum(len(paths) for paths in subtype_reservoirs.values())}` compact records across `{len(subtype_reservoirs)}` subtype directories.",
        ],
    )
    write_context(
        "31_xgnid_oversampling_resplit.md",
        "XG-NID Oversampling Resplit",
        [
            "## Action",
            f"- Rebuilt `{config.COMPACT_RESERVOIR_MANIFEST_PATH}` from the existing compact reservoir.",
            (
                "- Rebuilt train/validation/test splits without allowing compact record references "
                "to overlap across splits."
            ),
            (
                f"- Oversampled train only to {config.TRAIN_SAMPLES_PER_CLASS:,} records per class; "
                "validation/test remain held-out unique records and may be smaller for underrepresented classes."
            ),
            "",
            "## Oversampling Summary",
            "```json",
            json.dumps(oversampling_summary, indent=2),
            "```",
        ],
    )
    return config.GRAPH_RESERVOIR_DIR, config.COMPACT_RESERVOIR_MANIFEST_PATH


def regenerate_selected_subtype_reservoirs(selected_subtypes: list[str]) -> tuple[Path, Path]:
    ensure_directories()
    assert_memory_available("selected subtype regeneration startup")
    pcap_groups = discover_pcap_groups()
    normalized = [subtype.strip() for subtype in selected_subtypes if subtype.strip()]
    if not normalized:
        raise ValueError("No subtypes were provided for selected regeneration.")

    regenerated: dict[str, dict[str, object]] = {}
    for subtype in normalized:
        if subtype not in pcap_groups:
            raise ValueError(f"Requested subtype {subtype!r} has no discovered PCAP group.")
        class_name = canonical_label(subtype)
        if class_name is None:
            raise ValueError(f"Requested subtype {subtype!r} does not map to a known class.")
        safe_subtype = subtype.replace("/", "_")
        subtype_dir = config.GRAPH_RESERVOIR_DIR / safe_subtype
        if subtype_dir.exists():
            shutil.rmtree(subtype_dir)
        subtype_target = per_subtype_target(class_name)
        class_index = config.CLASS_TO_INDEX[class_name]
        print(
            f"[preprocess] regenerate {subtype} -> {class_name}/{subtype} "
            f"files={len(pcap_groups[subtype])} target={subtype_target}",
            flush=True,
        )
        summary = run_extraction_worker(pcap_groups[subtype], subtype, class_name, class_index, subtype_target)
        regenerated[subtype] = {
            "class_name": class_name,
            "target": subtype_target,
            "seen": summary.get("seen"),
            "stored": summary.get("stored"),
            "mac_filter": summary.get("mac_filter", {}),
        }
        print(
            f"[preprocess] regenerated {subtype}: {summary.get('seen')} usable graph flows; "
            f"stored={summary.get('stored')}",
            flush=True,
        )

    reservoir_dir, manifest_path = resplit_existing_reservoir()
    write_context(
        "48_class_conditional_filtering_regeneration.md",
        "Class-Conditional Filtering Regeneration",
        [
            "## Action",
            "- Applied class-conditional MAC filtering.",
            f"- MAC-filtered classes: `{sorted(config.MAC_FILTERED_CLASSES)}`.",
            "- WebBased and BruteForce bypass attacker-MAC filtering and use filename/subtype labels.",
            "- Benign remains strict and drops flows involving known attacker MACs.",
            f"- Regenerated selected subtype reservoirs: `{normalized}`.",
            f"- Rebuilt compact split manifest at `{manifest_path}` using split-first/train-only oversampling.",
            "",
            "## Regeneration Summary",
            "```json",
            json.dumps(regenerated, indent=2),
            "```",
        ],
    )
    return reservoir_dir, manifest_path


def preprocess() -> tuple[Path, Path]:
    ensure_directories()
    pcap_groups = discover_pcap_groups()
    pcap_files = [path for paths in pcap_groups.values() for path in paths]
    if not pcap_groups:
        raise FileNotFoundError(f"No .pcap files found under {config.PCAP_DIR}")
    assert_full_run_is_allowed(pcap_files)
    assert_memory_available("startup")
    clear_reservoir_dir()
    coverage = validate_pcap_class_coverage(pcap_files)
    total_bytes = sum(path.stat().st_size for path in pcap_files)
    write_context(
        "01_dataset_acquisition.md",
        "PCAP Dataset Acquisition",
        [
            "## Action",
            f"- Using `{config.PCAP_DIR}` as the raw dataset source.",
            f"- Split chunk source enabled: `{config.USE_SPLIT_PCAP_CHUNKS}`.",
            f"- Split chunk directory: `{config.PCAP_CHUNK_DIR}`.",
            f"- Found `{len(pcap_files)}` PCAP files.",
            f"- Total PCAP size: `{total_bytes / (1024 ** 3):.2f} GiB`.",
            "- The previous CSV export is ignored by the final XG-NID graph pipeline.",
            "",
            "## Class Coverage",
            "```text",
            pd.Series({class_name: len(files) for class_name, files in coverage.items()}).to_string(),
            "```",
        ],
    )

    subtype_reservoirs: dict[str, list[Path]] = {}
    seen_counts = {subtype: 0 for subtype in config.SUBTYPE_TO_CLASS}
    stored_counts: dict[str, int] = {}
    skipped_files: list[str] = []
    mac_filter_summaries: dict[str, object] = {}
    skipped_zero_packet_flows = 0
    rng = np.random.default_rng(config.RANDOM_SEED)

    for subtype, subtype_paths in pcap_groups.items():
        class_name = canonical_label(subtype)
        if class_name is None:
            continue
        subtype_target = per_subtype_target(class_name)
        if reservoir_is_full(subtype_reservoirs, subtype, subtype_target):
            skipped_files.extend(path.name for path in subtype_paths)
            continue

        class_index = config.CLASS_TO_INDEX[class_name]
        remaining_target = subtype_target - len(subtype_reservoirs.get(subtype, []))
        print(
            f"[preprocess] start {subtype} -> {class_name}/{subtype} "
            f"files={len(subtype_paths)} target={remaining_target}",
            flush=True,
        )
        summary = run_extraction_worker(subtype_paths, subtype, class_name, class_index, remaining_target)
        paths = [Path(item) for item in summary["paths"]]
        subtype_reservoirs.setdefault(subtype, []).extend(paths)
        seen_counts[subtype] += int(summary["seen"])
        skipped_zero_packet_flows += int(summary["skipped_zero_packet"])
        mac_filter_summaries[subtype] = summary.get("mac_filter", {})
        stored_counts[subtype] = len(subtype_reservoirs[subtype])
        print(
            f"[preprocess] done {subtype}: {summary['seen']} usable graph flows; "
            f"stored_for_subtype={stored_counts[subtype]}",
            flush=True,
        )

    if not subtype_reservoirs:
        raise ValueError("No usable graph flows were extracted from the PCAP files.")

    train_graphs, val_graphs, test_graphs, oversampling_summary, class_pool_counts = build_balanced_splits(
        subtype_reservoirs, rng
    )
    source = {
            "pcap_dir": str(config.PCAP_DIR),
            "pcap_chunk_dir": str(config.PCAP_CHUNK_DIR),
            "use_split_chunks": config.USE_SPLIT_PCAP_CHUNKS,
            "subtypes": {
                subtype: [str(path) for path in paths]
                for subtype, paths in sorted(pcap_groups.items())
            },
    }
    write_compact_manifest(
        train_graphs,
        val_graphs,
        test_graphs,
        source,
        seen_counts,
        stored_counts,
        class_pool_counts,
        oversampling_summary,
        skipped_zero_packet_flows,
        skipped_files,
        mac_filter_summaries,
        [
            f"- Streamed `{len(pcap_files)}` PCAP files from `{config.PCAP_DIR}` with NFStream.",
            f"- Processed `{len(pcap_groups)}` subtype groups with one temporal extractor per subtype.",
            "- Captured up to 20 packet payloads per flow through the `PacketCapture` NFPlugin.",
            "- Computed the 16 temporal features during streaming, before reservoir sampling.",
            "- Wrote compact `.pkl` records only; PyTorch/PyG graph construction is handled by `secureedge.data.build_graphs`.",
            "- Used per-subtype reservoirs before class-level XG-NID oversampling.",
            f"- Attacker-MAC filtering enabled: `{config.ENABLE_ATTACKER_MAC_FILTER}`.",
            f"- Used disk-backed temporary reservoirs under `{config.GRAPH_RESERVOIR_DIR}` to reduce peak memory use.",
        ],
    )
    return config.GRAPH_RESERVOIR_DIR, config.COMPACT_RESERVOIR_MANIFEST_PATH


def main() -> None:
    regenerate_subtypes = os.getenv("SECUREEDGE_REGENERATE_SUBTYPES", "")
    if regenerate_subtypes.strip():
        reservoir_dir, manifest_path = regenerate_selected_subtype_reservoirs(regenerate_subtypes.split(","))
    elif os.getenv("SECUREEDGE_RESPLIT_EXISTING_RESERVOIR", "0") == "1":
        reservoir_dir, manifest_path = resplit_existing_reservoir()
    else:
        reservoir_dir, manifest_path = preprocess()
    print(f"Wrote compact reservoir records under {reservoir_dir}")
    print(f"Wrote compact reservoir manifest to {manifest_path}")


if __name__ == "__main__":
    main()
