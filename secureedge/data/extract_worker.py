from __future__ import annotations

import argparse
import json
import pickle
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import psutil

from secureedge import config
from secureedge.data.graph_builder import build_compact_graph_record
from secureedge.data.pcap_flows import iter_flow_records
from secureedge.features.temporal import TemporalFeatureExtractor


def split_pcap_if_needed(path: Path, chunk_threshold_mb: int, chunk_size_mb: int) -> tuple[list[Path], tempfile.TemporaryDirectory[str] | None]:
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb <= chunk_threshold_mb:
        return [path], None
    if not config.ALLOW_AUTOMATIC_PCAP_SPLITTING:
        raise RuntimeError(
            f"{path} is {size_mb:.1f} MB, above the safe direct-processing threshold "
            f"of {chunk_threshold_mb} MB. Automatic tcpdump splitting is disabled because "
            "it previously caused system-wide memory/swap pressure on this workstation. "
            "Use pre-split PCAP chunks below the threshold, or set "
            "SECUREEDGE_ALLOW_AUTOMATIC_PCAP_SPLITTING=1 only in a controlled batch run."
        )
    if shutil.which("tcpdump") is None:
        raise RuntimeError(
            f"{path} is {size_mb:.1f} MB and requires chunking, but tcpdump is not available."
        )
    temp_dir = tempfile.TemporaryDirectory(prefix="secureedge_pcap_chunks_", dir=str(config.GRAPH_DIR))
    output_prefix = Path(temp_dir.name) / "chunk.pcap"
    subprocess.run(
        ["tcpdump", "-r", str(path), "-w", str(output_prefix), "-C", str(chunk_size_mb)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    chunks = sorted(Path(temp_dir.name).glob("chunk.pcap*"), key=lambda item: (len(item.name), item.name))
    if not chunks:
        temp_dir.cleanup()
        raise RuntimeError(f"tcpdump did not create chunks for {path}")
    return chunks, temp_dir


def memory_ok(max_rss_gb: float, min_available_gb: float) -> tuple[bool, str]:
    rss_gb = psutil.Process().memory_info().rss / (1024**3)
    available_gb = psutil.virtual_memory().available / (1024**3)
    if rss_gb > max_rss_gb:
        return False, f"process RSS {rss_gb:.2f} GiB exceeded {max_rss_gb:.2f} GiB"
    if available_gb < min_available_gb:
        return False, f"available memory {available_gb:.2f} GiB below {min_available_gb:.2f} GiB"
    return True, f"rss={rss_gb:.2f}GiB available={available_gb:.2f}GiB"


def save_compact_record(record: dict[str, object], directory: Path, subtype: str, index: int) -> Path:
    safe_subtype = subtype.replace("/", "_")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{safe_subtype}_{index:08d}.pkl"
    with path.open("wb") as handle:
        pickle.dump(record, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return path


def mac_filter_decision(flow_record: dict[str, object], class_name: str) -> tuple[bool, str]:
    if not config.ENABLE_ATTACKER_MAC_FILTER:
        return True, "disabled"
    if not config.ATTACKER_MACS:
        raise ValueError(
            "SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 requires SECUREEDGE_ATTACKER_MACS to contain "
            "the CIC-IoT2023 attacker MAC addresses."
        )
    src_mac = config.normalize_mac_address(flow_record.get("src_mac", ""))
    dst_mac = config.normalize_mac_address(flow_record.get("dst_mac", ""))
    if not src_mac and not dst_mac:
        return True, "missing_mac_kept"
    attacker_involved = src_mac in config.ATTACKER_MACS or dst_mac in config.ATTACKER_MACS
    if class_name == "Benign":
        if config.BENIGN_ONLY_ENFORCE and attacker_involved:
            return False, "benign_attacker_dropped"
        return True, "benign_kept"
    if class_name not in config.MAC_FILTERED_CLASSES:
        return True, "attack_mac_filter_not_configured_for_class"
    if attacker_involved:
        return True, "attack_attacker_kept"
    return False, "attack_background_dropped"


def extract(args: argparse.Namespace) -> dict[str, object]:
    rng = np.random.default_rng(args.seed)
    out_dir = Path(args.out_dir)
    reservoir: list[Path] = []
    seen = 0
    skipped_zero_packet = 0
    kept_by_mac_filter = 0
    dropped_by_mac_filter = 0
    missing_mac_kept = 0
    mac_filter_reasons: dict[str, int] = {}
    first_flow_macs: list[dict[str, object]] = []
    stopped_reason = "target_reached"
    chunks_used = 0

    ok, reason = memory_ok(args.max_rss_gb, args.min_available_gb)
    if not ok:
        return {
            "pcap": str(args.pcap),
            "subtype": args.subtype,
            "class_name": args.class_name,
            "seen": seen,
            "stored": len(reservoir),
            "skipped_zero_packet": skipped_zero_packet,
            "mac_filter": {
                "enabled": config.ENABLE_ATTACKER_MAC_FILTER,
                "attacker_mac_count": len(config.ATTACKER_MACS),
                "kept": kept_by_mac_filter,
                "dropped": dropped_by_mac_filter,
                "missing_mac_kept": missing_mac_kept,
                "reasons": mac_filter_reasons,
                "first_flow_macs": first_flow_macs,
            },
            "stopped_reason": reason,
            "chunks_used": chunks_used,
            "paths": [],
        }

    temp_dirs: list[tempfile.TemporaryDirectory[str]] = []
    extractor = TemporalFeatureExtractor(window_size=config.TEMPORAL_WINDOW_SIZE)
    pcap_paths = [Path(item) for item in args.pcap]
    try:
        for pcap_path in pcap_paths:
            chunks, temp_dir = split_pcap_if_needed(pcap_path, args.chunk_threshold_mb, args.chunk_size_mb)
            if temp_dir is not None:
                temp_dirs.append(temp_dir)
            for chunk_path in chunks:
                chunks_used += 1
                ok, reason = memory_ok(args.max_rss_gb, args.min_available_gb)
                if not ok:
                    stopped_reason = reason
                    break
                for emitted, flow_record in enumerate(iter_flow_records(chunk_path, args.subtype, extractor), start=1):
                    if len(first_flow_macs) < 5:
                        first_flow_macs.append(
                            {
                                "source_file": str(flow_record.get(config.SOURCE_FILE_COLUMN, chunk_path.name)),
                                "source_order": int(flow_record.get(config.SOURCE_ORDER_COLUMN, emitted - 1)),
                                "src_mac": str(flow_record.get("src_mac", "")),
                                "dst_mac": str(flow_record.get("dst_mac", "")),
                            }
                        )
                    keep_flow, filter_reason = mac_filter_decision(flow_record, args.class_name)
                    mac_filter_reasons[filter_reason] = mac_filter_reasons.get(filter_reason, 0) + 1
                    if not keep_flow:
                        dropped_by_mac_filter += 1
                        continue
                    kept_by_mac_filter += 1
                    if filter_reason == "missing_mac_kept":
                        missing_mac_kept += 1

                    if emitted % args.memory_check_interval == 0:
                        ok, reason = memory_ok(args.max_rss_gb, args.min_available_gb)
                        if not ok:
                            stopped_reason = reason
                            return {
                                "pcaps": [str(path) for path in pcap_paths],
                                "subtype": args.subtype,
                                "class_name": args.class_name,
                                "seen": seen,
                                "stored": len(reservoir),
                                "skipped_zero_packet": skipped_zero_packet,
                                "mac_filter": {
                                    "enabled": config.ENABLE_ATTACKER_MAC_FILTER,
                                    "attacker_mac_count": len(config.ATTACKER_MACS),
                                    "kept": kept_by_mac_filter,
                                    "dropped": dropped_by_mac_filter,
                                    "missing_mac_kept": missing_mac_kept,
                                    "reasons": mac_filter_reasons,
                                    "first_flow_macs": first_flow_macs,
                                },
                                "stopped_reason": stopped_reason,
                                "chunks_used": chunks_used,
                                "paths": [str(path) for path in reservoir],
                            }

                    compact = build_compact_graph_record(
                        flow_record["flow_features"],
                        flow_record["temporal_features"],
                        flow_record["packet_records"],
                        int(args.class_index),
                        args.subtype,
                        args.class_name,
                        str(flow_record[config.SOURCE_FILE_COLUMN]),
                        int(flow_record[config.SOURCE_ORDER_COLUMN]),
                    )
                    if compact is None:
                        skipped_zero_packet += 1
                        continue

                    seen += 1
                    new_path = save_compact_record(compact, out_dir, args.subtype, seen)
                    if len(reservoir) < args.target:
                        reservoir.append(new_path)
                    else:
                        replacement_index = int(rng.integers(0, seen))
                        if replacement_index < args.target:
                            old_path = reservoir[replacement_index]
                            if old_path.exists():
                                old_path.unlink()
                            reservoir[replacement_index] = new_path
                        elif new_path.exists():
                            new_path.unlink()

                    if len(reservoir) >= args.target and seen >= args.target:
                        stopped_reason = "target_reached"
                        raise StopIteration
                if stopped_reason != "target_reached":
                    break
            if stopped_reason != "target_reached":
                break
    except StopIteration:
        pass
    finally:
        for temp_dir in temp_dirs:
            temp_dir.cleanup()

    return {
        "pcaps": [str(path) for path in pcap_paths],
        "subtype": args.subtype,
        "class_name": args.class_name,
        "seen": seen,
        "stored": len(reservoir),
        "skipped_zero_packet": skipped_zero_packet,
        "mac_filter": {
            "enabled": config.ENABLE_ATTACKER_MAC_FILTER,
            "attacker_mac_count": len(config.ATTACKER_MACS),
            "kept": kept_by_mac_filter,
            "dropped": dropped_by_mac_filter,
            "missing_mac_kept": missing_mac_kept,
            "reasons": mac_filter_reasons,
            "first_flow_macs": first_flow_macs,
        },
        "stopped_reason": stopped_reason,
        "chunks_used": chunks_used,
        "paths": [str(path) for path in reservoir],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", action="append", required=True)
    parser.add_argument("--subtype", required=True)
    parser.add_argument("--class-name", required=True)
    parser.add_argument("--class-index", type=int, required=True)
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--summary-path", required=True)
    parser.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    parser.add_argument("--max-rss-gb", type=float, default=config.MAX_PROCESS_RSS_GB)
    parser.add_argument("--min-available-gb", type=float, default=config.MIN_AVAILABLE_MEMORY_GB)
    parser.add_argument("--memory-check-interval", type=int, default=500)
    parser.add_argument("--chunk-threshold-mb", type=int, default=config.PCAP_CHUNK_THRESHOLD_MB)
    parser.add_argument("--chunk-size-mb", type=int, default=config.PCAP_CHUNK_SIZE_MB)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = extract(args)
    summary_path = Path(args.summary_path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    if summary["stopped_reason"] != "target_reached":
        raise MemoryError(summary["stopped_reason"])


if __name__ == "__main__":
    main()
