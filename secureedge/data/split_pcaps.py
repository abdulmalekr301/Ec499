from __future__ import annotations

import argparse
import json
import shutil
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from secureedge import config
from secureedge.data.preprocess import subtype_from_pcap
from secureedge.utils import ensure_directories, write_context


def available_gb() -> float:
    return psutil.virtual_memory().available / (1024**3)


def oversized_pcaps(threshold_mb: int) -> list[Path]:
    threshold_bytes = threshold_mb * 1024 * 1024
    return sorted(
        path
        for path in config.PCAP_DIR.glob("*.pcap")
        if path.is_file() and path.stat().st_size > threshold_bytes
    )


def chunk_paths_for(output_dir: Path, stem: str) -> list[Path]:
    return sorted(output_dir.glob(f"{stem}.pcap*"), key=lambda item: (len(item.name), item.name))


def manifest_path_for(output_dir: Path) -> Path:
    return output_dir / "split_manifest.json"


def load_completed_manifest(output_dir: Path) -> dict[str, object] | None:
    manifest_path = manifest_path_for(output_dir)
    if not manifest_path.exists():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if manifest.get("status") != "completed":
        return None
    chunks = [Path(item) for item in manifest.get("chunks", [])]
    if chunks and all(path.exists() for path in chunks):
        return manifest
    return None


def split_command(path: Path, output_prefix: Path, chunk_size_mb: int) -> tuple[list[str], str]:
    editcap = shutil.which("editcap")
    if editcap is not None:
        return [editcap, "-b", str(chunk_size_mb * 1024 * 1024), str(path), str(output_prefix)], "editcap"
    tcpdump = shutil.which("tcpdump")
    if tcpdump is not None:
        return [tcpdump, "-r", str(path), "-w", str(output_prefix), "-C", str(chunk_size_mb)], "tcpdump"
    raise RuntimeError("PCAP splitting requires editcap or tcpdump, but neither was found on PATH.")


def split_one_pcap(path: Path, output_root: Path, threshold_mb: int, chunk_size_mb: int, min_available_gb: float, poll_seconds: float) -> dict[str, object]:

    output_dir = output_root / subtype_from_pcap(path)
    completed = load_completed_manifest(output_dir)
    if completed is not None:
        return completed | {"status": "skipped_completed"}

    if available_gb() < min_available_gb:
        raise MemoryError(
            f"Refusing to split {path.name}: available memory is {available_gb():.2f} GiB, "
            f"below the configured floor of {min_available_gb:.2f} GiB."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    for stale_chunk in chunk_paths_for(output_dir, path.stem):
        stale_chunk.unlink()

    log_path = output_dir / "tcpdump.log"
    output_prefix = output_dir / f"{path.stem}.pcap"
    command, splitter = split_command(path, output_prefix, chunk_size_mb)
    started_at = datetime.now(timezone.utc).isoformat()

    with log_path.open("w", encoding="utf-8") as log_handle:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=log_handle,
            text=True,
            start_new_session=True,
        )
        stop_reason = "completed"
        peak_used_gb = 0.0
        try:
            while process.poll() is None:
                vm = psutil.virtual_memory()
                current_available = vm.available / (1024**3)
                current_used = vm.used / (1024**3)
                peak_used_gb = max(peak_used_gb, current_used)
                if current_available < min_available_gb:
                    stop_reason = (
                        f"available memory {current_available:.2f} GiB below "
                        f"{min_available_gb:.2f} GiB"
                    )
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.send_signal(signal.SIGKILL)
                    break
                time.sleep(poll_seconds)
        finally:
            return_code = process.wait()

    chunks = chunk_paths_for(output_dir, path.stem)
    status = "completed" if return_code == 0 and stop_reason == "completed" and chunks else "stopped"
    manifest = {
        "source_pcap": str(path),
        "source_size_bytes": path.stat().st_size,
        "threshold_mb": threshold_mb,
        "chunk_size_mb": chunk_size_mb,
        "status": status,
        "stop_reason": stop_reason,
        "return_code": return_code,
        "splitter": splitter,
        "chunk_count": len(chunks),
        "chunk_total_bytes": sum(chunk.stat().st_size for chunk in chunks),
        "chunks": [str(chunk) for chunk in chunks],
        "log_path": str(log_path),
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "peak_used_memory_gb": round(peak_used_gb, 3),
    }
    manifest_path_for(output_dir).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if status != "completed":
        raise RuntimeError(f"Stopped splitting {path.name}: {stop_reason}")
    return manifest


def write_split_context(results: list[dict[str, object]], output_root: Path, chunk_size_mb: int, min_available_gb: float) -> None:
    rows = [
        "| Source PCAP | Status | Chunks | Size GiB | Stop reason |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for result in results:
        source = Path(str(result["source_pcap"])).name
        size_gib = int(result["source_size_bytes"]) / (1024**3)
        rows.append(
            f"| {source} | {result['status']} | {result['chunk_count']} | "
            f"{size_gib:.2f} | {result['stop_reason']} |"
        )

    write_context(
        "15_pcap_splitting.md",
        "Controlled PCAP Splitting",
        [
            "## Action",
            f"- Split oversized PCAP files into smaller chunks under `{output_root}`.",
            f"- Used chunk size `{chunk_size_mb}` MiB.",
            f"- Required at least `{min_available_gb}` GiB available memory while splitting.",
            "- Split one source PCAP at a time and wrote a per-PCAP `split_manifest.json`.",
            "",
            "## Results",
            *rows,
            "",
            "## Safety Note",
            "This phase only prepares smaller PCAP chunks. It does not run NFStream extraction or graph materialization.",
        ],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safely split large PCAP files into bounded chunks.")
    parser.add_argument("--output-root", type=Path, default=config.PCAP_CHUNK_DIR)
    parser.add_argument("--threshold-mb", type=int, default=config.PCAP_CHUNK_THRESHOLD_MB)
    parser.add_argument("--chunk-size-mb", type=int, default=config.PCAP_CHUNK_SIZE_MB)
    parser.add_argument("--min-available-gb", type=float, default=config.PCAP_SPLIT_MIN_AVAILABLE_MEMORY_GB)
    parser.add_argument("--poll-seconds", type=float, default=config.PCAP_SPLIT_POLL_SECONDS)
    parser.add_argument("--pause-seconds", type=float, default=config.PCAP_SPLIT_PAUSE_SECONDS)
    parser.add_argument("--limit-files", type=int, default=0)
    parser.add_argument("--only", action="append", default=[], help="PCAP stem or filename to split; may be repeated.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_directories()
    args.output_root.mkdir(parents=True, exist_ok=True)

    files = oversized_pcaps(args.threshold_mb)
    if args.only:
        requested = set(args.only)
        files = [path for path in files if path.name in requested or path.stem in requested]
    if args.limit_files > 0:
        files = files[: args.limit_files]
    if not files:
        print("No oversized PCAP files need splitting.")
        return

    results: list[dict[str, object]] = []
    for index, path in enumerate(files, start=1):
        print(f"[split_pcaps] {index}/{len(files)} start {path.name}", flush=True)
        result = split_one_pcap(
            path,
            args.output_root,
            args.threshold_mb,
            args.chunk_size_mb,
            args.min_available_gb,
            args.poll_seconds,
        )
        results.append(result)
        print(
            f"[split_pcaps] done {path.name}: status={result['status']} chunks={result['chunk_count']}",
            flush=True,
        )
        if index < len(files):
            time.sleep(args.pause_seconds)

    write_split_context(results, args.output_root, args.chunk_size_mb, args.min_available_gb)
    print(f"Wrote split chunks under {args.output_root}")


if __name__ == "__main__":
    main()
