from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureedge import config as root_config
from secureedge.office.config import DEFAULT_OFFICE_CONFIG_PATH, OfficeConfig, load_office_config
from secureedge.office.manifests import atomic_write_text, stable_json_hash


DEFAULT_REGISTRY_PATH = root_config.ARTIFACTS_DIR / "office_model" / "dataset_registry.json"
DEFAULT_GATE_REPORT_DIR = root_config.ARTIFACTS_DIR / "office_model" / "gate_reports"
DEFAULT_GATE1_PATH = DEFAULT_GATE_REPORT_DIR / "gate1_raw.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_base_metadata(path: Path) -> dict[str, Any]:
    exists = path.exists()
    item: dict[str, Any] = {
        "path": str(path),
        "exists": exists,
    }
    if exists:
        stat = path.stat()
        item.update(
            {
                "size_bytes": int(stat.st_size),
                "mtime_ns": int(stat.st_mtime_ns),
            }
        )
    return item


def csv_header_and_rows(path: Path, count_rows: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "header": [],
        "header_count": 0,
        "row_count": None,
        "csv_status": "missing" if not path.exists() else "unchecked",
    }
    if not path.exists():
        return result
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            result["header"] = header
            result["header_count"] = len(header)
            result["header_hash"] = hashlib.sha256(
                json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if count_rows:
                rows = 0
                for rows, _row in enumerate(reader, start=1):
                    pass
                result["row_count"] = rows
                result["csv_status"] = "ok"
            else:
                result["csv_status"] = "header_only"
    except Exception as exc:  # noqa: BLE001 - registry records all input failures.
        result["csv_status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def tcpdump_read_check(path: Path, tcpdump_path: str | None, timeout_seconds: int) -> dict[str, Any]:
    if tcpdump_path is None:
        return {"read_check_status": "tool_unavailable", "tool": "tcpdump"}
    if not path.exists():
        return {"read_check_status": "missing", "tool": "tcpdump"}
    command = [tcpdump_path, "-r", str(path), "-c", "1", "-nn"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "read_check_status": "timeout",
            "tool": "tcpdump",
            "timeout_seconds": timeout_seconds,
            "error": str(exc),
        }
    return {
        "read_check_status": "ok" if completed.returncode == 0 else "error",
        "tool": "tcpdump",
        "returncode": completed.returncode,
        "stdout_sample": completed.stdout[:500],
        "stderr_sample": completed.stderr[:500],
    }


def selected_csv_files(office_config: OfficeConfig) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    improved_dir = office_config.resolve_path("improved_csv")
    original_dir = office_config.resolve_path("original_csv")
    cicids2017_improved_dir = office_config.resolve_path("cicids2017_improved_csv")
    days = [str(spec["day"]) for spec in office_config.data["day_specs"]]
    for day in days:
        files.append(
            {
                "role": "cic_ids_2018_improved_csv",
                "day": day,
                "path": improved_dir / f"{day}.csv",
                "required": True,
            }
        )
        files.append(
            {
                "role": "cic_ids_2018_original_csv",
                "day": day,
                "path": original_dir / f"{day}_TrafficForML_CICFlowMeter.csv",
                "required": True,
            }
        )
    files.append(
        {
            "role": "cicids2017_improved_csv",
            "day": "Thursday-06-07-2017",
            "path": cicids2017_improved_dir / "thursday.csv",
            "required": True,
        }
    )
    return files


def selected_pcap_files(office_config: OfficeConfig) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    raw_root = office_config.resolve_path("raw_pcaps")
    for spec in office_config.data["day_specs"]:
        day = str(spec["day"])
        day_dir = raw_root / day / "pcap"
        paths = sorted(path for path in day_dir.iterdir() if path.is_file()) if day_dir.exists() else []
        if not paths:
            files.append(
                {
                    "role": "cic_ids_2018_day_pcap",
                    "day": day,
                    "path": day_dir,
                    "required": True,
                    "directory_missing_or_empty": True,
                }
            )
            continue
        for path in paths:
            files.append(
                {
                    "role": "cic_ids_2018_endpoint_pcap",
                    "day": day,
                    "path": path,
                    "required": True,
                }
            )
    files.append(
        {
            "role": "cicids2017_webbased_raw_pcap",
            "day": "Thursday-06-07-2017",
            "path": office_config.resolve_path("cicids2017_raw_pcap"),
            "required": True,
        }
    )
    return files


def inspect_csv_file(item: dict[str, Any], checksum: bool, count_rows: bool) -> dict[str, Any]:
    path = Path(item["path"])
    result = {
        "role": item["role"],
        "day": item.get("day"),
        "required": bool(item.get("required", True)),
        **file_base_metadata(path),
    }
    result.update(csv_header_and_rows(path, count_rows=count_rows))
    if checksum and path.exists():
        result["sha256"] = sha256_file(path)
        result["sha256_status"] = "ok"
    else:
        result["sha256"] = None
        result["sha256_status"] = "skipped" if path.exists() else "missing"
    return result


def inspect_pcap_file(
    item: dict[str, Any],
    checksum: bool,
    read_check: bool,
    tcpdump_path: str | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    path = Path(item["path"])
    result = {
        "role": item["role"],
        "day": item.get("day"),
        "required": bool(item.get("required", True)),
        **file_base_metadata(path),
    }
    if item.get("directory_missing_or_empty"):
        result["directory_missing_or_empty"] = True
    if checksum and path.exists() and path.is_file():
        result["sha256"] = sha256_file(path)
        result["sha256_status"] = "ok"
    else:
        result["sha256"] = None
        result["sha256_status"] = "skipped" if path.exists() else "missing"
    if read_check and path.exists() and path.is_file():
        result.update(tcpdump_read_check(path, tcpdump_path, timeout_seconds))
    else:
        result["read_check_status"] = "skipped" if path.exists() else "missing"
    return result


def build_gate1_report(registry: dict[str, Any]) -> dict[str, Any]:
    hard_failures: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for section in ("csv_files", "pcap_files"):
        for item in registry[section]:
            path = item["path"]
            if item.get("required", True) and not item.get("exists", False):
                hard_failures.append({"path": path, "section": section, "reason": "missing_required_file"})
            if section == "csv_files" and item.get("csv_status") == "error":
                hard_failures.append({"path": path, "section": section, "reason": item.get("error", "csv_error")})
            if item.get("sha256_status") == "skipped":
                warnings.append({"path": path, "section": section, "reason": "sha256_skipped"})
            if section == "pcap_files" and item.get("read_check_status") in {"skipped", "tool_unavailable"}:
                warnings.append({"path": path, "section": section, "reason": f"pcap_read_check_{item.get('read_check_status')}"})
            if section == "pcap_files" and item.get("read_check_status") in {"error", "timeout"}:
                hard_failures.append({"path": path, "section": section, "reason": f"pcap_read_check_{item.get('read_check_status')}"})
    status = "pass" if not hard_failures else "fail"
    return {
        "schema_version": 1,
        "gate": "G1_RAW_DATA",
        "generated_at": utc_now(),
        "status": status,
        "hard_failure_count": len(hard_failures),
        "warning_count": len(warnings),
        "hard_failures": hard_failures[:500],
        "warnings": warnings[:500],
        "registry_path": registry["registry_path"],
        "registry_hash": registry["registry_hash"],
        "summary": registry["summary"],
    }


def build_registry(
    config_path: Path,
    registry_path: Path,
    gate1_path: Path,
    checksum_csv: bool,
    checksum_pcaps: bool,
    count_csv_rows: bool,
    read_check_pcaps: bool,
    pcap_read_check_limit: int,
    tcpdump_timeout_seconds: int,
) -> dict[str, Any]:
    office_config = load_office_config(config_path)
    tcpdump_path = shutil.which("tcpdump")
    capinfos_path = shutil.which("capinfos")

    csv_items = selected_csv_files(office_config)
    pcap_items = selected_pcap_files(office_config)
    csv_files = [
        inspect_csv_file(item, checksum=checksum_csv, count_rows=count_csv_rows)
        for item in csv_items
    ]

    pcap_files: list[dict[str, Any]] = []
    for index, item in enumerate(pcap_items):
        do_read_check = read_check_pcaps and (pcap_read_check_limit <= 0 or index < pcap_read_check_limit)
        pcap_files.append(
            inspect_pcap_file(
                item,
                checksum=checksum_pcaps,
                read_check=do_read_check,
                tcpdump_path=tcpdump_path,
                timeout_seconds=tcpdump_timeout_seconds,
            )
        )

    csv_status = Counter(str(item.get("csv_status", "unknown")) for item in csv_files)
    pcap_read_status = Counter(str(item.get("read_check_status", "unknown")) for item in pcap_files)
    pcap_sha_status = Counter(str(item.get("sha256_status", "unknown")) for item in pcap_files)
    csv_sha_status = Counter(str(item.get("sha256_status", "unknown")) for item in csv_files)
    summary = {
        "csv_file_count": len(csv_files),
        "pcap_file_count": len(pcap_files),
        "csv_total_size_bytes": sum(int(item.get("size_bytes", 0) or 0) for item in csv_files),
        "pcap_total_size_bytes": sum(int(item.get("size_bytes", 0) or 0) for item in pcap_files),
        "csv_status": dict(sorted(csv_status.items())),
        "pcap_read_status": dict(sorted(pcap_read_status.items())),
        "csv_sha256_status": dict(sorted(csv_sha_status.items())),
        "pcap_sha256_status": dict(sorted(pcap_sha_status.items())),
    }
    registry = {
        "schema_version": 1,
        "pipeline": "office_dataset_registry",
        "generated_at": utc_now(),
        **office_config.provenance(),
        "registry_path": str(registry_path.resolve()),
        "tools": {
            "tcpdump": tcpdump_path,
            "capinfos": capinfos_path,
        },
        "options": {
            "checksum_csv": checksum_csv,
            "checksum_pcaps": checksum_pcaps,
            "count_csv_rows": count_csv_rows,
            "read_check_pcaps": read_check_pcaps,
            "pcap_read_check_limit": pcap_read_check_limit,
            "tcpdump_timeout_seconds": tcpdump_timeout_seconds,
        },
        "summary": summary,
        "csv_files": csv_files,
        "pcap_files": pcap_files,
    }
    registry["registry_hash"] = stable_json_hash(
        {key: value for key, value in registry.items() if key != "registry_hash"}
    )
    registry["registry_path"] = str(registry_path.resolve())
    atomic_write_text(registry_path, json.dumps(registry, indent=2, sort_keys=True) + "\n")

    gate1 = build_gate1_report(registry)
    gate1_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(gate1_path, json.dumps(gate1, indent=2, sort_keys=True) + "\n")
    return registry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the CIC-IDS-2018 office raw dataset registry.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--registry-path", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--gate1-path", type=Path, default=DEFAULT_GATE1_PATH)
    parser.add_argument("--checksum-csv", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--checksum-pcaps", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--count-csv-rows", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--read-check-pcaps", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument(
        "--pcap-read-check-limit",
        type=int,
        default=0,
        help="Limit PCAP readability checks. 0 means every selected PCAP when --read-check-pcaps is enabled.",
    )
    parser.add_argument("--tcpdump-timeout-seconds", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    registry = build_registry(
        config_path=args.config,
        registry_path=args.registry_path,
        gate1_path=args.gate1_path,
        checksum_csv=args.checksum_csv,
        checksum_pcaps=args.checksum_pcaps,
        count_csv_rows=args.count_csv_rows,
        read_check_pcaps=args.read_check_pcaps,
        pcap_read_check_limit=args.pcap_read_check_limit,
        tcpdump_timeout_seconds=args.tcpdump_timeout_seconds,
    )
    gate1 = json.loads(args.gate1_path.read_text(encoding="utf-8"))
    print(
        json.dumps(
            {
                "registry": str(args.registry_path),
                "gate1": str(args.gate1_path),
                "status": gate1["status"],
                "summary": registry["summary"],
                "warning_count": gate1["warning_count"],
                "hard_failure_count": gate1["hard_failure_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
