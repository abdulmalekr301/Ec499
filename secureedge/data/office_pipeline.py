from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import heapq
import ipaddress
import json
import os
import pickle
import random
import re
import resource
import shutil
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
import psutil

from secureedge import config
from secureedge.data.graph_builder import build_compact_graph_record
from secureedge.data.pcap_flows import iter_flow_records
from secureedge.office.config import load_office_config
from secureedge.office.flow_identity import CanonicalFlowKey
from secureedge.office.manifests import DEFAULT_CUMULATIVE_PATH, DEFAULT_DONE_REGISTRY_PATH, DoneRegistry
from secureedge.office.temporal_index import TemporalIndex, load_temporal_index, lookup_temporal_features
from secureedge.utils import ensure_directories, write_context


_OFFICE_CONFIG = load_office_config()

OFFICE_DATASET_ROOT = _OFFICE_CONFIG.dataset_root
OFFICE_IMPROVED_CSV_DIR = _OFFICE_CONFIG.resolve_path("improved_csv")
OFFICE_2017_IMPROVED_CSV_DIR = _OFFICE_CONFIG.resolve_path("cicids2017_improved_csv")
OFFICE_ORIGINAL_CSV_DIR = _OFFICE_CONFIG.resolve_path("original_csv")
OFFICE_RAW_PCAP_DIR = _OFFICE_CONFIG.raw_pcaps_dir
OFFICE_2017_RAW_PCAP_PATH = _OFFICE_CONFIG.resolve_path("cicids2017_raw_pcap")
OFFICE_ARTIFACT_DIR = _OFFICE_CONFIG.artifacts_dir
OFFICE_CONTEXT_PREFIX = "64_office_model_graph_generation_pipeline"
OFFICE_CANDIDATE_DIR = OFFICE_ARTIFACT_DIR / "candidate_flows"
OFFICE_FINAL_SPLIT_DIR = OFFICE_ARTIFACT_DIR / "final_candidate_splits"
OFFICE_PILOT_GRAPH_DIR = OFFICE_ARTIFACT_DIR / "pilot_graphs"
OFFICE_COMPACT_GRAPH_DIR = _OFFICE_CONFIG.compact_root
OFFICE_MATERIALIZATION_WORK_DIR = OFFICE_ARTIFACT_DIR / "materialization_work"
OFFICE_PCAP_SLICE_DIR = OFFICE_MATERIALIZATION_WORK_DIR / "pcap_slices"
OFFICE_COMPACT_MANIFEST_PATH = OFFICE_ARTIFACT_DIR / "office_compact_graph_manifest.json"
OFFICE_OPEN_FLOW_DIAGNOSTIC_PATH = OFFICE_ARTIFACT_DIR / "open_flow_diagnostic_manifest.json"
OFFICE_NFSTREAM_RSS_DIAGNOSTIC_PATH = OFFICE_ARTIFACT_DIR / "nfstream_rss_diagnostic_manifest.json"
OFFICE_INFILTRATION_PAYLOAD_AUDIT_PATH = OFFICE_ARTIFACT_DIR / "infiltration_payload_audit_manifest.json"
OFFICE_READABLE_SAMPLE_DIR = OFFICE_ARTIFACT_DIR / "readable_graph_samples"
OFFICE_READABLE_SAMPLE_MANIFEST_PATH = OFFICE_ARTIFACT_DIR / "readable_graph_samples_manifest.json"
OFFICE_FINAL_SPLIT_MANIFEST_PATH = OFFICE_ARTIFACT_DIR / "final_candidate_split_manifest.json"
OFFICE_WEB_ATTEMPT_AUDIT_PATH = OFFICE_ARTIFACT_DIR / "webbased_attempted_payload_audit.json"
OFFICE_2017_WEB_AUGMENT_PATH = OFFICE_ARTIFACT_DIR / "cicids2017_webbased_augmentation_manifest.json"

OFFICE_CLASS_NAMES = _OFFICE_CONFIG.class_names
OFFICE_ATTACK_CLASSES = [name for name in OFFICE_CLASS_NAMES if name != "Benign"]
OFFICE_CLASS_TO_INDEX = {name: index for index, name in enumerate(OFFICE_CLASS_NAMES)}
_OFFICE_SPLITS = _OFFICE_CONFIG.split_targets
OFFICE_STANDARD_TRAIN_TARGET = _OFFICE_SPLITS.standard_train
OFFICE_STANDARD_VAL_TARGET = _OFFICE_SPLITS.standard_val
OFFICE_STANDARD_TEST_TARGET = _OFFICE_SPLITS.standard_test
OFFICE_STANDARD_POOL_TARGET = OFFICE_STANDARD_TRAIN_TARGET + OFFICE_STANDARD_VAL_TARGET + OFFICE_STANDARD_TEST_TARGET
OFFICE_WEB_TRAIN_NATIVE_TARGET = _OFFICE_SPLITS.webbased_native_train
OFFICE_WEB_VAL_TARGET = _OFFICE_SPLITS.webbased_val
OFFICE_WEB_TEST_TARGET = _OFFICE_SPLITS.webbased_test
OFFICE_WEB_TRAIN_TARGET = _OFFICE_SPLITS.webbased_train_target
OFFICE_PRESLICE_CLASSES = _OFFICE_CONFIG.preslice_classes
OFFICE_PRESLICE_TIME_WINDOW_SECONDS = float(
    os.getenv("SECUREEDGE_OFFICE_PRESLICE_TIME_WINDOW_SECONDS", str(_OFFICE_CONFIG.preslice_time_window_seconds))
)
OFFICE_ALLOW_FULL_MATERIALIZATION = os.getenv("SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION", "0") == "1"
OFFICE_PROCESS = psutil.Process()

ATTEMPTED_MARKERS = ("attempted", "startup", "teardown", "closed-port", "closed port")


@dataclass(frozen=True)
class OfficeDaySpec:
    day: str
    target_classes: tuple[str, ...]
    expected_subtypes: tuple[str, ...]


@dataclass(frozen=True)
class OfficeAttackWindow:
    day: str
    subtype: str
    class_name: str
    attacker_ips: tuple[str, ...]
    victim_ips: tuple[str, ...]
    start: str
    finish: str


OFFICE_DAY_SPECS: tuple[OfficeDaySpec, ...] = (
    OfficeDaySpec("Wednesday-14-02-2018", ("BruteForce",), ("FTP-BruteForce", "SSH-Bruteforce")),
    OfficeDaySpec("Friday-16-02-2018", ("DoS",), ("DoS-Hulk", "DoS-SlowHTTPTest")),
    OfficeDaySpec("Wednesday-21-02-2018", ("DDoS",), ("DDOS-HOIC", "DDOS-LOIC-UDP")),
    OfficeDaySpec("Thursday-22-02-2018", ("WebBased",), ("Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL")),
    OfficeDaySpec("Friday-23-02-2018", ("WebBased",), ("Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL")),
    OfficeDaySpec("Friday-02-03-2018", ("Bot",), ("Bot",)),
    OfficeDaySpec("Thursday-01-03-2018", ("Infiltration",), ("Infiltration",)),
)


DDOS_ROTATING_ATTACKERS = (
    "18.218.115.60",
    "18.219.9.1",
    "18.219.32.43",
    "18.218.55.126",
    "52.14.136.135",
    "18.219.5.43",
    "18.216.200.189",
    "18.218.229.235",
    "18.218.11.51",
    "18.216.24.42",
)

BOT_VICTIMS = (
    "172.31.69.6",
    "172.31.69.8",
    "172.31.69.10",
    "172.31.69.12",
    "172.31.69.14",
    "172.31.69.17",
    "172.31.69.23",
    "172.31.69.26",
    "172.31.69.29",
    "172.31.69.30",
)

# CIC's public schedule times are four hours behind the timestamps in the
# improved CSVs. Example: DoS-Hulk 13:45 in the table appears as 17:45 in CSV.
OFFICE_ATTACK_WINDOWS: tuple[OfficeAttackWindow, ...] = (
    OfficeAttackWindow(
        "Wednesday-14-02-2018",
        "FTP-BruteForce",
        "BruteForce",
        ("172.31.70.4", "18.221.219.4"),
        ("172.31.69.25", "18.217.21.148"),
        "2018-02-14 14:32:00",
        "2018-02-14 16:09:00",
    ),
    OfficeAttackWindow(
        "Wednesday-14-02-2018",
        "SSH-Bruteforce",
        "BruteForce",
        ("172.31.70.6", "13.58.98.64"),
        ("172.31.69.25", "18.217.21.148"),
        "2018-02-14 18:01:00",
        "2018-02-14 19:31:00",
    ),
    OfficeAttackWindow(
        "Friday-16-02-2018",
        "DoS-SlowHTTPTest",
        "DoS",
        ("172.31.70.23", "13.59.126.31"),
        ("172.31.69.25", "18.217.21.148"),
        "2018-02-16 14:12:00",
        "2018-02-16 15:08:00",
    ),
    OfficeAttackWindow(
        "Friday-16-02-2018",
        "DoS-Hulk",
        "DoS",
        ("172.31.70.16", "18.219.193.20"),
        ("172.31.69.25", "18.217.21.148"),
        "2018-02-16 17:45:00",
        "2018-02-16 18:19:00",
    ),
    OfficeAttackWindow(
        "Wednesday-21-02-2018",
        "DDOS-LOIC-UDP",
        "DDoS",
        DDOS_ROTATING_ATTACKERS,
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-21 14:09:00",
        "2018-02-21 14:43:00",
    ),
    OfficeAttackWindow(
        "Wednesday-21-02-2018",
        "DDOS-HOIC",
        "DDoS",
        DDOS_ROTATING_ATTACKERS,
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-21 18:05:00",
        "2018-02-21 19:05:00",
    ),
    OfficeAttackWindow(
        "Friday-02-03-2018",
        "Bot",
        "Bot",
        ("18.219.211.138",),
        BOT_VICTIMS,
        "2018-03-02 14:11:00",
        "2018-03-02 19:55:00",
    ),
    OfficeAttackWindow(
        "Thursday-01-03-2018",
        "Infiltration",
        "Infiltration",
        ("13.58.225.34",),
        ("172.31.69.13", "18.216.254.154"),
        "2018-03-01 13:53:00",
        "2018-03-01 14:55:00",
    ),
    OfficeAttackWindow(
        "Thursday-01-03-2018",
        "Infiltration",
        "Infiltration",
        ("13.58.225.34",),
        ("172.31.69.13", "18.216.254.154"),
        "2018-03-01 18:00:00",
        "2018-03-01 19:38:00",
    ),
    OfficeAttackWindow(
        "Thursday-22-02-2018",
        "Brute Force-Web",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-22 14:17:00",
        "2018-02-22 15:24:00",
    ),
    OfficeAttackWindow(
        "Thursday-22-02-2018",
        "Brute Force-XSS",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-22 17:50:00",
        "2018-02-22 18:29:00",
    ),
    OfficeAttackWindow(
        "Thursday-22-02-2018",
        "SQL Injection",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-22 20:15:00",
        "2018-02-22 20:29:00",
    ),
    OfficeAttackWindow(
        "Friday-23-02-2018",
        "Brute Force-Web",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-23 14:03:00",
        "2018-02-23 15:03:00",
    ),
    OfficeAttackWindow(
        "Friday-23-02-2018",
        "Brute Force-XSS",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-23 17:00:00",
        "2018-02-23 18:10:00",
    ),
    OfficeAttackWindow(
        "Friday-23-02-2018",
        "SQL Injection",
        "WebBased",
        ("18.218.115.60",),
        ("172.31.69.28", "18.218.83.150"),
        "2018-02-23 19:05:00",
        "2018-02-23 19:18:00",
    ),
)

_ATTACK_WINDOWS_BY_DAY: dict[str, tuple[OfficeAttackWindow, ...]] = {}
for _window in OFFICE_ATTACK_WINDOWS:
    _ATTACK_WINDOWS_BY_DAY.setdefault(_window.day, ())
    _ATTACK_WINDOWS_BY_DAY[_window.day] = (*_ATTACK_WINDOWS_BY_DAY[_window.day], _window)


# CICIDS2017 Thursday-WorkingHours stores timestamps in the CSV as UTC-style
# times. The same packets are displayed by tcpdump in the local +02:00 timezone,
# so the matching code keeps the CSV timestamps as UTC epoch seconds.
CICIDS2017_WEB_ATTACK_WINDOWS: tuple[OfficeAttackWindow, ...] = (
    OfficeAttackWindow(
        "Thursday-06-07-2017",
        "Brute Force-Web",
        "WebBased",
        ("172.16.0.1", "205.174.165.73", "205.174.165.80"),
        ("192.168.10.50", "205.174.165.68"),
        "2017-07-06 12:15:00",
        "2017-07-06 13:01:00",
    ),
    OfficeAttackWindow(
        "Thursday-06-07-2017",
        "XSS",
        "WebBased",
        ("172.16.0.1", "205.174.165.73", "205.174.165.80"),
        ("192.168.10.50", "205.174.165.68"),
        "2017-07-06 13:15:00",
        "2017-07-06 13:36:00",
    ),
    OfficeAttackWindow(
        "Thursday-06-07-2017",
        "SQL Injection",
        "WebBased",
        ("172.16.0.1", "205.174.165.73", "205.174.165.80"),
        ("192.168.10.50", "205.174.165.68"),
        "2017-07-06 13:35:00",
        "2017-07-06 13:43:00",
    ),
)


def _office_day_specs_from_config() -> tuple[OfficeDaySpec, ...]:
    return tuple(
        OfficeDaySpec(
            day=str(item["day"]),
            target_classes=tuple(str(value) for value in item.get("target_classes", [])),
            expected_subtypes=tuple(str(value) for value in item.get("expected_subtypes", [])),
        )
        for item in _OFFICE_CONFIG.data["day_specs"]
    )


def _office_windows_from_config(section: str) -> tuple[OfficeAttackWindow, ...]:
    return tuple(
        OfficeAttackWindow(
            day=window.day,
            subtype=window.subtype,
            class_name=window.class_name,
            attacker_ips=window.attacker_ips,
            victim_ips=window.victim_ips,
            start=window.start,
            finish=window.finish,
        )
        for window in (
            _OFFICE_CONFIG.attack_windows
            if section == "attack_windows"
            else _OFFICE_CONFIG.cicids2017_web_attack_windows
        )
    )


OFFICE_DAY_SPECS = _office_day_specs_from_config()
OFFICE_ATTACK_WINDOWS = _office_windows_from_config("attack_windows")
CICIDS2017_WEB_ATTACK_WINDOWS = _office_windows_from_config("cicids2017_web_attack_windows")
_ATTACK_WINDOWS_BY_DAY = {}
for _window in OFFICE_ATTACK_WINDOWS:
    _ATTACK_WINDOWS_BY_DAY.setdefault(_window.day, ())
    _ATTACK_WINDOWS_BY_DAY[_window.day] = (*_ATTACK_WINDOWS_BY_DAY[_window.day], _window)


LABEL_TO_CLASS = {
    "benign": "Benign",
    "benigntraffic": "Benign",
    "ftpbruteforce": "BruteForce",
    "sshbruteforce": "BruteForce",
    "sshbruteforcing": "BruteForce",
    "dosattacks-hulk": "DoS",
    "doshulk": "DoS",
    "dosattackshulk": "DoS",
    "dosattacks-slowhttptest": "DoS",
    "dosslowhttptest": "DoS",
    "dosattacksslowhttptest": "DoS",
    "ddosattack-hoic": "DDoS",
    "ddoshoic": "DDoS",
    "ddosattackloicudp": "DDoS",
    "ddos-loic-udp": "DDoS",
    "ddosloicudp": "DDoS",
    "webattack-bruteforce": "WebBased",
    "webattackxss": "WebBased",
    "webattacksql": "WebBased",
    "webattack-bruteforce-attempted": "WebBased",
    "webattack-xss-attempted": "WebBased",
    "bot": "Bot",
    "botnetares": "Bot",
    "infiltration": "Infiltration",
}


def compact_label(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())


def normalize_label(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def office_label_to_class(label: object) -> str | None:
    text = normalize_label(label)
    compact = compact_label(text)
    if compact in LABEL_TO_CLASS:
        return LABEL_TO_CLASS[compact]
    if compact.startswith("webattack"):
        return "WebBased"
    if compact.startswith("dos") and "ddos" not in compact:
        return "DoS"
    if compact.startswith("ddos"):
        return "DDoS"
    if "bruteforce" in compact:
        return "BruteForce"
    if compact.startswith("infiltration"):
        return "Infiltration"
    return None


def is_attempted_or_non_success(label: object) -> bool:
    text = str(label or "").strip().lower()
    return any(marker in text for marker in ATTEMPTED_MARKERS)


def parse_csv_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def attack_windows_by_day() -> dict[str, tuple[OfficeAttackWindow, ...]]:
    return dict(_ATTACK_WINDOWS_BY_DAY)


def row_matches_attack_window(row: dict[str, str], window: OfficeAttackWindow) -> bool:
    timestamp = parse_csv_timestamp(row.get("Timestamp", ""))
    if timestamp is None:
        return False
    start = datetime.fromisoformat(window.start)
    finish = datetime.fromisoformat(window.finish)
    if not start <= timestamp <= finish:
        return False
    src = row.get("Src IP", "")
    dst = row.get("Dst IP", "")
    if window.subtype == "Infiltration":
        return src in window.victim_ips or dst in window.victim_ips
    return (src in window.attacker_ips and dst in window.victim_ips) or (
        dst in window.attacker_ips and src in window.victim_ips
    )


def ground_truth_window_for_row(row: dict[str, str], day: str) -> OfficeAttackWindow | None:
    for window in _ATTACK_WINDOWS_BY_DAY.get(day, ()):
        if row_matches_attack_window(row, window):
            return window
    return None


def stable_flow_key(row: dict[str, str]) -> str:
    parts = [
        row.get("Flow ID", ""),
        row.get("Src IP", ""),
        row.get("Src Port", ""),
        row.get("Dst IP", ""),
        row.get("Dst Port", ""),
        row.get("Protocol", ""),
        row.get("Timestamp", ""),
    ]
    return "|".join(parts)


def stable_flow_hash(row: dict[str, str]) -> str:
    return hashlib.sha256(stable_flow_key(row).encode("utf-8")).hexdigest()


def flow_tuple_parts(record: dict[str, object]) -> tuple[str, str, str, str, str]:
    return (
        str(record.get("src_ip", "")),
        str(record.get("dst_ip", "")),
        str(record.get("src_port", "")),
        str(record.get("dst_port", "")),
        str(record.get("protocol", "")),
    )


def reverse_flow_tuple(parts: tuple[str, str, str, str, str]) -> tuple[str, str, str, str, str]:
    src_ip, dst_ip, src_port, dst_port, protocol = parts
    return dst_ip, src_ip, dst_port, src_port, protocol


def candidate_flow_tuple(candidate: dict[str, object]) -> tuple[str, str, str, str, str]:
    return (
        str(candidate.get("src_ip", "")),
        str(candidate.get("dst_ip", "")),
        str(candidate.get("src_port", "")),
        str(candidate.get("dst_port", "")),
        str(candidate.get("protocol", "")),
    )


def candidate_timestamp_seconds(candidate: dict[str, object]) -> float | None:
    timestamp = parse_csv_timestamp(candidate.get("timestamp", ""))
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=timezone.utc).timestamp()


def _candidate_int(value: object) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def candidate_temporal_key(candidate: dict[str, object]) -> CanonicalFlowKey | None:
    timestamp_seconds = candidate_timestamp_seconds(candidate)
    if timestamp_seconds is None:
        return None
    return CanonicalFlowKey(
        day=str(candidate.get("day", "")),
        src_ip=str(candidate.get("src_ip", "")),
        src_port=_candidate_int(candidate.get("src_port", 0)),
        dst_ip=str(candidate.get("dst_ip", "")),
        dst_port=_candidate_int(candidate.get("dst_port", 0)),
        protocol=_candidate_int(candidate.get("protocol", 0)),
        first_seen_ms=int(round(timestamp_seconds * 1000.0)),
    )


def attach_candidate_temporal_features(
    candidates: list[dict[str, object]],
    temporal_index: TemporalIndex | None,
    *,
    tolerance_ms: int,
) -> list[dict[str, object]]:
    if temporal_index is None:
        return candidates
    enriched: list[dict[str, object]] = []
    for candidate in candidates:
        item = dict(candidate)
        key = candidate_temporal_key(item)
        if key is None:
            item["temporal_context_status"] = "missing_timestamp"
        else:
            try:
                item["temporal_features"] = lookup_temporal_features(temporal_index, key, tolerance_ms=tolerance_ms)
                item["temporal_context_status"] = "full"
            except (KeyError, ValueError) as exc:
                item["temporal_context_status"] = str(exc).split(" ", 1)[0].strip("'")
        enriched.append(item)
    return enriched


def csv_row_timestamp_seconds(row: dict[str, str]) -> float | None:
    timestamp = parse_csv_timestamp(row.get("Timestamp", ""))
    if timestamp is None:
        return None
    return timestamp.replace(tzinfo=timezone.utc).timestamp()


def csv_forward_payload_bytes(row: dict[str, str]) -> float:
    for name in ("Total Length of Fwd Packet", "Total Length of Fwd Packets", "Fwd Packet Length Total", "Subflow Fwd Bytes"):
        value = row.get(name, "")
        if value not in {"", None}:
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def payload_bytes_from_packet_record(packet: dict[str, object]) -> bytes:
    values = packet.get("payload", [])
    if not isinstance(values, list | tuple):
        return b""
    data = bytes(int(value) & 0xFF for value in values)
    return data.rstrip(b"\x00")


def payload_text_from_records(packet_records: list[dict[str, object]]) -> str:
    payloads = [payload_bytes_from_packet_record(packet) for packet in packet_records]
    combined = b"\n".join(payload for payload in payloads if payload)
    return combined.decode("latin-1", errors="replace")


def compact_payload_excerpt(text: str, limit: int = 220) -> str:
    collapsed = re.sub(r"\s+", " ", text.replace("\x00", " ")).strip()
    return collapsed[:limit]


def webbased_payload_signature(label: str, text: str) -> tuple[str, list[str]]:
    lowered = text.lower()
    hits: list[str] = []
    if "sql" in label.lower():
        patterns = {
            "sql_quote_or": r"('|%27)\s*(or|and)\s+",
            "union_select": r"union\s+(all\s+)?select|union\+select",
            "sql_comment": r"(--|%2d%2d|#|%23)",
            "sql_keyword": r"information_schema|sleep\s*\(|benchmark\s*\(|select\s+",
        }
    elif "xss" in label.lower():
        patterns = {
            "script_tag": r"<\s*script|%3cscript",
            "event_handler": r"onerror\s*=|onload\s*=|onclick\s*=",
            "javascript_uri": r"javascript\s*:|javascript%3a",
            "alert_call": r"alert\s*\(|alert%28",
        }
    else:
        patterns = {
            "http_post": r"\bpost\s+/.+http/",
            "login_endpoint": r"login|signin|wp-login|user\\.php",
            "credential_field": r"(username|user|email|login|password|pass|pwd)=",
            "form_encoded": r"content-type:\s*application/x-www-form-urlencoded",
        }
    for name, pattern in patterns.items():
        if re.search(pattern, lowered):
            hits.append(name)
    if hits:
        return "recover", hits
    if text.strip():
        return "manual_review", []
    return "keep_excluded", []


def csv_label_column(fieldnames: Iterable[str]) -> str:
    for name in fieldnames:
        normalized = name.strip().lower().replace(" ", "_")
        if normalized in {"label", "class", "attack", "attack_type"}:
            return name
    raise ValueError("No label/class/attack column found in CSV header.")


def office_day_specs_by_day() -> dict[str, OfficeDaySpec]:
    return {spec.day: spec for spec in OFFICE_DAY_SPECS}


def improved_csv_path(day: str) -> Path:
    return OFFICE_IMPROVED_CSV_DIR / f"{day}.csv"


def original_csv_path(day: str) -> Path:
    return OFFICE_ORIGINAL_CSV_DIR / f"{day}_TrafficForML_CICFlowMeter.csv"


def raw_pcap_day_dir(day: str) -> Path:
    return OFFICE_RAW_PCAP_DIR / day / "pcap"


def native_source_tag_for_day(day: str) -> str:
    weekday = day.split("-", 1)[0]
    return f"CIC-IDS2018-{weekday}"


def pcap_ip_from_name(path: Path) -> str | None:
    match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", path.name)
    return match.group(1) if match else None


def office_candidate_requires_preslice(candidate: dict[str, object]) -> bool:
    return str(candidate.get("class_name", "")) in OFFICE_PRESLICE_CLASSES


def office_preslice_windows_for_candidates(candidates: Iterable[dict[str, object]]) -> tuple[OfficeAttackWindow, ...]:
    wanted = {
        (str(candidate.get("day", "")), str(candidate.get("class_name", "")))
        for candidate in candidates
        if office_candidate_requires_preslice(candidate)
    }
    windows = [
        window
        for window in OFFICE_ATTACK_WINDOWS
        if (window.day, window.class_name) in wanted
    ]
    return tuple(windows)


def office_preslice_ip_pairs_for_pcap(
    pcap_path: str,
    candidates: Iterable[dict[str, object]],
) -> tuple[tuple[str, str], ...]:
    pcap_ip = pcap_ip_from_name(Path(pcap_path))
    pairs: set[tuple[str, str]] = set()
    for window in office_preslice_windows_for_candidates(candidates):
        if pcap_ip and pcap_ip in window.victim_ips:
            pairs.update((attacker, pcap_ip) for attacker in window.attacker_ips)
        elif pcap_ip and pcap_ip in window.attacker_ips:
            pairs.update((pcap_ip, victim) for victim in window.victim_ips)
        else:
            pairs.update((attacker, victim) for attacker in window.attacker_ips for victim in window.victim_ips)
    return tuple(sorted(pairs))


def office_preslice_bpf_for_pairs(ip_pairs: Iterable[tuple[str, str]]) -> str:
    clauses: list[str] = []
    for attacker, victim in ip_pairs:
        ipaddress.ip_address(attacker)
        ipaddress.ip_address(victim)
        clauses.append(f"(host {attacker} and host {victim})")
    return " or ".join(clauses)


def bpf_protocol_name(protocol: object) -> str:
    text = str(protocol or "").strip().lower()
    if text in {"6", "tcp"}:
        return "tcp"
    if text in {"17", "udp"}:
        return "udp"
    if text.isdigit():
        return f"ip proto {int(text)}"
    return "ip"


def bpf_port_clause(protocol: str, src_port: str, dst_port: str) -> str:
    if protocol not in {"tcp", "udp"}:
        return ""
    try:
        src = int(src_port)
        dst = int(dst_port)
    except ValueError:
        return ""
    if not (0 <= src <= 65535 and 0 <= dst <= 65535):
        return ""
    return f" and src port {src} and dst port {dst}"


def office_preslice_bpf_for_candidates(candidates: Iterable[dict[str, object]]) -> tuple[str, int]:
    clauses: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for candidate in candidates:
        forward = candidate_flow_tuple(candidate)
        for parts in (forward, reverse_flow_tuple(forward)):
            src_ip, dst_ip, src_port, dst_port, protocol_value = parts
            if parts in seen:
                continue
            seen.add(parts)
            try:
                ipaddress.ip_address(src_ip)
                ipaddress.ip_address(dst_ip)
            except ValueError:
                continue
            protocol = bpf_protocol_name(protocol_value)
            port_clause = bpf_port_clause(protocol, src_port, dst_port)
            clauses.append(f"({protocol} and src host {src_ip} and dst host {dst_ip}{port_clause})")
    return " or ".join(clauses), len(seen)


def merge_time_windows(windows: list[tuple[float, float]]) -> list[tuple[float, float]]:
    if not windows:
        return []
    merged: list[tuple[float, float]] = []
    for start, finish in sorted(windows):
        if not merged or start > merged[-1][1]:
            merged.append((start, finish))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], finish))
    return merged


def office_candidate_tuple_windows(
    candidates: Iterable[dict[str, object]],
    *,
    window_seconds: float,
) -> dict[tuple[str, str, str, str, str], list[tuple[float, float]]]:
    tuple_windows: dict[tuple[str, str, str, str, str], list[tuple[float, float]]] = defaultdict(list)
    for candidate in candidates:
        timestamp = candidate_timestamp_seconds(candidate)
        if timestamp is None:
            continue
        start = timestamp - window_seconds
        finish = timestamp + window_seconds
        forward = candidate_flow_tuple(candidate)
        tuple_windows[forward].append((start, finish))
        tuple_windows[reverse_flow_tuple(forward)].append((start, finish))
    return {parts: merge_time_windows(windows) for parts, windows in tuple_windows.items()}


def pcap_byte_order_and_resolution(global_header: bytes) -> tuple[str, float]:
    magic = global_header[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<", 1_000_000.0
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">", 1_000_000.0
    if magic == b"\x4d\x3c\xb2\xa1":
        return "<", 1_000_000_000.0
    if magic == b"\xa1\xb2\x3c\x4d":
        return ">", 1_000_000_000.0
    raise ValueError("Unsupported PCAP magic; expected classic pcap, not pcapng.")


def ipv4_text(raw: bytes) -> str:
    return ".".join(str(value) for value in raw)


def packet_flow_tuple(packet: bytes) -> tuple[str, str, str, str, str] | None:
    if len(packet) < 14:
        return None
    offset = 14
    eth_type = struct.unpack("!H", packet[12:14])[0]
    while eth_type in {0x8100, 0x88A8}:
        if len(packet) < offset + 4:
            return None
        eth_type = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        offset += 4
    if eth_type != 0x0800 or len(packet) < offset + 20:
        return None
    version_ihl = packet[offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(packet) < offset + ihl + 4:
        return None
    protocol = packet[offset + 9]
    if protocol not in {1, 6, 17}:
        return None
    flags_fragment = struct.unpack("!H", packet[offset + 6 : offset + 8])[0]
    if flags_fragment & 0x1FFF:
        return None
    if protocol == 1:
        return (
            ipv4_text(packet[offset + 12 : offset + 16]),
            ipv4_text(packet[offset + 16 : offset + 20]),
            "0",
            "0",
            str(protocol),
        )
    transport_offset = offset + ihl
    src_port, dst_port = struct.unpack("!HH", packet[transport_offset : transport_offset + 4])
    return (
        ipv4_text(packet[offset + 12 : offset + 16]),
        ipv4_text(packet[offset + 16 : offset + 20]),
        str(src_port),
        str(dst_port),
        str(protocol),
    )


def timestamp_in_windows(timestamp: float, windows: list[tuple[float, float]]) -> bool:
    return any(start <= timestamp <= finish for start, finish in windows)


def build_office_candidate_window_pcap(
    *,
    pcap_path: str,
    output_path: Path,
    candidates: list[dict[str, object]],
    window_seconds: float,
) -> dict[str, object]:
    tuple_windows = office_candidate_tuple_windows(candidates, window_seconds=window_seconds)
    packets_scanned = 0
    packets_written = 0
    truncated = False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as target:
        target.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        try:
            for timestamp, packet in iter_capture_packets(Path(pcap_path)):
                packets_scanned += 1
                parts = packet_flow_tuple(packet)
                if parts is None:
                    continue
                windows = tuple_windows.get(parts)
                if not windows:
                    continue
                if not timestamp_in_windows(timestamp, windows):
                    continue
                ts_sec = int(timestamp)
                ts_usec = int(round((timestamp - ts_sec) * 1_000_000))
                if ts_usec >= 1_000_000:
                    ts_sec += 1
                    ts_usec -= 1_000_000
                target.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
                target.write(packet)
                packets_written += 1
        except ValueError:
            truncated = True
            raise
    return {
        "packets_scanned": packets_scanned,
        "packets_written": packets_written,
        "truncated_input": truncated,
        "candidate_tuple_count": len(tuple_windows),
        "window_seconds": window_seconds,
        "output_bytes": output_path.stat().st_size if output_path.exists() else 0,
    }


def build_ip_to_pcap_lookup(day: str) -> dict[str, list[str]]:
    day_dir = raw_pcap_day_dir(day)
    lookup: dict[str, list[str]] = defaultdict(list)
    if not day_dir.exists():
        return {}
    for path in sorted(item for item in day_dir.iterdir() if item.is_file()):
        ip = pcap_ip_from_name(path)
        if ip:
            lookup[ip].append(str(path))
    return dict(lookup)


def is_private_endpoint(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def candidate_endpoint_files(row: dict[str, str], lookup: dict[str, list[str]]) -> tuple[list[str], str]:
    src = row.get("Src IP", "")
    dst = row.get("Dst IP", "")
    src_files = lookup.get(src, [])
    dst_files = lookup.get(dst, [])
    src_private = is_private_endpoint(src)
    dst_private = is_private_endpoint(dst)
    if src_files and not dst_files:
        return src_files, "src_only" if len(src_files) == 1 else "src_multi_part"
    if dst_files and not src_files:
        return dst_files, "dst_only" if len(dst_files) == 1 else "dst_multi_part"
    if src_files and dst_files:
        if dst_private and not src_private:
            return dst_files, "dst_private_preferred" if len(dst_files) == 1 else "dst_private_multi_part"
        if src_private and not dst_private:
            return src_files, "src_private_preferred" if len(src_files) == 1 else "src_private_multi_part"
        if dst_files:
            return dst_files, "dst_preferred" if len(dst_files) == 1 else "dst_multi_part_preferred"
        if src_files:
            return src_files, "src_fallback" if len(src_files) == 1 else "src_multi_part_fallback"
    if src_files or dst_files:
        return [], "ambiguous_multiple_endpoint_files"
    return [], "no_endpoint_file"


def candidate_endpoint_file(row: dict[str, str], lookup: dict[str, list[str]]) -> tuple[str | None, str]:
    files, status = candidate_endpoint_files(row, lookup)
    return (files[0] if files else None), status


def load_ip_time_windows(path: Path | None) -> dict[str, object]:
    if path is None:
        return {}
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def label_row_status(row: dict[str, str], day: str, label_col: str) -> tuple[str | None, str, str]:
    label = normalize_label(row.get(label_col, ""))
    class_name = office_label_to_class(label)
    if class_name is None:
        return None, label, "unknown_label"
    if is_attempted_or_non_success(label):
        return class_name, label, "excluded_attempted_or_non_success"

    # Documented brute-force contamination from corrected-label research.
    if day == "Wednesday-14-02-2018" and class_name == "BruteForce":
        src = row.get("Src IP", "")
        dst = row.get("Dst IP", "")
        dst_port = str(row.get("Dst Port", ""))
        total_fwd = str(row.get("Total Length of Fwd Packet", row.get("Total Length of Fwd Packets", "")))
        timestamp = row.get("Timestamp", "")
        if src == "18.221.219.4" and dst == "172.31.69.25":
            return class_name, label, "excluded_documented_ftp_closed_port"
        if src == "13.58.98.64" and dst == "172.31.69.25" and total_fwd in {"0", "0.0"}:
            return class_name, label, "excluded_documented_ssh_no_attacker_payload"
        if src == "13.58.98.64" and dst == "172.31.69.25" and dst_port == "21":
            return class_name, label, "excluded_documented_ssh_wrong_service_port"
        _ = timestamp

    return class_name, label, "accepted_label"


def scan_improved_csv(
    day: str,
    *,
    max_rows: int | None = None,
    keep_per_class: int = 0,
) -> dict[str, object]:
    path = improved_csv_path(day)
    if not path.exists():
        raise FileNotFoundError(path)
    label_counts: Counter[str] = Counter()
    class_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    accepted_by_class: Counter[str] = Counter()
    attempted_by_class: Counter[str] = Counter()
    samples: dict[str, list[dict[str, str]]] = defaultdict(list)
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        label_col = csv_label_column(fieldnames)
        rows = 0
        for row in reader:
            rows += 1
            if max_rows is not None and rows > max_rows:
                break
            class_name, label, status = label_row_status(row, day, label_col)
            label_counts[label] += 1
            status_counts[status] += 1
            if class_name:
                class_counts[class_name] += 1
                if status == "accepted_label":
                    accepted_by_class[class_name] += 1
                    if keep_per_class > 0 and len(samples[class_name]) < keep_per_class:
                        samples[class_name].append(
                            {
                                "flow_hash": stable_flow_hash(row),
                                "flow_id": row.get("Flow ID", ""),
                                "src_ip": row.get("Src IP", ""),
                                "src_port": row.get("Src Port", ""),
                                "dst_ip": row.get("Dst IP", ""),
                                "dst_port": row.get("Dst Port", ""),
                                "protocol": row.get("Protocol", ""),
                                "timestamp": row.get("Timestamp", ""),
                                "label": label,
                            }
                        )
                elif status.startswith("excluded"):
                    attempted_by_class[class_name] += 1
    return {
        "day": day,
        "csv_path": str(path),
        "rows_scanned": rows if max_rows is None else min(rows, max_rows),
        "scan_limited": max_rows is not None,
        "label_column": label_col,
        "label_counts": dict(label_counts),
        "class_counts": dict(class_counts),
        "accepted_by_class": dict(accepted_by_class),
        "excluded_by_class": dict(attempted_by_class),
        "status_counts": dict(status_counts),
        "samples": dict(samples),
    }


def update_reservoir(items: list[dict[str, object]], candidate: dict[str, object], seen: int, target: int, rng: random.Random) -> None:
    if target <= 0:
        return
    if len(items) < target:
        items.append(candidate)
        return
    replacement_index = rng.randrange(seen)
    if replacement_index < target:
        items[replacement_index] = candidate


def candidate_targets() -> dict[str, int]:
    return {class_name: 20000 for class_name in OFFICE_CLASS_NAMES}


def stratified_day_targets(total: int, days: tuple[OfficeDaySpec, ...] = OFFICE_DAY_SPECS) -> dict[str, int]:
    base = total // len(days)
    remainder = total - (base * len(days))
    return {
        spec.day: base + (1 if index < remainder else 0)
        for index, spec in enumerate(days)
    }


def row_identity(row: dict[str, str], label: str, csv_class: str | None, gt_window: OfficeAttackWindow | None) -> dict[str, str]:
    return {
        "flow_hash": stable_flow_hash(row),
        "flow_id": row.get("Flow ID", ""),
        "src_ip": row.get("Src IP", ""),
        "src_port": row.get("Src Port", ""),
        "dst_ip": row.get("Dst IP", ""),
        "dst_port": row.get("Dst Port", ""),
        "protocol": row.get("Protocol", ""),
        "timestamp": row.get("Timestamp", ""),
        "csv_label": label,
        "csv_class": csv_class or "",
        "gt_class": gt_window.class_name if gt_window else "",
        "gt_subtype": gt_window.subtype if gt_window else "",
        "gt_window_start": gt_window.start if gt_window else "",
        "gt_window_finish": gt_window.finish if gt_window else "",
    }


def crosscheck_status(csv_class: str | None, label_status: str, gt_window: OfficeAttackWindow | None) -> str:
    if csv_class is None:
        return "unknown_csv_label"
    if label_status != "accepted_label":
        if gt_window is not None:
            return "excluded_csv_label_with_gt_match"
        return "excluded_csv_label_without_gt_match"
    if gt_window is None:
        return "agreement_benign" if csv_class == "Benign" else "csv_attack_no_gt_match"
    if csv_class == "Benign":
        return "csv_benign_gt_attack_match"
    if csv_class == gt_window.class_name:
        return "agreement_attack"
    return "csv_gt_class_mismatch"


def build_ip_time_crosscheck_manifest(
    *,
    max_rows_per_day: int | None = None,
    keep_samples_per_status: int = 10,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    day_results: dict[str, object] = {}
    total_status_counts: Counter[str] = Counter()
    total_csv_class_counts: Counter[str] = Counter()
    total_gt_class_counts: Counter[str] = Counter()

    for spec in OFFICE_DAY_SPECS:
        path = improved_csv_path(spec.day)
        status_counts: Counter[str] = Counter()
        csv_class_counts: Counter[str] = Counter()
        gt_class_counts: Counter[str] = Counter()
        gt_subtype_counts: Counter[str] = Counter()
        samples: dict[str, list[dict[str, str]]] = defaultdict(list)
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            label_col = csv_label_column(reader.fieldnames or [])
            rows = 0
            for row in reader:
                rows += 1
                if max_rows_per_day is not None and rows > max_rows_per_day:
                    break
                csv_class, label, label_status = label_row_status(row, spec.day, label_col)
                gt_window = ground_truth_window_for_row(row, spec.day)
                status = crosscheck_status(csv_class, label_status, gt_window)
                status_counts[status] += 1
                total_status_counts[status] += 1
                if csv_class:
                    csv_class_counts[csv_class] += 1
                    total_csv_class_counts[csv_class] += 1
                if gt_window:
                    gt_class_counts[gt_window.class_name] += 1
                    gt_subtype_counts[gt_window.subtype] += 1
                    total_gt_class_counts[gt_window.class_name] += 1
                if status != "agreement_benign" and len(samples[status]) < keep_samples_per_status:
                    samples[status].append(row_identity(row, label, csv_class, gt_window))
        day_results[spec.day] = {
            "csv_path": str(path),
            "rows_scanned": rows if max_rows_per_day is None else min(rows, max_rows_per_day),
            "scan_limited": max_rows_per_day is not None,
            "status_counts": dict(status_counts),
            "csv_class_counts": dict(csv_class_counts),
            "gt_class_counts": dict(gt_class_counts),
            "gt_subtype_counts": dict(gt_subtype_counts),
            "samples": dict(samples),
        }

    manifest = {
        "pipeline": "office_model_ip_time_crosscheck",
        "max_rows_per_day": max_rows_per_day,
        "keep_samples_per_status": keep_samples_per_status,
        "timestamp_interpretation": "Official schedule times are shifted +4 hours to match improved CSV timestamps.",
        "attack_windows": [asdict(window) for window in OFFICE_ATTACK_WINDOWS],
        "days": day_results,
        "total_status_counts": dict(total_status_counts),
        "total_csv_class_counts": dict(total_csv_class_counts),
        "total_gt_class_counts": dict(total_gt_class_counts),
        "retention_rule": {
            "attack": "retain only if CSV class is an attack class and the IP/time-window class matches it",
            "benign": "retain only if CSV class is Benign and no IP/time-window attack matches",
            "disagreement": "flag and exclude from candidate graph materialization",
        },
    }
    path = OFFICE_ARTIFACT_DIR / "ip_time_crosscheck_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_ip_time_crosscheck_context(manifest: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Encoded the CIC-IDS2018 attacker/victim IP and time-window table from `office-model-pretraining-checklist.md`.",
        "- Cross-checked improved CSV labels against IP/time-window ground truth using streaming reads.",
        "- Used a `+4 hour` timestamp shift because the improved CSV timestamps are four hours ahead of the official schedule table.",
        "- Added a strict retention rule for future candidate graph materialization: attacks require CSV/IP-time agreement; benign rows require no IP-time attack match.",
        "",
        "## Outputs",
        f"- Manifest: `{OFFICE_ARTIFACT_DIR / 'ip_time_crosscheck_manifest.json'}`",
        "",
        "## Run Details",
        f"- Max rows per day: `{manifest['max_rows_per_day']}`",
        f"- Samples per non-benign status: `{manifest['keep_samples_per_status']}`",
        "",
        "## Total Status Counts",
        "```json",
        json.dumps(manifest["total_status_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Total CSV Class Counts",
        "```json",
        json.dumps(manifest["total_csv_class_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Total IP/Time Ground-Truth Class Counts",
        "```json",
        json.dumps(manifest["total_gt_class_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Per-Day Summary",
        "",
        "| Day | Rows scanned | Limited | Status counts | Ground-truth subtypes |",
        "|---|---:|---|---|---|",
    ]
    for day, info in manifest["days"].items():
        lines.append(
            f"| {day} | {info['rows_scanned']} | `{info['scan_limited']}` | `{json.dumps(info['status_counts'], sort_keys=True)}` | `{json.dumps(info['gt_subtype_counts'], sort_keys=True)}` |"
        )
    lines.extend(
        [
            "",
            "## Retention Rule",
            "",
            f"- Attack rows: {manifest['retention_rule']['attack']}.",
            f"- Benign rows: {manifest['retention_rule']['benign']}.",
            f"- Disagreements: {manifest['retention_rule']['disagreement']}.",
            "",
            "## Notes",
            "",
            "- This is still a label/candidate audit; it does not materialize graph tensors.",
            "- The CICIDS2017 WebBased augmentation remains separate and must be train-only when integrated.",
        ]
    )
    write_context("67_office_ip_time_crosscheck.md", "Office Model IP-Time Cross-Check", lines)


def load_pilot_candidates(
    *,
    classes: tuple[str, ...],
    target_per_class: int,
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for class_name in classes:
        path = OFFICE_CANDIDATE_DIR / f"{class_name}.jsonl"
        if not path.exists():
            raise FileNotFoundError(f"Candidate file not found: {path}")
        kept = 0
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                candidate = json.loads(line)
                candidates.append(candidate)
                kept += 1
                if kept >= target_per_class:
                    break
    return candidates


def recovered_webbased_attempted_hashes() -> set[str]:
    if not OFFICE_WEB_ATTEMPT_AUDIT_PATH.exists():
        return set()
    try:
        manifest = json.loads(OFFICE_WEB_ATTEMPT_AUDIT_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return {str(value) for value in manifest.get("recovered_flow_hashes", [])}


def graph_record_stats(record: dict[str, object]) -> dict[str, object]:
    flow_x = np.asarray(record["flow_x"], dtype=np.float32)
    packet_x = np.asarray(record["packet_x_uint8"], dtype=np.uint8)
    contain_edge_attr = np.asarray(record["contain_edge_attr"], dtype=np.float32)
    link_edge_attr = np.asarray(record["link_edge_attr"], dtype=np.float32)
    return {
        "flow_features": int(flow_x.shape[0]),
        "packet_nodes": int(packet_x.shape[0]),
        "packet_feature_width": int(packet_x.shape[1]) if packet_x.ndim == 2 else 0,
        "contain_edges": int(contain_edge_attr.shape[0]),
        "link_edges": int(link_edge_attr.shape[0]),
        "flow_finite": bool(np.isfinite(flow_x).all()),
        "contain_finite": bool(np.isfinite(contain_edge_attr).all()),
        "link_finite": bool(np.isfinite(link_edge_attr).all()),
        "payload_nonzero_fraction": float(np.count_nonzero(packet_x) / packet_x.size) if packet_x.size else 0.0,
        "payload_mean": float(packet_x.mean() / 255.0) if packet_x.size else 0.0,
        "flow_min": float(np.nanmin(flow_x)) if flow_x.size else 0.0,
        "flow_max": float(np.nanmax(flow_x)) if flow_x.size else 0.0,
    }


def save_pilot_graph(record: dict[str, object], candidate: dict[str, object], index: int) -> Path:
    class_name = str(candidate["class_name"])
    subtype = str(candidate.get("gt_subtype") or candidate.get("label") or class_name).replace("/", "_").replace(" ", "_")
    out_dir = OFFICE_PILOT_GRAPH_DIR / class_name
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{index:04d}_{subtype}.pkl"
    with path.open("wb") as handle:
        pickle.dump(record, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return path


def build_pilot_extraction_manifest(
    *,
    classes: tuple[str, ...],
    target_per_class: int = 3,
    max_flows_per_pcap: int = 200000,
    timestamp_tolerance_seconds: float = 3.0,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_PILOT_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    candidates = load_pilot_candidates(classes=classes, target_per_class=target_per_class)
    by_pcap: dict[str, list[dict[str, object]]] = defaultdict(list)
    for candidate in candidates:
        for pcap in candidate.get("endpoint_pcaps") or [candidate.get("endpoint_pcap")]:
            if pcap:
                by_pcap[str(pcap)].append(candidate)

    found_by_hash: dict[str, dict[str, object]] = {}
    missing_by_hash = {str(candidate["flow_hash"]): candidate for candidate in candidates}
    pcap_summaries: dict[str, object] = {}
    graph_paths: list[str] = []
    graph_stats: list[dict[str, object]] = []
    class_counts: Counter[str] = Counter()
    stop_reason = "completed"

    for pcap_path, pcap_candidates in by_pcap.items():
        pcap = Path(pcap_path)
        if not pcap.exists():
            pcap_summaries[pcap_path] = {
                "status": "missing_pcap",
                "candidate_count": len(pcap_candidates),
                "matched": 0,
                "flows_scanned": 0,
            }
            continue
        pending = {str(candidate["flow_hash"]): candidate for candidate in pcap_candidates if str(candidate["flow_hash"]) in missing_by_hash}
        if not pending:
            continue
        tuple_to_candidates: dict[tuple[str, str, str, str, str], list[dict[str, object]]] = defaultdict(list)
        for candidate in pending.values():
            forward = candidate_flow_tuple(candidate)
            tuple_to_candidates[forward].append(candidate)
            tuple_to_candidates[reverse_flow_tuple(forward)].append(candidate)

        flows_scanned = 0
        matched = 0
        try:
            for flows_scanned, flow_record in enumerate(iter_flow_records(pcap, "office_pilot"), start=1):
                if flows_scanned > max_flows_per_pcap:
                    stop_reason = "max_flows_per_pcap_reached"
                    break
                flow_tuple = flow_tuple_parts(flow_record)
                possible = tuple_to_candidates.get(flow_tuple, [])
                if not possible:
                    continue
                flow_timestamp = float(flow_record.get("timestamp", 0.0) or 0.0)
                for candidate in list(possible):
                    flow_hash = str(candidate["flow_hash"])
                    if flow_hash not in pending:
                        continue
                    candidate_ts = candidate_timestamp_seconds(candidate)
                    if candidate_ts is not None and abs(flow_timestamp - candidate_ts) > timestamp_tolerance_seconds:
                        continue
                    compact = build_compact_graph_record(
                        flow_record["flow_features"],
                        flow_record["temporal_features"],
                        flow_record["packet_records"],
                        int(candidate["class_index"]),
                        str(candidate.get("gt_subtype") or candidate.get("label") or candidate["class_name"]),
                        str(candidate["class_name"]),
                        str(flow_record[config.SOURCE_FILE_COLUMN]),
                        int(flow_record[config.SOURCE_ORDER_COLUMN]),
                    )
                    if compact is None:
                        found_by_hash[flow_hash] = {
                            "candidate": candidate,
                            "status": "matched_zero_packet_graph",
                            "pcap": pcap_path,
                            "candidate_timestamp_seconds": candidate_ts,
                            "flow_timestamp_seconds": flow_timestamp,
                            "timestamp_delta_seconds": abs(flow_timestamp - candidate_ts) if candidate_ts is not None else None,
                        }
                    else:
                        output_path = save_pilot_graph(compact, candidate, len(graph_paths) + 1)
                        stats = graph_record_stats(compact)
                        stats.update(
                            {
                                "path": str(output_path),
                                "class_name": str(candidate["class_name"]),
                                "gt_subtype": str(candidate.get("gt_subtype", "")),
                                "flow_hash": flow_hash,
                                "pcap": pcap_path,
                                "candidate_timestamp": str(candidate.get("timestamp", "")),
                                "candidate_timestamp_seconds": candidate_ts,
                                "flow_timestamp_seconds": flow_timestamp,
                                "timestamp_delta_seconds": abs(flow_timestamp - candidate_ts) if candidate_ts is not None else None,
                            }
                        )
                        graph_paths.append(str(output_path))
                        graph_stats.append(stats)
                        class_counts[str(candidate["class_name"])] += 1
                        found_by_hash[flow_hash] = {
                            "candidate": candidate,
                            "status": "materialized",
                            "path": str(output_path),
                            "pcap": pcap_path,
                            "stats": stats,
                        }
                    matched += 1
                    pending.pop(flow_hash, None)
                    missing_by_hash.pop(flow_hash, None)
                if not pending:
                    break
        except ModuleNotFoundError as exc:
            stop_reason = "missing_nfstream"
            pcap_summaries[pcap_path] = {
                "status": stop_reason,
                "error": str(exc),
                "candidate_count": len(pcap_candidates),
                "matched": matched,
                "flows_scanned": flows_scanned,
            }
            break
        except Exception as exc:  # noqa: BLE001 - pilot audit must capture extractor failures.
            stop_reason = "extractor_error"
            pcap_summaries[pcap_path] = {
                "status": stop_reason,
                "error": repr(exc),
                "candidate_count": len(pcap_candidates),
                "matched": matched,
                "flows_scanned": flows_scanned,
            }
            break
        pcap_summaries[pcap_path] = {
            "status": "completed",
            "candidate_count": len(pcap_candidates),
            "matched": matched,
            "flows_scanned": flows_scanned,
            "remaining_candidates_for_pcap": len(pending),
        }
        if stop_reason != "completed":
            break

    manifest = {
        "pipeline": "office_model_bounded_pilot_extraction",
        "classes": list(classes),
        "target_per_class": target_per_class,
        "requested_candidates": len(candidates),
        "materialized_graphs": len(graph_paths),
        "class_counts": dict(class_counts),
        "graph_paths": graph_paths,
        "graph_stats": graph_stats,
        "pcap_summaries": pcap_summaries,
        "missing_candidates": list(missing_by_hash),
        "stop_reason": stop_reason,
        "max_flows_per_pcap": max_flows_per_pcap,
        "timestamp_tolerance_seconds": timestamp_tolerance_seconds,
    }
    path = OFFICE_ARTIFACT_DIR / "pilot_extraction_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_pilot_extraction_context(manifest: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Ran a bounded pilot graph extraction from the strict office candidate manifest.",
        "- Streamed selected endpoint PCAPs only; did not glob all per-host captures.",
        "- Matched candidate flows by 5-tuple with timestamp tolerance.",
        "- Wrote compact graph records for matched flows.",
        "",
        "## Run Details",
        f"- Classes: `{manifest['classes']}`",
        f"- Target per class: `{manifest['target_per_class']}`",
        f"- Requested candidates: `{manifest['requested_candidates']}`",
        f"- Materialized graphs: `{manifest['materialized_graphs']}`",
        f"- Stop reason: `{manifest['stop_reason']}`",
        f"- Max flows per PCAP: `{manifest['max_flows_per_pcap']}`",
        f"- Timestamp tolerance seconds: `{manifest['timestamp_tolerance_seconds']}`",
        "",
        "## Output",
        f"- Manifest: `{OFFICE_ARTIFACT_DIR / 'pilot_extraction_manifest.json'}`",
        f"- Graph directory: `{OFFICE_PILOT_GRAPH_DIR}`",
        "",
        "## Class Counts",
        "```json",
        json.dumps(manifest["class_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## PCAP Summaries",
        "```json",
        json.dumps(manifest["pcap_summaries"], indent=2, sort_keys=True),
        "```",
        "",
        "## Graph Stats",
        "```json",
        json.dumps(manifest["graph_stats"], indent=2, sort_keys=True),
        "```",
    ]
    if manifest["missing_candidates"]:
        lines.extend(
            [
                "",
                "## Missing Candidate Hashes",
                "",
                "```json",
                json.dumps(manifest["missing_candidates"], indent=2, sort_keys=True),
                "```",
            ]
        )
    write_context("69_office_bounded_pilot_extraction.md", "Office Bounded Pilot Extraction", lines)


def native_webbased_days() -> tuple[str, ...]:
    return tuple(spec.day for spec in OFFICE_DAY_SPECS if "WebBased" in spec.target_classes)


def collect_webbased_attempted_rows(days: tuple[str, ...] | None = None) -> list[dict[str, object]]:
    selected_days = days or native_webbased_days()
    rows: list[dict[str, object]] = []
    for day in selected_days:
        path = improved_csv_path(day)
        lookup = build_ip_to_pcap_lookup(day)
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            label_col = csv_label_column(reader.fieldnames or [])
            for row in reader:
                label = normalize_label(row.get(label_col, ""))
                if "Web Attack" not in label or not is_attempted_or_non_success(label):
                    continue
                endpoint_paths, endpoint_status = candidate_endpoint_files(row, lookup)
                rows.append(
                    {
                        "flow_hash": stable_flow_hash(row),
                        "day": day,
                        "source": native_source_tag_for_day(day),
                        "source_dataset": "CSE-CIC-IDS2018",
                        "class_name": "WebBased",
                        "class_index": OFFICE_CLASS_TO_INDEX["WebBased"],
                        "label": label,
                        "flow_id": row.get("Flow ID", ""),
                        "src_ip": row.get("Src IP", ""),
                        "src_port": row.get("Src Port", ""),
                        "dst_ip": row.get("Dst IP", ""),
                        "dst_port": row.get("Dst Port", ""),
                        "protocol": row.get("Protocol", ""),
                        "timestamp": row.get("Timestamp", ""),
                        "csv_forward_payload_bytes": csv_forward_payload_bytes(row),
                        "endpoint_pcaps": endpoint_paths,
                        "endpoint_selection": endpoint_status,
                    }
                )
    return rows


def cicids2017_improved_csv_path() -> Path:
    return OFFICE_2017_IMPROVED_CSV_DIR / "thursday.csv"


def cicids2017_web_subtype(label: object) -> str | None:
    text = normalize_label(label).lower()
    if "web attack" not in text:
        return None
    if "brute force" in text:
        return "Brute Force-Web"
    if "xss" in text:
        return "XSS"
    if "sql" in text:
        return "SQL Injection"
    return None


def cicids2017_window_for_row(row: dict[str, str]) -> OfficeAttackWindow | None:
    timestamp = parse_csv_timestamp(row.get("Timestamp", ""))
    if timestamp is None:
        return None
    src = row.get("Src IP", "")
    dst = row.get("Dst IP", "")
    dst_port = str(row.get("Dst Port", ""))
    if dst_port != "80":
        return None
    for window in CICIDS2017_WEB_ATTACK_WINDOWS:
        start = datetime.fromisoformat(window.start)
        finish = datetime.fromisoformat(window.finish)
        if not start <= timestamp <= finish:
            continue
        if (src in window.attacker_ips and dst in window.victim_ips) or (
            dst in window.attacker_ips and src in window.victim_ips
        ):
            return window
    return None


def cicids2017_candidate_from_row(
    row: dict[str, str],
    label: str,
    subtype: str,
    *,
    recovered_attempted: bool,
) -> dict[str, object]:
    return {
        "flow_hash": stable_flow_hash(row),
        "day": "Thursday-06-07-2017",
        "source_dataset": "CICIDS2017",
        "split_scope": "train_only",
        "class_name": "WebBased",
        "class_index": OFFICE_CLASS_TO_INDEX["WebBased"],
        "label": label,
        "flow_id": row.get("Flow ID", ""),
        "src_ip": row.get("Src IP", ""),
        "src_port": row.get("Src Port", ""),
        "dst_ip": row.get("Dst IP", ""),
        "dst_port": row.get("Dst Port", ""),
        "protocol": row.get("Protocol", ""),
        "timestamp": row.get("Timestamp", ""),
        "flow_duration_us": row.get("Flow Duration", ""),
        "gt_subtype": subtype,
        "gt_window_start": next((window.start for window in CICIDS2017_WEB_ATTACK_WINDOWS if window.subtype == subtype), ""),
        "gt_window_finish": next((window.finish for window in CICIDS2017_WEB_ATTACK_WINDOWS if window.subtype == subtype), ""),
        "recovered_attempted": recovered_attempted,
        "csv_forward_payload_bytes": csv_forward_payload_bytes(row),
        "endpoint_pcap": str(OFFICE_2017_RAW_PCAP_PATH),
        "endpoint_pcaps": [str(OFFICE_2017_RAW_PCAP_PATH)],
        "endpoint_selection": "single_cicids2017_thursday_pcap",
    }


def candidate_duration_seconds(candidate: dict[str, object]) -> float:
    try:
        return max(0.0, float(candidate.get("flow_duration_us", 0.0) or 0.0) / 1_000_000.0)
    except (TypeError, ValueError):
        return 0.0


def pcap_timestamp_unit(magic: bytes) -> tuple[str, float]:
    if magic == b"\xd4\xc3\xb2\xa1":
        return "<", 1_000_000.0
    if magic == b"\xa1\xb2\xc3\xd4":
        return ">", 1_000_000.0
    if magic == b"\x4d\x3c\xb2\xa1":
        return "<", 1_000_000_000.0
    if magic == b"\xa1\xb2\x3c\x4d":
        return ">", 1_000_000_000.0
    raise ValueError(f"Unsupported PCAP magic: {magic!r}")


def pcapng_endian(byte_order_magic: bytes) -> str:
    if byte_order_magic == b"\x4d\x3c\x2b\x1a":
        return "<"
    if byte_order_magic == b"\x1a\x2b\x3c\x4d":
        return ">"
    raise ValueError(f"Unsupported PCAPNG byte-order magic: {byte_order_magic!r}")


def pcapng_ts_resolution(option_value: bytes) -> float:
    if not option_value:
        return 1_000_000.0
    value = option_value[0]
    if value & 0x80:
        return float(2 ** (value & 0x7F))
    return float(10 ** value)


def parse_pcapng_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = defaultdict(list)
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack(f"{endian}HH", data[offset:offset + 4])
        offset += 4
        if code == 0:
            break
        value = data[offset:offset + length]
        options[code].append(value)
        offset += length
        padding = (-length) % 4
        offset += padding
    return options


def iter_pcapng_packets(path: Path, first_header: bytes) -> Iterable[tuple[float, bytes]]:
    endian = pcapng_endian(first_header[8:12])
    first_total_len = struct.unpack(f"{endian}I", first_header[4:8])[0]
    interface_ts_resolution: dict[int, float] = defaultdict(lambda: 1_000_000.0)
    interface_linktype: dict[int, int] = {}
    interface_index = 0

    with path.open("rb") as handle:
        handle.seek(0)
        while True:
            header = handle.read(8)
            if not header:
                break
            if len(header) != 8:
                break
            block_type, block_total_len = struct.unpack(f"{endian}II", header)
            if block_total_len < 12:
                break
            remaining = handle.read(block_total_len - 8)
            if len(remaining) != block_total_len - 8:
                break
            body = remaining[:-4]
            if block_type == 0x0A0D0D0A:
                if len(body) >= 4:
                    endian = pcapng_endian(body[:4])
                continue
            if block_type == 0x00000001 and len(body) >= 8:
                linktype = struct.unpack(f"{endian}H", body[:2])[0]
                options = parse_pcapng_options(body[8:], endian)
                ts_resolution = 1_000_000.0
                if 9 in options:
                    ts_resolution = pcapng_ts_resolution(options[9][0])
                interface_linktype[interface_index] = linktype
                interface_ts_resolution[interface_index] = ts_resolution
                interface_index += 1
                continue
            if block_type != 0x00000006 or len(body) < 20:
                continue
            interface_id, ts_high, ts_low, captured_len, _packet_len = struct.unpack(f"{endian}IIIII", body[:20])
            if interface_linktype.get(interface_id, 1) != 1:
                continue
            packet = body[20:20 + captured_len]
            timestamp_value = (int(ts_high) << 32) | int(ts_low)
            yield float(timestamp_value) / interface_ts_resolution[interface_id], packet
    _ = first_total_len


def iter_classic_pcap_packets(path: Path, global_header: bytes) -> Iterable[tuple[float, bytes]]:
    endian, timestamp_divisor = pcap_timestamp_unit(global_header[:4])
    packet_header = struct.Struct(f"{endian}IIII")
    with path.open("rb") as handle:
        handle.seek(24)
        while True:
            header = handle.read(16)
            if not header:
                break
            if len(header) != 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = packet_header.unpack(header)
            packet = handle.read(incl_len)
            if len(packet) != incl_len:
                break
            yield float(ts_sec) + (float(ts_frac) / timestamp_divisor), packet


def iter_capture_packets(path: Path) -> Iterable[tuple[float, bytes]]:
    with path.open("rb") as handle:
        header = handle.read(24)
    if len(header) < 4:
        return
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        yield from iter_pcapng_packets(path, header[:12])
        return
    yield from iter_classic_pcap_packets(path, header)


def ipv4_text(value: bytes) -> str:
    return ".".join(str(part) for part in value)


def iter_pcap_ipv4_tcp_payloads(path: Path) -> Iterable[dict[str, object]]:
    for timestamp, packet in iter_capture_packets(path):
        if len(packet) < 14:
            continue
        offset = 14
        ethertype = int.from_bytes(packet[12:14], "big")
        if ethertype == 0x8100 and len(packet) >= 18:
            ethertype = int.from_bytes(packet[16:18], "big")
            offset = 18
        if ethertype != 0x0800 or len(packet) < offset + 20:
            continue
        ip = packet[offset:]
        version = ip[0] >> 4
        ihl = (ip[0] & 0x0F) * 4
        if version != 4 or len(ip) < ihl + 20:
            continue
        protocol = ip[9]
        if protocol != 6:
            continue
        total_len = int.from_bytes(ip[2:4], "big")
        if total_len <= ihl:
            continue
        src_ip = ipv4_text(ip[12:16])
        dst_ip = ipv4_text(ip[16:20])
        tcp = ip[ihl:total_len]
        if len(tcp) < 20:
            continue
        src_port = int.from_bytes(tcp[0:2], "big")
        dst_port = int.from_bytes(tcp[2:4], "big")
        tcp_header_len = (tcp[12] >> 4) * 4
        if len(tcp) < tcp_header_len:
            continue
        payload = tcp[tcp_header_len:]
        yield {
            "timestamp": float(timestamp),
            "tuple": (src_ip, dst_ip, str(src_port), str(dst_port), "6"),
            "payload": payload,
        }


def iter_pcap_ipv4_transport_packets(path: Path) -> Iterable[dict[str, object]]:
    for timestamp, packet in iter_capture_packets(path):
        if len(packet) < 14:
            continue
        offset = 14
        ethertype = int.from_bytes(packet[12:14], "big")
        if ethertype == 0x8100 and len(packet) >= 18:
            ethertype = int.from_bytes(packet[16:18], "big")
            offset = 18
        if ethertype != 0x0800 or len(packet) < offset + 20:
            continue
        ip = packet[offset:]
        version = ip[0] >> 4
        ihl = (ip[0] & 0x0F) * 4
        if version != 4 or len(ip) < ihl:
            continue
        total_len = min(int.from_bytes(ip[2:4], "big"), len(ip))
        if total_len <= ihl:
            continue
        protocol = ip[9]
        src_ip = ipv4_text(ip[12:16])
        dst_ip = ipv4_text(ip[16:20])
        body = ip[ihl:total_len]
        if protocol in {6, 17}:
            if len(body) < 4:
                continue
            src_port = int.from_bytes(body[0:2], "big")
            dst_port = int.from_bytes(body[2:4], "big")
        elif protocol == 1:
            if len(body) < 2:
                continue
            src_port = int(body[0])
            dst_port = int(body[1])
        else:
            src_port = 0
            dst_port = 0
        yield {
            "timestamp": float(timestamp),
            "protocol": str(protocol),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": str(src_port),
            "dst_port": str(dst_port),
        }


def canonical_transport_flow_key(packet: dict[str, object]) -> tuple[str, tuple[str, str], tuple[str, str]]:
    left = (str(packet["src_ip"]), str(packet["src_port"]))
    right = (str(packet["dst_ip"]), str(packet["dst_port"]))
    if right < left:
        left, right = right, left
    return str(packet["protocol"]), left, right


def build_open_flow_diagnostic_manifest(
    *,
    pcap_path: Path,
    max_packets: int = 0,
    report_interval: int = 5000,
    idle_timeout_seconds: float | None = None,
    active_timeout_seconds: float = 1800.0,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    idle_timeout = float(config.FLOW_IDLE_TIMEOUT_SECONDS if idle_timeout_seconds is None else idle_timeout_seconds)
    active_timeout = float(active_timeout_seconds)
    report_every = max(int(report_interval), 1)
    active: dict[tuple[str, tuple[str, str], tuple[str, str]], tuple[float, float]] = {}
    expiry_heap: list[tuple[float, tuple[str, tuple[str, str], tuple[str, str]]]] = []
    protocol_counts: Counter[str] = Counter()
    packet_count = 0
    expired_count = 0
    opened_count = 0
    max_active = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    reports: list[dict[str, object]] = []

    def flow_expiry(first_seen: float, last_seen: float) -> float:
        return min(first_seen + active_timeout, last_seen + idle_timeout)

    def expire_due(timestamp: float) -> None:
        nonlocal expired_count
        while expiry_heap and expiry_heap[0][0] <= timestamp:
            expires_at, key = heapq.heappop(expiry_heap)
            current = active.get(key)
            if current is None:
                continue
            current_expiry = flow_expiry(current[0], current[1])
            if abs(current_expiry - expires_at) > 1e-6:
                continue
            active.pop(key, None)
            expired_count += 1

    if not pcap_path.exists():
        raise FileNotFoundError(f"Diagnostic PCAP does not exist: {pcap_path}")

    for packet in iter_pcap_ipv4_transport_packets(pcap_path):
        timestamp = float(packet["timestamp"])
        if first_timestamp is None:
            first_timestamp = timestamp
        last_timestamp = timestamp
        expire_due(timestamp)
        key = canonical_transport_flow_key(packet)
        current = active.get(key)
        if current is None:
            current = (timestamp, timestamp)
            opened_count += 1
        else:
            current = (current[0], timestamp)
        active[key] = current
        heapq.heappush(expiry_heap, (flow_expiry(current[0], current[1]), key))
        protocol_counts[str(packet["protocol"])] += 1
        packet_count += 1
        max_active = max(max_active, len(active))
        if packet_count % report_every == 0:
            reports.append(
                {
                    "transport_packets": packet_count,
                    "timestamp": timestamp,
                    "elapsed_seconds": None if first_timestamp is None else timestamp - first_timestamp,
                    "active_flows": len(active),
                    "max_active_flows": max_active,
                    "opened_flows": opened_count,
                    "expired_flows": expired_count,
                    "process_rss_gb": OFFICE_PROCESS.memory_info().rss / (1024**3),
                    "available_memory_gb": psutil.virtual_memory().available / (1024**3),
                }
            )
        if max_packets > 0 and packet_count >= max_packets:
            break

    if last_timestamp is not None:
        expire_due(last_timestamp + max(idle_timeout, active_timeout) + 1.0)

    manifest = {
        "pipeline": "office_open_flow_memory_diagnostic",
        "pcap": str(pcap_path),
        "max_packets": max_packets,
        "report_interval": report_every,
        "idle_timeout_seconds": idle_timeout,
        "active_timeout_seconds": active_timeout,
        "transport_packets_scanned": packet_count,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "elapsed_seconds": None if first_timestamp is None or last_timestamp is None else last_timestamp - first_timestamp,
        "opened_flows": opened_count,
        "expired_flows": expired_count,
        "active_flows_at_scan_end": len(active),
        "max_active_flows": max_active,
        "protocol_counts": dict(protocol_counts),
        "reports": reports,
        "final_process_rss_gb": OFFICE_PROCESS.memory_info().rss / (1024**3),
        "final_available_memory_gb": psutil.virtual_memory().available / (1024**3),
    }
    OFFICE_OPEN_FLOW_DIAGNOSTIC_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def build_nfstream_rss_diagnostic_manifest(
    *,
    pcap_path: Path,
    max_flows: int = 0,
    report_interval: int = 250,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    report_every = max(int(report_interval), 1)
    reports: list[dict[str, object]] = []
    flows_scanned = 0
    peak_rss_gb = OFFICE_PROCESS.memory_info().rss / (1024**3)
    packet_records_seen = 0
    retained_payload_bytes_seen = 0
    status = "completed"
    error = ""

    if not pcap_path.exists():
        raise FileNotFoundError(f"NFStream RSS diagnostic PCAP does not exist: {pcap_path}")

    try:
        for flows_scanned, flow_record in enumerate(iter_flow_records(pcap_path, "office_nfstream_rss_diagnostic"), start=1):
            packet_records = list(flow_record.get("packet_records", []) or [])
            packet_records_seen += len(packet_records)
            retained_payload_bytes_seen += sum(len(payload_bytes_from_packet_record(packet)) for packet in packet_records)
            if flows_scanned % report_every == 0:
                gc.collect()
                rss_gb = OFFICE_PROCESS.memory_info().rss / (1024**3)
                peak_rss_gb = max(peak_rss_gb, rss_gb)
                available_gb = psutil.virtual_memory().available / (1024**3)
                reports.append(
                    {
                        "flows_scanned": flows_scanned,
                        "rss_gb": rss_gb,
                        "peak_rss_gb": peak_rss_gb,
                        "available_memory_gb": available_gb,
                        "packet_records_seen": packet_records_seen,
                        "retained_payload_bytes_seen": retained_payload_bytes_seen,
                    }
                )
                office_assert_memory_available(f"NFStream RSS diagnostic scanning {pcap_path.name} at flow {flows_scanned}")
            if max_flows > 0 and flows_scanned >= max_flows:
                status = "max_flows_reached"
                break
            del flow_record
    except Exception as exc:  # noqa: BLE001
        status = "diagnostic_error"
        error = repr(exc)

    gc.collect()
    final_rss_gb = OFFICE_PROCESS.memory_info().rss / (1024**3)
    peak_rss_gb = max(peak_rss_gb, final_rss_gb)
    rss_delta_gb = final_rss_gb - reports[0]["rss_gb"] if reports else 0.0
    manifest = {
        "pipeline": "office_nfstream_rss_diagnostic",
        "pcap": str(pcap_path),
        "status": status,
        "error": error,
        "max_flows": max_flows,
        "report_interval": report_every,
        "flows_scanned": flows_scanned,
        "packet_records_seen": packet_records_seen,
        "retained_payload_bytes_seen": retained_payload_bytes_seen,
        "final_rss_gb": final_rss_gb,
        "peak_rss_gb": peak_rss_gb,
        "rss_delta_from_first_report_gb": rss_delta_gb,
        "final_available_memory_gb": psutil.virtual_memory().available / (1024**3),
        "reports": reports,
    }
    OFFICE_NFSTREAM_RSS_DIAGNOSTIC_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def cicids2018_webbased_subtype_counts() -> dict[str, int]:
    path = OFFICE_CANDIDATE_DIR / "WebBased.jsonl"
    counts: Counter[str] = Counter()
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            counts[str(row.get("gt_subtype") or row.get("label") or "unknown")] += 1
    return dict(counts)


def collect_cicids2017_webbased_rows(*, include_sql: bool = False) -> dict[str, object]:
    path = cicids2017_improved_csv_path()
    if not path.exists():
        raise FileNotFoundError(path)

    accepted_candidates: list[dict[str, object]] = []
    attempted_rows: list[dict[str, object]] = []
    label_counts: Counter[str] = Counter()
    subtype_counts: Counter[str] = Counter()
    accepted_subtype_counts: Counter[str] = Counter()
    attempted_subtype_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    attempted_category_counts: Counter[str] = Counter()
    csv_payload_groups: Counter[str] = Counter()
    observed_ranges: dict[str, dict[str, object]] = {}

    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        label_col = csv_label_column(reader.fieldnames or [])
        rows_scanned = 0
        for row in reader:
            rows_scanned += 1
            label = normalize_label(row.get(label_col, ""))
            subtype = cicids2017_web_subtype(label)
            if subtype is None:
                continue
            label_counts[label] += 1
            subtype_counts[subtype] += 1
            attempted_category_counts[str(row.get("Attempted Category", ""))] += 1
            payload_group = "zero_csv_forward_payload" if csv_forward_payload_bytes(row) == 0.0 else "nonzero_csv_forward_payload"
            csv_payload_groups[payload_group] += 1
            range_item = observed_ranges.setdefault(
                subtype,
                {
                    "min_timestamp": None,
                    "max_timestamp": None,
                    "src_ips": Counter(),
                    "dst_ips": Counter(),
                },
            )
            timestamp = row.get("Timestamp", "")
            if range_item["min_timestamp"] is None or timestamp < range_item["min_timestamp"]:
                range_item["min_timestamp"] = timestamp
            if range_item["max_timestamp"] is None or timestamp > range_item["max_timestamp"]:
                range_item["max_timestamp"] = timestamp
            range_item["src_ips"][row.get("Src IP", "")] += 1
            range_item["dst_ips"][row.get("Dst IP", "")] += 1

            if subtype == "SQL Injection" and not include_sql:
                status_counts["excluded_sql_minimized_by_plan"] += 1
                continue
            window = cicids2017_window_for_row(row)
            if window is None:
                status_counts["excluded_no_ip_time_window_match"] += 1
                continue
            if window.subtype != subtype:
                status_counts["excluded_label_window_subtype_mismatch"] += 1
                continue
            if is_attempted_or_non_success(label):
                attempted_subtype_counts[subtype] += 1
                attempted_rows.append(
                    {
                        **cicids2017_candidate_from_row(row, label, subtype, recovered_attempted=False),
                        "attempted_category": row.get("Attempted Category", ""),
                    }
                )
                status_counts["attempted_pending_payload_audit"] += 1
                continue
            candidate = cicids2017_candidate_from_row(row, label, subtype, recovered_attempted=False)
            accepted_candidates.append(candidate)
            accepted_subtype_counts[subtype] += 1
            status_counts["accepted_label_ip_time_match"] += 1

    serializable_ranges = {
        subtype: {
            "min_timestamp": item["min_timestamp"],
            "max_timestamp": item["max_timestamp"],
            "src_ips": dict(item["src_ips"]),
            "dst_ips": dict(item["dst_ips"]),
        }
        for subtype, item in observed_ranges.items()
    }
    return {
        "csv_path": str(path),
        "pcap_path": str(OFFICE_2017_RAW_PCAP_PATH),
        "rows_scanned": rows_scanned,
        "include_sql": include_sql,
        "label_counts": dict(label_counts),
        "subtype_counts": dict(subtype_counts),
        "accepted_subtype_counts_before_payload_recovery": dict(accepted_subtype_counts),
        "attempted_subtype_counts": dict(attempted_subtype_counts),
        "status_counts": dict(status_counts),
        "attempted_category_counts": dict(attempted_category_counts),
        "csv_payload_groups": dict(csv_payload_groups),
        "observed_ranges": serializable_ranges,
        "accepted_candidates": accepted_candidates,
        "attempted_rows": attempted_rows,
    }


def audit_cicids2017_attempted_payloads(
    attempted_rows: list[dict[str, object]],
    *,
    max_flows_per_pcap: int,
    timestamp_tolerance_seconds: float,
) -> dict[str, object]:
    nonzero_rows = [
        row for row in attempted_rows
        if float(row.get("csv_forward_payload_bytes", 0.0) or 0.0) > 0.0
    ]
    audits: dict[str, dict[str, object]] = {
        str(row["flow_hash"]): {
            **row,
            "pcap_match_status": "not_scanned_zero_csv_forward_payload",
            "signature_decision": "keep_excluded",
            "signature_hits": [],
            "actual_captured_payload_bytes": 0,
            "payload_excerpt": "",
        }
        for row in attempted_rows
    }
    for row in nonzero_rows:
        audits[str(row["flow_hash"])].update(
            {
                "pcap_match_status": "not_matched",
                "signature_decision": "manual_review",
            }
        )

    if not nonzero_rows:
        return {
            "audits": list(audits.values()),
            "pcap_summaries": {},
            "stop_reason": "no_nonzero_attempted_rows",
        }
    if not OFFICE_2017_RAW_PCAP_PATH.exists():
        return {
            "audits": list(audits.values()),
            "pcap_summaries": {
                str(OFFICE_2017_RAW_PCAP_PATH): {
                    "status": "missing_pcap",
                    "candidate_count": len(nonzero_rows),
                    "matched": 0,
                    "flows_scanned": 0,
                }
            },
            "stop_reason": "missing_pcap",
        }

    pending = {str(row["flow_hash"]): row for row in nonzero_rows}
    tuple_to_rows: dict[tuple[str, str, str, str, str], list[dict[str, object]]] = defaultdict(list)
    windows_by_hash: dict[str, tuple[float, float]] = {}
    max_window_finish = 0.0
    for row in pending.values():
        parts = candidate_flow_tuple(row)
        tuple_to_rows[parts].append(row)
        tuple_to_rows[reverse_flow_tuple(parts)].append(row)
        row_ts = candidate_timestamp_seconds(row)
        duration = candidate_duration_seconds(row)
        if row_ts is None:
            start = 0.0
            finish = float("inf")
        else:
            start = row_ts - timestamp_tolerance_seconds
            finish = row_ts + duration + timestamp_tolerance_seconds
            max_window_finish = max(max_window_finish, finish)
        windows_by_hash[str(row["flow_hash"])] = (start, finish)

    payload_parts: dict[str, list[bytes]] = defaultdict(list)
    packets_seen: Counter[str] = Counter()
    flows_scanned = 0
    matched = 0
    max_payload_bytes_per_flow = 65536
    stop_reason = "completed"
    try:
        for flows_scanned, packet in enumerate(iter_pcap_ipv4_tcp_payloads(OFFICE_2017_RAW_PCAP_PATH), start=1):
            if flows_scanned > max_flows_per_pcap:
                stop_reason = "max_flows_per_pcap_reached"
                break
            packet_ts = float(packet["timestamp"])
            if max_window_finish and packet_ts > max_window_finish and not pending:
                break
            possible = tuple_to_rows.get(packet["tuple"], [])
            if not possible:
                continue
            for row in list(possible):
                flow_hash = str(row["flow_hash"])
                start, finish = windows_by_hash.get(flow_hash, (0.0, float("inf")))
                if not start <= packet_ts <= finish:
                    continue
                packets_seen[flow_hash] += 1
                payload = bytes(packet["payload"])
                if payload and sum(len(part) for part in payload_parts[flow_hash]) < max_payload_bytes_per_flow:
                    payload_parts[flow_hash].append(payload)
                if flow_hash in pending:
                    pending.pop(flow_hash, None)
                    matched += 1
        for row in nonzero_rows:
            flow_hash = str(row["flow_hash"])
            row_ts = candidate_timestamp_seconds(row)
            text = b"\n".join(payload_parts.get(flow_hash, [])).decode("latin-1", errors="replace")
            payload_bytes = sum(len(part) for part in payload_parts.get(flow_hash, []))
            if packets_seen[flow_hash] == 0:
                continue
            decision, hits = webbased_payload_signature(str(row["label"]), text)
            audits[flow_hash].update(
                {
                    "pcap_match_status": "matched",
                    "actual_captured_payload_bytes": payload_bytes,
                    "packet_records_captured": int(packets_seen[flow_hash]),
                    "csv_timestamp_seconds": row_ts,
                    "signature_decision": decision,
                    "signature_hits": hits,
                    "payload_excerpt": compact_payload_excerpt(text),
                }
            )
    except Exception as exc:  # noqa: BLE001
        stop_reason = "raw_pcap_scanner_error"
        pcap_summaries = {
            str(OFFICE_2017_RAW_PCAP_PATH): {
                "status": stop_reason,
                "error": str(exc),
                "candidate_count": len(nonzero_rows),
                "matched": matched,
                "flows_scanned": flows_scanned,
            }
        }
        return {"audits": list(audits.values()), "pcap_summaries": pcap_summaries, "stop_reason": stop_reason}

    pcap_summaries = {
        str(OFFICE_2017_RAW_PCAP_PATH): {
            "status": "completed" if stop_reason == "completed" else stop_reason,
            "candidate_count": len(nonzero_rows),
            "matched": matched,
            "packets_scanned": flows_scanned,
            "remaining": len(pending),
            "scanner": "raw_pcap_ipv4_tcp_payload",
        }
    }
    return {"audits": list(audits.values()), "pcap_summaries": pcap_summaries, "stop_reason": stop_reason}


def build_cicids2017_webbased_augmentation_manifest(
    *,
    include_sql: bool = False,
    max_flows_per_pcap: int = 120000,
    timestamp_tolerance_seconds: float = 3.0,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    collected = collect_cicids2017_webbased_rows(include_sql=include_sql)
    payload_audit = audit_cicids2017_attempted_payloads(
        list(collected["attempted_rows"]),
        max_flows_per_pcap=max_flows_per_pcap,
        timestamp_tolerance_seconds=timestamp_tolerance_seconds,
    )
    recovered_by_hash = {
        str(audit["flow_hash"]): audit
        for audit in payload_audit["audits"]
        if audit.get("signature_decision") == "recover"
    }
    candidate_by_hash = {str(row["flow_hash"]): dict(row) for row in collected["accepted_candidates"]}
    for row in collected["attempted_rows"]:
        flow_hash = str(row["flow_hash"])
        if flow_hash not in recovered_by_hash:
            continue
        recovered = dict(row)
        recovered["recovered_attempted"] = True
        recovered["payload_signature_hits"] = recovered_by_hash[flow_hash].get("signature_hits", [])
        candidate_by_hash[flow_hash] = recovered

    candidates = sorted(candidate_by_hash.values(), key=lambda item: (str(item["gt_subtype"]), str(item["timestamp"]), str(item["flow_hash"])))
    candidate_path = OFFICE_CANDIDATE_DIR / "WebBased_CICIDS2017_train_only.jsonl"
    with candidate_path.open("w", encoding="utf-8") as handle:
        for candidate in candidates:
            handle.write(json.dumps(candidate, sort_keys=True) + "\n")

    final_subtype_counts = Counter(str(candidate["gt_subtype"]) for candidate in candidates)
    recovered_subtype_counts = Counter(
        str(row["gt_subtype"])
        for row in candidates
        if bool(row.get("recovered_attempted"))
    )
    audit_decision_counts = Counter(str(audit.get("signature_decision", "")) for audit in payload_audit["audits"])
    audit_label_decision_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for audit in payload_audit["audits"]:
        audit_label_decision_counts[str(audit.get("label", ""))][str(audit.get("signature_decision", ""))] += 1

    manifest = {
        "pipeline": "cicids2017_webbased_train_only_augmentation",
        "source_dataset": "CICIDS2017",
        "split_scope": "train_only",
        "csv_path": collected["csv_path"],
        "pcap_path": collected["pcap_path"],
        "pcap_size_bytes": OFFICE_2017_RAW_PCAP_PATH.stat().st_size if OFFICE_2017_RAW_PCAP_PATH.exists() else None,
        "candidate_path": str(candidate_path),
        "include_sql": include_sql,
        "official_schedule_note": "Official 09:20-10:42 web windows were verified against local files as CSV UTC-style 12:15-13:43 and tcpdump local +02 display 14:15-15:43.",
        "original_cicids2017_csv_available": False,
        "original_cicids2017_csv_note": "Only the improved CICIDS2017 thursday.csv exists in the workspace; original-label cross-check remains unavailable locally.",
        "classes": ["WebBased"],
        "rows_scanned": collected["rows_scanned"],
        "label_counts": collected["label_counts"],
        "subtype_counts": collected["subtype_counts"],
        "observed_ranges": collected["observed_ranges"],
        "status_counts": collected["status_counts"],
        "csv_payload_groups": collected["csv_payload_groups"],
        "accepted_subtype_counts_before_payload_recovery": collected["accepted_subtype_counts_before_payload_recovery"],
        "attempted_subtype_counts": collected["attempted_subtype_counts"],
        "attempted_category_counts": collected["attempted_category_counts"],
        "payload_audit_decision_counts": dict(audit_decision_counts),
        "payload_audit_label_decision_counts": {label: dict(counts) for label, counts in audit_label_decision_counts.items()},
        "payload_audit_pcap_summaries": payload_audit["pcap_summaries"],
        "payload_audit_stop_reason": payload_audit["stop_reason"],
        "max_flows_per_pcap": max_flows_per_pcap,
        "timestamp_tolerance_seconds": timestamp_tolerance_seconds,
        "candidate_count": len(candidates),
        "final_subtype_counts": dict(final_subtype_counts),
        "recovered_attempted_count": sum(1 for row in candidates if bool(row.get("recovered_attempted"))),
        "recovered_attempted_subtype_counts": dict(recovered_subtype_counts),
        "cicids2018_webbased_subtype_counts": cicids2018_webbased_subtype_counts(),
        "leakage_guard": "Do not put this JSONL into val/test. It is train-only augmentation for WebBased.",
        "audits": payload_audit["audits"],
    }
    OFFICE_2017_WEB_AUGMENT_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_cicids2017_webbased_augmentation_context(manifest: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Started the CICIDS2017 WebBased augmentation path before graph generation.",
        "- Used `datasets/cic_ids_2018/improved-csv/CICIDS2017_improved/thursday.csv` as the corrected label source.",
        "- Used the single PCAP `datasets/cic_ids_2018/cic_ids_2017/raw_pcaps/Thursday-WorkingHours.pcap`.",
        "- Verified the on-wire WebBased path as `172.16.0.1 -> 192.168.10.50` over TCP/80.",
        "- Kept all CICIDS2017 candidates source-tagged and marked `split_scope=train_only`.",
        "- Minimized SQL Injection augmentation by default, per the plan.",
        "- Applied payload-retention auditing to nonzero attempted rows before recovery.",
        "",
        "## Outputs",
        f"- Manifest: `{OFFICE_2017_WEB_AUGMENT_PATH}`",
        f"- Train-only candidate JSONL: `{manifest['candidate_path']}`",
        "",
        "## Run Details",
        f"- Include SQL: `{manifest['include_sql']}`",
        f"- PCAP size bytes: `{manifest['pcap_size_bytes']}`",
        f"- Rows scanned: `{manifest['rows_scanned']}`",
        f"- Max packet records per PCAP during payload audit: `{manifest['max_flows_per_pcap']}`",
        f"- Payload audit stop reason: `{manifest['payload_audit_stop_reason']}`",
        f"- Timestamp tolerance seconds: `{manifest['timestamp_tolerance_seconds']}`",
        "",
        "## CICIDS2018 Native WebBased Baseline",
        "```json",
        json.dumps(manifest["cicids2018_webbased_subtype_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## CICIDS2017 Label Counts",
        "```json",
        json.dumps(manifest["label_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## CICIDS2017 Observed Ranges",
        "```json",
        json.dumps(manifest["observed_ranges"], indent=2, sort_keys=True),
        "```",
        "",
        "## Candidate Counts",
        f"- Final train-only candidates: `{manifest['candidate_count']}`",
        f"- Recovered attempted candidates: `{manifest['recovered_attempted_count']}`",
        "",
        "### Final Subtype Counts",
        "```json",
        json.dumps(manifest["final_subtype_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "### Recovered Attempted Subtype Counts",
        "```json",
        json.dumps(manifest["recovered_attempted_subtype_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Payload Audit",
        "### CSV Payload Groups",
        "```json",
        json.dumps(manifest["csv_payload_groups"], indent=2, sort_keys=True),
        "```",
        "",
        "### Audit Decision Counts",
        "```json",
        json.dumps(manifest["payload_audit_decision_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "### Audit Label Decision Counts",
        "```json",
        json.dumps(manifest["payload_audit_label_decision_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "### PCAP Summaries",
        "```json",
        json.dumps(manifest["payload_audit_pcap_summaries"], indent=2, sort_keys=True),
        "```",
        "",
        "## Limitations",
        f"- Original CICIDS2017 CSV available locally: `{manifest['original_cicids2017_csv_available']}`.",
        f"- {manifest['original_cicids2017_csv_note']}",
        "- This step creates candidates only; it does not materialize graph tensors.",
        "- CICIDS2017 augmentation must remain train-only and source-tagged during graph generation and splitting.",
    ]
    write_context("71_cicids2017_webbased_augmentation.md", "CICIDS2017 WebBased Augmentation", lines)


def audit_webbased_attempted_payloads(
    *,
    max_flows_per_pcap: int = 250000,
    timestamp_tolerance_seconds: float = 3.0,
) -> dict[str, object]:
    attempted_rows = collect_webbased_attempted_rows()
    attempted_by_day = Counter(str(row["day"]) for row in attempted_rows)
    by_pcap: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in attempted_rows:
        for pcap in row.get("endpoint_pcaps") or []:
            by_pcap[str(pcap)].append(row)

    audits: dict[str, dict[str, object]] = {
        str(row["flow_hash"]): {
            **row,
            "pcap_match_status": "not_matched",
            "actual_captured_payload_bytes": 0,
            "payload_nonzero_fraction": 0.0,
            "signature_decision": "keep_excluded" if float(row["csv_forward_payload_bytes"]) == 0.0 else "manual_review",
            "signature_hits": [],
            "payload_excerpt": "",
        }
        for row in attempted_rows
    }
    pcap_summaries: dict[str, object] = {}
    stop_reason = "completed"

    for pcap_path, rows in by_pcap.items():
        pcap = Path(pcap_path)
        pending = {str(row["flow_hash"]): row for row in rows}
        tuple_to_rows: dict[tuple[str, str, str, str, str], list[dict[str, object]]] = defaultdict(list)
        for row in pending.values():
            parts = candidate_flow_tuple(row)
            tuple_to_rows[parts].append(row)
            tuple_to_rows[reverse_flow_tuple(parts)].append(row)

        flows_scanned = 0
        matched = 0
        if not pcap.exists():
            pcap_summaries[pcap_path] = {
                "status": "missing_pcap",
                "candidate_count": len(rows),
                "matched": 0,
                "flows_scanned": 0,
            }
            continue
        try:
            for flows_scanned, flow_record in enumerate(iter_flow_records(pcap, "webbased_attempted_audit"), start=1):
                if flows_scanned > max_flows_per_pcap:
                    stop_reason = "max_flows_per_pcap_reached"
                    break
                possible = tuple_to_rows.get(flow_tuple_parts(flow_record), [])
                if not possible:
                    continue
                flow_timestamp = float(flow_record.get("timestamp", 0.0) or 0.0)
                for row in list(possible):
                    flow_hash = str(row["flow_hash"])
                    if flow_hash not in pending:
                        continue
                    row_ts = csv_row_timestamp_seconds({"Timestamp": str(row["timestamp"])})
                    if row_ts is not None and abs(flow_timestamp - row_ts) > timestamp_tolerance_seconds:
                        continue
                    packet_records = list(flow_record.get("packet_records", []) or [])
                    text = payload_text_from_records(packet_records)
                    payload_bytes = sum(len(payload_bytes_from_packet_record(packet)) for packet in packet_records)
                    nonzero_bytes = sum(np.count_nonzero(np.frombuffer(payload_bytes_from_packet_record(packet), dtype=np.uint8)) for packet in packet_records if payload_bytes_from_packet_record(packet))
                    total_bytes = sum(len(payload_bytes_from_packet_record(packet)) for packet in packet_records)
                    if float(row["csv_forward_payload_bytes"]) == 0.0:
                        decision, hits = "keep_excluded", []
                    else:
                        decision, hits = webbased_payload_signature(str(row["label"]), text)
                    audits[flow_hash].update(
                        {
                            "pcap_match_status": "matched",
                            "actual_captured_payload_bytes": payload_bytes,
                            "packet_records_captured": len(packet_records),
                            "payload_nonzero_fraction": float(nonzero_bytes / total_bytes) if total_bytes else 0.0,
                            "flow_timestamp_seconds": flow_timestamp,
                            "csv_timestamp_seconds": row_ts,
                            "timestamp_delta_seconds": abs(flow_timestamp - row_ts) if row_ts is not None else None,
                            "signature_decision": decision,
                            "signature_hits": hits,
                            "payload_excerpt": compact_payload_excerpt(text),
                        }
                    )
                    pending.pop(flow_hash, None)
                    matched += 1
                if not pending:
                    break
        except ModuleNotFoundError as exc:
            stop_reason = "missing_nfstream"
            pcap_summaries[pcap_path] = {
                "status": stop_reason,
                "error": str(exc),
                "candidate_count": len(rows),
                "matched": matched,
                "flows_scanned": flows_scanned,
            }
            break
        except Exception as exc:  # noqa: BLE001
            stop_reason = "extractor_error"
            pcap_summaries[pcap_path] = {
                "status": stop_reason,
                "error": repr(exc),
                "candidate_count": len(rows),
                "matched": matched,
                "flows_scanned": flows_scanned,
            }
            break
        pcap_summaries[pcap_path] = {
            "status": "completed",
            "candidate_count": len(rows),
            "matched": matched,
            "flows_scanned": flows_scanned,
            "remaining": len(pending),
        }
        if stop_reason != "completed":
            break

    decision_counts = Counter(str(audit["signature_decision"]) for audit in audits.values())
    label_decision_counts: dict[str, Counter[str]] = defaultdict(Counter)
    csv_payload_groups = Counter("zero_csv_forward_payload" if float(row["csv_forward_payload_bytes"]) == 0.0 else "nonzero_csv_forward_payload" for row in attempted_rows)
    for audit in audits.values():
        label_decision_counts[str(audit["label"])][str(audit["signature_decision"])] += 1

    recovered = [audit for audit in audits.values() if audit["signature_decision"] == "recover"]
    manual_review = [audit for audit in audits.values() if audit["signature_decision"] == "manual_review"]
    keep_excluded = [audit for audit in audits.values() if audit["signature_decision"] == "keep_excluded"]

    manifest = {
        "pipeline": "office_webbased_attempted_payload_audit",
        "days": list(native_webbased_days()),
        "attempted_rows": len(attempted_rows),
        "attempted_by_day": dict(attempted_by_day),
        "csv_payload_groups": dict(csv_payload_groups),
        "decision_counts": dict(decision_counts),
        "label_decision_counts": {label: dict(counts) for label, counts in label_decision_counts.items()},
        "pcap_summaries": pcap_summaries,
        "stop_reason": stop_reason,
        "timestamp_tolerance_seconds": timestamp_tolerance_seconds,
        "max_flows_per_pcap": max_flows_per_pcap,
        "recovered_count": len(recovered),
        "manual_review_count": len(manual_review),
        "keep_excluded_count": len(keep_excluded),
        "recovered_flow_hashes": [str(audit["flow_hash"]) for audit in recovered],
        "manual_review_flow_hashes": [str(audit["flow_hash"]) for audit in manual_review],
        "audits": list(audits.values()),
    }
    OFFICE_WEB_ATTEMPT_AUDIT_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_webbased_attempted_payload_context(manifest: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Audited native CIC-IDS2018 WebBased `Attempted` rows before graph generation.",
        "- Compared CSV forward-payload bytes with payload captured from the matched endpoint PCAP.",
        "- Classified non-zero payload rows using subtype-specific attack-content signatures.",
        "- Kept the rule scoped to WebBased only; FTP/SSH BruteForce `Attempted` handling is unchanged.",
        "",
        "## Outputs",
        f"- Audit manifest: `{OFFICE_WEB_ATTEMPT_AUDIT_PATH}`",
        "",
        "## Summary",
        f"- Days: `{manifest.get('days', [])}`",
        f"- Attempted WebBased rows: `{manifest['attempted_rows']}`",
        f"- Recovered rows: `{manifest['recovered_count']}`",
        f"- Manual-review rows: `{manifest['manual_review_count']}`",
        f"- Keep-excluded rows: `{manifest['keep_excluded_count']}`",
        f"- Stop reason: `{manifest['stop_reason']}`",
        "",
        "## Attempted Rows By Day",
        "```json",
        json.dumps(manifest.get("attempted_by_day", {}), indent=2, sort_keys=True),
        "```",
        "",
        "## CSV Payload Groups",
        "```json",
        json.dumps(manifest["csv_payload_groups"], indent=2, sort_keys=True),
        "```",
        "",
        "## Decision Counts",
        "```json",
        json.dumps(manifest["decision_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## Label Decision Counts",
        "```json",
        json.dumps(manifest["label_decision_counts"], indent=2, sort_keys=True),
        "```",
        "",
        "## PCAP Summaries",
        "```json",
        json.dumps(manifest["pcap_summaries"], indent=2, sort_keys=True),
        "```",
        "",
        "## Recovered Flow Hashes",
        "```json",
        json.dumps(manifest["recovered_flow_hashes"], indent=2, sort_keys=True),
        "```",
    ]
    if manifest["manual_review_flow_hashes"]:
        lines.extend(
            [
                "",
                "## Manual Review Flow Hashes",
                "```json",
                json.dumps(manifest["manual_review_flow_hashes"], indent=2, sort_keys=True),
                "```",
            ]
        )
    lines.extend(
        [
            "",
            "## Decision Rule Applied",
            "",
            "- `zero CSV forward payload` -> keep excluded.",
            "- `non-zero payload with subtype-matching attack syntax` -> recover.",
            "- `non-zero payload without matching syntax` -> manual review.",
            "",
            "## Next Step",
            "",
            "- If recovery is non-zero, regenerate the strict WebBased candidate manifest with the recovered attempted rows included.",
        ]
    )
    write_context("70_webbased_attempted_payload_check.md", "WebBased Attempted Payload Check", lines)


def build_candidate_flow_manifest(
    *,
    max_rows_per_day: int | None = None,
    target_per_class: int = 20000,
    benign_strategy: str = "equal_per_day",
    enforce_ip_time_crosscheck: bool = True,
) -> dict[str, object]:
    ensure_directories()
    OFFICE_CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(config.RANDOM_SEED)
    day_specs = office_day_specs_by_day()
    class_reservoirs: dict[str, list[dict[str, object]]] = {class_name: [] for class_name in OFFICE_CLASS_NAMES}
    class_seen: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    endpoint_counts: Counter[str] = Counter()
    day_class_counts: dict[str, Counter[str]] = {}
    excluded_by_day: dict[str, Counter[str]] = {}
    benign_day_targets = stratified_day_targets(target_per_class)
    recovered_webbased_hashes = recovered_webbased_attempted_hashes() if enforce_ip_time_crosscheck else set()

    for spec in OFFICE_DAY_SPECS:
        path = improved_csv_path(spec.day)
        lookup = build_ip_to_pcap_lookup(spec.day)
        day_counts: Counter[str] = Counter()
        day_excluded: Counter[str] = Counter()
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            label_col = csv_label_column(reader.fieldnames or [])
            rows = 0
            for row in reader:
                rows += 1
                if max_rows_per_day is not None and rows > max_rows_per_day:
                    break
                class_name, label, status = label_row_status(row, spec.day, label_col)
                flow_hash = stable_flow_hash(row)
                status_counts[status] += 1
                if class_name is None:
                    continue
                if status != "accepted_label":
                    if class_name == "WebBased" and flow_hash in recovered_webbased_hashes:
                        status_counts["accepted_recovered_webbased_attempted"] += 1
                    else:
                        day_excluded[class_name] += 1
                        continue
                gt_window = ground_truth_window_for_row(row, spec.day)
                if enforce_ip_time_crosscheck:
                    if class_name == "Benign" and gt_window is not None:
                        status_counts["excluded_csv_benign_gt_attack_match"] += 1
                        day_excluded[class_name] += 1
                        continue
                    if class_name != "Benign" and gt_window is None:
                        status_counts["excluded_csv_attack_no_gt_match"] += 1
                        day_excluded[class_name] += 1
                        continue
                    if gt_window is not None and class_name != gt_window.class_name:
                        status_counts["excluded_csv_gt_class_mismatch"] += 1
                        day_excluded[class_name] += 1
                        continue
                if class_name != "Benign" and class_name not in spec.target_classes:
                    status_counts["accepted_but_not_day_target"] += 1
                    continue
                endpoint_paths, endpoint_status = candidate_endpoint_files(row, lookup)
                endpoint_counts[endpoint_status] += 1
                if not endpoint_paths:
                    status_counts["accepted_but_no_endpoint_file"] += 1
                    continue
                target = benign_day_targets[spec.day] if class_name == "Benign" and benign_strategy == "equal_per_day" else target_per_class
                candidate = {
                    "flow_hash": flow_hash,
                    "day": spec.day,
                    "source": native_source_tag_for_day(spec.day),
                    "source_dataset": "CSE-CIC-IDS2018",
                    "class_name": class_name,
                    "class_index": OFFICE_CLASS_TO_INDEX[class_name],
                    "label": label,
                    "flow_id": row.get("Flow ID", ""),
                    "src_ip": row.get("Src IP", ""),
                    "src_port": row.get("Src Port", ""),
                    "dst_ip": row.get("Dst IP", ""),
                    "dst_port": row.get("Dst Port", ""),
                    "protocol": row.get("Protocol", ""),
                    "timestamp": row.get("Timestamp", ""),
                    "gt_subtype": gt_window.subtype if gt_window else "",
                    "gt_window_start": gt_window.start if gt_window else "",
                    "gt_window_finish": gt_window.finish if gt_window else "",
                    "recovered_attempted": bool(flow_hash in recovered_webbased_hashes),
                    "endpoint_pcap": endpoint_paths[0],
                    "endpoint_pcaps": endpoint_paths,
                    "endpoint_selection": endpoint_status,
                }
                key = f"Benign::{spec.day}" if class_name == "Benign" and benign_strategy == "equal_per_day" else class_name
                if key not in class_reservoirs:
                    class_reservoirs[key] = []
                class_seen[key] += 1
                update_reservoir(class_reservoirs[key], candidate, class_seen[key], target, rng)
                day_counts[class_name] += 1
        day_class_counts[spec.day] = day_counts
        excluded_by_day[spec.day] = day_excluded

    if benign_strategy == "equal_per_day":
        benign_records: list[dict[str, object]] = []
        for spec in OFFICE_DAY_SPECS:
            benign_records.extend(class_reservoirs.pop(f"Benign::{spec.day}", []))
        if len(benign_records) > target_per_class:
            rng.shuffle(benign_records)
            benign_records = benign_records[:target_per_class]
        class_reservoirs["Benign"] = benign_records

    candidate_paths: dict[str, str] = {}
    for class_name in OFFICE_CLASS_NAMES:
        path = OFFICE_CANDIDATE_DIR / f"{class_name}.jsonl"
        candidate_paths[class_name] = str(path)
        with path.open("w", encoding="utf-8") as handle:
            for record in class_reservoirs.get(class_name, []):
                handle.write(json.dumps(record, sort_keys=True) + "\n")

    manifest = {
        "pipeline": "office_model_candidate_flow_manifest",
        "target_per_class": target_per_class,
        "benign_strategy": benign_strategy,
        "enforce_ip_time_crosscheck": enforce_ip_time_crosscheck,
        "benign_day_targets": benign_day_targets,
        "max_rows_per_day": max_rows_per_day,
        "classes": OFFICE_CLASS_NAMES,
        "recovered_webbased_attempted_count": len(recovered_webbased_hashes),
        "candidate_paths": candidate_paths,
        "candidate_counts": {class_name: len(class_reservoirs.get(class_name, [])) for class_name in OFFICE_CLASS_NAMES},
        "seen_counts": dict(class_seen),
        "day_class_counts": {day: dict(counts) for day, counts in day_class_counts.items()},
        "excluded_by_day": {day: dict(counts) for day, counts in excluded_by_day.items()},
        "status_counts": dict(status_counts),
        "endpoint_counts": dict(endpoint_counts),
        "limitations": [
            "This manifest selects flow keys and endpoint PCAP files only; it does not materialize graph tensors.",
            "IP/time-window cross-check is enforced for retained CIC-IDS2018 candidate rows.",
            "CICIDS2017 WebBased augmentation is not merged by this CSE-CIC-IDS2018 candidate command.",
        ],
    }
    path = OFFICE_ARTIFACT_DIR / "candidate_flow_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_candidate_context(manifest: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Built an office-model candidate flow manifest from improved CIC-IDS2018 CSV labels.",
        "- Used streaming CSV reads and reservoir sampling; full CSVs are not loaded into memory.",
        "- Attached the selected endpoint capture file or capture parts for each retained flow.",
        "- Stratified Benign candidates by day using `equal_per_day` sampling.",
        "- Excluded labels containing `Attempted` and the documented BruteForce contamination rules.",
        "- Enforced the IP/time-window cross-check for retained CIC-IDS2018 rows.",
        "- Included audited WebBased attempted rows only when payload evidence justified recovery.",
        "",
        "## Run Details",
        f"- Target per class: `{manifest['target_per_class']}`",
        f"- Max rows per day: `{manifest['max_rows_per_day']}`",
        f"- Benign strategy: `{manifest['benign_strategy']}`",
        f"- Enforce IP/time-window cross-check: `{manifest['enforce_ip_time_crosscheck']}`",
        f"- Recovered WebBased attempted hashes available: `{manifest.get('recovered_webbased_attempted_count', 0)}`",
        "",
        "## Outputs",
        f"- Manifest: `{OFFICE_ARTIFACT_DIR / 'candidate_flow_manifest.json'}`",
        f"- Candidate JSONL directory: `{OFFICE_CANDIDATE_DIR}`",
        "",
        "## Candidate Counts",
        "",
        "| Class | Candidate records |",
        "|---|---:|",
    ]
    for class_name, count in manifest["candidate_counts"].items():
        lines.append(f"| {class_name} | {count} |")
    lines.extend(
        [
            "",
            "## Accepted Rows By Day",
            "",
            "```json",
            json.dumps(manifest["day_class_counts"], indent=2, sort_keys=True),
            "```",
            "",
            "## Excluded Rows By Day",
            "",
            "```json",
            json.dumps(manifest["excluded_by_day"], indent=2, sort_keys=True),
            "```",
            "",
            "## Status Counts",
            "",
            "```json",
            json.dumps(manifest["status_counts"], indent=2, sort_keys=True),
            "```",
            "",
            "## Endpoint Selection Counts",
            "```json",
            json.dumps(manifest["endpoint_counts"], indent=2, sort_keys=True),
            "```",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in manifest["limitations"])
    write_context("65_office_model_candidate_flow_manifest.md", "Office Model Candidate Flow Manifest", lines)


def read_candidate_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        raise FileNotFoundError(path)
    rows: list[dict[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, object]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
            count += 1
    return count


def candidate_sort_key(candidate: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(candidate.get("day", "")),
        str(candidate.get("timestamp", "")),
        str(candidate.get("flow_hash", "")),
    )


def split_candidates(
    candidates: list[dict[str, object]],
    *,
    train_count: int,
    val_count: int,
    test_count: int,
    seed: int,
    class_name: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    required = train_count + val_count + test_count
    if len(candidates) < required:
        raise ValueError(f"{class_name} has {len(candidates)} candidates, but {required} are required.")
    shuffled = sorted((dict(candidate) for candidate in candidates), key=candidate_sort_key)
    random.Random(seed).shuffle(shuffled)
    train = shuffled[:train_count]
    val = shuffled[train_count : train_count + val_count]
    test = shuffled[train_count + val_count : required]
    return train, val, test


def mark_split(candidate: dict[str, object], split: str, *, oversampled: bool = False, copy_index: int = 0) -> dict[str, object]:
    item = dict(candidate)
    item["candidate_split"] = split
    item["oversampled_train_reference"] = oversampled
    item["oversample_copy_index"] = copy_index
    return item


def materialization_identity(candidate: dict[str, object]) -> str:
    source_dataset = str(candidate.get("source_dataset", candidate.get("source", "")))
    return f"{source_dataset}|{candidate.get('day', '')}|{candidate.get('flow_hash', '')}"


def build_office_final_candidate_split_manifest() -> dict[str, object]:
    ensure_directories()
    OFFICE_FINAL_SPLIT_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(config.RANDOM_SEED)

    train_real: list[dict[str, object]] = []
    train_oversampled: list[dict[str, object]] = []
    val: list[dict[str, object]] = []
    test: list[dict[str, object]] = []
    per_class: dict[str, dict[str, object]] = {}

    for class_name in OFFICE_CLASS_NAMES:
        if class_name == "WebBased":
            continue
        candidates = read_candidate_jsonl(OFFICE_CANDIDATE_DIR / f"{class_name}.jsonl")
        class_train, class_val, class_test = split_candidates(
            candidates,
            train_count=OFFICE_STANDARD_TRAIN_TARGET,
            val_count=OFFICE_STANDARD_VAL_TARGET,
            test_count=OFFICE_STANDARD_TEST_TARGET,
            seed=config.RANDOM_SEED + OFFICE_CLASS_TO_INDEX[class_name],
            class_name=class_name,
        )
        train_real.extend(mark_split(candidate, "train") for candidate in class_train)
        train_oversampled.extend(mark_split(candidate, "train") for candidate in class_train)
        val.extend(mark_split(candidate, "val") for candidate in class_val)
        test.extend(mark_split(candidate, "test") for candidate in class_test)
        per_class[class_name] = {
            "candidate_pool": len(candidates),
            "train_real": len(class_train),
            "train_target": len(class_train),
            "val": len(class_val),
            "test": len(class_test),
            "oversampled_train_references": 0,
        }

    native_web = read_candidate_jsonl(OFFICE_CANDIDATE_DIR / "WebBased.jsonl")
    cicids2017_web = read_candidate_jsonl(OFFICE_CANDIDATE_DIR / "WebBased_CICIDS2017_train_only.jsonl")
    web_train_native, web_val, web_test = split_candidates(
        native_web,
        train_count=OFFICE_WEB_TRAIN_NATIVE_TARGET,
        val_count=OFFICE_WEB_VAL_TARGET,
        test_count=OFFICE_WEB_TEST_TARGET,
        seed=config.RANDOM_SEED + OFFICE_CLASS_TO_INDEX["WebBased"],
        class_name="WebBased-native",
    )
    for candidate in cicids2017_web:
        if str(candidate.get("split_scope", "")) != "train_only":
            raise ValueError(f"CICIDS2017 WebBased candidate is missing split_scope=train_only: {candidate.get('flow_hash')}")
        if str(candidate.get("source_dataset", "")) != "CICIDS2017":
            raise ValueError(f"CICIDS2017 WebBased candidate is missing source_dataset=CICIDS2017: {candidate.get('flow_hash')}")

    web_train_seed = [*web_train_native, *cicids2017_web]
    if len(web_train_seed) != 373:
        raise ValueError(f"Expected 373 real WebBased train candidates, found {len(web_train_seed)}.")
    web_train_balanced = [mark_split(candidate, "train") for candidate in web_train_seed]
    for copy_index in range(OFFICE_WEB_TRAIN_TARGET - len(web_train_seed)):
        web_train_balanced.append(mark_split(rng.choice(web_train_seed), "train", oversampled=True, copy_index=copy_index + 1))
    rng.shuffle(web_train_balanced)

    train_real.extend(mark_split(candidate, "train") for candidate in web_train_seed)
    train_oversampled.extend(web_train_balanced)
    val.extend(mark_split(candidate, "val") for candidate in web_val)
    test.extend(mark_split(candidate, "test") for candidate in web_test)
    per_class["WebBased"] = {
        "native_pool": len(native_web),
        "cicids2017_train_only_pool": len(cicids2017_web),
        "train_native_real": len(web_train_native),
        "train_cicids2017_real": len(cicids2017_web),
        "train_real": len(web_train_seed),
        "train_target": len(web_train_balanced),
        "val": len(web_val),
        "test": len(web_test),
        "oversampled_train_references": len(web_train_balanced) - len(web_train_seed),
    }

    unique_by_identity: dict[str, dict[str, object]] = {}
    for candidate in [*train_real, *val, *test]:
        identity = materialization_identity(candidate)
        existing = unique_by_identity.get(identity)
        if existing and existing.get("candidate_split") != candidate.get("candidate_split"):
            raise ValueError(f"Candidate {identity} appears in multiple real splits.")
        unique_by_identity[identity] = candidate
    materialization_unique = list(unique_by_identity.values())

    paths = {
        "train_real": OFFICE_FINAL_SPLIT_DIR / "train_real.jsonl",
        "train": OFFICE_FINAL_SPLIT_DIR / "train.jsonl",
        "val": OFFICE_FINAL_SPLIT_DIR / "val.jsonl",
        "test": OFFICE_FINAL_SPLIT_DIR / "test.jsonl",
        "materialization_unique": OFFICE_FINAL_SPLIT_DIR / "materialization_unique.jsonl",
    }
    counts = {
        "train_real": write_jsonl(paths["train_real"], train_real),
        "train": write_jsonl(paths["train"], train_oversampled),
        "val": write_jsonl(paths["val"], val),
        "test": write_jsonl(paths["test"], test),
        "materialization_unique": write_jsonl(paths["materialization_unique"], materialization_unique),
    }

    manifest = {
        "pipeline": "office_model_final_candidate_splits",
        "seed": config.RANDOM_SEED,
        "class_names": OFFICE_CLASS_NAMES,
        "split_strategy": "split_first_then_oversample_train_only",
        "targets": {
            "standard_classes": {
                "train": OFFICE_STANDARD_TRAIN_TARGET,
                "val": OFFICE_STANDARD_VAL_TARGET,
                "test": OFFICE_STANDARD_TEST_TARGET,
                "candidate_pool": OFFICE_STANDARD_POOL_TARGET,
            },
            "WebBased": {
                "native_train": OFFICE_WEB_TRAIN_NATIVE_TARGET,
                "cicids2017_train_only": len(cicids2017_web),
                "train_real": len(web_train_seed),
                "train_target": OFFICE_WEB_TRAIN_TARGET,
                "val": OFFICE_WEB_VAL_TARGET,
                "test": OFFICE_WEB_TEST_TARGET,
            },
        },
        "paths": {name: str(path) for name, path in paths.items()},
        "counts": counts,
        "per_class": per_class,
        "leakage_guards": {
            "cicids2017_in_val": sum(1 for row in val if row.get("source_dataset") == "CICIDS2017"),
            "cicids2017_in_test": sum(1 for row in test if row.get("source_dataset") == "CICIDS2017"),
            "real_candidate_cross_split_identity_overlap": 0,
        },
    }
    OFFICE_FINAL_SPLIT_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_office_final_split_context(manifest: dict[str, object]) -> None:
    write_context(
        "73_office_final_candidate_splits.md",
        "Office Final Candidate Splits",
        [
            "## Action",
            "- Built final office-model candidate split JSONLs before graph materialization.",
            "- Used 24,000 real candidates for each standard class: 20,000 train, 2,000 validation, 2,000 test.",
            "- Split native WebBased 50/25/25, added CICIDS2017 only to train, then oversampled WebBased train references to 6,000.",
            f"- Saved split manifest to `{OFFICE_FINAL_SPLIT_MANIFEST_PATH}`.",
            "",
            "## Counts",
            "```json",
            json.dumps({"counts": manifest["counts"], "per_class": manifest["per_class"], "leakage_guards": manifest["leakage_guards"]}, indent=2),
            "```",
        ],
    )


def compact_path_for_candidate(candidate: dict[str, object]) -> Path:
    class_name = str(candidate["class_name"])
    day = str(candidate.get("day", "unknown")).replace("/", "_")
    source_dataset = str(candidate.get("source_dataset", candidate.get("source", "unknown"))).replace("/", "_")
    flow_hash = str(candidate["flow_hash"])
    return OFFICE_COMPACT_GRAPH_DIR / class_name / f"{source_dataset}_{day}_{flow_hash}.pkl"


def candidate_endpoint_paths(candidate: dict[str, object]) -> list[str]:
    paths = candidate.get("endpoint_pcaps") or []
    if isinstance(paths, list) and paths:
        return [str(path) for path in paths]
    path = candidate.get("endpoint_pcap")
    return [str(path)] if path else []


def primary_candidate_endpoint_path(candidate: dict[str, object]) -> str:
    paths = candidate_endpoint_paths(candidate)
    return paths[0] if paths else ""


def density_aware_candidate_subset(
    candidates: list[dict[str, object]],
    limit_unique: int | None,
    max_primary_pcaps: int = 0,
    excluded_primary_pcaps: set[str] | None = None,
) -> list[dict[str, object]]:
    excluded = excluded_primary_pcaps or set()
    if excluded:
        candidates = [
            candidate
            for candidate in candidates
            if primary_candidate_endpoint_path(candidate) not in excluded
        ]
    if limit_unique is None or limit_unique <= 0 or len(candidates) <= limit_unique:
        return candidates
    by_primary_pcap: dict[str, list[dict[str, object]]] = defaultdict(list)
    no_endpoint: list[dict[str, object]] = []
    for candidate in candidates:
        path = primary_candidate_endpoint_path(candidate)
        if path:
            by_primary_pcap[path].append(candidate)
        else:
            no_endpoint.append(candidate)
    selected: list[dict[str, object]] = []
    ordered_groups = sorted(by_primary_pcap.items(), key=lambda item: (-len(item[1]), item[0]))
    if max_primary_pcaps > 0:
        bounded_groups = [
            sorted(group, key=lambda item: (str(item.get("timestamp", "")), str(item.get("flow_hash", ""))))
            for _path, group in ordered_groups[:max_primary_pcaps]
        ]
        group_indexes = [0 for _group in bounded_groups]
        while len(selected) < limit_unique:
            advanced = False
            for index, group in enumerate(bounded_groups):
                if group_indexes[index] >= len(group):
                    continue
                selected.append(group[group_indexes[index]])
                group_indexes[index] += 1
                advanced = True
                if len(selected) >= limit_unique:
                    break
            if not advanced:
                break
    else:
        for _path, group in ordered_groups:
            if len(selected) >= limit_unique:
                break
            selected.extend(group[: limit_unique - len(selected)])
    if len(selected) < limit_unique:
        selected.extend(no_endpoint[: limit_unique - len(selected)])
    return selected


def compact_tensor_hash(record: dict[str, object]) -> str:
    h = hashlib.sha256()
    for key in ("flow_x", "packet_x_uint8", "contain_edge_attr", "link_edge_attr"):
        h.update(np.asarray(record[key]).tobytes())
    h.update(str(record["label"]).encode("utf-8"))
    return h.hexdigest()


def enrich_compact_record(record: dict[str, object], candidate: dict[str, object]) -> dict[str, object]:
    enriched = dict(record)
    for key in (
        "flow_hash",
        "day",
        "source",
        "source_dataset",
        "gt_subtype",
        "split_scope",
        "candidate_split",
        "endpoint_selection",
        "recovered_attempted",
        "selection_policy",
        "exception_policy",
        "exception_reason",
        "attempted_category",
        "csv_attempted_category",
        "exception_rank",
        "evidence_score",
        "evidence_rank_tuple",
        "selection_group",
        "reference_profile_id",
        "reference_distance",
        "reference_similarity",
        "original_csv_class",
        "original_label_status",
        "exception_source_class",
        "attacker_private_ip",
        "attacker_public_ip",
        "victim_private_ip",
        "victim_public_ip",
    ):
        if key in candidate:
            enriched[key] = candidate[key]
    if "label" in candidate:
        enriched["candidate_label"] = candidate["label"]
    enriched["candidate_timestamp"] = str(candidate.get("timestamp", ""))
    enriched["candidate_identity"] = materialization_identity(candidate)
    enriched["compact_tensor_hash"] = compact_tensor_hash(enriched)
    return enriched


def safety_flags(stats: dict[str, object]) -> list[str]:
    flags: list[str] = []
    for key in ("flow_finite", "contain_finite", "link_finite"):
        if not bool(stats.get(key, False)):
            flags.append(key)
    nonzero = float(stats.get("payload_nonzero_fraction", 0.0) or 0.0)
    if nonzero == 0.0 or nonzero > 0.60:
        flags.append("payload_nonzero_fraction_outlier")
    flow_max = float(stats.get("flow_max", 0.0) or 0.0)
    if not np.isfinite(flow_max):
        flags.append("flow_max_nonfinite")
    return flags


def load_office_materialization_candidates(
    limit_unique: int | None = None,
    max_primary_pcaps: int = 0,
    excluded_primary_pcaps: set[str] | None = None,
    target_classes: set[str] | None = None,
    materialized_identities: set[str] | None = None,
) -> list[dict[str, object]]:
    if not OFFICE_FINAL_SPLIT_MANIFEST_PATH.exists():
        manifest = build_office_final_candidate_split_manifest()
        write_office_final_split_context(manifest)
    manifest = json.loads(OFFICE_FINAL_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    candidates = read_candidate_jsonl(Path(str(manifest["paths"]["materialization_unique"])))
    if target_classes:
        candidates = [candidate for candidate in candidates if str(candidate.get("class_name", "")) in target_classes]
    if materialized_identities:
        candidates = [
            candidate
            for candidate in candidates
            if materialization_identity(candidate) not in materialized_identities
        ]
    return density_aware_candidate_subset(
        candidates,
        limit_unique,
        max_primary_pcaps=max_primary_pcaps,
        excluded_primary_pcaps=excluded_primary_pcaps,
    )


def load_office_materialized_identity_index(
    cumulative_path: Path = DEFAULT_CUMULATIVE_PATH,
) -> dict[str, str]:
    if not cumulative_path.exists():
        return {}
    manifest = json.loads(cumulative_path.read_text(encoding="utf-8"))
    root = Path(str(manifest.get("compact_root", OFFICE_COMPACT_GRAPH_DIR)))
    identities: dict[str, str] = {}
    for record in manifest.get("records", []):
        if not isinstance(record, dict):
            continue
        identity = str(record.get("candidate_identity", ""))
        rel_path = str(record.get("path", ""))
        if not identity or not rel_path:
            continue
        path = root / rel_path
        if path.exists():
            identities[identity] = str(path)
    return identities


def load_office_all_materialization_candidates_by_hash() -> dict[str, dict[str, object]]:
    if not OFFICE_FINAL_SPLIT_MANIFEST_PATH.exists():
        manifest = build_office_final_candidate_split_manifest()
        write_office_final_split_context(manifest)
    manifest = json.loads(OFFICE_FINAL_SPLIT_MANIFEST_PATH.read_text(encoding="utf-8"))
    candidates = read_candidate_jsonl(Path(str(manifest["paths"]["materialization_unique"])))
    return {str(candidate["flow_hash"]): candidate for candidate in candidates}


def candidate_matches_infiltration_rule(candidate: dict[str, object]) -> bool:
    row = {
        "Timestamp": str(candidate.get("timestamp", "")),
        "Src IP": str(candidate.get("src_ip", "")),
        "Dst IP": str(candidate.get("dst_ip", "")),
    }
    window = ground_truth_window_for_row(row, str(candidate.get("day", "")))
    return window is not None and window.class_name == "Infiltration"


def compact_payload_sample(packet_x: np.ndarray, limit: int = 96) -> dict[str, object]:
    combined = bytearray()
    for row in packet_x:
        payload = bytes(int(value) & 0xFF for value in row.tolist()).rstrip(b"\x00")
        if payload:
            combined.extend(payload)
            combined.extend(b"\n")
        if len(combined) >= limit:
            break
    sample = bytes(combined[:limit])
    return {
        "hex": sample.hex(),
        "ascii": compact_payload_excerpt(sample.decode("latin-1", errors="replace"), limit=limit),
    }


def payload_preview_from_row(row: np.ndarray, limit: int = 48) -> dict[str, object]:
    payload = bytes(int(value) & 0xFF for value in row.tolist()).rstrip(b"\x00")
    sample = payload[:limit]
    return {
        "bytes": len(payload),
        "nonzero_bytes": int(np.count_nonzero(row)),
        "hex": sample.hex(),
        "ascii": compact_payload_excerpt(sample.decode("latin-1", errors="replace"), limit=limit),
    }


def markdown_escape_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_readable_compact_graph(path: Path, compact: dict[str, object], sample_id: str) -> dict[str, object]:
    stats = graph_record_stats(compact)
    packet_x = np.asarray(compact["packet_x_uint8"], dtype=np.uint8)
    contain = np.asarray(compact["contain_edge_attr"], dtype=np.float32)
    link = np.asarray(compact["link_edge_attr"], dtype=np.float32).reshape(-1)
    feature_names = list(compact.get("flow_feature_names", []))
    flow_values = np.asarray(compact["flow_x"], dtype=np.float32)
    feature_pairs = []
    for index, value in enumerate(flow_values.tolist()):
        name = feature_names[index] if index < len(feature_names) else f"feature_{index}"
        if float(value) != 0.0:
            feature_pairs.append((name, float(value)))
    feature_pairs = sorted(feature_pairs, key=lambda item: abs(item[1]), reverse=True)[:20]
    out_path = OFFICE_READABLE_SAMPLE_DIR / str(compact["class_name"]) / f"{sample_id}.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# {compact['class_name']} Graph Sample {sample_id}",
        "",
        "## Graph Identity",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for key in (
        "flow_hash",
        "class_name",
        "subtype_label",
        "day",
        "source_dataset",
        "candidate_split",
        "candidate_timestamp",
        "source_file",
        "source_order",
        "endpoint_selection",
    ):
        lines.append(f"| `{key}` | {markdown_escape_cell(compact.get(key, ''))} |")

    lines.extend(
        [
            "",
            "## Shape And Safety",
            "",
            "```json",
            json.dumps(stats, indent=2, sort_keys=True),
            "```",
            "",
            "## Flow Node",
            "",
            "One flow node with the top non-zero flow features by absolute value.",
            "",
            "| Feature | Value |",
            "|---|---:|",
        ]
    )
    for name, value in feature_pairs:
        lines.append(f"| `{markdown_escape_cell(name)}` | {value:.6g} |")

    lines.extend(
        [
            "",
            "## Packet Nodes And Contain Edges",
            "",
            "| Packet | Direction | IP size | Transport size | Payload size | Non-zero payload bytes | Payload preview |",
            "|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for index, row in enumerate(packet_x):
        contain_row = contain[index].tolist() if contain.ndim == 2 and index < contain.shape[0] else [0, 0, 0, 0]
        preview = payload_preview_from_row(row)
        preview_text = preview["ascii"] or preview["hex"]
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    f"{float(contain_row[0]):.0f}",
                    f"{float(contain_row[1]):.0f}",
                    f"{float(contain_row[2]):.0f}",
                    f"{float(contain_row[3]):.0f}",
                    str(preview["nonzero_bytes"]),
                    markdown_escape_cell(preview_text),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Packet Link Edges",
            "",
            "| Edge | Source packet | Target packet | Delta ms |",
            "|---:|---:|---:|---:|",
        ]
    )
    for index, delta in enumerate(link.tolist()):
        lines.append(f"| {index} | {index} | {index + 1} | {float(delta):.6g} |")
    if not link.size:
        lines.append("| - | - | - | - |")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "sample_id": sample_id,
        "class_name": str(compact["class_name"]),
        "source_path": str(path),
        "readable_path": str(out_path),
        "stats": stats,
    }


def export_office_readable_graph_samples(samples_per_class: int = 10) -> dict[str, object]:
    ensure_directories()
    OFFICE_READABLE_SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
    samples: list[dict[str, object]] = []
    per_class_counts: dict[str, int] = {}
    missing_classes: list[str] = []
    for class_name in OFFICE_CLASS_NAMES:
        paths = sorted((OFFICE_COMPACT_GRAPH_DIR / class_name).glob("*.pkl"))
        selected = paths[:samples_per_class]
        per_class_counts[class_name] = len(selected)
        if len(selected) < samples_per_class:
            missing_classes.append(class_name)
        for index, path in enumerate(selected, start=1):
            with path.open("rb") as handle:
                compact = pickle.load(handle)
            samples.append(write_readable_compact_graph(path, compact, f"{index:02d}_{path.stem[:32]}"))
    manifest = {
        "pipeline": "office_readable_graph_samples",
        "compact_dir": str(OFFICE_COMPACT_GRAPH_DIR),
        "output_dir": str(OFFICE_READABLE_SAMPLE_DIR),
        "samples_per_class_requested": samples_per_class,
        "per_class_counts": per_class_counts,
        "missing_classes": missing_classes,
        "sample_count": len(samples),
        "samples": samples,
    }
    OFFICE_READABLE_SAMPLE_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def audit_infiltration_payload_graphs(sample_limit: int = 40) -> dict[str, object]:
    ensure_directories()
    OFFICE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    candidate_by_hash = load_office_all_materialization_candidates_by_hash()
    graph_paths = sorted((OFFICE_COMPACT_GRAPH_DIR / "Infiltration").glob("*.pkl"))
    if sample_limit > 0:
        graph_paths = graph_paths[:sample_limit]

    audits: list[dict[str, object]] = []
    decision_counts: Counter[str] = Counter()
    payload_size_counts: Counter[str] = Counter()
    endpoint_counts: Counter[str] = Counter()
    packet_node_counts: Counter[str] = Counter()
    candidate_missing = 0

    for path in graph_paths:
        with path.open("rb") as handle:
            compact = pickle.load(handle)
        flow_hash = str(compact.get("flow_hash", ""))
        candidate = candidate_by_hash.get(flow_hash)
        if candidate is None:
            candidate_missing += 1
            continue
        stats = graph_record_stats(compact)
        packet_x = np.asarray(compact["packet_x_uint8"], dtype=np.uint8)
        contain = np.asarray(compact["contain_edge_attr"], dtype=np.float32)
        payload_sizes = contain[:, 3].tolist() if contain.ndim == 2 and contain.shape[1] >= 4 else []
        ip_sizes = contain[:, 1].tolist() if contain.ndim == 2 and contain.shape[1] >= 2 else []
        transport_sizes = contain[:, 2].tolist() if contain.ndim == 2 and contain.shape[1] >= 3 else []
        directions = contain[:, 0].tolist() if contain.ndim == 2 and contain.shape[1] >= 1 else []
        nonzero_bytes = int(np.count_nonzero(packet_x))
        total_payload_size = float(sum(float(value) for value in payload_sizes))
        all_payload_sizes_zero = bool(payload_sizes) and all(float(value) == 0.0 for value in payload_sizes)
        endpoint_rule_match = candidate_matches_infiltration_rule(candidate)
        compromised_host_endpoint = "172.31.69.13" in {
            str(candidate.get("src_ip", "")),
            str(candidate.get("dst_ip", "")),
        }
        source_file = str(compact.get("source_file", ""))
        endpoint_pcaps = candidate_endpoint_paths(candidate)
        source_file_matches_endpoint = any(source_file and source_file in Path(endpoint).name for endpoint in endpoint_pcaps)
        protocol = str(candidate.get("protocol", ""))
        scan_like_sizes = (
            protocol == "6"
            and all_payload_sizes_zero
            and nonzero_bytes == 0
            and bool(ip_sizes)
            and all(40.0 <= float(value) <= 60.0 for value in ip_sizes)
            and bool(transport_sizes)
            and all(20.0 <= float(value) <= 40.0 for value in transport_sizes)
        )
        if endpoint_rule_match and compromised_host_endpoint and source_file_matches_endpoint and scan_like_sizes:
            decision = "confirmed_zero_payload_scan_probe"
        elif endpoint_rule_match and compromised_host_endpoint and source_file_matches_endpoint and nonzero_bytes > 0:
            decision = "matched_infiltration_with_payload"
        else:
            decision = "manual_review"
        decision_counts[decision] += 1
        payload_size_counts["all_zero_payload_size" if all_payload_sizes_zero else "nonzero_payload_size"] += 1
        endpoint_counts["compromised_host_endpoint" if compromised_host_endpoint else "missing_compromised_host_endpoint"] += 1
        packet_node_counts[str(int(stats["packet_nodes"]))] += 1
        audits.append(
            {
                "flow_hash": flow_hash,
                "path": str(path),
                "decision": decision,
                "class_name": compact.get("class_name"),
                "day": compact.get("day"),
                "label": candidate.get("label"),
                "src_ip": candidate.get("src_ip"),
                "dst_ip": candidate.get("dst_ip"),
                "src_port": candidate.get("src_port"),
                "dst_port": candidate.get("dst_port"),
                "protocol": protocol,
                "timestamp": candidate.get("timestamp"),
                "gt_window_start": candidate.get("gt_window_start"),
                "gt_window_finish": candidate.get("gt_window_finish"),
                "endpoint_selection": candidate.get("endpoint_selection"),
                "source_file": source_file,
                "endpoint_pcaps": endpoint_pcaps,
                "endpoint_rule_match": endpoint_rule_match,
                "compromised_host_endpoint": compromised_host_endpoint,
                "source_file_matches_endpoint": source_file_matches_endpoint,
                "packet_nodes": stats["packet_nodes"],
                "payload_nonzero_fraction": stats["payload_nonzero_fraction"],
                "nonzero_payload_bytes": nonzero_bytes,
                "total_payload_size_from_edges": total_payload_size,
                "all_payload_sizes_zero": all_payload_sizes_zero,
                "directions": directions,
                "ip_sizes": ip_sizes,
                "transport_sizes": transport_sizes,
                "payload_sizes": payload_sizes,
                "payload_sample": compact_payload_sample(packet_x),
            }
        )

    manifest = {
        "pipeline": "office_infiltration_payload_audit",
        "compact_dir": str(OFFICE_COMPACT_GRAPH_DIR / "Infiltration"),
        "sample_limit": sample_limit,
        "graphs_audited": len(audits),
        "candidate_missing": candidate_missing,
        "decision_counts": dict(decision_counts),
        "payload_size_counts": dict(payload_size_counts),
        "endpoint_counts": dict(endpoint_counts),
        "packet_node_counts": dict(packet_node_counts),
        "audits": audits,
    }
    OFFICE_INFILTRATION_PAYLOAD_AUDIT_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def office_assert_memory_available(context: str) -> None:
    rss_gb = OFFICE_PROCESS.memory_info().rss / (1024**3)
    if rss_gb > config.MAX_PROCESS_RSS_GB:
        raise MemoryError(
            f"Stopping office materialization during {context}: parent RSS is {rss_gb:.2f} GiB, "
            f"above configured ceiling {config.MAX_PROCESS_RSS_GB:.2f} GiB."
        )
    available_gb = psutil.virtual_memory().available / (1024**3)
    if available_gb < config.MIN_AVAILABLE_MEMORY_GB:
        raise MemoryError(
            f"Stopping office materialization during {context}: available memory is {available_gb:.2f} GiB, "
            f"below configured floor {config.MIN_AVAILABLE_MEMORY_GB:.2f} GiB."
        )


def office_worker_limits() -> None:
    if config.ALLOW_UNSAFE_PREPROCESS:
        return
    limit_bytes = int((config.MAX_PROCESS_RSS_GB + 0.75) * 1024**3)
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def office_worker_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("MALLOC_ARENA_MAX", "2")
    env.setdefault("OMP_NUM_THREADS", "1")
    env.setdefault("OPENBLAS_NUM_THREADS", "1")
    env.setdefault("MKL_NUM_THREADS", "1")
    return env


def office_work_id_for_pcap(path: str) -> str:
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    return f"{Path(path).name.replace('/', '_')}_{digest}"


def office_preslice_path_for_pcap(path: str, bpf: str) -> Path:
    pcap_digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    bpf_digest = hashlib.sha256(bpf.encode("utf-8")).hexdigest()[:16]
    return OFFICE_PCAP_SLICE_DIR / f"{Path(path).stem}_{pcap_digest}_{bpf_digest}.pcap"


def office_pcap_slice_has_packets(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 24


def build_office_presliced_pcap(
    *,
    pcap_path: str,
    candidates: list[dict[str, object]],
    overwrite: bool,
) -> dict[str, object]:
    ip_pairs = office_preslice_ip_pairs_for_pcap(pcap_path, candidates)
    candidate_bpf, candidate_tuple_count = office_preslice_bpf_for_candidates(candidates)
    bpf = candidate_bpf or office_preslice_bpf_for_pairs(ip_pairs)
    bpf_strategy = "candidate_5tuple" if candidate_bpf else "attack_ip_pairs"
    if not bpf:
        return {
            "status": "preslice_no_filter_pairs",
            "pcap": pcap_path,
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "ip_pairs": [],
            "bpf": "",
        }
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        return {
            "status": "preslice_missing_tcpdump",
            "pcap": pcap_path,
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "ip_pairs": [list(pair) for pair in ip_pairs],
            "bpf": bpf,
        }
    OFFICE_PCAP_SLICE_DIR.mkdir(parents=True, exist_ok=True)
    slice_key = f"{bpf_strategy}|window={OFFICE_PRESLICE_TIME_WINDOW_SECONDS}|{bpf}"
    output_path = office_preslice_path_for_pcap(pcap_path, slice_key)
    if output_path.exists() and not overwrite:
        return {
            "status": "preslice_reused" if office_pcap_slice_has_packets(output_path) else "preslice_empty",
            "pcap": pcap_path,
            "worker_pcap": str(output_path),
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "window_seconds": OFFICE_PRESLICE_TIME_WINDOW_SECONDS,
            "ip_pairs": [list(pair) for pair in ip_pairs],
            "bpf": bpf,
            "output_bytes": output_path.stat().st_size,
        }

    if candidate_bpf:
        try:
            slice_summary = build_office_candidate_window_pcap(
                pcap_path=pcap_path,
                output_path=output_path,
                candidates=candidates,
                window_seconds=OFFICE_PRESLICE_TIME_WINDOW_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "preslice_failed",
                "error": repr(exc),
                "pcap": pcap_path,
                "worker_pcap": str(output_path),
                "candidate_count": len(candidates),
                "candidate_tuple_count": candidate_tuple_count,
                "bpf_strategy": bpf_strategy,
                "window_seconds": OFFICE_PRESLICE_TIME_WINDOW_SECONDS,
                "ip_pairs": [list(pair) for pair in ip_pairs],
                "bpf": bpf,
            }
        return {
            "status": "preslice_completed" if office_pcap_slice_has_packets(output_path) else "preslice_empty",
            "pcap": pcap_path,
            "worker_pcap": str(output_path),
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "window_seconds": OFFICE_PRESLICE_TIME_WINDOW_SECONDS,
            "ip_pairs": [list(pair) for pair in ip_pairs],
            "bpf": bpf,
            **slice_summary,
        }

    command = [tcpdump, "-n", "-r", pcap_path, "-w", str(output_path), bpf]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=config.PCAP_WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "preslice_timeout",
            "error": str(exc),
            "pcap": pcap_path,
            "worker_pcap": str(output_path),
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "ip_pairs": [list(pair) for pair in ip_pairs],
            "bpf": bpf,
        }
    except subprocess.CalledProcessError as exc:
        if office_pcap_slice_has_packets(output_path):
            return {
                "status": "preslice_completed_with_warning",
                "error": exc.stderr or str(exc),
                "returncode": exc.returncode,
                "pcap": pcap_path,
                "worker_pcap": str(output_path),
                "candidate_count": len(candidates),
                "candidate_tuple_count": candidate_tuple_count,
                "bpf_strategy": bpf_strategy,
                "ip_pairs": [list(pair) for pair in ip_pairs],
                "bpf": bpf,
                "output_bytes": output_path.stat().st_size,
            }
        return {
            "status": "preslice_failed",
            "error": exc.stderr or str(exc),
            "returncode": exc.returncode,
            "pcap": pcap_path,
            "worker_pcap": str(output_path),
            "candidate_count": len(candidates),
            "candidate_tuple_count": candidate_tuple_count,
            "bpf_strategy": bpf_strategy,
            "ip_pairs": [list(pair) for pair in ip_pairs],
            "bpf": bpf,
        }
    return {
        "status": "preslice_completed" if office_pcap_slice_has_packets(output_path) else "preslice_empty",
        "pcap": pcap_path,
        "worker_pcap": str(output_path),
        "candidate_count": len(candidates),
        "candidate_tuple_count": candidate_tuple_count,
        "bpf_strategy": bpf_strategy,
        "ip_pairs": [list(pair) for pair in ip_pairs],
        "bpf": bpf,
        "output_bytes": output_path.stat().st_size if output_path.exists() else 0,
        "stderr": result.stderr,
    }


def load_office_pcap_health_skips(
    *,
    health_manifest_path: Path,
    min_yield: float = 0.05,
) -> dict[str, object]:
    if not health_manifest_path.exists():
        return {
            "enabled": True,
            "manifest_path": str(health_manifest_path),
            "status": "missing_health_manifest",
            "skip_pcaps": [],
            "skip_reasons": {},
        }
    manifest = json.loads(health_manifest_path.read_text(encoding="utf-8"))
    skip_reasons: dict[str, list[str]] = defaultdict(list)
    for pcap in manifest.get("pcap_health", {}).get("skip_pcaps", []) or []:
        skip_reasons[str(pcap)].append("carried_forward_health_skip")
    for item in manifest.get("deferred_pcaps", []) or []:
        pcap = str(item.get("pcap", ""))
        if pcap:
            skip_reasons[pcap].append(str(item.get("status", "deferred")))
    for pcap, summary in (manifest.get("pcap_summaries", {}) or {}).items():
        candidate_count = int(summary.get("candidate_count", 0) or 0)
        matched = int(summary.get("matched", 0) or 0)
        status = str(summary.get("status", ""))
        if status in {
            "worker_error",
            "worker_failed",
            "worker_timeout",
            "worker_missing_summary",
            "max_flows_per_pcap_reached",
            "missing_pcap",
            "preslice_empty",
            "preslice_failed",
            "preslice_missing_tcpdump",
            "preslice_no_filter_pairs",
            "preslice_timeout",
        }:
            skip_reasons[str(pcap)].append(status)
            continue
        if candidate_count > 0:
            yield_rate = matched / candidate_count
            if yield_rate < min_yield:
                skip_reasons[str(pcap)].append(f"low_yield_{yield_rate:.4f}")
    return {
        "enabled": True,
        "manifest_path": str(health_manifest_path),
        "status": "loaded",
        "min_yield": min_yield,
        "skip_pcaps": sorted(skip_reasons),
        "skip_reasons": {pcap: reasons for pcap, reasons in sorted(skip_reasons.items())},
    }


def materialize_office_pcap_candidates(
    *,
    pcap_path: str,
    candidates: list[dict[str, object]],
    overwrite: bool,
    timestamp_tolerance_seconds: float,
    max_flows_per_pcap: int,
    allow_local_temporal_fallback: bool = False,
) -> dict[str, object]:
    pcap = Path(pcap_path)
    pending = {str(candidate["flow_hash"]): candidate for candidate in candidates}
    tuple_to_candidates: dict[tuple[str, str, str, str, str], list[dict[str, object]]] = defaultdict(list)
    for candidate in pending.values():
        forward = candidate_flow_tuple(candidate)
        tuple_to_candidates[forward].append(candidate)
        tuple_to_candidates[reverse_flow_tuple(forward)].append(candidate)

    materialized_paths: dict[str, str] = {}
    materialized_flow_hashes: list[str] = []
    zero_packet_flow_hashes: list[str] = []
    temporal_context_missing_flow_hashes: list[str] = []
    local_temporal_fallback_flow_hashes: list[str] = []
    class_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    safety_summary: Counter[str] = Counter()
    safety_samples: list[dict[str, object]] = []
    flows_scanned = 0
    matched = 0
    stop_reason = "completed"

    if not pcap.exists():
        return {
            "status": "missing_pcap",
            "pcap": pcap_path,
            "candidate_count": len(candidates),
            "matched": 0,
            "flows_scanned": 0,
            "remaining": len(pending),
            "materialized_paths": materialized_paths,
            "materialized_flow_hashes": materialized_flow_hashes,
            "zero_packet_flow_hashes": zero_packet_flow_hashes,
            "temporal_context_missing_flow_hashes": temporal_context_missing_flow_hashes,
            "local_temporal_fallback_flow_hashes": local_temporal_fallback_flow_hashes,
            "class_counts": {},
            "source_counts": {},
            "safety_summary": {},
            "safety_samples": [],
        }

    try:
        for flows_scanned, flow_record in enumerate(
            iter_flow_records(
                pcap,
                "office_materialization_worker",
                flow_key_filter=set(tuple_to_candidates),
                temporal_mode="calculate" if allow_local_temporal_fallback else "disabled",
            ),
            start=1,
        ):
            if flows_scanned % max(config.PCAP_MEMORY_CHECK_INTERVAL, 1) == 0:
                office_assert_memory_available(f"worker scanning {pcap.name} at flow {flows_scanned}")
            if max_flows_per_pcap > 0 and flows_scanned > max_flows_per_pcap:
                stop_reason = "max_flows_per_pcap_reached"
                break
            possible = tuple_to_candidates.get(flow_tuple_parts(flow_record), [])
            if not possible:
                continue
            flow_timestamp = float(flow_record.get("timestamp", 0.0) or 0.0)
            for candidate in list(possible):
                flow_hash = str(candidate["flow_hash"])
                if flow_hash not in pending:
                    continue
                candidate_ts = candidate_timestamp_seconds(candidate)
                if candidate_ts is not None and abs(flow_timestamp - candidate_ts) > timestamp_tolerance_seconds:
                    continue
                temporal_features = candidate.get("temporal_features") or candidate.get("precomputed_temporal_features")
                temporal_context_status = str(candidate.get("temporal_context_status", "full" if isinstance(temporal_features, dict) else ""))
                if not isinstance(temporal_features, dict):
                    fallback_features = flow_record.get("temporal_features") if allow_local_temporal_fallback else None
                    if isinstance(fallback_features, dict):
                        temporal_features = {str(key): float(value) for key, value in fallback_features.items()}
                        temporal_context_status = "local_worker_fallback"
                        local_temporal_fallback_flow_hashes.append(flow_hash)
                        safety_summary["LOCAL_TEMPORAL_CONTEXT_FALLBACK"] += 1
                    else:
                        pending.pop(flow_hash, None)
                        matched += 1
                        temporal_context_missing_flow_hashes.append(flow_hash)
                        safety_summary["TEMPORAL_CONTEXT_MISSING"] += 1
                        if len(safety_samples) < 25:
                            safety_samples.append(
                                {
                                    "flow_hash": flow_hash,
                                    "class_name": candidate.get("class_name"),
                                    "day": candidate.get("day"),
                                    "reason": "TEMPORAL_CONTEXT_MISSING",
                                }
                            )
                        continue
                compact = build_compact_graph_record(
                    flow_record["flow_features"],
                    temporal_features,
                    flow_record["packet_records"],
                    int(candidate["class_index"]),
                    str(candidate.get("gt_subtype") or candidate.get("label") or candidate["class_name"]),
                    str(candidate["class_name"]),
                    str(flow_record[config.SOURCE_FILE_COLUMN]),
                    int(flow_record[config.SOURCE_ORDER_COLUMN]),
                )
                pending.pop(flow_hash, None)
                matched += 1
                if compact is None:
                    zero_packet_flow_hashes.append(flow_hash)
                    safety_summary["matched_zero_packet_graph"] += 1
                    continue
                compact = enrich_compact_record(compact, candidate)
                compact["temporal_context_status"] = temporal_context_status
                stats = graph_record_stats(compact)
                flags = safety_flags(stats)
                if flags:
                    safety_summary["flagged_graphs"] += 1
                    if len(safety_samples) < 25:
                        safety_samples.append(
                            {
                                "flow_hash": flow_hash,
                                "class_name": candidate.get("class_name"),
                                "day": candidate.get("day"),
                                "source_dataset": candidate.get("source_dataset"),
                                "flags": flags,
                                "stats": stats,
                            }
                        )
                out_path = compact_path_for_candidate(candidate)
                if out_path.exists() and not overwrite:
                    materialized_paths[flow_hash] = str(out_path)
                    materialized_flow_hashes.append(flow_hash)
                    continue
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with out_path.open("wb") as handle:
                    pickle.dump(compact, handle, protocol=pickle.HIGHEST_PROTOCOL)
                materialized_paths[flow_hash] = str(out_path)
                materialized_flow_hashes.append(flow_hash)
                class_counts[str(candidate["class_name"])] += 1
                source_counts[str(candidate.get("source_dataset", candidate.get("source", "")))] += 1
            if not pending:
                break
    except Exception as exc:  # noqa: BLE001
        stop_reason = "worker_error"
        return {
            "status": stop_reason,
            "error": repr(exc),
            "pcap": pcap_path,
            "candidate_count": len(candidates),
            "matched": matched,
            "flows_scanned": flows_scanned,
            "remaining": len(pending),
            "materialized_paths": materialized_paths,
            "materialized_flow_hashes": materialized_flow_hashes,
            "zero_packet_flow_hashes": zero_packet_flow_hashes,
            "temporal_context_missing_flow_hashes": temporal_context_missing_flow_hashes,
            "local_temporal_fallback_flow_hashes": local_temporal_fallback_flow_hashes,
            "class_counts": dict(class_counts),
            "source_counts": dict(source_counts),
            "safety_summary": dict(safety_summary),
            "safety_samples": safety_samples,
        }

    return {
        "status": "completed" if stop_reason == "completed" else stop_reason,
        "pcap": pcap_path,
        "candidate_count": len(candidates),
        "matched": matched,
        "flows_scanned": flows_scanned,
        "remaining": len(pending),
        "materialized_paths": materialized_paths,
        "materialized_flow_hashes": materialized_flow_hashes,
        "zero_packet_flow_hashes": zero_packet_flow_hashes,
        "temporal_context_missing_flow_hashes": temporal_context_missing_flow_hashes,
        "local_temporal_fallback_flow_hashes": local_temporal_fallback_flow_hashes,
        "class_counts": dict(class_counts),
        "source_counts": dict(source_counts),
        "safety_summary": dict(safety_summary),
        "safety_samples": safety_samples,
    }


def run_office_materialization_worker(
    *,
    pcap_path: str,
    candidates_path: Path,
    summary_path: Path,
    overwrite: bool,
    timestamp_tolerance_seconds: float,
    max_flows_per_pcap: int,
    allow_local_temporal_fallback: bool = False,
) -> dict[str, object]:
    candidates = read_candidate_jsonl(candidates_path)
    summary = materialize_office_pcap_candidates(
        pcap_path=pcap_path,
        candidates=candidates,
        overwrite=overwrite,
        timestamp_tolerance_seconds=timestamp_tolerance_seconds,
        max_flows_per_pcap=max_flows_per_pcap,
        allow_local_temporal_fallback=allow_local_temporal_fallback,
    )
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def build_office_compact_graph_manifest(
    *,
    limit_unique: int | None = None,
    overwrite: bool = False,
    timestamp_tolerance_seconds: float = 3.0,
    max_flows_per_pcap: int = 0,
    max_pcaps: int = 0,
    health_aware: bool = False,
    health_manifest_path: Path = OFFICE_COMPACT_MANIFEST_PATH,
    health_min_yield: float = 0.05,
    target_classes: set[str] | None = None,
    temporal_index_path: Path | None = None,
    allow_local_temporal_fallback: bool = False,
) -> dict[str, object]:
    ensure_directories()
    if limit_unique is None and not OFFICE_ALLOW_FULL_MATERIALIZATION:
        raise RuntimeError(
            "Refusing to start full office graph materialization inside the interactive workspace. "
            "Run a bounded pilot with --office-limit-unique and --office-max-pcaps first. "
            "For a controlled full batch run, set SECUREEDGE_ALLOW_FULL_OFFICE_MATERIALIZATION=1."
        )
    office_assert_memory_available("office materialization startup")
    pcap_health = (
        load_office_pcap_health_skips(
            health_manifest_path=health_manifest_path,
            min_yield=health_min_yield,
        )
        if health_aware
        else {
            "enabled": False,
            "manifest_path": str(health_manifest_path),
            "status": "disabled",
            "skip_pcaps": [],
            "skip_reasons": {},
        }
    )
    health_skip_pcaps = {str(path) for path in pcap_health.get("skip_pcaps", [])}
    materialized_identity_index: dict[str, str] = {}
    done_registry_count = 0
    if not overwrite:
        materialized_identity_index = load_office_materialized_identity_index()
        done_registry = DoneRegistry(DEFAULT_DONE_REGISTRY_PATH)
        done_registry_count = len(done_registry)
    candidates = load_office_materialization_candidates(
        limit_unique=limit_unique,
        max_primary_pcaps=max_pcaps,
        excluded_primary_pcaps=health_skip_pcaps,
        target_classes=target_classes,
        materialized_identities=set(materialized_identity_index),
    )
    if temporal_index_path is not None and not temporal_index_path.exists():
        raise FileNotFoundError(f"Office temporal index not found: {temporal_index_path}")
    temporal_index = load_temporal_index(temporal_index_path) if temporal_index_path is not None else None
    if overwrite and OFFICE_COMPACT_GRAPH_DIR.exists():
        shutil.rmtree(OFFICE_COMPACT_GRAPH_DIR)
    OFFICE_COMPACT_GRAPH_DIR.mkdir(parents=True, exist_ok=True)
    OFFICE_MATERIALIZATION_WORK_DIR.mkdir(parents=True, exist_ok=True)
    OFFICE_PCAP_SLICE_DIR.mkdir(parents=True, exist_ok=True)

    candidate_by_hash = {str(candidate["flow_hash"]): candidate for candidate in candidates}
    missing_by_hash = dict(candidate_by_hash)
    existing_paths: dict[str, Path] = {}
    for flow_hash, candidate in list(missing_by_hash.items()):
        path = compact_path_for_candidate(candidate)
        if path.exists() and not overwrite:
            existing_paths[flow_hash] = path
            missing_by_hash.pop(flow_hash, None)

    by_work_item: dict[tuple[str, bool], list[dict[str, object]]] = defaultdict(list)
    for candidate in missing_by_hash.values():
        for path in candidate_endpoint_paths(candidate):
            if path in health_skip_pcaps:
                continue
            by_work_item[(path, office_candidate_requires_preslice(candidate))].append(candidate)

    materialized_paths: dict[str, str] = {flow_hash: str(path) for flow_hash, path in existing_paths.items()}
    pcap_summaries: dict[str, object] = {}
    safety_summary: Counter[str] = Counter()
    safety_samples: list[dict[str, object]] = []
    class_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    deferred_pcaps: list[dict[str, object]] = []
    stop_reason = "completed"
    processed_pcaps = 0

    pcap_order = sorted(by_work_item.items(), key=lambda item: (-len(item[1]), item[0][0], item[0][1]))
    for (pcap_path, needs_preslice), pcap_candidates in pcap_order:
        if not missing_by_hash:
            break
        if max_pcaps > 0 and processed_pcaps >= max_pcaps:
            stop_reason = "max_pcaps_reached"
            break
        pending = [candidate for candidate in pcap_candidates if str(candidate["flow_hash"]) in missing_by_hash]
        pending = attach_candidate_temporal_features(
            pending,
            temporal_index,
            tolerance_ms=int(round(timestamp_tolerance_seconds * 1000.0)),
        )
        if not pending:
            continue
        processed_pcaps += 1
        summary_key = f"{pcap_path}::presliced" if needs_preslice else pcap_path
        worker_pcap_path = pcap_path
        preslice_summary: dict[str, object] | None = None
        if needs_preslice:
            preslice_summary = build_office_presliced_pcap(
                pcap_path=pcap_path,
                candidates=pending,
                overwrite=overwrite,
            )
            preslice_status = str(preslice_summary.get("status", "preslice_unknown"))
            if preslice_status not in {"preslice_completed", "preslice_completed_with_warning", "preslice_reused"}:
                pcap_summaries[summary_key] = preslice_summary
                deferred_pcaps.append(
                    {
                        "pcap": pcap_path,
                        "status": preslice_status,
                        "error": str(preslice_summary.get("error", "")),
                        "candidate_count": len(pending),
                        "matched": 0,
                        "flows_scanned": 0,
                        "remaining": len(pending),
                    }
                )
                continue
            worker_pcap_path = str(preslice_summary["worker_pcap"])
        work_id = office_work_id_for_pcap(summary_key)
        candidate_path = OFFICE_MATERIALIZATION_WORK_DIR / f"{work_id}.candidates.jsonl"
        summary_path = OFFICE_MATERIALIZATION_WORK_DIR / f"{work_id}.summary.json"
        write_jsonl(candidate_path, pending)
        command = [
            sys.executable,
            "-m",
            "secureedge.data.office_pipeline",
            "--mode",
            "office-materialize-pcap-worker",
            "--office-worker-pcap",
            worker_pcap_path,
            "--office-worker-candidates",
            str(candidate_path),
            "--office-worker-summary",
            str(summary_path),
            "--office-timestamp-tolerance-seconds",
            str(timestamp_tolerance_seconds),
            "--office-max-flows-per-pcap",
            str(max_flows_per_pcap),
        ]
        if allow_local_temporal_fallback:
            command.append("--office-allow-local-temporal-fallback")
        if overwrite:
            command.append("--office-overwrite-compact")
        try:
            subprocess.run(
                command,
                check=True,
                env=office_worker_env(),
                timeout=config.PCAP_WORKER_TIMEOUT_SECONDS,
                preexec_fn=office_worker_limits if not config.ALLOW_UNSAFE_PREPROCESS else None,
            )
        except subprocess.TimeoutExpired as exc:
            status = "worker_timeout"
            pcap_summaries[summary_key] = {
                "status": status,
                "error": str(exc),
                "pcap": pcap_path,
                "worker_pcap": worker_pcap_path,
                "candidate_count": len(pending),
            }
            deferred_pcaps.append(
                {
                    "pcap": pcap_path,
                    "worker_pcap": worker_pcap_path,
                    "status": status,
                    "error": str(exc),
                    "candidate_count": len(pending),
                    "matched": 0,
                    "flows_scanned": 0,
                    "remaining": len(pending),
                }
            )
            continue
        except subprocess.CalledProcessError as exc:
            status = "worker_failed"
            pcap_summaries[summary_key] = {
                "status": status,
                "returncode": exc.returncode,
                "pcap": pcap_path,
                "worker_pcap": worker_pcap_path,
                "candidate_count": len(pending),
                "summary_path": str(summary_path),
            }
            deferred_pcaps.append(
                {
                    "pcap": pcap_path,
                    "worker_pcap": worker_pcap_path,
                    "status": status,
                    "error": f"returncode={exc.returncode}",
                    "candidate_count": len(pending),
                    "matched": 0,
                    "flows_scanned": 0,
                    "remaining": len(pending),
                }
            )
            continue
        if not summary_path.exists():
            status = "worker_missing_summary"
            pcap_summaries[summary_key] = {
                "status": status,
                "pcap": pcap_path,
                "worker_pcap": worker_pcap_path,
                "candidate_count": len(pending),
                "summary_path": str(summary_path),
            }
            deferred_pcaps.append(
                {
                    "pcap": pcap_path,
                    "worker_pcap": worker_pcap_path,
                    "status": status,
                    "error": "",
                    "candidate_count": len(pending),
                    "matched": 0,
                    "flows_scanned": 0,
                    "remaining": len(pending),
                }
            )
            continue
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if preslice_summary is not None:
            summary["original_pcap"] = pcap_path
            summary["worker_pcap"] = worker_pcap_path
            summary["preslice"] = preslice_summary
        pcap_summaries[summary_key] = summary
        materialized_paths.update({str(key): str(value) for key, value in summary.get("materialized_paths", {}).items()})
        for flow_hash in summary.get("materialized_flow_hashes", []):
            missing_by_hash.pop(str(flow_hash), None)
        for flow_hash in summary.get("zero_packet_flow_hashes", []):
            missing_by_hash.pop(str(flow_hash), None)
        class_counts.update(Counter({str(key): int(value) for key, value in summary.get("class_counts", {}).items()}))
        source_counts.update(Counter({str(key): int(value) for key, value in summary.get("source_counts", {}).items()}))
        safety_summary.update(Counter({str(key): int(value) for key, value in summary.get("safety_summary", {}).items()}))
        if len(safety_samples) < 25:
            safety_samples.extend(list(summary.get("safety_samples", []))[: 25 - len(safety_samples)])
        office_assert_memory_available(f"after worker for {Path(pcap_path).name}")
        summary_status = str(summary.get("status", "worker_noncompleted"))
        summary_error = str(summary.get("error", ""))
        deferable = summary_status in {"missing_pcap", "max_flows_per_pcap_reached", "worker_error"}
        if summary_status != "completed" and deferable:
            deferred_pcaps.append(
                {
                    "pcap": pcap_path,
                    "worker_pcap": worker_pcap_path,
                    "status": summary_status,
                    "error": summary_error,
                    "candidate_count": len(pending),
                    "matched": int(summary.get("matched", 0) or 0),
                    "flows_scanned": int(summary.get("flows_scanned", 0) or 0),
                    "remaining": int(summary.get("remaining", len(pending)) or 0),
                }
            )
            continue
        if summary_status != "completed":
            stop_reason = summary_status
            break

    if stop_reason == "completed" and deferred_pcaps and missing_by_hash:
        stop_reason = "completed_with_deferred_pcaps"

    manifest = {
        "pipeline": "office_model_compact_graph_materialization",
        "compact_dir": str(OFFICE_COMPACT_GRAPH_DIR),
        "split_manifest": str(OFFICE_FINAL_SPLIT_MANIFEST_PATH),
        "limit_unique": limit_unique,
        "overwrite": overwrite,
        "timestamp_tolerance_seconds": timestamp_tolerance_seconds,
        "temporal_index_path": str(temporal_index_path) if temporal_index_path is not None else None,
        "temporal_index_loaded": temporal_index is not None,
        "allow_local_temporal_fallback": allow_local_temporal_fallback,
        "max_flows_per_pcap": max_flows_per_pcap,
        "max_pcaps": max_pcaps,
        "target_classes": sorted(target_classes) if target_classes else [],
        "done_registry": {
            "path": str(DEFAULT_DONE_REGISTRY_PATH),
            "registered_candidate_count": done_registry_count,
            "cumulative_manifest_path": str(DEFAULT_CUMULATIVE_PATH),
            "skipped_materialized_identity_count": len(materialized_identity_index),
            "enabled": not overwrite,
        },
        "processed_pcaps": processed_pcaps,
        "pcap_health": pcap_health,
        "candidate_selection": "primary_endpoint_candidate_density_desc_bounded_round_robin",
        "pcap_worker_order": "pending_candidate_density_desc",
        "pcap_density_preview": [
            {"pcap": key[0], "presliced": key[1], "pending_candidates": len(group)}
            for key, group in pcap_order[:25]
        ],
        "deferred_pcaps": deferred_pcaps,
        "full_materialization_allowed": OFFICE_ALLOW_FULL_MATERIALIZATION,
        "requested_unique_candidates": len(candidates),
        "materialized_or_existing": len(materialized_paths),
        "newly_materialized_class_counts": dict(class_counts),
        "newly_materialized_source_counts": dict(source_counts),
        "missing_count": len(missing_by_hash),
        "missing_flow_hashes_sample": sorted(missing_by_hash)[:50],
        "pcap_summaries": pcap_summaries,
        "safety_summary": dict(safety_summary),
        "safety_samples": safety_samples,
        "stop_reason": stop_reason,
        "materialized_paths_by_flow_hash": materialized_paths,
    }
    OFFICE_COMPACT_MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_office_compact_context(manifest: dict[str, object]) -> None:
    write_context(
        "74_office_compact_graph_materialization.md",
        "Office Compact Graph Materialization",
        [
            "## Action",
            "- Materialized office-model compact graph records from final split candidates.",
            "- Matched candidate flows by endpoint PCAP, 5-tuple, and timestamp tolerance.",
            "- Ordered bounded pilots by endpoint-PCAP candidate density to reduce one-graph full-PCAP scans.",
            "- Deferred max-flow and memory-floor PCAP stops instead of letting one worst-case scan end the whole pilot.",
            "- Recomputed 92 flow-node features from matched packets via NFStream-derived records.",
            "- Logged per-graph numerical and payload safety flags while building records.",
            f"- Saved compact graph manifest to `{OFFICE_COMPACT_MANIFEST_PATH}`.",
            "",
            "## Counts",
            "```json",
            json.dumps(
                {
                    "requested_unique_candidates": manifest["requested_unique_candidates"],
                    "materialized_or_existing": manifest["materialized_or_existing"],
                    "missing_count": manifest["missing_count"],
                    "stop_reason": manifest["stop_reason"],
                    "newly_materialized_class_counts": manifest["newly_materialized_class_counts"],
                    "newly_materialized_source_counts": manifest["newly_materialized_source_counts"],
                    "processed_pcaps": manifest["processed_pcaps"],
                    "deferred_pcaps": manifest["deferred_pcaps"],
                    "pcap_health": manifest["pcap_health"],
                    "safety_summary": manifest["safety_summary"],
                },
                indent=2,
            ),
            "```",
            "",
            "## Safety Samples",
            "```json",
            json.dumps(manifest["safety_samples"], indent=2, sort_keys=True),
            "```",
        ],
    )


def write_open_flow_diagnostic_context(manifest: dict[str, object]) -> None:
    reports = manifest.get("reports", [])
    tail_reports = reports[-5:] if isinstance(reports, list) else []
    write_context(
        "77_office_open_flow_memory_diagnostic.md",
        "Office Open-Flow Memory Diagnostic",
        [
            "## Action",
            "- Ran a packet-level approximation of NFStream's simultaneously-open flow table.",
            "- Used the same `idle_timeout` and `active_timeout` values for expiry pressure, without changing NFStream extraction settings.",
            f"- Saved diagnostic JSON to `{OFFICE_OPEN_FLOW_DIAGNOSTIC_PATH}`.",
            "",
            "## Summary",
            "```json",
            json.dumps(
                {
                    "pcap": manifest["pcap"],
                    "transport_packets_scanned": manifest["transport_packets_scanned"],
                    "elapsed_seconds": manifest["elapsed_seconds"],
                    "opened_flows": manifest["opened_flows"],
                    "expired_flows": manifest["expired_flows"],
                    "active_flows_at_scan_end": manifest["active_flows_at_scan_end"],
                    "max_active_flows": manifest["max_active_flows"],
                    "protocol_counts": manifest["protocol_counts"],
                    "final_process_rss_gb": manifest["final_process_rss_gb"],
                    "final_available_memory_gb": manifest["final_available_memory_gb"],
                },
                indent=2,
            ),
            "```",
            "",
            "## Last Reports",
            "```json",
            json.dumps(tail_reports, indent=2),
            "```",
        ],
    )


def write_nfstream_rss_diagnostic_context(manifest: dict[str, object]) -> None:
    reports = manifest.get("reports", [])
    tail_reports = reports[-8:] if isinstance(reports, list) else []
    write_context(
        "79_office_nfstream_rss_diagnostic.md",
        "Office NFStream RSS Diagnostic",
        [
            "## Action",
            "- Ran real NFStream extraction with the configured plugins, without candidate matching or graph construction.",
            "- Logged process RSS and available system memory at bounded flow intervals.",
            "- Kept the diagnostic bounded; this was not a larger materialization run.",
            f"- Saved diagnostic JSON to `{OFFICE_NFSTREAM_RSS_DIAGNOSTIC_PATH}`.",
            "",
            "## Summary",
            "```json",
            json.dumps(
                {
                    "pcap": manifest["pcap"],
                    "status": manifest["status"],
                    "error": manifest["error"],
                    "flows_scanned": manifest["flows_scanned"],
                    "packet_records_seen": manifest["packet_records_seen"],
                    "retained_payload_bytes_seen": manifest["retained_payload_bytes_seen"],
                    "final_rss_gb": manifest["final_rss_gb"],
                    "peak_rss_gb": manifest["peak_rss_gb"],
                    "rss_delta_from_first_report_gb": manifest["rss_delta_from_first_report_gb"],
                    "final_available_memory_gb": manifest["final_available_memory_gb"],
                },
                indent=2,
            ),
            "```",
            "",
            "## Last Reports",
            "```json",
            json.dumps(tail_reports, indent=2),
            "```",
        ],
    )


def write_infiltration_payload_audit_context(manifest: dict[str, object]) -> None:
    sample_audits = list(manifest.get("audits", []))[:10]
    write_context(
        "80_office_infiltration_payload_audit.md",
        "Office Infiltration Payload Audit",
        [
            "## Action",
            "- Audited materialized Infiltration compact graphs that were flagged for payload nonzero-fraction outliers.",
            "- Checked retained payload bytes, packet edge payload sizes, candidate endpoint evidence, and the `172.31.69.13` attack-window rule.",
            "- Classified zero-payload TCP-control graphs as scan/probe-like only when graph and candidate evidence aligned.",
            f"- Saved audit JSON to `{OFFICE_INFILTRATION_PAYLOAD_AUDIT_PATH}`.",
            "",
            "## Summary",
            "```json",
            json.dumps(
                {
                    "graphs_audited": manifest["graphs_audited"],
                    "candidate_missing": manifest["candidate_missing"],
                    "decision_counts": manifest["decision_counts"],
                    "payload_size_counts": manifest["payload_size_counts"],
                    "endpoint_counts": manifest["endpoint_counts"],
                    "packet_node_counts": manifest["packet_node_counts"],
                },
                indent=2,
                sort_keys=True,
            ),
            "```",
            "",
            "## Sample Audits",
            "```json",
            json.dumps(sample_audits, indent=2, sort_keys=True),
            "```",
        ],
    )


def write_readable_graph_samples_context(manifest: dict[str, object]) -> None:
    write_context(
        "83_office_readable_graph_samples.md",
        "Office Readable Graph Samples",
        [
            "## Action",
            "- Exported compact office graph records into Markdown files for project documentation.",
            "- Each readable graph includes identity metadata, graph shape/safety stats, top flow features, packet nodes, contain-edge attributes, and packet-link edges.",
            f"- Output directory: `{OFFICE_READABLE_SAMPLE_DIR}`.",
            f"- Manifest: `{OFFICE_READABLE_SAMPLE_MANIFEST_PATH}`.",
            "",
            "## Counts",
            "```json",
            json.dumps(
                {
                    "samples_per_class_requested": manifest["samples_per_class_requested"],
                    "per_class_counts": manifest["per_class_counts"],
                    "missing_classes": manifest["missing_classes"],
                    "sample_count": manifest["sample_count"],
                },
                indent=2,
                sort_keys=True,
            ),
            "```",
        ],
    )


def build_preflight_manifest(max_rows: int | None = None, keep_per_class: int = 25) -> dict[str, object]:
    ensure_directories()
    OFFICE_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    days: dict[str, object] = {}
    for spec in OFFICE_DAY_SPECS:
        lookup = build_ip_to_pcap_lookup(spec.day)
        scan = scan_improved_csv(spec.day, max_rows=max_rows, keep_per_class=keep_per_class)
        days[spec.day] = {
            "spec": asdict(spec),
            "improved_csv": str(improved_csv_path(spec.day)),
            "original_csv": str(original_csv_path(spec.day)),
            "raw_pcap_dir": str(raw_pcap_day_dir(spec.day)),
            "pcap_file_count": sum(len(paths) for paths in lookup.values()),
            "pcap_ip_count": len(lookup),
            "duplicate_ip_capture_count": sum(1 for paths in lookup.values() if len(paths) > 1),
            "scan": scan,
        }
    manifest = {
        "pipeline": "office_model_graph_generation",
        "status": "preflight_manifest",
        "target_graphs_per_class": 20000,
        "classes": OFFICE_CLASS_NAMES,
        "attack_classes": OFFICE_ATTACK_CLASSES,
        "dataset_root": str(OFFICE_DATASET_ROOT),
        "improved_csv_dir": str(OFFICE_IMPROVED_CSV_DIR),
        "raw_pcap_dir": str(OFFICE_RAW_PCAP_DIR),
        "days": days,
        "known_blockers": [
            "Full PCAP graph extraction is intentionally not started by preflight; run it only after manifest counts and label gates pass.",
            "CICIDS2017 WebBased augmentation is still not merged into the CIC-IDS2018 candidate manifest.",
        ],
    }
    path = OFFICE_ARTIFACT_DIR / "preflight_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def write_preflight_context(manifest: dict[str, object]) -> None:
    rows = []
    for day, info in manifest["days"].items():
        scan = info["scan"]
        rows.append(
            [
                day,
                info["pcap_file_count"],
                info["pcap_ip_count"],
                scan["rows_scanned"],
                scan["scan_limited"],
                scan["accepted_by_class"],
                scan["excluded_by_class"],
            ]
        )
    lines = [
        "## Action",
        "- Added the office-network graph generation preflight pipeline.",
        "- Registered the final seven-class office taxonomy: `Benign`, `BruteForce`, `DoS`, `DDoS`, `WebBased`, `Bot`, `Infiltration`.",
        "- Verified the improved CIC-IDS2018 CSV directory and per-day raw PCAP directory layout.",
        "- Built per-day IP-to-capture-file lookup counts from `datasets/cic_ids_2018/raw_pcaps/<day>/pcap`.",
        "- Added streaming improved-CSV scanning with corrected-label exclusion handling for `Attempted` labels and documented BruteForce contamination rules.",
        "- Added the IP/time-window cross-check gate from `office-model-pretraining-checklist.md`.",
        "- Did not start full PCAP graph extraction; that remains gated by candidate-manifest checks, pilot extraction, and memory/runtime controls.",
        "",
        "## Preflight Manifest",
        f"- JSON: `{OFFICE_ARTIFACT_DIR / 'preflight_manifest.json'}`",
        "",
        "## Per-Day Summary",
        "",
        "| Day | PCAP files | PCAP IPs | Rows scanned | Limited | Accepted by class | Excluded by class |",
        "|---|---:|---:|---:|---|---|---|",
    ]
    for day, pcap_files, pcap_ips, scanned, limited, accepted, excluded in rows:
        lines.append(
            f"| {day} | {pcap_files} | {pcap_ips} | {scanned} | `{limited}` | `{json.dumps(accepted, sort_keys=True)}` | `{json.dumps(excluded, sort_keys=True)}` |"
        )
    lines.extend(
        [
            "",
            "## Blocking Items Before Full Extraction",
            "",
            "- Run and inspect `ip-time-crosscheck` for full-day CSV/IP-time disagreements.",
            "- Run a bounded extraction pilot for one day/class before any full six-day run.",
            "- Keep CICIDS2017 WebBased augmentation source-tagged and train-only.",
        ]
    )
    write_context(f"{OFFICE_CONTEXT_PREFIX}.md", "Office Model Graph Generation Preflight", lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Office-network CIC-IDS graph-generation preflight pipeline.")
    parser.add_argument(
        "--mode",
        choices=(
            "preflight",
            "candidate-manifest",
            "ip-time-crosscheck",
            "pilot-extract",
            "webbased-attempted-check",
            "cicids2017-webbased-augment",
            "office-final-splits",
            "office-materialize-compact",
            "office-materialize-pcap-worker",
            "office-open-flow-diagnostic",
            "office-nfstream-rss-diagnostic",
            "office-infiltration-payload-audit",
            "office-readable-graph-samples",
        ),
        default="preflight",
        help="Run a lightweight preflight scan, build candidate flow JSONL manifests, or audit labels against IP/time windows.",
    )
    parser.add_argument("--max-rows", type=int, default=0, help="Limit CSV scan rows per day. 0 means full scan.")
    parser.add_argument("--keep-per-class", type=int, default=25, help="Sample accepted flow keys to keep per class.")
    parser.add_argument("--target-per-class", type=int, default=20000)
    parser.add_argument("--pilot-class", action="append", default=None, help="Class to include in bounded pilot extraction.")
    parser.add_argument("--pilot-target-per-class", type=int, default=3)
    parser.add_argument("--pilot-max-flows-per-pcap", type=int, default=200000)
    parser.add_argument("--pilot-timestamp-tolerance-seconds", type=float, default=3.0)
    parser.add_argument("--web-attempt-max-flows-per-pcap", type=int, default=250000)
    parser.add_argument("--cicids2017-max-flows-per-pcap", type=int, default=120000)
    parser.add_argument("--cicids2017-timestamp-tolerance-seconds", type=float, default=3.0)
    parser.add_argument("--cicids2017-include-sql", action="store_true")
    parser.add_argument("--office-limit-unique", type=int, default=0, help="Limit unique candidates for office compact materialization pilot runs.")
    parser.add_argument("--office-overwrite-compact", action="store_true", help="Delete existing office compact records before materialization.")
    parser.add_argument("--office-max-flows-per-pcap", type=int, default=0, help="Optional per-PCAP NFStream flow scan cap. 0 means no cap.")
    parser.add_argument("--office-max-pcaps", type=int, default=0, help="Limit number of endpoint PCAP workers for bounded office pilots. 0 means no cap.")
    parser.add_argument("--office-timestamp-tolerance-seconds", type=float, default=3.0)
    parser.add_argument("--office-target-class", action="append", choices=OFFICE_CLASS_NAMES, default=None, help="Restrict office compact materialization to one class. Repeat for multiple classes.")
    parser.add_argument("--office-health-aware", action="store_true", help="Skip/deprioritize PCAPs marked unhealthy by a previous office compact manifest.")
    parser.add_argument("--office-health-manifest", default=str(OFFICE_COMPACT_MANIFEST_PATH), help="Previous office compact manifest used for PCAP-health skips.")
    parser.add_argument("--office-health-min-yield", type=float, default=0.05, help="Skip previous PCAPs whose matched/candidate yield is below this threshold.")
    parser.add_argument("--office-temporal-index", default="", help="Precomputed full-context temporal index JSON for office materialization.")
    parser.add_argument("--office-allow-local-temporal-fallback", action="store_true", help="Compute worker-local temporal features when no full temporal index match is available.")
    parser.add_argument("--office-worker-pcap", default="")
    parser.add_argument("--office-worker-candidates", default="")
    parser.add_argument("--office-worker-summary", default="")
    parser.add_argument("--office-diagnostic-pcap", default="")
    parser.add_argument("--office-diagnostic-max-packets", type=int, default=0)
    parser.add_argument("--office-diagnostic-report-interval", type=int, default=5000)
    parser.add_argument("--office-diagnostic-idle-timeout", type=float, default=0.0)
    parser.add_argument("--office-diagnostic-active-timeout", type=float, default=1800.0)
    parser.add_argument("--office-nfstream-rss-pcap", default="")
    parser.add_argument("--office-nfstream-rss-max-flows", type=int, default=0)
    parser.add_argument("--office-nfstream-rss-report-interval", type=int, default=250)
    parser.add_argument("--office-infiltration-audit-sample-limit", type=int, default=40)
    parser.add_argument("--office-readable-samples-per-class", type=int, default=10)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    max_rows = args.max_rows if args.max_rows > 0 else None
    if args.mode == "candidate-manifest":
        manifest = build_candidate_flow_manifest(max_rows_per_day=max_rows, target_per_class=args.target_per_class)
        write_candidate_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_ARTIFACT_DIR / "candidate_flow_manifest.json")}, indent=2))
    elif args.mode == "ip-time-crosscheck":
        manifest = build_ip_time_crosscheck_manifest(max_rows_per_day=max_rows, keep_samples_per_status=args.keep_per_class)
        write_ip_time_crosscheck_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_ARTIFACT_DIR / "ip_time_crosscheck_manifest.json")}, indent=2))
    elif args.mode == "pilot-extract":
        classes = tuple(args.pilot_class or ["WebBased"])
        manifest = build_pilot_extraction_manifest(
            classes=classes,
            target_per_class=args.pilot_target_per_class,
            max_flows_per_pcap=args.pilot_max_flows_per_pcap,
            timestamp_tolerance_seconds=args.pilot_timestamp_tolerance_seconds,
        )
        write_pilot_extraction_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_ARTIFACT_DIR / "pilot_extraction_manifest.json")}, indent=2))
    elif args.mode == "webbased-attempted-check":
        manifest = audit_webbased_attempted_payloads(max_flows_per_pcap=args.web_attempt_max_flows_per_pcap)
        write_webbased_attempted_payload_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_WEB_ATTEMPT_AUDIT_PATH)}, indent=2))
    elif args.mode == "cicids2017-webbased-augment":
        manifest = build_cicids2017_webbased_augmentation_manifest(
            include_sql=args.cicids2017_include_sql,
            max_flows_per_pcap=args.cicids2017_max_flows_per_pcap,
            timestamp_tolerance_seconds=args.cicids2017_timestamp_tolerance_seconds,
        )
        write_cicids2017_webbased_augmentation_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_2017_WEB_AUGMENT_PATH)}, indent=2))
    elif args.mode == "office-final-splits":
        manifest = build_office_final_candidate_split_manifest()
        write_office_final_split_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_FINAL_SPLIT_MANIFEST_PATH)}, indent=2))
    elif args.mode == "office-materialize-compact":
        manifest = build_office_compact_graph_manifest(
            limit_unique=args.office_limit_unique if args.office_limit_unique > 0 else None,
            overwrite=args.office_overwrite_compact,
            timestamp_tolerance_seconds=args.office_timestamp_tolerance_seconds,
            max_flows_per_pcap=args.office_max_flows_per_pcap,
            max_pcaps=args.office_max_pcaps,
            health_aware=args.office_health_aware,
            health_manifest_path=Path(args.office_health_manifest),
            health_min_yield=args.office_health_min_yield,
            target_classes=set(args.office_target_class or []),
            temporal_index_path=Path(args.office_temporal_index) if args.office_temporal_index else None,
            allow_local_temporal_fallback=args.office_allow_local_temporal_fallback,
        )
        write_office_compact_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_COMPACT_MANIFEST_PATH)}, indent=2))
    elif args.mode == "office-materialize-pcap-worker":
        if not args.office_worker_pcap or not args.office_worker_candidates or not args.office_worker_summary:
            raise ValueError("Worker mode requires --office-worker-pcap, --office-worker-candidates, and --office-worker-summary.")
        summary = run_office_materialization_worker(
            pcap_path=args.office_worker_pcap,
            candidates_path=Path(args.office_worker_candidates),
            summary_path=Path(args.office_worker_summary),
            overwrite=args.office_overwrite_compact,
            timestamp_tolerance_seconds=args.office_timestamp_tolerance_seconds,
            max_flows_per_pcap=args.office_max_flows_per_pcap,
            allow_local_temporal_fallback=args.office_allow_local_temporal_fallback,
        )
        print(json.dumps({"summary": args.office_worker_summary, "status": summary.get("status")}, indent=2))
    elif args.mode == "office-open-flow-diagnostic":
        if not args.office_diagnostic_pcap:
            raise ValueError("Diagnostic mode requires --office-diagnostic-pcap.")
        manifest = build_open_flow_diagnostic_manifest(
            pcap_path=Path(args.office_diagnostic_pcap),
            max_packets=args.office_diagnostic_max_packets,
            report_interval=args.office_diagnostic_report_interval,
            idle_timeout_seconds=args.office_diagnostic_idle_timeout if args.office_diagnostic_idle_timeout > 0 else None,
            active_timeout_seconds=args.office_diagnostic_active_timeout,
        )
        write_open_flow_diagnostic_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_OPEN_FLOW_DIAGNOSTIC_PATH)}, indent=2))
    elif args.mode == "office-nfstream-rss-diagnostic":
        if not args.office_nfstream_rss_pcap:
            raise ValueError("NFStream RSS diagnostic mode requires --office-nfstream-rss-pcap.")
        manifest = build_nfstream_rss_diagnostic_manifest(
            pcap_path=Path(args.office_nfstream_rss_pcap),
            max_flows=args.office_nfstream_rss_max_flows,
            report_interval=args.office_nfstream_rss_report_interval,
        )
        write_nfstream_rss_diagnostic_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_NFSTREAM_RSS_DIAGNOSTIC_PATH)}, indent=2))
    elif args.mode == "office-infiltration-payload-audit":
        manifest = audit_infiltration_payload_graphs(sample_limit=args.office_infiltration_audit_sample_limit)
        write_infiltration_payload_audit_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_INFILTRATION_PAYLOAD_AUDIT_PATH)}, indent=2))
    elif args.mode == "office-readable-graph-samples":
        manifest = export_office_readable_graph_samples(samples_per_class=args.office_readable_samples_per_class)
        write_readable_graph_samples_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_READABLE_SAMPLE_MANIFEST_PATH)}, indent=2))
    else:
        manifest = build_preflight_manifest(max_rows=max_rows, keep_per_class=args.keep_per_class)
        write_preflight_context(manifest)
        print(json.dumps({"manifest": str(OFFICE_ARTIFACT_DIR / "preflight_manifest.json")}, indent=2))


if __name__ == "__main__":
    main()
