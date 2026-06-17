from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secureedge import config


def ensure_directories() -> None:
    for path in (
        config.RAW_DATA_DIR,
        config.PCAP_CHUNK_DIR,
        config.PROCESSED_DIR,
        config.GRAPH_TRAIN_DIR,
        config.GRAPH_TEST_DIR,
        config.GRAPH_TRAIN_SHARD_DIR,
        config.GRAPH_TEST_SHARD_DIR,
        config.GRAPH_RESERVOIR_DIR,
        config.ARTIFACTS_DIR,
        config.TRAINING_RUNS_DIR,
        config.CONTEXT_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def write_context(filename: str, title: str, lines: list[str]) -> None:
    ensure_directories()
    path = config.CONTEXT_DIR / filename
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    body = [f"# {title}", "", f"Generated: `{timestamp}`", "", *lines, ""]
    path.write_text("\n".join(body), encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
