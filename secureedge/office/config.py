from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from secureedge import config as root_config


DEFAULT_OFFICE_CONFIG_PATH = root_config.ROOT_DIR / "configs" / "office_cic_ids_2018.yaml"

TOP_LEVEL_KEYS = {
    "schema_version",
    "seed",
    "paths",
    "labels",
    "day_specs",
    "ddos_rotating_attackers",
    "bot_victims",
    "attack_windows",
    "cicids2017_web_attack_windows",
    "matching",
    "slicing",
    "materialization",
    "splits",
    "graph",
    "architecture_policy",
}


@dataclass(frozen=True)
class OfficeConfig:
    path: Path
    data: dict[str, Any]
    config_hash: str

    @property
    def schema_version(self) -> int:
        return int(self.data["schema_version"])

    @property
    def class_names(self) -> list[str]:
        return list(self.data["labels"]["classes"])

    @property
    def timestamp_offset_hours(self) -> int:
        return int(self.data["labels"]["timestamp_offset_hours"])

    @property
    def architecture_policy(self) -> dict[str, Any]:
        return dict(self.data["architecture_policy"])

    def resolve_path(self, key: str) -> Path:
        value = self.data["paths"][key]
        path = Path(str(value))
        if path.is_absolute():
            return path
        return root_config.ROOT_DIR / path

    def provenance(self) -> dict[str, Any]:
        return {
            "config_path": str(self.path),
            "config_hash": self.config_hash,
            "config_schema_version": self.schema_version,
        }


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    return value


def config_hash(data: dict[str, Any]) -> str:
    canonical = json.dumps(_canonicalize(data), sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()


def _expand_references(data: dict[str, Any]) -> dict[str, Any]:
    expanded = json.loads(json.dumps(data))
    replacements = {
        "${ddos_rotating_attackers}": expanded.get("ddos_rotating_attackers", []),
        "${bot_victims}": expanded.get("bot_victims", []),
    }
    for section_name in ("attack_windows", "cicids2017_web_attack_windows"):
        for window in expanded.get(section_name, []):
            for key in ("attacker_ips", "victim_ips"):
                value = window.get(key)
                if isinstance(value, str) and value in replacements:
                    window[key] = list(replacements[value])
    return expanded


def _validate_known_keys(data: dict[str, Any]) -> None:
    unknown = set(data) - TOP_LEVEL_KEYS
    missing = TOP_LEVEL_KEYS - set(data)
    if unknown:
        raise ValueError(f"Unknown office config top-level keys: {sorted(unknown)}")
    if missing:
        raise ValueError(f"Missing office config top-level keys: {sorted(missing)}")


def _validate_config(data: dict[str, Any]) -> None:
    _validate_known_keys(data)
    if int(data["schema_version"]) != 1:
        raise ValueError(f"Unsupported office config schema_version={data['schema_version']}")
    class_names = data["labels"]["classes"]
    if len(class_names) != len(set(class_names)):
        raise ValueError("Office class names must be unique")
    if data["architecture_policy"]["do_not_use"] != "SAGEConv":
        raise ValueError("Architecture policy must preserve the explicit SAGEConv rejection")
    if data["architecture_policy"]["future_attention_conv"] != "GATv2Conv":
        raise ValueError("Future attention convolution must be GATv2Conv")
    for key in ("paths", "labels", "matching", "slicing", "materialization", "splits", "graph"):
        if not isinstance(data[key], dict):
            raise ValueError(f"Office config section {key!r} must be a mapping")


def load_office_config(path: Path = DEFAULT_OFFICE_CONFIG_PATH) -> OfficeConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Office config {path} did not parse to a mapping")
    data = _expand_references(raw)
    _validate_config(data)
    return OfficeConfig(path=path, data=data, config_hash=config_hash(data))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect the CIC-IDS-2018 office configuration.")
    parser.add_argument("--config", type=Path, default=DEFAULT_OFFICE_CONFIG_PATH)
    parser.add_argument("--print-hash", action="store_true")
    parser.add_argument("--dump-json", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    office_config = load_office_config(args.config)
    if args.dump_json:
        print(json.dumps(office_config.data, indent=2, sort_keys=True))
    elif args.print_hash:
        print(office_config.config_hash)
    else:
        print(json.dumps(office_config.provenance(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
