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
    "imbalance",
    "graph",
    "architecture_policy",
}


@dataclass(frozen=True)
class AttackWindow:
    day: str
    subtype: str
    class_name: str
    attacker_ips: tuple[str, ...]
    victim_ips: tuple[str, ...]
    start: str
    finish: str


@dataclass(frozen=True)
class SplitTargets:
    standard_train: int
    standard_val: int
    standard_test: int
    standard_candidate_pool: int
    webbased_native_train: int
    webbased_cicids2017_train_only: int
    webbased_train_real: int
    webbased_train_target: int
    webbased_val: int
    webbased_test: int
    split_strategy: str


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
    def matching_tolerance_seconds(self) -> float:
        return float(self.data["matching"]["timestamp_tolerance_seconds"])

    @property
    def allow_reverse_direction(self) -> bool:
        return bool(self.data["matching"]["allow_reverse_direction"])

    @property
    def preslice_classes(self) -> set[str]:
        return {str(item) for item in self.data["slicing"]["preslice_classes"]}

    @property
    def preslice_time_window_seconds(self) -> float:
        return float(self.data["slicing"]["preslice_time_window_seconds"])

    @property
    def max_slice_mb(self) -> int:
        return int(self.data["slicing"]["max_slice_mb"])

    @property
    def materialization_batch_size(self) -> int:
        return int(self.data["materialization"]["batch_max_candidates"])

    @property
    def materialization_retry_count(self) -> int:
        return int(self.data["materialization"]["max_retries"])

    @property
    def worker_rss_cap_mb(self) -> int:
        return int(self.data["materialization"]["worker_rss_cap_mb"])

    @property
    def graph_feature_version(self) -> str:
        return str(self.data["graph"]["compact_feature_version"])

    @property
    def flow_feature_count(self) -> int:
        return int(self.data["graph"]["flow_features"])

    @property
    def packet_feature_count(self) -> int:
        return int(self.data["graph"]["packet_bytes"])

    @property
    def flow_packet_limit(self) -> int:
        return int(self.data["graph"]["flow_packet_limit"])

    @property
    def attack_windows(self) -> list[AttackWindow]:
        return [_attack_window_from_mapping(item) for item in self.data["attack_windows"]]

    @property
    def cicids2017_web_attack_windows(self) -> list[AttackWindow]:
        return [_attack_window_from_mapping(item) for item in self.data["cicids2017_web_attack_windows"]]

    @property
    def split_targets(self) -> SplitTargets:
        standard = self.data["splits"]["standard"]
        webbased = self.data["splits"]["webbased"]
        return SplitTargets(
            standard_train=int(standard["train"]),
            standard_val=int(standard["val"]),
            standard_test=int(standard["test"]),
            standard_candidate_pool=int(standard["candidate_pool"]),
            webbased_native_train=int(webbased["native_train"]),
            webbased_cicids2017_train_only=int(webbased["cicids2017_train_only"]),
            webbased_train_real=int(webbased["train_real"]),
            webbased_train_target=int(webbased["train_target"]),
            webbased_val=int(webbased["val"]),
            webbased_test=int(webbased["test"]),
            split_strategy=str(self.data["splits"]["split_strategy"]),
        )

    @property
    def architecture_policy(self) -> dict[str, Any]:
        return dict(self.data["architecture_policy"])

    @property
    def imbalance_policy(self) -> dict[str, Any]:
        return dict(self.data["imbalance"])

    def resolve_path(self, key: str) -> Path:
        value = self.data["paths"][key]
        path = Path(str(value))
        if path.is_absolute():
            return path
        return root_config.ROOT_DIR / path

    @property
    def dataset_root(self) -> Path:
        return self.resolve_path("dataset_root")

    @property
    def raw_pcaps_dir(self) -> Path:
        return self.resolve_path("raw_pcaps")

    @property
    def artifacts_dir(self) -> Path:
        return self.resolve_path("artifacts")

    @property
    def compact_root(self) -> Path:
        return self.resolve_path("compact_out")

    def provenance(self) -> dict[str, Any]:
        return {
            "config_path": str(self.path),
            "config_hash": self.config_hash,
            "config_schema_version": self.schema_version,
        }


def _attack_window_from_mapping(value: dict[str, Any]) -> AttackWindow:
    return AttackWindow(
        day=str(value["day"]),
        subtype=str(value["subtype"]),
        class_name=str(value["class_name"]),
        attacker_ips=tuple(str(item) for item in value.get("attacker_ips", [])),
        victim_ips=tuple(str(item) for item in value.get("victim_ips", [])),
        start=str(value["start"]),
        finish=str(value["finish"]),
    )


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
    if data["architecture_policy"]["current_attention_conv"] != "GATv2Conv":
        raise ValueError("Office training must use GATv2Conv for the current attention convolution")
    if data["architecture_policy"]["future_attention_conv"] != "GATv2Conv":
        raise ValueError("Future attention convolution must be GATv2Conv")
    for key in ("paths", "labels", "matching", "slicing", "materialization", "splits", "imbalance", "graph"):
        if not isinstance(data[key], dict):
            raise ValueError(f"Office config section {key!r} must be a mapping")
    loss_name = str(data["imbalance"].get("loss", {}).get("name", ""))
    if loss_name not in {"plain_cross_entropy", "cross_entropy", "weighted_cross_entropy"}:
        raise ValueError(f"Unsupported office imbalance loss: {loss_name!r}")
    sampler_method = str(data["imbalance"].get("balanced_batches", {}).get("method", ""))
    if sampler_method not in {"none", "weighted_random_sampler"}:
        raise ValueError(f"Unsupported office balanced batch method: {sampler_method!r}")


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
