from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import torch

from secureedge import config
from secureedge.data.dataset import load_graph_manifest
from secureedge.utils import ensure_directories, write_context, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pack individual SecureEdge .pt graphs into larger shard files.")
    parser.add_argument("--graph-manifest", type=Path, default=config.GRAPH_MANIFEST_PATH)
    parser.add_argument("--output-root", type=Path, default=config.GRAPH_DIR)
    parser.add_argument("--manifest-path", type=Path, default=config.GRAPH_SHARD_MANIFEST_PATH)
    parser.add_argument("--shard-size", type=int, default=config.GRAPH_SHARD_SIZE)
    parser.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    parser.add_argument("--overwrite", action="store_true", help="Replace existing shard files.")
    parser.add_argument("--allow-incomplete-development-run", action="store_true")
    return parser.parse_args()


def split_manifest_paths(manifest: dict, split: str, class_names: list[str]) -> list[Path]:
    paths_by_class = manifest["splits"][split]["paths"]
    paths: list[Path] = []
    for class_name in class_names:
        paths.extend(Path(path) for path in paths_by_class.get(class_name, []))
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise FileNotFoundError(f"{split} manifest references missing graph files: {missing[:10]}")
    return paths


def prepare_output_dir(path: Path, overwrite: bool) -> None:
    path.mkdir(parents=True, exist_ok=True)
    existing = sorted(path.glob("shard_*.pt"))
    if existing and not overwrite:
        raise FileExistsError(f"{path} already contains shards. Use --overwrite to rebuild them.")
    for shard_path in existing:
        shard_path.unlink()


def create_split_shards(paths: list[Path], output_dir: Path, shard_size: int, seed: int, overwrite: bool) -> dict[str, object]:
    if shard_size < 1:
        raise ValueError("--shard-size must be at least 1")
    prepare_output_dir(output_dir, overwrite)
    shuffled = list(paths)
    random.Random(seed).shuffle(shuffled)

    shards: list[dict[str, object]] = []
    for shard_index, start in enumerate(range(0, len(shuffled), shard_size)):
        chunk = shuffled[start : start + shard_size]
        graphs = [torch.load(path, map_location="cpu", weights_only=False) for path in chunk]
        shard_path = output_dir / f"shard_{shard_index:04d}.pt"
        torch.save(graphs, shard_path)
        shards.append(
            {
                "path": str(shard_path),
                "count": len(graphs),
                "source_paths": [str(path) for path in chunk],
            }
        )
        print(f"[create_shards] wrote {shard_path} count={len(graphs)}")

    return {
        "output_dir": str(output_dir),
        "shard_size": shard_size,
        "total_graphs": len(shuffled),
        "shard_count": len(shards),
        "shards": shards,
    }


def create_shards(
    shard_size: int = config.GRAPH_SHARD_SIZE,
    seed: int = config.RANDOM_SEED,
    overwrite: bool = False,
    graph_manifest_path: Path = config.GRAPH_MANIFEST_PATH,
    output_root: Path = config.GRAPH_DIR,
    shard_manifest_path: Path = config.GRAPH_SHARD_MANIFEST_PATH,
    allow_incomplete_development_run: bool = False,
) -> dict:
    ensure_directories()
    manifest = load_graph_manifest(graph_manifest_path)
    if manifest.get("materialization_incomplete") and not allow_incomplete_development_run:
        raise ValueError(
            "Graph manifest is marked materialization_incomplete. "
            "Use --allow-incomplete-development-run only for explicit development shard builds."
        )
    class_names = [str(item) for item in manifest.get("class_names", config.CLASS_NAMES)]
    train_dir = output_root / "train_shards"
    val_dir = output_root / "val_shards"
    test_dir = output_root / "test_shards"
    train_dir.mkdir(parents=True, exist_ok=True)
    val_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    shard_manifest = {
        "source_manifest": str(graph_manifest_path),
        "source_manifest_hash": manifest.get("manifest_hash"),
        "seed": seed,
        "class_names": class_names,
        "feature_dimensions": manifest["feature_dimensions"],
        "splits": {
            "train": create_split_shards(
                split_manifest_paths(manifest, "train", class_names),
                train_dir,
                shard_size,
                seed,
                overwrite,
            ),
            "val": create_split_shards(
                split_manifest_paths(manifest, "val", class_names),
                val_dir,
                shard_size,
                seed + 1,
                overwrite,
            ),
            "test": create_split_shards(
                split_manifest_paths(manifest, "test", class_names),
                test_dir,
                shard_size,
                seed + 2,
                overwrite,
            ),
        },
    }
    write_json(shard_manifest_path, shard_manifest)
    write_context(
        "24_graph_sharding.md",
        "Graph Sharding",
        [
            "## Action",
            f"- Packed individual graph files into shard files of up to `{shard_size}` graphs.",
            f"- Train shards: `{shard_manifest['splits']['train']['shard_count']}`.",
            f"- Validation shards: `{shard_manifest['splits']['val']['shard_count']}`.",
            f"- Test shards: `{shard_manifest['splits']['test']['shard_count']}`.",
            f"- Source graph manifest: `{graph_manifest_path}`.",
            f"- Saved shard manifest to `{shard_manifest_path}`.",
            "",
            "## Counts",
            "```json",
            json.dumps(
                {
                    "train_graphs": shard_manifest["splits"]["train"]["total_graphs"],
                    "val_graphs": shard_manifest["splits"]["val"]["total_graphs"],
                    "test_graphs": shard_manifest["splits"]["test"]["total_graphs"],
                    "train_shards": shard_manifest["splits"]["train"]["shard_count"],
                    "val_shards": shard_manifest["splits"]["val"]["shard_count"],
                    "test_shards": shard_manifest["splits"]["test"]["shard_count"],
                },
                indent=2,
            ),
            "```",
        ],
    )
    return shard_manifest


def main() -> None:
    args = parse_args()
    manifest = create_shards(
        shard_size=args.shard_size,
        seed=args.seed,
        overwrite=args.overwrite,
        graph_manifest_path=args.graph_manifest,
        output_root=args.output_root,
        shard_manifest_path=args.manifest_path,
        allow_incomplete_development_run=args.allow_incomplete_development_run,
    )
    print(
        json.dumps(
            {
                "manifest": str(args.manifest_path),
                "train_shards": manifest["splits"]["train"]["shard_count"],
                "val_shards": manifest["splits"]["val"]["shard_count"],
                "test_shards": manifest["splits"]["test"]["shard_count"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
