from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Iterable

import torch

from secureedge import config


DEFAULT_OUTPUT_DIR = config.ARTIFACTS_DIR / "graph_visualizations"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a small number of SecureEdge HeteroData graph samples as SVG files."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Specific .pt graph files to render. If omitted, samples are selected from --split.",
    )
    parser.add_argument(
        "--split",
        choices=("train", "test"),
        default="train",
        help="Dataset split to sample from when explicit paths are omitted.",
    )
    parser.add_argument(
        "--class-name",
        choices=tuple(config.CLASS_NAMES),
        help="Optional class filter when sampling from a split.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=6,
        help="Maximum number of graphs to render. Kept small by default.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for SVG outputs and index.html.",
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="Include the first flow feature values in the side panel.",
    )
    return parser.parse_args()


def graph_paths_from_split(split: str, class_name: str | None, limit: int) -> list[Path]:
    graph_dir = config.GRAPH_TRAIN_DIR if split == "train" else config.GRAPH_TEST_DIR
    pattern = f"{class_name}_*.pt" if class_name else "*.pt"
    selected: list[Path] = []
    for path in sorted(graph_dir.glob(pattern)):
        selected.append(path)
        if len(selected) >= limit:
            break
    return selected


def sanitize_id(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)


def load_graph(path: Path):
    return torch.load(path, map_location="cpu", weights_only=False)


def edge_count(graph, edge_type: tuple[str, str, str]) -> int:
    if edge_type not in graph.edge_types:
        return 0
    return int(graph[edge_type].edge_index.shape[1])


def packet_color(packet_values) -> str:
    if packet_values.numel() == 0:
        return "#b7c4cf"
    mean_value = float(packet_values.mean().item())
    if mean_value < 0.02:
        return "#d7dee7"
    if mean_value < 0.10:
        return "#86b7fe"
    if mean_value < 0.25:
        return "#4dab8c"
    return "#f59f00"


def text(x: float, y: float, value: object, size: int = 13, weight: str = "400", anchor: str = "start") -> str:
    escaped = html.escape(str(value))
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="Inter, Arial, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" fill="#17202a">{escaped}</text>'
    )


def line(x1: float, y1: float, x2: float, y2: float, color: str, width: float = 2.0, dash: str = "") -> str:
    dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{color}" stroke-width="{width:.1f}" stroke-linecap="round"{dash_attr}/>'
    )


def rect(x: float, y: float, w: float, h: float, fill: str, stroke: str = "#334155", rx: float = 8.0) -> str:
    return (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx:.1f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>'
    )


def circle(cx: float, cy: float, r: float, fill: str, stroke: str = "#334155") -> str:
    return (
        f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="1.4"/>'
    )


def flow_feature_rows(graph, show_values: bool) -> list[str]:
    names = list(getattr(graph, "flow_feature_names", []))
    if not names:
        return ["flow_feature_names unavailable"]

    if not show_values:
        rows = names[:12]
        if len(names) > 12:
            rows.append(f"... {len(names) - 12} more flow/temporal features")
        return rows

    values = graph["flow"].x.squeeze(0).detach().cpu().tolist()
    rows = [f"{name}: {values[index]:.4g}" for index, name in enumerate(names[:14])]
    if len(names) > 14:
        rows.append(f"... {len(names) - 14} more feature values")
    return rows


def render_graph_svg(path: Path, graph, show_values: bool = False) -> str:
    n_packets = int(graph["packet"].x.shape[0])
    packet_spacing = 72
    flow_x = 82
    flow_y = 210
    packet_start_x = 212
    packet_y = 210
    width = max(980, packet_start_x + max(n_packets - 1, 0) * packet_spacing + 360)
    height = 520
    panel_x = width - 320

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#f8fafc"/>',
        text(32, 42, path.name, 22, "700"),
        text(32, 68, f"class={graph.class_name}  subtype={graph.subtype_label}  label={int(graph.y.item())}", 13),
        text(32, 90, f"source={Path(str(graph.source_file)).name}  source_order={graph.source_order}", 12),
    ]

    parts.extend(
        [
            rect(28, 120, panel_x - 56, 292, "#ffffff", "#cbd5e1", 8),
            rect(panel_x, 120, 288, 292, "#ffffff", "#cbd5e1", 8),
            text(48, 148, "Graph Structure", 16, "700"),
            text(panel_x + 20, 148, "Graph Data", 16, "700"),
        ]
    )

    packet_positions = [(packet_start_x + index * packet_spacing, packet_y) for index in range(n_packets)]
    for px, py in packet_positions:
        parts.append(line(flow_x + 34, flow_y, px - 17, py, "#64748b", 1.4, "5 5"))

    for index in range(max(0, n_packets - 1)):
        x1, y1 = packet_positions[index]
        x2, y2 = packet_positions[index + 1]
        parts.append(line(x1 + 17, y1 + 32, x2 - 17, y2 + 32, "#0f766e", 2.0))

    parts.append(rect(flow_x - 46, flow_y - 34, 92, 68, "#1d4ed8", "#1e3a8a", 10))
    parts.append(text(flow_x, flow_y - 5, "flow", 15, "700", "middle"))
    parts.append(text(flow_x, flow_y + 16, "92 features", 11, "400", "middle"))

    packet_values = graph["packet"].x.detach().cpu()
    for index, (px, py) in enumerate(packet_positions):
        color = packet_color(packet_values[index])
        parts.append(circle(px, py, 22, color))
        parts.append(text(px, py + 5, index, 12, "700", "middle"))

    parts.append(text(48, 304, "Dashed edges: flow contains packet", 12))
    parts.append(text(48, 324, "Green edges: packet temporal order", 12))
    parts.append(text(48, 344, "Packet color: average normalized byte intensity", 12))
    parts.append(text(48, 374, f"packets={n_packets}", 12, "700"))
    parts.append(text(48, 394, f"contains_edges={edge_count(graph, ('flow', 'contains', 'packet'))}", 12))
    parts.append(text(48, 414, f"rev_contains_edges={edge_count(graph, ('packet', 'rev_contains', 'flow'))}", 12))
    parts.append(text(48, 434, f"linked_to_edges={edge_count(graph, ('packet', 'linked_to', 'packet'))}", 12))

    parts.append(text(panel_x + 20, 176, f"flow tensor: {tuple(graph['flow'].x.shape)}", 12))
    parts.append(text(panel_x + 20, 196, f"packet tensor: {tuple(graph['packet'].x.shape)}", 12))
    parts.append(text(panel_x + 20, 216, f"edge types: {len(graph.edge_types)}", 12))
    parts.append(text(panel_x + 20, 244, "Feature preview", 13, "700"))

    y = 266
    for row in flow_feature_rows(graph, show_values):
        parts.append(text(panel_x + 20, y, row, 11))
        y += 17
        if y > 394:
            break

    parts.extend(
        [
            rect(28, 432, width - 56, 54, "#eef2ff", "#c7d2fe", 8),
            text(48, 459, "This is a per-flow heterogeneous graph: one flow node, packet payload nodes, contain edges, reverse contain edges, and packet-to-packet temporal links.", 12),
            text(48, 478, "Only the selected samples are rendered; the full dataset is not traversed unless you request a larger --limit.", 12),
            "</svg>",
        ]
    )
    return "\n".join(parts)


def write_index(output_dir: Path, rendered: Iterable[Path]) -> Path:
    rendered = list(rendered)
    links = "\n".join(
        f'<li><a href="{html.escape(path.name)}">{html.escape(path.name)}</a></li>' for path in rendered
    )
    index = output_dir / "index.html"
    index.write_text(
        "\n".join(
            [
                "<!doctype html>",
                '<html lang="en">',
                "<head>",
                '<meta charset="utf-8">',
                "<title>SecureEdge Graph Samples</title>",
                '<style>body{font-family:Arial,sans-serif;margin:32px;line-height:1.5;background:#f8fafc;color:#17202a} a{color:#1d4ed8}</style>',
                "</head>",
                "<body>",
                "<h1>SecureEdge Graph Samples</h1>",
                "<ul>",
                links,
                "</ul>",
                "</body>",
                "</html>",
            ]
        ),
        encoding="utf-8",
    )
    return index


def main() -> None:
    args = parse_args()
    if args.limit < 1:
        raise SystemExit("--limit must be at least 1")

    paths = list(args.paths)
    if paths:
        paths = paths[: args.limit]
    else:
        paths = graph_paths_from_split(args.split, args.class_name, args.limit)

    if not paths:
        raise SystemExit("No graph files matched the requested selection.")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rendered: list[Path] = []
    summaries: list[dict[str, object]] = []

    for path in paths:
        graph = load_graph(path)
        output_name = f"{sanitize_id(path.stem)}.svg"
        output_path = args.out_dir / output_name
        output_path.write_text(render_graph_svg(path, graph, args.show_values), encoding="utf-8")
        rendered.append(output_path)
        summaries.append(
            {
                "input": str(path),
                "output": str(output_path),
                "class_name": str(graph.class_name),
                "subtype_label": str(graph.subtype_label),
                "flow_shape": list(graph["flow"].x.shape),
                "packet_shape": list(graph["packet"].x.shape),
                "edge_types": [list(edge_type) for edge_type in graph.edge_types],
            }
        )

    index_path = write_index(args.out_dir, rendered)
    summary_path = args.out_dir / "summary.json"
    summary_path.write_text(json.dumps(summaries, indent=2), encoding="utf-8")
    print(json.dumps({"rendered": len(rendered), "index": str(index_path), "summary": str(summary_path)}, indent=2))


if __name__ == "__main__":
    main()
