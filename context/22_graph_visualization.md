# SecureEdge Graph Visualization Utility

> Generated: 2026-06-15  
> Scope: Added a small graph sample viewer for the regenerated SecureEdge `.pt`
> graph files.

## What Was Added

Added the visualization module:

```text
secureedge/visualize/graph_view.py
secureedge/visualize/__init__.py
```

The script renders selected PyTorch Geometric `HeteroData` graph files as SVG
diagrams. It is intentionally sample-oriented and defaults to a small render
limit so it does not walk the full 192,000-graph dataset by accident.

## Output Location

Rendered samples are written to:

```text
artifacts/graph_visualizations/
```

The browser entry point is:

```text
artifacts/graph_visualizations/index.html
```

The script also writes:

```text
artifacts/graph_visualizations/summary.json
```

## Commands Run

Rendered three Benign samples:

```bash
.venv/bin/python -m secureedge.visualize.graph_view \
  --split train \
  --class-name Benign \
  --limit 3
```

Rendered one sample from each canonical class:

```bash
.venv/bin/python -m secureedge.visualize.graph_view \
  --limit 8 \
  data/graphs/train/Benign_000001.pt \
  data/graphs/train/DDoS_000001.pt \
  data/graphs/train/DoS_000001.pt \
  data/graphs/train/Mirai_000001.pt \
  data/graphs/train/Recon_000001.pt \
  data/graphs/train/Spoofing_000001.pt \
  data/graphs/train/WebBased_000001.pt \
  data/graphs/train/BruteForce_000001.pt
```

## What the Diagram Shows

Each rendered SVG shows:

- one blue flow node containing the 92-dimensional flow feature vector
- up to 20 packet nodes containing normalized 1500-byte packet payload vectors
- dashed flow-to-packet `contains` edges
- green packet-to-packet temporal `linked_to` edges
- graph metadata such as class, subtype, tensor shapes, source file, and edge
  counts
- a preview of the flow feature names

Packet node color represents average normalized byte intensity in that packet.

## Usage Examples

Render the first 6 training graphs:

```bash
.venv/bin/python -m secureedge.visualize.graph_view --split train --limit 6
```

Render 4 DDoS test graphs:

```bash
.venv/bin/python -m secureedge.visualize.graph_view \
  --split test \
  --class-name DDoS \
  --limit 4
```

Render specific graph files and include feature values in the side panel:

```bash
.venv/bin/python -m secureedge.visualize.graph_view \
  --show-values \
  data/graphs/train/Benign_000001.pt \
  data/graphs/train/DDoS_000001.pt
```

## Verification

The visualization module compiled successfully:

```bash
.venv/bin/python -m compileall secureedge/visualize
```

The sample render completed successfully and produced:

```text
artifacts/graph_visualizations/index.html
artifacts/graph_visualizations/summary.json
```
