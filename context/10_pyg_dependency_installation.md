# PyTorch Geometric Dependency Installation

Generated: `2026-06-14`

## Action

- Installed `torch-geometric` into the project virtual environment.
- Installed matching prebuilt wheels for:
  - `torch-scatter`
  - `torch-sparse`
- Verified the SecureEdge graph/HGNN smoke checks now run with PyG enabled.

## Environment

```text
Python: 3.14.4
Torch: 2.12.0+cu130
PyG: 2.8.0
torch-scatter: 2.1.2+pt212cu130
torch-sparse: 0.6.18+pt212cu130
```

## Installation Notes

The first install attempt failed inside the sandbox because network/DNS access was blocked. After network-enabled pip execution was allowed, `torch-geometric` installed successfully from PyPI.

The optional compiled packages needed matching wheels from the PyG wheel index:

```bash
.venv/bin/pip install torch-scatter torch-sparse -f https://data.pyg.org/whl/torch-2.12.0+cu130.html
```

`torch-cluster` did not install because the PyG wheel index did not provide a matching Python 3.14 wheel for this environment and pip fell back to a source build. The current SecureEdge HGNN path uses `GATConv`, `HeteroConv`, graph batching, and pooling, and the smoke test passed without `torch-cluster`.

## Memory-Safety Fix Applied

After dependencies were installed, preprocessing was able to start graph extraction. I stopped the full run after confirming it passed the dependency blocker because the previous implementation would have held large packet-payload graph objects in memory.

To avoid another memory-pressure crash, preprocessing now uses disk-backed temporary graph reservoirs under:

```text
data/graphs/_reservoir/
```

The final train/test graph writer streams those temporary `.pt` graph references, fits scalers from training graphs, normalizes graphs, and writes final graph files under:

```text
data/graphs/train/
data/graphs/test/
```

## Verification

Passed:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Also verified a tiny synthetic graph save/normalize/manifest path. The synthetic check reported:

```text
flow_node=76
packet_node=1500
contain_edge=4
link_edge=1
```

## Remaining Caveat

The active Python version is 3.14.4, while the final methodology recommends Python 3.10 or 3.11. The project now works for the implemented graph smoke path in this environment, but for strict replication and future Jetson compatibility, a Python 3.10/3.11 environment is still the cleaner long-term setup.
