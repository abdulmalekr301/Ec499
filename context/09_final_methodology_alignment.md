# Final Methodology Alignment

Generated: `2026-06-14`

## Action

- Reworked the active pipeline to follow `context/secureedge_methodology_final.md`.
- Deprecated the flat MLP/CSV execution path for the final project workflow.
- Added graph dataset output under `data/graphs/train/` and `data/graphs/test/`.
- Added graph artifacts:
  - `artifacts/flow_node_scaler.joblib`
  - `artifacts/contain_edge_scaler.joblib`
  - `artifacts/link_edge_norm_value.json`
  - `artifacts/graph_dataset_manifest.json`
  - `artifacts/best_hgnn.pt`
  - `artifacts/secureedge_hgnn.ts`

## Code Changes

- `secureedge/config.py`
  - Added graph paths, graph artifact paths, HGNN constants, packet feature dimensions, and edge feature dimensions.
  - Updated training hyperparameters to the final methodology values: batch size 64, warmup from `1e-3` to `1e-2`, max epochs 200, patience 20.
  - Kept `N_FLOW_FEATURES = 60` because the installed NFStream 6.6.0 output exposes 60 usable numeric feature fields, including `src_port`, `dst_port`, and `protocol`.

- `secureedge/data/pcap_flows.py`
  - Added `PacketCapture`, an NFStream plugin that captures up to 20 packet records per flow.
  - Added 1,500-byte payload padding/truncation.
  - Added IPv4/TCP/UDP header stripping when NFStream only exposes full IP packet bytes.
  - Kept `FlowCapper` and runs plugins as `PacketCapture` before `FlowCapper`.
  - Emits `flow_features`, `temporal_features`, and `packet_records` for graph construction.

- `secureedge/data/graph_builder.py`
  - Added `build_hetero_graph()` for PyG `HeteroData` construction.
  - Creates flow nodes, packet nodes, contain edges, reverse contain edges, and packet link edges.
  - Fits and applies separate flow-node, contain-edge, and link-edge normalizers from training graphs only.
  - Saves one `.pt` file per graph and writes the graph dataset manifest.

- `secureedge/data/preprocess.py`
  - Replaced tabular row reservoirs with graph-object reservoirs.
  - Preserved per-subtype sampling targets.
  - Splits real test graphs before training oversampling.
  - Writes graph files and scaler artifacts instead of CSV model files.

- `secureedge/features/pipeline.py`
  - Replaced CSV feature scaling with graph artifact validation.

- `secureedge/data/dataset.py`
  - Replaced tabular dataset loading with `GraphFileDataset` and manifest-backed split loading.

- `secureedge/models/hgnn.py`
  - Added `SecureEdgeHGNN`, a two-layer heterogeneous GAT model with global mean pooling and an 8-class classifier.

- `secureedge/models/train.py`
  - Replaced MLP training with PyG graph training.
  - Saves `artifacts/best_hgnn.pt`.

- `secureedge/models/evaluate.py`
  - Replaced tabular evaluation with graph-level HGNN evaluation.
  - Added DDoS subtype prediction distribution and DDoS recall diagnostics.

- `secureedge/ood/detector.py`
  - Replaced tabular MSP calibration with graph MSP calibration on correctly classified training graphs.

- `secureedge/export/export.py`
  - Replaced MLP TorchScript export with HGNN TorchScript export to `artifacts/secureedge_hgnn.ts`.

- `tests/smoke_checks.py`
  - Updated label, PacketCapture, temporal, graph, DataLoader, and HGNN checks.
  - PyG-specific smoke checks are skipped clearly when PyG is not installed.

- `requirements.txt`
  - Added the PyTorch Geometric dependency set required by the final methodology.

## Verification Performed

- Confirmed NFStream 6.6.0 is installed.
- Confirmed the active venv does not currently have `torch_geometric`.
- Ran an NFStream probe on `PCAPs/Uploading_Attack.pcap`.
- Confirmed the installed NFStream feature count is 60 numeric model features.
- Confirmed `src_port`, `dst_port`, and `protocol` are included in those 60 features.
- Confirmed `PacketCapture` emits 20 packet records with 1,500-byte payload vectors.
- Confirmed the payload fallback strips protocol headers and retains application payload bytes when present.

## Current Blocker

The final graph model path requires PyTorch Geometric. The current virtual environment has Torch `2.12.0+cu130`, but `torch_geometric` is not installed. The methodology's example install commands target Torch 2.1/cu121, so installation must either:

- use a fresh Torch 2.1/cu121 environment exactly as the methodology states, or
- install PyG wheels that match the current Torch 2.12/cu130 environment.

Until PyG is installed, graph construction imports, graph DataLoader batching, HGNN forward passes, training, evaluation, OOD calibration, and export cannot be executed end to end.
