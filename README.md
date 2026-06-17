# SecureEdge

SecureEdge is a CIC-IoT2023 graph-based training and evaluation pipeline for an edge-deployed network intrusion detection model. The final project methodology follows XG-NID: NFStream flow statistics plus temporal context and raw packet payload nodes are converted into PyTorch Geometric heterogeneous graphs and trained with an HGNN.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

PyTorch Geometric must match the installed PyTorch build. The final methodology uses the Torch 2.1/cu121 installation sequence; if your environment already has a newer Torch build, install matching PyG wheels from `https://data.pyg.org/whl/`.

NFStream requires `libpcap` on Linux:

```bash
sudo apt-get install libpcap-dev
```

The default DataLoader worker count is `0` so the scripts run in restricted sandboxes. On a normal workstation, you can use background workers:

```bash
SECUREEDGE_NUM_WORKERS=2 python -m secureedge.models.train
```

For a bounded CPU training sanity check, use small per-class limits:

```bash
SECUREEDGE_DEVICE=cpu \
SECUREEDGE_BATCH_SIZE=16 \
SECUREEDGE_MAX_EPOCHS=1 \
SECUREEDGE_TRAIN_LIMIT_PER_CLASS=50 \
SECUREEDGE_EVAL_LIMIT_PER_CLASS=20 \
python -m secureedge.models.train
```

For the full final-methodology training run, leave the per-class limits unset and run on CUDA:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_MAX_EPOCHS=200 \
python -m secureedge.models.train
```

## Execution Order

```bash
python -m secureedge.data.preprocess
python -m secureedge.data.build_graphs
python -m secureedge.features.pipeline
python -m secureedge.models.train
python -m secureedge.models.evaluate
python -m secureedge.ood.detector
python -m secureedge.export.export
```

Each completed component writes an explanation file under `context/`.

The PCAP preprocessing step is intentionally locked against accidental full-scale runs because the CIC-IoT2023 PCAP corpus is large enough to exhaust memory/swap on a 16 GiB workstation. Use a bounded development run first:

```bash
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 python -m secureedge.data.preprocess
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 python -m secureedge.data.build_graphs
```

Only start the full final-methodology extraction in a batch environment with enough RAM:

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 python -m secureedge.data.preprocess
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 python -m secureedge.data.build_graphs
```

Useful safety knobs:

```bash
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4
SECUREEDGE_MAX_PROCESS_RSS_GB=2
SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64
SECUREEDGE_PCAP_CHUNK_SIZE_MB=16
```

Automatic splitting of large PCAPs is disabled by default because splitting entire multi-GiB files with `tcpdump -C` previously destabilized the workstation. Prefer pre-splitting PCAPs into files below `SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB` before running the SecureEdge extractor. Only re-enable automatic splitting in a controlled batch run:

```bash
SECUREEDGE_ALLOW_AUTOMATIC_PCAP_SPLITTING=1 python -m secureedge.data.preprocess
```

## Dataset Notes

The active pipeline uses raw PCAP files from `PCAPs/` and ignores the previous `CSV.zip` export. PCAP filenames provide fine-grained `subtype_label` values, which are mapped into the eight Stage 1 classes.

Each completed flow becomes one graph:

- one `flow` node with NFStream numeric flow features plus 16 temporal features
- up to 20 `packet` nodes with 1,500 normalized payload-byte features each
- `flow -> packet` contain edges with 4 edge features
- `packet -> flow` reverse contain edges for bidirectional message passing
- `packet -> packet` link edges with normalized inter-packet time deltas

Processed graph objects are written to `data/graphs/train/` and `data/graphs/test/`, with `artifacts/graph_dataset_manifest.json` recording counts, paths, dimensions, and scaler artifacts.
