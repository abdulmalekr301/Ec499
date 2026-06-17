# Project Context

Generated: 2026-06-17

## Overview

This EC499 workspace contains the SecureEdge project: a Python implementation of
an XG-NID-style graph intrusion detection pipeline for CIC-IoT2023 traffic.

The project converts PCAP traffic into heterogeneous graphs, trains a graph neural
network, evaluates per-class performance, and documents each implementation phase
under `context/`.

## Current Methodology State

The active pipeline now follows the XG-NID oversampling strategy documented in:

```text
context/32_revert_to_xgnid_oversampling.md
```

The active dataset split strategy is:

- build a 24,000-record balanced pool per canonical class
- randomly undersample classes above 24,000
- randomly oversample classes below 24,000
- split each balanced class pool into 20,000 training records and 4,000 test records
- train with plain `CrossEntropyLoss()`
- use cosine learning-rate scheduling, warmup, batch size 512, and label smoothing 0.0

The current regenerated graph counts are:

```text
Train graphs: 160,000
Test graphs:   32,000
Train shards:     160
Test shards:       32
```

These graph files are generated locally and are not committed to GitHub.

## Main Source Directories

### `secureedge/`

The main Python package.

Important modules:

- `secureedge/config.py`: central paths, class names, feature dimensions, training settings, and memory guardrails
- `secureedge/data/preprocess.py`: PCAP discovery, compact reservoir handling, balanced-pool splitting, and manifest generation
- `secureedge/data/extract_worker.py`: bounded NFStream extraction worker used to avoid memory crashes
- `secureedge/data/pcap_flows.py`: NFStream plugins for packet capture, flow capping, active/idle features, and flow conversion
- `secureedge/data/graph_builder.py`: compact-record to PyTorch Geometric graph conversion, 92-feature flow node construction, scalers
- `secureedge/data/build_graphs.py`: graph materialization from compact records
- `secureedge/data/create_shards.py`: shard creation for memory-safe training
- `secureedge/data/payload_diagnostic.py`: payload-density diagnostics
- `secureedge/data/verify_packet_capture.py`: direct NFStream packet attribute verification
- `secureedge/features/temporal.py`: temporal feature extractor
- `secureedge/models/hgnn.py`: heterogeneous graph neural network
- `secureedge/models/train.py`: HGNN training loop, metrics, logging, checkpointing
- `secureedge/models/evaluate.py`: evaluation utilities
- `secureedge/visualize/graph_view.py`: graph sample visualization

### `tests/`

Contains lightweight smoke checks for critical project behavior.

### `context/`

Contains methodology documents, implementation notes, progress reports, run logs,
fix instructions, and verification reports. This folder is intentionally committed
because it preserves the reasoning trail for the project.

### Root Files

- `README.md`: execution order and project usage
- `requirements.txt`: Python dependency list
- `.gitignore`: excludes large datasets, generated data, checkpoints, and local environments
- `FOLDER_STRUCTURE.md`: workspace structure summary
- `Project Context.md`: this project summary

## Ignored Local Data and Artifacts

The following are present locally but excluded from Git:

- `CSV.zip`
- `CSV/`
- `PCAPs/`
- `cse2018/`
- `data/raw/`
- `data/processed/`
- `data/graphs/`
- `artifacts/`
- `.venv/`
- `.uv-python/`

These paths contain raw datasets, generated graph files, model checkpoints,
scalers, manifests, metrics, visualizations, or local tooling caches. They are
too large or too machine-specific for the GitHub repository.

## Memory-Safety Context

Earlier full PCAP extraction attempts caused system crashes due to memory and
swap exhaustion. The current pipeline includes guardrails:

- PCAP splitting and chunk usage
- bounded worker extraction
- RSS and available-memory checks
- graph sharding
- `NUM_WORKERS=0` default for training
- no full PCAP reprocessing unless explicitly requested

The compact reservoir is reused when possible to avoid repeating expensive
NFStream extraction.

## PacketCapture Status

`PacketCapture` has been verified in:

```text
context/30_packetcapture_verification.md
```

NFStream exposes usable raw packet bytes through `packet.ip_packet`, and the
current implementation derives application payload bytes from that source. No
better raw payload attribute was found when NFStream dissections were enabled.

## Latest Training Command

The current intended training command is:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=512 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=50 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
.venv/bin/python -m secureedge.models.train
```

## Repository Policy

The GitHub repository should contain:

- Python source code
- tests
- README and dependency files
- methodology and progress documentation
- folder/context summaries

The GitHub repository should not contain:

- raw PCAP or CSV datasets
- generated graph files or shards
- virtual environments
- checkpoints and model exports
- generated scalers/manifests/metrics
- external dataset scratch files
