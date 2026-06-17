# EC499 Folder Structure

Generated: 2026-06-17

This document summarizes the EC499 workspace layout for the GitHub repository.
Large datasets, generated graph files, model artifacts, virtual environments,
and caches are intentionally excluded from Git by `.gitignore`.

## Repository Root

```text
EC499/
├── .gitignore
├── FOLDER_STRUCTURE.md
├── Project Context.md
├── README.md
├── requirements.txt
├── context/
├── secureedge/
└── tests/
```

## Tracked Source Layout

```text
secureedge/
├── __init__.py
├── config.py
├── utils.py
├── data/
│   ├── __init__.py
│   ├── acquire.py
│   ├── build_graphs.py
│   ├── create_shards.py
│   ├── dataset.py
│   ├── extract_worker.py
│   ├── graph_builder.py
│   ├── payload_diagnostic.py
│   ├── pcap_flows.py
│   ├── preprocess.py
│   ├── split_pcaps.py
│   └── verify_packet_capture.py
├── export/
│   ├── __init__.py
│   └── export.py
├── features/
│   ├── __init__.py
│   ├── pipeline.py
│   └── temporal.py
├── models/
│   ├── __init__.py
│   ├── architecture.py
│   ├── evaluate.py
│   ├── hgnn.py
│   └── train.py
├── ood/
│   ├── __init__.py
│   └── detector.py
└── visualize/
    ├── __init__.py
    └── graph_view.py
```

```text
tests/
└── smoke_checks.py
```

## Project Context Documents

```text
context/
├── 01_dataset_acquisition.md
├── 02_preprocessing.md
├── 03_feature_engineering.md
├── 04_model_architecture.md
├── 05_training.md
├── 06_evaluation.md
├── 07_ood_detection.md
├── 08_export.md
├── 09_final_methodology_alignment.md
├── 10_pyg_dependency_installation.md
├── 11_python311_cuda13_environment.md
├── 12_memory_safety_after_crash.md
├── 13_pcap_crash_root_cause_and_guardrails.md
├── 14_safe_small_pcap_extraction_run.md
├── 15_pcap_splitting.md
├── 16_bounded_nfstream_graph_materialization.md
├── 17_build_graphs.md
├── 18_preprocessing_with_fixes_applied.md
├── 19_full_preprocessing_run.md
├── 20_missing_flow_features_fix.md
├── 21_full_92_feature_regeneration.md
├── 22_graph_visualization.md
├── 23_hgnn_training_phase_validation.md
├── 24_graph_sharding.md
├── 25_training_round_2_adjustments.md
├── 26_oversampling_audit.md
├── 27_training_round_3_adjustments.md
├── 28_class_imbalance_deduped_shards.md
├── 29_class_imbalance_fixes.md
├── 30_packetcapture_verification.md
├── 31_xgnid_oversampling_resplit.md
├── 32_revert_to_xgnid_oversampling.md
├── class-imbalance-fixes.md
├── fixes.md
├── fixes-2.md
├── logs-1.md
├── logs-2.md
├── logs-3.md
├── logs-4.md
├── payload-diagnostic-graphs-train.md
├── payload-diagnostic-shards-train.md
├── preprocessing-find-missing.md
├── preprocessing-with-fixes.md
├── progress-report.md
├── progress-report-fixes.md
├── progress-report-all-fixes.md
├── revert-to-oversampling.md
├── secureedge_methodology second draft.md
├── secureedge_methodology_final.md
├── training-gpu-starvation.md
├── training-round-2.md
└── training-round-3.md
```

## Ignored Large Workspace Areas

These paths exist locally but are intentionally not committed:

```text
CSV.zip                         # CIC-IoT2023 CSV archive, about 1.4G
CSV/                            # extracted CSV dataset, about 8.4G
PCAPs/                          # raw PCAP captures, about 39G
cse2018/                        # external dataset scratch area, about 16M
data/raw/                       # raw CSV/PCAP chunk data, about 47G
data/processed/                 # generated processed tabular data
data/graphs/                    # generated compact records, graphs, and shards, about 31G
artifacts/                      # checkpoints, scalers, manifests, metrics, visualizations
.venv/                          # local Python 3.11 virtual environment, about 5.2G
.uv-python/                     # local Python tooling cache
```

## Generated Data Layout

The generated data area is ignored, but its local structure is:

```text
data/
├── raw/
│   ├── CSV/
│   └── pcap_chunks/
├── processed/
└── graphs/
    ├── _reservoir/
    ├── _safe_small_run/
    ├── train/
    ├── test/
    ├── train_shards/
    └── test_shards/
```

The current regenerated XG-NID graph split contains:

```text
data/graphs/train/         160,000 graph files
data/graphs/test/           32,000 graph files
data/graphs/train_shards/      160 shard files
data/graphs/test_shards/        32 shard files
```

## Notes

- The GitHub repository stores source code, project documentation, methodology
  notes, and reproducibility instructions.
- Raw datasets and generated artifacts must be recreated locally using the
  pipeline commands in `README.md` and the context reports.
- The latest active methodology state is documented in
  `context/32_revert_to_xgnid_oversampling.md`.
