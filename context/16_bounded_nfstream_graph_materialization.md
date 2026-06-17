# Bounded NFStream Extraction and Graph Materialization

## Purpose

This run resumed PCAP processing after the large source PCAPs were split into safe chunks. The goal was to verify the final-methodology NFStream extraction and PyTorch Geometric graph materialization path without restarting the full 192,000-graph workload that previously exhausted memory/swap.

## Safety Settings

- Used split PCAP chunks from `data/raw/pcap_chunks`.
- Did not process the original multi-GiB PCAP files directly.
- Bounded sample counts:
  - `SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=16`
  - `SECUREEDGE_TEST_SAMPLES_PER_CLASS=4`
- Required at least `8 GiB` available memory during extraction.
- Limited worker process RSS to `2 GiB`.
- Checked worker memory every `10` emitted flows.
- Limited allocator/math thread behavior with:
  - `MALLOC_ARENA_MAX=2`
  - `OMP_NUM_THREADS=1`
  - `OPENBLAS_NUM_THREADS=1`
  - `MKL_NUM_THREADS=1`

## First Attempt

A larger bounded run using `40` train and `10` test graphs per class was started first. The safety guard stopped that run during `DoS-SYN_Flood` extraction when available memory briefly dipped below the configured `8 GiB` floor.

This was a controlled stop, not a crash. The system recovered with approximately `9.9 GiB` available memory afterward.

## Completed Run

The smaller bounded run completed successfully.

| Split | Count |
| --- | ---: |
| Training graphs | 128 |
| Test graphs | 32 |
| Total graphs | 160 |

Per-class output:

| Class | Train | Test |
| --- | ---: | ---: |
| Benign | 16 | 4 |
| DDoS | 16 | 4 |
| DoS | 16 | 4 |
| Mirai | 16 | 4 |
| Recon | 16 | 4 |
| Spoofing | 16 | 4 |
| WebBased | 16 | 4 |
| BruteForce | 16 | 4 |

## Outputs

- Training graph directory: `data/graphs/train`
- Test graph directory: `data/graphs/test`
- Temporary compact reservoir: `data/graphs/_reservoir`
- Graph manifest: `artifacts/graph_dataset_manifest.json`
- Flow-node scaler: `artifacts/flow_node_scaler.joblib`
- Contain-edge scaler: `artifacts/contain_edge_scaler.joblib`
- Link-edge normalizer: `artifacts/link_edge_norm_value.json`

Output sizes after completion:

- `data/graphs/train`: approximately `16 MiB`
- `data/graphs/test`: approximately `4 MiB`
- `data/graphs/_reservoir`: approximately `6 MiB`

## Validation

The graph feature validation command completed successfully when run with the same bounded sample-count environment:

```bash
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=16 SECUREEDGE_TEST_SAMPLES_PER_CLASS=4 python -m secureedge.features.pipeline
```

The validator reported:

```json
{
  "graph_manifest": "artifacts/graph_dataset_manifest.json",
  "total_graph_count": 160
}
```

## Memory Result

After completion and validation, the system still had approximately `9.8 GiB` available memory and swap usage remained approximately `1.2 GiB`.

## Important Limitation

This is a bounded safety run for the final graph pipeline, not the full final dataset. The full methodology target remains `160,000` training graphs and `32,000` test graphs. That full run should only be attempted gradually or in a controlled batch environment.
