# Office Training Readiness Status

Date: 2026-07-29

## Summary

The CIC-IDS-2018 office graph-generation phase is now good enough to proceed into model training. The graph pool is not perfectly complete, but the remaining shortages are bounded and documented:

- `Benign` remains 597 graphs below the 24,000 target.
- `Infiltration` remains 10 graphs below the 24,000 target.
- `WebBased` remains intentionally scarce and is handled as a special imbalanced class.

The current office PyG graph dataset has 143,805 graphs and passes the structural and leakage gates needed before training.

## Current Graph Counts

Counts from `artifacts/office_model/office_graph_dataset_manifest.json`:

| Class | Train | Validation | Test | Total |
| --- | ---: | ---: | ---: | ---: |
| Benign | 19,503 | 1,949 | 1,951 | 23,403 |
| BruteForce | 20,000 | 2,000 | 2,000 | 24,000 |
| DoS | 20,000 | 2,000 | 2,000 | 24,000 |
| DDoS | 20,000 | 2,000 | 2,000 | 24,000 |
| WebBased | 206 | 103 | 103 | 412 |
| Bot | 20,000 | 2,000 | 2,000 | 24,000 |
| Infiltration | 19,991 | 1,999 | 2,000 | 23,990 |
| **Total** | **119,700** | **12,051** | **12,054** | **143,805** |

`materialization_incomplete` is `false` in the office graph dataset manifest.

## Duplicate and Leakage Status

Gate 7 passes with no hard failures and no warnings.

Current leakage status:

| Check | Result |
| --- | --- |
| Duplicate candidate identity | 0 |
| Cross-split candidate overlap | 0 |
| Cross-split graph ID overlap | 0 |
| Cross-split flow hash overlap | 0 |
| CICIDS2017 validation/test leakage | None detected |

This means the current graph dataset is safe to use for the next training run from a split-leakage perspective.

## Validation Gate Status

| Gate | Report | Status | Records | Hard failures | Warnings |
| --- | --- | --- | ---: | ---: | ---: |
| G5 compact features | `artifacts/office_model/gate_reports/gate5_compact_features.json` | pass | 143,805 | 0 | 2 |
| G6 graph structure | `artifacts/office_model/gate_reports/gate6_graph_structure.json` | pass | 143,805 | 0 | 0 |
| G7 split leakage | `artifacts/office_model/gate_reports/gate7_split_leakage.json` | pass | 143,805 | 0 | 0 |

The two Gate 5 warnings are known and not training blockers:

- Tuple context features are present: `src_port`, `dst_port`, `protocol`.
- No raw IP/MAC feature names were found.

## Shard Status

The office graph shard manifest exists at:

```text
artifacts/office_model/office_graph_shard_manifest.json
```

Current shard counts:

| Split | Graphs | Shards |
| --- | ---: | ---: |
| Train | 119,700 | 120 |
| Validation | 12,051 | 13 |
| Test | 12,054 | 13 |

The shard set is ready for downstream training or batched loading work. The current office trainer still loads graph paths from the graph dataset manifest directly.

## Benign and Infiltration Recovery Status

`Infiltration` recovery is good enough:

- Target: 24,000
- Current: 23,990
- Remaining gap: 10

`Benign` recovery is also good enough for training:

- Target: 24,000
- Current: 23,403
- Remaining gap: 597

The remaining 597 Benign candidates were audited:

| Reason | Count |
| --- | ---: |
| Tuple not seen in scanned PCAPs | 515 |
| Primary tuple outside window | 15 |
| Primary tuple within window but unrecovered | 67 |

A targeted recovery pass over these Benign candidates recovered 0 additional graphs. The remaining gap is therefore treated as a materialization limitation, not a counting or duplicate issue.

## WebBased Imbalance Policy

Phase 6 of `docs/CIC_IDS_2018_PREPROCESSING_AND_GRAPH_GENERATION_REPORT.md` is now implemented.

Current WebBased split:

| Split | Graphs |
| --- | ---: |
| Train | 206 |
| Validation | 103 |
| Test | 103 |

Important caveat:

- The config still records 167 CICIDS2017 WebBased train-only references.
- Those 167 references did not materialize into the current graph dataset.
- The current materialized CICIDS2017 train-only shortfall is therefore 167.
- Validation and test remain native-only.

Implemented imbalance handling:

| Area | Current implementation |
| --- | --- |
| Config source | `configs/office_cic_ids_2018.yaml` `imbalance` section |
| Loss | `weighted_cross_entropy` |
| Weight method | Effective number of samples |
| Weight source | Train split only |
| `beta` | `0.9999` |
| Max class weight | `8.0` |
| Balanced batches | Enabled with `WeightedRandomSampler` |
| Sampler weighting | Inverse train-class frequency |
| Replacement | Enabled |

Current train-only class weights:

| Class | Weight |
| --- | ---: |
| Benign | 0.145747 |
| BruteForce | 0.144585 |
| DoS | 0.144585 |
| DDoS | 0.144585 |
| WebBased | 6.131310 |
| Bot | 0.144585 |
| Infiltration | 0.144605 |

The imbalance audit artifact is:

```text
artifacts/office_model/office_imbalance_policy.json
```

## Code and Commit Status

Latest local commits:

```text
bab30ba Add office class imbalance training policy
d0f4e6f Update office benign graph generation state
737910c Add office recovery audit tooling
ba9c0ae Update office graph generation context
e71f960 Improve office graph generation pipeline
```

Local branch status at the time of this report:

```text
main...origin/main [ahead 5]
```

The push to GitHub is blocked by credentials. The escalated network push reached GitHub, but failed because the noninteractive environment could not provide the GitHub password or token.

Failure:

```text
fatal: could not read Password for 'https://Konodioda2004%2F%2F@github.com': terminal prompts disabled
```

## Training Readiness Decision

Proceed to Phase 7 training.

Reasons:

- Non-WebBased attack classes are at or very near the 24,000 target.
- `WebBased` scarcity is explicitly handled by train-only class weighting and balanced sampling.
- Validation and test splits are not used to compute training weights.
- G5, G6, and G7 pass.
- No duplicate graphs or split leakage are currently reported.

## Next Recommended Step

Start the office model training run with:

```bash
.venv/bin/python -m secureedge.office.train
```

After training completes:

1. Evaluate the best checkpoint with the office evaluator.
2. Inspect macro-F1, weighted-F1, per-class recall, and especially WebBased precision/recall/F1.
3. Treat WebBased metrics as high-variance because test support is only 103 graphs.
4. Export only after evaluation passes the expected validation threshold.
