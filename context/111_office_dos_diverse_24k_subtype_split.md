# Office DoS Diverse 24k Subtype Split

Date: `2026-08-02`

## Summary

Created a duplicate-free `24,000` graph DoS selection with substantially better subtype diversity than the previous all-Hulk DoS set.

The selected set keeps the existing office class split shape:

| Split | DoS graphs |
|---|---:|
| `train` | 20,000 |
| `val` | 2,000 |
| `test` | 2,000 |
| **Total** | **24,000** |

## Subtype Mix

| DoS subtype | Available files | Unique tensor graphs available | Selected |
|---|---:|---:|---:|
| `DoS-Hulk` | 24,000 | 20,476 | 8,093 |
| `DoS-GoldenEye` | 6,007 | 6,007 | 6,000 |
| `DoS-Slowloris` | 6,173 | 6,173 | 6,000 |
| `DoS-SlowHTTPTest` | 4,000 | 3,907 | 3,907 |

`DoS-SlowHTTPTest` could not safely contribute all `4,000` files because `93` are exact duplicate tensor graphs. Those duplicates were excluded, and the deficit was assigned to `DoS-Hulk` so the total stays at `24,000`.

## Split By Subtype

| Split | `DoS-Hulk` | `DoS-GoldenEye` | `DoS-Slowloris` | `DoS-SlowHTTPTest` | Total |
|---|---:|---:|---:|---:|---:|
| `train` | 6,745 | 5,000 | 5,000 | 3,255 | 20,000 |
| `val` | 674 | 500 | 500 | 326 | 2,000 |
| `test` | 674 | 500 | 500 | 326 | 2,000 |
| **Total** | **8,093** | **6,000** | **6,000** | **3,907** | **24,000** |

## Validation

| Check | Result |
|---|---:|
| Selected DoS graphs | 24,000 |
| Duplicate `flow_hash` surplus | 0 |
| Duplicate `compact_tensor_hash` surplus | 0 |
| Read errors | 0 |
| Variant cumulative manifest DoS count | 24,000 |
| Variant cumulative manifest total records | 143,805 |

## Artifacts

| Artifact | Path |
|---|---|
| DoS selection JSONL | `artifacts/office_model/balanced_subtype_sets/dos_diverse_24k_paths.jsonl` |
| DoS selection manifest | `artifacts/office_model/balanced_subtype_sets/dos_diverse_24k_manifest.json` |
| Full cumulative manifest variant | `artifacts/office_model/office_compact_cumulative_manifest_dos_diverse_24k.json` |

Selection policy:

`dos_diverse_24k_subtype_balanced_no_duplicate_tensor_v2`

## Notes

- The active `artifacts/office_model/office_compact_cumulative_manifest.json` was not overwritten.
- The new variant replaces only the DoS records from the active cumulative manifest; all non-DoS records are preserved from the previous cumulative manifest.
- The next graph-conversion/training step should use `artifacts/office_model/office_compact_cumulative_manifest_dos_diverse_24k.json` if we want this diverse DoS class in the PyG training graphs.
