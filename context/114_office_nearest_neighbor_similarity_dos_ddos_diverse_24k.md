# Office Nearest-Neighbor Similarity Audit After DDoS Diverse 24k

Date: 2026-08-02

## Objective

Rerun the nearest-neighbor train/validation similarity audit using the current selected compact graph set:

`artifacts/office_model/office_compact_cumulative_manifest_dos_ddos_diverse_24k.json`

The comparison baseline is the immediately previous selected compact manifest:

`artifacts/office_model/office_compact_cumulative_manifest_dos_diverse_24k.json`

Both runs used the same sampling parameters:

| Field | Value |
| --- | ---: |
| Train cap per class | 5,000 |
| Validation cap per class | 500 |
| Train sample size | 30,206 |
| Validation sample size | 3,103 |
| Seed | 42 |
| Neighbors | 5 |
| Vector dimension | 126 |

## Method

Added:

`secureedge/office/compact_nearest_neighbor_similarity_audit.py`

This compact audit mirrors the original PyG nearest-neighbor audit vector layout, but reads directly from compact records to avoid rebuilding the full PyG graph dataset:

- graph size counts;
- flow feature stats plus mean feature vector;
- packet byte stats;
- contain edge stats;
- reverse-contain proxy stats;
- packet-link edge stats;
- train-standardized cosine nearest-neighbor search.

For records without explicit ground-truth window timestamps, `same_window` falls back to source dataset, day, class, subtype, and source PCAP.

## Commands

Previous compact baseline:

```bash
.venv/bin/python -m secureedge.office.compact_nearest_neighbor_similarity_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_dos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_diverse_24k_previous \
  --train-per-class 5000 \
  --val-per-class 500 \
  --seed 42 \
  --n-neighbors 5
```

New compact set:

```bash
.venv/bin/python -m secureedge.office.compact_nearest_neighbor_similarity_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_dos_ddos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k \
  --train-per-class 5000 \
  --val-per-class 500 \
  --seed 42 \
  --n-neighbors 5
```

## Overall Comparison

| Metric | Previous compact set | New compact set | Delta |
| --- | ---: | ---: | ---: |
| Median nearest-neighbor distance | 0.000046849 | 0.000036001 | -0.000010848 |
| P95 nearest-neighbor distance | 0.009165072 | 0.010228837 | +0.001063764 |
| Distances <= 0.001 | 2,547 | 2,559 | +12 |
| Distances <= 0.01 | 2,953 | 2,944 | -9 |
| Same-class rate | 0.999355 | 0.999355 | +0.000000 |
| Same-subtype rate | 0.999033 | 0.999033 | +0.000000 |
| Same-day rate | 0.858524 | 0.857879 | -0.000645 |
| Same-window rate | 0.485015 | 0.530132 | +0.045118 |
| Same-PCAP rate | 0.493071 | 0.538511 | +0.045440 |
| Same endpoint/service rate | 0.858524 | 0.822430 | -0.036094 |

## DDoS Comparison

| Metric | Previous compact DDoS | New compact DDoS | Delta |
| --- | ---: | ---: | ---: |
| Median nearest-neighbor distance | 0.000060111 | 0.000020325 | -0.000039786 |
| P95 nearest-neighbor distance | 0.000582430 | 0.000446415 | -0.000136015 |
| Same-class rate | 1.000000 | 1.000000 | +0.000000 |
| Same-subtype rate | 1.000000 | 1.000000 | +0.000000 |
| Same-day rate | 1.000000 | 0.992000 | -0.008000 |
| Same-window rate | 0.486000 | 0.766000 | +0.280000 |
| Same-PCAP rate | 0.486000 | 0.766000 | +0.280000 |
| Same endpoint/service rate | 1.000000 | 0.772000 | -0.228000 |

## Interpretation

The result is mixed.

What improved:

- DDoS same-day nearest-neighbor rate dropped from `1.000000` to `0.992000`.
- DDoS same endpoint/service rate dropped from `1.000000` to `0.772000`.
- Overall same endpoint/service rate dropped from `0.858524` to `0.822430`.
- Overall P95 distance increased from `0.009165072` to `0.010228837`, which means the less-similar tail got slightly less close.

What did not improve:

- Same-class and same-subtype rates stayed essentially unchanged and extremely high.
- Overall median nearest-neighbor distance got smaller, from `0.000046849` to `0.000036001`.
- The number of validation samples with distance <= `0.001` increased by `12`.
- DDoS median and P95 distances both got smaller, meaning DDoS validation samples became closer to their nearest training samples under this compact traffic-shape vector.
- Compact fallback same-window/same-PCAP rates increased for DDoS because the new Tuesday LOIC-HTTP contribution is concentrated in one filtered PCAP source.

Compared with the original PyG audit in `context/103_office_nearest_neighbor_similarity_audit.md`, the new DDoS same-window/same-PCAP rates are below the earlier reported `1.000000`; however, that comparison is less controlled because the original audit used candidate split metadata while this rerun uses compact manifest metadata with fallback window keys.

## Conclusion

The diverse DDoS split improved endpoint/service diversity, but it did not eliminate train/validation near-neighbor similarity. The model can still see validation graphs that are extremely close to training graphs under traffic-shape features.

This means the new set is better for subtype coverage, but it is still not a strong independence test. For robustness evaluation, the next stronger split should hold out whole attack windows, days, PCAPs, or endpoint/service groups rather than only mixing more subtypes into random train/validation splits.

## Artifacts

| Artifact | Path |
| --- | --- |
| Compact audit module | `secureedge/office/compact_nearest_neighbor_similarity_audit.py` |
| Previous compact audit JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_diverse_24k_previous/nearest_neighbor_similarity_compact_audit.json` |
| Previous compact audit Markdown | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_diverse_24k_previous/nearest_neighbor_similarity_compact_audit.md` |
| New compact audit JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k/nearest_neighbor_similarity_compact_audit.json` |
| New compact audit Markdown | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k/nearest_neighbor_similarity_compact_audit.md` |
| Comparison JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k/comparison_to_dos_diverse_24k_previous.json` |
