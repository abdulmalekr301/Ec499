# Office Nearest-Neighbor Similarity Stratified Sampling Rerun

Date: 2026-08-02

## Objective

Rerun the nearest-neighbor similarity audit with explicitly diverse sampling instead of random per-class sampling.

The audit is still the same train-to-validation nearest-neighbor test used before. It does not evaluate the test split.

## Code Change

Updated:

`secureedge/office/compact_nearest_neighbor_similarity_audit.py`

Added:

```bash
--sampling-strategy stratified
```

The stratified sampler samples within each class using round-robin buckets keyed by:

```text
subtype -> source dataset -> day -> ground-truth window or source PCAP
```

If a compact manifest record does not contain enough metadata for this key, the sampler reads the compact graph metadata and uses `source_file`, `endpoint_pcap`, `gt_window_start`, and `gt_window_finish` where available.

The audit JSON now also records sample distributions:

- `train_sample_group_summary`
- `validation_sample_group_summary`

These include per-class subtype, day, PCAP, and group counts.

## Commands

Previous compact baseline, stratified:

```bash
.venv/bin/python -m secureedge.office.compact_nearest_neighbor_similarity_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_dos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_diverse_24k_previous_stratified \
  --train-per-class 5000 \
  --val-per-class 500 \
  --seed 42 \
  --n-neighbors 5 \
  --sampling-strategy stratified
```

New DoS+DDoS diverse set, stratified:

```bash
.venv/bin/python -m secureedge.office.compact_nearest_neighbor_similarity_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_dos_ddos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k_stratified \
  --train-per-class 5000 \
  --val-per-class 500 \
  --seed 42 \
  --n-neighbors 5 \
  --sampling-strategy stratified
```

## Sample Diversity Check

### DDoS Train Sample

| Set | HOIC | LOIC-HTTP | LOIC-UDP | Days | PCAP/source groups |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous compact baseline | 4,967 | 0 | 33 | 1 | 4 |
| New DoS+DDoS diverse set | 1,940 | 979 | 2,081 | 2 | 10 |

### DDoS Validation Sample

| Set | HOIC | LOIC-HTTP | LOIC-UDP | Days | PCAP/source groups |
| --- | ---: | ---: | ---: | ---: | ---: |
| Previous compact baseline | 497 | 0 | 3 | 1 | 3 |
| New DoS+DDoS diverse set | 195 | 97 | 208 | 2 | 8 |

This confirms the rerun used a diverse DDoS sample rather than an arbitrary random slice.

## Overall Result

| Metric | Previous stratified baseline | New stratified set | Delta |
| --- | ---: | ---: | ---: |
| Median nearest-neighbor distance | 0.000051796 | 0.000039518 | -0.000012279 |
| P95 nearest-neighbor distance | 0.009879088 | 0.009453863 | -0.000425225 |
| Distances <= 0.001 | 2,536 | 2,540 | +4 |
| Distances <= 0.01 | 2,948 | 2,954 | +6 |
| Same-class rate | 0.998066 | 0.998066 | +0.000000 |
| Same-subtype rate | 0.997744 | 0.997744 | +0.000000 |
| Same-day rate | 0.862391 | 0.862391 | +0.000000 |
| Same-window rate | 0.450209 | 0.471479 | +0.021270 |
| Same-PCAP rate | 0.458588 | 0.479858 | +0.021270 |
| Same endpoint/service rate | 0.862391 | 0.841444 | -0.020947 |

## DDoS Result

| Metric | Previous stratified DDoS | New stratified DDoS | Delta |
| --- | ---: | ---: | ---: |
| Median nearest-neighbor distance | 0.000060201 | 0.000011891 | -0.000048310 |
| P95 nearest-neighbor distance | 0.000681385 | 0.000510663 | -0.000170723 |
| Same-class rate | 1.000000 | 1.000000 | +0.000000 |
| Same-subtype rate | 1.000000 | 1.000000 | +0.000000 |
| Same-day rate | 1.000000 | 0.992000 | -0.008000 |
| Same-window rate | 0.538000 | 0.656000 | +0.118000 |
| Same-PCAP rate | 0.538000 | 0.656000 | +0.118000 |
| Same endpoint/service rate | 1.000000 | 0.862000 | -0.138000 |

## New Per-Subtype Output

After adding `FTP-BruteForce` to the selected BruteForce manifest, the audit was rerun with:

```bash
.venv/bin/python -m secureedge.office.compact_nearest_neighbor_similarity_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/nearest_neighbor_similarity_compact_bruteforce_dos_ddos_diverse_24k_stratified \
  --train-per-class 5000 \
  --val-per-class 500 \
  --seed 42 \
  --n-neighbors 5 \
  --sampling-strategy stratified
```

The refreshed audit Markdown now outputs this per-subtype table:

| Class | Subtype | Median NN distance | Same subtype | Same window | Same PCAP | Same endpoint |
| ---------- | --------- | -----------------: | -----------: | ----------: | --------: | ------------: |
| BruteForce | SSH | 0.000027 | 1.000000 | 0.406504 | 0.406504 | 1.000000 |
| BruteForce | FTP | 0.000000 | 0.603053 | 0.603053 | 0.603053 | 0.603053 |
| DoS | Hulk | 0.000826 | 1.000000 | 0.512077 | 0.512077 | 1.000000 |
| DoS | GoldenEye | 0.001234 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
| DoS | Slowloris | 0.000065 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
| DDoS | HOIC | 0.000083 | 1.000000 | 0.425641 | 0.425641 | 1.000000 |
| DDoS | LOIC-HTTP | 0.000022 | 1.000000 | 1.000000 | 1.000000 | 0.515464 |
| DDoS | LOIC-UDP | 0.000000 | 1.000000 | 0.625000 | 0.625000 | 0.932692 |
| DoS | SlowHTTPTest | 0.000000 | 0.438776 | 0.438776 | 0.438776 | 0.438776 |

The `FTP` row is now populated from the BruteForce-balanced selected manifest. `DoS-SlowHTTPTest` is included as an additional observed subtype because it exists in the selected DoS set.

## Interpretation

The stratified sampler corrected the sampling issue: the new DDoS sample now includes all three DDoS subtypes and two days.

The new set improved endpoint/service diversity:

- Overall same endpoint/service rate decreased from `0.862391` to `0.841444`.
- DDoS same endpoint/service rate decreased from `1.000000` to `0.862000`.
- DDoS same-day rate decreased from `1.000000` to `0.992000`.

However, nearest-neighbor similarity is still very high:

- Overall same-class and same-subtype rates did not improve.
- Overall median and P95 distances both got smaller.
- DDoS median and P95 distances both got smaller.
- DDoS same-window/same-PCAP fallback rates increased because the new LOIC-HTTP validation samples still come from the same Tuesday filtered PCAP source as many training LOIC-HTTP samples.

## Conclusion

The diverse sampling rerun confirms that the DDoS subtype mix is better, but the random train/validation split remains weak as an independence test. Even with diverse sampling, validation graphs still have very close training neighbors.

The next stronger robustness step should use group holdouts, especially by whole attack window, source PCAP, or endpoint/service group.

## Artifacts

| Artifact | Path |
| --- | --- |
| Previous stratified audit JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_diverse_24k_previous_stratified/nearest_neighbor_similarity_compact_audit.json` |
| New stratified audit JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k_stratified/nearest_neighbor_similarity_compact_audit.json` |
| New stratified audit CSV | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k_stratified/nearest_neighbor_similarity_compact_audit.csv` |
| Stratified comparison JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_dos_ddos_diverse_24k_stratified/comparison_to_dos_diverse_24k_previous_stratified.json` |
| Latest BruteForce-balanced stratified audit JSON | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_bruteforce_dos_ddos_diverse_24k_stratified/nearest_neighbor_similarity_compact_audit.json` |
| Latest BruteForce-balanced stratified audit Markdown | `artifacts/office_model/robustness/nearest_neighbor_similarity_compact_bruteforce_dos_ddos_diverse_24k_stratified/nearest_neighbor_similarity_compact_audit.md` |
