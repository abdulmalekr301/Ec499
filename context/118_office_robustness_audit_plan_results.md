# Office Robustness Audit Plan Results

Date: 2026-08-02

## Scope

This report follows `context/gpt_office_next_robustness_audit_plan.md` against the current selected compact Office manifest:

```text
artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json
```

This pass completed the compact-vector nearest-neighbor audits, generated the robust PyG fold manifests needed for retraining, ran local metadata/temporal/ablation/group-balance/campaign-cap audits, and documented the remaining hard blockers. Full HGNN retraining was not run in this session because no CUDA device was visible to PyTorch.

## Current Selected Manifest

| Class | Graphs | Subtypes | Days | PCAP groups | Window groups | Endpoint/service groups |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Benign | 23,403 | BENIGN 23,403 | 7 | 455 | 3,035 | 7 |
| Bot | 24,000 | Bot 24,000 | 1 | 10 | 10 | 1 |
| BruteForce | 24,000 | FTP-BruteForce 12,000; SSH-Bruteforce 12,000 | 1 | 7 | 7 | 1 |
| DDoS | 24,000 | DDOS-HOIC 10,767; DDOS-LOIC-HTTP 10,736; DDOS-LOIC-UDP 2,497 | 2 | 8 | 10 | 11 |
| DoS | 24,000 | GoldenEye 6,000; Hulk 8,093; SlowHTTPTest 3,907; Slowloris 6,000 | 2 | 9 | 10 | 3 |
| Infiltration | 23,990 | Infiltration 23,990 | 1 | 18 | 18 | 1 |
| WebBased | 412 | BF-Web 257; BF-XSS 112; SQLi 43 | 2 | 1 | 6 | 2 |

Endpoint/service grouping is only partially useful in this compact manifest. Several attack classes collapse to one endpoint/service group because the compact records do not consistently retain `src_ip`, `dst_ip`, `dst_port`, and `protocol`.

## Audit Status

| Audit | Status | Result |
| --- | --- | --- |
| 1. Subtype-stratified similarity report | Complete | Existing stratified compact NN audit was rerun with FTP included. |
| 2. Group-held-out NN similarity | Complete | 14 held-out folds were run. |
| 3. Top-k group-held-out neighbor audit | Complete | Integrated into the group-held-out fold output for k=1,3,5,10. |
| 4. NN margin audit | Complete | Integrated into the group-held-out fold output. |
| 5. Targeted leave-one-window-out model retraining | Complete locally / model runs blocked | Robust PyG fold manifests and exact training commands were generated; full retraining was not run because this session has no CUDA device visible. |
| 6. Whole-PCAP holdout retraining | Complete locally / model runs blocked | Five whole-PCAP robust PyG fold manifests were generated; full retraining was not run because this session has no CUDA device visible. |
| 7. Endpoint/service holdout retraining | Complete / blocked by metadata | Endpoint/service grouping was audited and is invalid in the current compact manifest because every class has unknown endpoint keys. |
| 8. Temporal-context holdout audit | Complete / rebuild required | Temporal feature/provenance audit was run; current graphs use local fallback/missing temporal context and no temporal-index provenance. |
| 9. Feature ablation audit | Complete as compact NN ablation | Eight compact-vector ablations were run across five priority held-out folds. |
| 10. Group-balanced training audit | Complete as data/sampler audit | Group concentration and group-balanced available coverage were measured. |
| 11. Campaign-capped training audit | Complete as manifest audit | A campaign-capped compact training manifest was generated. |
| 12. External/cross-dataset robustness test | Complete / blocked by data availability | Local dataset scan found no independent external dataset candidate. |

## Audit 1 Result

Artifact:

```text
artifacts/office_model/robustness/nearest_neighbor_similarity_compact_bruteforce_dos_ddos_diverse_24k_stratified/nearest_neighbor_similarity_compact_audit.md
```

Configuration:

- Train cap per class: 5,000
- Validation cap per class: 500
- Sampling strategy: stratified by subtype, source dataset, day, and window/PCAP
- Vector dimension: 126

Overall result:

| Metric | Value |
| --- | ---: |
| Train sample count | 30,206 |
| Validation sample count | 3,103 |
| Median NN cosine distance | 0.000035 |
| P95 NN cosine distance | 0.008943 |
| Same-class NN rate | 0.963584 |
| Same-subtype NN rate | 0.963261 |
| Same-day NN rate | 0.826942 |
| Same-window NN rate | 0.459233 |
| Same-PCAP NN rate | 0.467612 |
| Same endpoint/service NN rate | 0.809861 |

Per-subtype attack rows:

| Class | Subtype | Median NN distance | Same subtype | Same window | Same PCAP | Same endpoint |
| ---------- | --------- | -----------------: | -----------: | ----------: | --------: | ------------: |
| BruteForce | SSH | 0.000027 | 1.000000 | 0.406504 | 0.406504 | 1.000000 |
| BruteForce | FTP | 0.000000 | 0.603053 | 0.603053 | 0.603053 | 0.603053 |
| DoS | Hulk | 0.000826 | 1.000000 | 0.512077 | 0.512077 | 1.000000 |
| DoS | GoldenEye | 0.001234 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
| DoS | Slowloris | 0.000065 | 1.000000 | 1.000000 | 1.000000 | 1.000000 |
| DoS | SlowHTTPTest | 0.000000 | 0.438776 | 0.438776 | 0.438776 | 0.438776 |
| DDoS | HOIC | 0.000083 | 1.000000 | 0.425641 | 0.425641 | 1.000000 |
| DDoS | LOIC-HTTP | 0.000022 | 1.000000 | 1.000000 | 1.000000 | 0.515464 |
| DDoS | LOIC-UDP | 0.000000 | 1.000000 | 0.625000 | 0.625000 | 0.932692 |

Interpretation: the subtype-diverse sample is real, but the random graph-level train/validation split is still weak. Many validation graphs remain extremely close to training graphs from the same subtype/window/PCAP.

## Audits 2, 3, and 4 Results

New audit script:

```text
secureedge/office/compact_group_holdout_nn_audit.py
```

Artifacts:

```text
artifacts/office_model/robustness/compact_group_holdout_nn_bruteforce_dos_ddos_diverse_24k/compact_group_holdout_nn_audit.json
artifacts/office_model/robustness/compact_group_holdout_nn_bruteforce_dos_ddos_diverse_24k/compact_group_holdout_nn_audit.csv
artifacts/office_model/robustness/compact_group_holdout_nn_bruteforce_dos_ddos_diverse_24k/compact_group_holdout_nn_audit.md
```

Command:

```bash
.venv/bin/python -m secureedge.office.compact_group_holdout_nn_audit \
  --compact-manifest artifacts/office_model/office_compact_cumulative_manifest_bruteforce_dos_ddos_diverse_24k.json \
  --output-dir artifacts/office_model/robustness/compact_group_holdout_nn_bruteforce_dos_ddos_diverse_24k \
  --query-cap 1000 \
  --reference-per-class 5000 \
  --seed 42 \
  --n-neighbors 10
```

Configuration:

- Loaded compact records: 143,805
- Missing compact files: 0
- Query cap per fold: 1,000 graphs
- Reference cap per class: 5,000 graphs
- Top-k values: 1, 3, 5, 10
- Margin definition: `nearest_wrong_class_distance - nearest_correct_class_distance`

Fold results:

| Fold | Held-out group | Query graphs | Query sampled | Top-1 correct | Top-3 correct | Top-5 correct | Top-10 correct | Correct dist med | Wrong dist med | Margin med | Positive margin | Strongest competitor |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| DDoS holdout LOIC-HTTP | DDoS / LOIC-HTTP | 10,736 | 1,000 | 0.002000 | 0.002000 | 0.002000 | 0.002000 | 0.662637 | 0.167534 | -0.550602 | 0.002000 | DoS |
| DDoS holdout LOIC-UDP | DDoS / LOIC-UDP | 2,497 | 1,000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.348231 | 0.117532 | -0.230887 | 0.000000 | Benign |
| DDoS holdout HOIC | DDoS / HOIC | 10,767 | 1,000 | 0.657000 | 0.652333 | 0.588200 | 0.354000 | 0.232185 | 0.262171 | 0.038597 | 0.657000 | WebBased |
| DoS holdout GoldenEye | DoS / GoldenEye | 6,000 | 1,000 | 0.143000 | 0.131000 | 0.129200 | 0.128400 | 0.321552 | 0.243739 | -0.071371 | 0.143000 | Benign |
| DoS holdout Slowloris | DoS / Slowloris | 6,000 | 1,000 | 0.068000 | 0.054000 | 0.050600 | 0.068900 | 0.210571 | 0.174303 | -0.035783 | 0.064000 | Benign |
| DoS holdout SlowHTTPTest | DoS / SlowHTTPTest | 3,907 | 1,000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.163533 | 0.000000 | -0.163533 | 0.000000 | BruteForce |
| DoS holdout Hulk | DoS / Hulk | 8,093 | 1,000 | 0.103000 | 0.204000 | 0.236400 | 0.195600 | 0.540407 | 0.494429 | -0.047994 | 0.103000 | Benign |
| BruteForce holdout FTP | BruteForce / FTP | 12,000 | 1,000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.445163 | 0.000000 | -1.445163 | 0.000000 | DoS |
| BruteForce holdout SSH | BruteForce / SSH | 12,000 | 1,000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 1.463358 | 0.123770 | -1.339626 | 0.000000 | DoS |
| Infiltration holdout early window | Infiltration / 13-14h | 14,016 | 1,000 | 0.998000 | 0.997000 | 0.997000 | 0.997200 | 0.001319 | 0.056011 | 0.054275 | 0.998000 | Benign |
| Infiltration holdout late window | Infiltration / 18-19h | 9,974 | 1,000 | 0.995000 | 0.994333 | 0.994400 | 0.991100 | 0.000999 | 0.055666 | 0.053733 | 0.995000 | Benign |
| WebBased holdout BF-Web | WebBased / BF-Web | 257 | 257 | 1.000000 | 1.000000 | 1.000000 | 0.933852 | 0.038368 | 0.125670 | 0.097406 | 1.000000 | Benign |
| WebBased holdout BF-XSS | WebBased / BF-XSS | 112 | 112 | 0.982143 | 0.988095 | 0.858929 | 0.672321 | 0.025469 | 0.059341 | 0.028796 | 0.982143 | Benign |
| WebBased holdout SQLi | WebBased / SQLi | 43 | 43 | 1.000000 | 1.000000 | 1.000000 | 0.990698 | 0.085907 | 0.162114 | 0.071171 | 1.000000 | Benign |

The SQLi fold has weak support because only 43 selected SQLi graphs exist.

## Group-Held-Out Interpretation

The random-split similarity result was too optimistic. Once subtype/window groups are fully held out, the behavior separates sharply:

- Infiltration is robust under its two window holdouts. Both folds retain top-1 correct rates above 0.995 and positive median margins around 0.054.
- WebBased subtype holdouts look good, but the sample is too small to rely on, especially SQLi.
- HOIC partially maps to DDoS when held out, but performance decays in the top-10 neighborhood. Top-1 correct is 0.657, top-10 correct fraction is 0.354.
- LOIC-HTTP and LOIC-UDP do not map to the remaining DDoS subtypes in this compact NN space. They are closer to DoS or Benign than to same-class DDoS references.
- DoS subtype holdouts are weak. GoldenEye, Slowloris, SlowHTTPTest, and Hulk all have negative median margins.
- BruteForce FTP-vs-SSH subtype transfer fails in both directions. This is expected to be risky because FTP is a closest-attempt exception set rather than clean successful FTP-BruteForce traffic, and SSH/FTP are represented by very different campaign behavior.

The main conclusion is that subtype diversity in the manifest is necessary but not sufficient. A model trained with random graph splits can still appear excellent while failing broad-class transfer across held-out subtypes.

## Audit 5: Targeted Leave-One-Window-Out Model Retraining

Status: complete locally; model training run blocked in this session.

Generated artifact summary:

```text
artifacts/office_model/robustness/remaining_audits/remaining_robustness_audits.md
artifacts/office_model/robustness/remaining_audits/remaining_robustness_audits.json
artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/
```

The audit generated trainable PyG graph manifests for seven targeted robust folds. Each manifest removes the held-out group from training and uses the held-out group as the test split.

| Fold | Held out | Remaining train same class | Manifest |
| --- | ---: | ---: | --- |
| `ddos_holdout_loic-udp` | 2,497 | 17,919 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/ddos_holdout_loic-udp_graph_manifest.json` |
| `ddos_holdout_hoic` | 10,767 | 11,027 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/ddos_holdout_hoic_graph_manifest.json` |
| `dos_holdout_goldeneye` | 6,000 | 15,000 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/dos_holdout_goldeneye_graph_manifest.json` |
| `dos_holdout_hulk` | 8,093 | 13,255 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/dos_holdout_hulk_graph_manifest.json` |
| `bruteforce_holdout_ftp` | 12,000 | 10,000 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/bruteforce_holdout_ftp_graph_manifest.json` |
| `infiltration_holdout_early_13_14h` | 14,016 | 8,269 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/infiltration_holdout_early_13_14h_graph_manifest.json` |
| `infiltration_holdout_late_18_19h` | 9,974 | 11,722 | `artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/infiltration_holdout_late_18_19h_graph_manifest.json` |

Full HGNN retraining was not run because `torch.cuda.is_available()` returned `False` in this session. The original office run used about 140-153 seconds per epoch on an RTX 4060; running seven full folds on CPU here would not be a defensible completion path.

## Audit 6: Whole-PCAP Holdout Retraining

Status: complete locally; model training run blocked in this session.

Five whole-PCAP robust PyG manifests were generated:

| Fold | Class | Held out | PCAP |
| --- | --- | ---: | --- |
| `pcap_holdout_9e3c69ea9896` | BruteForce | 12,000 | `UCAP172.31.69_297fe3088e21e102_3e2da389c57f7b08.pcap` |
| `pcap_holdout_82f4aef8d960` | DoS | 12,000 | `UCAP172.31.69.25` |
| `pcap_holdout_d2e7450cac32` | DDoS | 11,488 | `tuesday20_ddos_loic_victim_attackers_port80.pcap` |
| `pcap_holdout_7be6a5fe28e8` | DoS | 7,132 | `UCAP172.31.69.25-part1_21bf134025b00e7a_6232ae4967095901.pcap` |
| `pcap_holdout_48dbfe25b680` | BruteForce | 6,532 | `UCAP172.31.69_297fe3088e21e102_306efe582ab13a2f.pcap` |

The manifests are stored under:

```text
artifacts/office_model/robustness/remaining_audits/robust_pyg_manifests/
```

No whole-PCAP HGNN retraining was run because CUDA is unavailable in this session.

## Audit 7: Endpoint/Service Holdout Retraining

Status: complete; blocked for the current compact manifest.

The planned endpoint/service key is:

```text
source_dataset | day | src_ip | dst_ip | dst_port | protocol
```

The endpoint/service audit confirmed the selected compact records do not preserve these fields. Every class has an unknown-key rate of `1.000000`.

| Class | Graphs | Endpoint/service groups | Unknown-key rate | Status |
| --- | ---: | ---: | ---: | --- |
| Benign | 23,403 | 7 | 1.000000 | blocked_or_weak_metadata |
| Bot | 24,000 | 1 | 1.000000 | blocked_or_weak_metadata |
| BruteForce | 24,000 | 1 | 1.000000 | blocked_or_weak_metadata |
| DDoS | 24,000 | 11 | 1.000000 | blocked_or_weak_metadata |
| DoS | 24,000 | 3 | 1.000000 | blocked_or_weak_metadata |
| Infiltration | 23,990 | 1 | 1.000000 | blocked_or_weak_metadata |
| WebBased | 412 | 2 | 1.000000 | blocked_or_weak_metadata |

To run this audit correctly, rebuild or rejoin compact metadata with endpoint fields retained for every selected graph.

## Audit 8: Temporal-Context Holdout Audit

Status: complete; rebuild required for the strict version.

The temporal provenance audit found:

| Metric | Value |
| --- | ---: |
| Flow feature count | 92 |
| Temporal feature count | 16 |
| `local_worker_fallback` records | 94,063 |
| `missing` temporal context records | 49,742 |
| Records with temporal index path provenance | 0 |

The existing compact graphs therefore cannot prove split-before-temporal-generation isolation. A strict temporal-context holdout still requires rebuilding splits before temporal feature generation, maintaining separate temporal state for train/validation/test, and resetting destination windows at group boundaries.

## Audit 9: Feature Ablation Audit

Status: complete as compact nearest-neighbor ablation.

Artifact:

```text
artifacts/office_model/robustness/remaining_audits/feature_ablation_compact_nn_audit.json
```

The ablation audit ran these variants over five priority held-out folds:

```text
full, no_temporal, temporal_only, flow_only, no_ports, no_protocol, no_packet_payload, packet_only
```

Selected results:

| Variant | Fold | Top-1 correct | Top-10 correct | Median margin | Competitor |
| --- | --- | ---: | ---: | ---: | --- |
| full | DDoS LOIC-UDP | 0.000000 | 0.000000 | -0.227589 | Benign |
| no_temporal | DDoS LOIC-UDP | 0.000000 | 0.000000 | -0.217579 | Benign |
| temporal_only | DDoS LOIC-UDP | 0.000000 | 0.000000 | -0.238782 | Infiltration |
| full | DoS Hulk | 0.230000 | 0.112800 | -0.032719 | Benign |
| packet_only | DoS Hulk | 0.974000 | 0.987800 | 0.000252 | Benign |
| full | BruteForce FTP | 0.000000 | 0.000000 | -1.415936 | DoS |
| full | Infiltration early | 1.000000 | 0.997600 | 0.058802 | Benign |
| no_temporal | Infiltration early | 0.998000 | 0.995400 | 0.024290 | Benign |
| packet_only | Infiltration early | 0.558000 | 0.686400 | 0.000000 | DoS |

Interpretation: temporal features are not the only driver of the observed similarity. Infiltration remains strong without temporal features, but packet-only representation damages Infiltration separation. DoS Hulk becomes much easier under packet-only compact statistics, which suggests packet-byte/packet-count regularities are a major shortcut candidate for that subtype.

## Audit 10: Group-Balanced Training Audit

Status: complete as data/sampler audit.

Artifact:

```text
artifacts/office_model/robustness/remaining_audits/group_balance_campaign_cap_audit.json
```

The current selected manifest still contains dominant campaign blocks:

| Class | Train graphs | Groups | Largest group share |
| --- | ---: | ---: | ---: |
| Benign | 19,503 | 3,011 | 0.001948 |
| Bot | 20,000 | 10 | 0.112600 |
| BruteForce | 20,000 | 7 | 0.500000 |
| DDoS | 20,000 | 10 | 0.446800 |
| DoS | 20,000 | 8 | 0.319850 |
| Infiltration | 19,991 | 18 | 0.207994 |
| WebBased | 206 | 6 | 0.339806 |

A group-balanced sampler should still sample by:

```text
broad class -> subtype -> window/PCAP/session group -> graph
```

This should be used for the next GPU training run and compared against ordinary graph-level sampling on the robust holdout manifests generated above.

## Audit 11: Campaign-Capped Training Audit

Status: complete as manifest audit.

Artifact:

```text
artifacts/office_model/robustness/remaining_audits/campaign_capped_train_compact_manifest.json
```

The generated cap is `1,000` train graphs per class/subtype/window group.

| Class | Original train | Capped train |
| --- | ---: | ---: |
| Benign | 19,503 | 19,503 |
| Bot | 20,000 | 9,717 |
| BruteForce | 20,000 | 4,227 |
| DDoS | 20,000 | 5,091 |
| DoS | 20,000 | 4,348 |
| Infiltration | 19,991 | 7,455 |
| WebBased | 206 | 206 |

This confirms the attack classes are heavily campaign-repeated. The capped manifest is not a replacement final training manifest by itself; it is an audit artifact for comparing capped-vs-uncapped training under the same robust holdout evaluation.

## Audit 12: External/Cross-Dataset Robustness Test

Status: complete; blocked by data availability.

The local dataset availability scan found:

| Metric | Value |
| --- | ---: |
| PCAP files under `datasets` | 3 |
| CSV files under `datasets` | 17 |
| Independent external candidates | 0 |

The local files are the project CIC-IDS-2018/CICIDS2017 sources, not an independent external compatible dataset. External robustness remains blocked until a separate source is added.

## Bottom Line

The robust audit substantially lowers confidence in random-split training results. Infiltration has encouraging unseen-window behavior, but DDoS, DoS, and BruteForce subtype transfer are weak in compact nearest-neighbor space. The next phase should not be another random-split training run; it should be targeted HGNN retraining on group-held-out folds, starting with Infiltration as a sanity-positive fold and one hard DDoS/DoS fold as a stress test.
