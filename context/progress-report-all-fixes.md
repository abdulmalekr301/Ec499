# SecureEdge Combined Fixes Progress Report

Generated: `2026-06-14`

## Purpose

This report documents the full implementation status after applying both fix instruction files:

- `context/fixes.md`
- `context/fixes-2.md`

It records what changed, what artifacts were regenerated, what validations passed, and what performance results were obtained after the latest end-to-end run.

## Baseline Before Fixes

Before the two fix passes, the project used a custom `dpkt`-based PCAP flow extractor and computed temporal features after sampling and balancing. The model reached:

```text
Macro F1: 0.774469
```

Major problems at that point:

- Flow features were produced by a custom parser instead of NFStream.
- Temporal features were computed after sampling, destroying real traffic-density context.
- The DDoS/DoS reservoir logic could be dominated by whichever subtype was processed first.
- Ports and protocol were excluded from the model feature vector.
- Flows longer than 20 packets were discarded instead of windowed/capped correctly.

## Fix Pass 1: `fixes.md`

### NFStream Migration

The custom packet parser in:

```text
secureedge/data/pcap_flows.py
```

was replaced with NFStream-based extraction.

Changes made:

- Added `nfstream>=6.3.3` to `requirements.txt`.
- Installed NFStream `6.6.0`.
- Used `NFStreamer` with:

```text
statistical_analysis=True
splt_analysis=0
n_dissections=0
idle_timeout=120
active_timeout=1800
accounting_mode=0
```

### Temporal Features Moved Before Sampling

Temporal features are now computed during PCAP streaming, before reservoir sampling and class balancing.

Corrected flow:

```text
PCAP
  -> NFStream flow
  -> temporal feature update
  -> enriched flow record
  -> reservoir sampling
  -> split/balance
```

`secureedge/features/pipeline.py` no longer recomputes temporal features after sampling. It now validates that temporal columns already exist, then scales the feature matrix.

### NFStream Feature Count

The installed NFStream version produced `57` numeric statistic fields after metadata exclusion during the first fix pass.

After adding `16` temporal features, the model input size became:

```text
57 + 16 = 73
```

### First Fix Pass Result

After applying `fixes.md`, regenerating artifacts, and retraining:

```text
Macro F1: 0.870941
OOD threshold: 0.4565748
Feature count: 73
```

This was a major improvement over the original `0.774469`, but the model was still below the methodology target.

## Fix Pass 2: `fixes-2.md`

The second fix pass addressed three remaining issues:

1. The 20-packet cap was implemented as a discard filter instead of a flow cap/window.
2. Class-level reservoirs biased training toward one subtype per class.
3. `src_port`, `dst_port`, and `protocol` were excluded from model features.

## Fix 2.1: 20-Packet FlowCapper

The old behavior after the first fix pass was:

```text
NFStream emits complete flow
if bidirectional_packets > 20:
    discard flow
```

This was wrong because long-running flows were lost instead of becoming multiple capped flow records.

Implemented a FlowCapper plugin in:

```text
secureedge/data/pcap_flows.py
```

The plugin expires a flow once it reaches `20` bidirectional packets:

```text
if flow.bidirectional_packets >= 20:
    flow.expiration_id = -1
```

NFStream `6.6.0` uses the `udps` parameter for plugins, so the streamer is now constructed with:

```text
udps=[NFStreamFlowCapper()]
```

The old post-filter that discarded flows over `20` packets was removed.

Verification:

```text
max bidirectional_packets in train_standard.csv: 20
max bidirectional_packets in test_standard.csv: 20
```

## Fix 2.2: Per-Subtype Reservoirs

The class-level reservoir was replaced with a two-level subtype-aware sampling strategy.

New behavior:

1. Each subtype gets its own target reservoir.
2. Subtype reservoirs are merged into class pools.
3. Class pools are balanced to `24,000` records each.
4. Each class pool is split into:

```text
20,000 train records
4,000 test records
```

Per-subtype targets:

```text
DDoS:       12 subtypes -> 2,000 each
DoS:         4 subtypes -> 6,000 each
Mirai:       3 subtypes -> 8,000 each
Recon:       5 subtypes -> 4,800 each
Spoofing:    2 subtypes -> 12,000 each
WebBased:    6 subtypes -> 4,000 each
BruteForce:  1 subtype  -> 24,000
Benign:      1 subtype  -> 24,000
```

Added subtype mapping in:

```text
secureedge/config.py
```

New mapping:

```text
SUBTYPE_TO_CLASS
```

The DDoS/DoS SYN-priority ordering from the previous fix pass was removed. PCAPs are now processed in natural sorted order because subtype reservoirs prevent one subtype from dominating a class.

Verification:

```text
train rows: 160000
test rows: 32000
DDoS training subtypes: 12
BruteForce training subtype: DictionaryBruteForce only
```

DDoS training subtype distribution:

```text
DDoS-ACK_Fragmentation     1676
DDoS-HTTP_Flood            1675
DDoS-ICMP_Flood            1655
DDoS-ICMP_Fragmentation    1639
DDoS-PSHACK_Flood          1660
DDoS-RSTFINFlood           1697
DDoS-SYN_Flood             1657
DDoS-SlowLoris             1692
DDoS-SynonymousIP_Flood    1668
DDoS-TCP_Flood             1645
DDoS-UDP_Flood             1658
DDoS-UDP_Fragmentation     1678
```

No DDoS subtype accounts for more than approximately `8.5%` of DDoS training rows.

## Fix 2.3: Ports and Protocol Included

The following fields were removed from the metadata exclusion lists and are now model features:

```text
src_port
dst_port
protocol
```

Updated files:

```text
secureedge/config.py
secureedge/features/pipeline.py
secureedge/data/dataset.py
```

Feature count after this fix:

```text
60 NFStream/flow features
16 temporal features
76 total model input features
```

Verification:

```text
feature_columns.json entries: 76
config.INPUT_DIM: 76
src_port present: yes
dst_port present: yes
protocol present: yes
```

## Model Alignment

Updated:

```text
secureedge/models/architecture.py
```

`SecureEdgeMLP` now defaults to:

```text
input_dim=config.INPUT_DIM
```

A `net` alias was added for compatibility with the verification instruction in `fixes-2.md`:

```text
model.net[0].in_features == config.INPUT_DIM
```

Current verification:

```text
model.net[0].in_features: 76
```

## Evaluation Enhancement

Updated:

```text
secureedge/models/evaluate.py
```

Evaluation now writes a DDoS per-subtype prediction distribution into:

```text
artifacts/metrics.json
context/06_evaluation.md
```

This was required by `fixes-2.md` so DDoS performance can be checked across all 12 subtypes instead of only as a class-level aggregate.

## Regenerated Artifacts

After applying both fix passes, all stale artifacts were deleted and regenerated.

Processed data:

```text
data/processed/train_standard.csv
data/processed/test_standard.csv
data/processed/train_features.csv
data/processed/test_features.csv
```

Artifacts:

```text
artifacts/standard_scaler.joblib
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
artifacts/best_model.pt
artifacts/metrics.json
artifacts/ood_threshold.json
artifacts/secureedge_model.ts
```

Context files regenerated or updated:

```text
context/01_dataset_acquisition.md
context/02_preprocessing.md
context/03_feature_engineering.md
context/04_model_architecture.md
context/05_training.md
context/06_evaluation.md
context/07_ood_detection.md
context/08_export.md
```

## Current Preprocessing Output

The latest preprocessing run produced:

```text
feature_columns=76
expected_input_dim=76
```

Raw usable flow counts by subtype:

```text
Backdoor_Malware            3236
BenignTraffic              25000
BrowserHijacking            4763
CommandInjection            5000
DDoS-ACK_Fragmentation      5000
DDoS-HTTP_Flood             5000
DDoS-ICMP_Flood             5000
DDoS-ICMP_Fragmentation     5000
DDoS-PSHACK_Flood           5000
DDoS-RSTFINFlood            5000
DDoS-SYN_Flood              5000
DDoS-SlowLoris              5000
DDoS-SynonymousIP_Flood     5000
DDoS-TCP_Flood              5000
DDoS-UDP_Flood              5000
DDoS-UDP_Fragmentation      5000
DNS_Spoofing               15000
DictionaryBruteForce       11043
DoS-HTTP_Flood             10000
DoS-SYN_Flood              10000
DoS-TCP_Flood              10000
DoS-UDP_Flood              10000
MITM-ArpSpoofing           15000
Mirai-greeth_flood         10000
Mirai-greip_flood          10000
Mirai-udpplain             10000
Recon-HostDiscovery         5000
Recon-OSScan                5000
Recon-PingSweep             2226
Recon-PortScan              5000
SqlInjection                5000
Uploading_Attack            1619
VulnerabilityScan           5000
XSS                         4270
```

Class pools before split:

```text
Benign        24000
DDoS          24000
DoS           24000
Mirai         24000
Recon         24000
Spoofing      24000
WebBased      24000
BruteForce    24000
```

Final train/test class counts:

```text
Train: 20,000 per class, 160,000 total
Test:   4,000 per class,  32,000 total
```

## Current Training Result

Training completed after epoch `148`.

Best macro F1:

```text
0.84956285320623
```

The result is lower than the first fix pass `0.870941`, but it is a more honest evaluation because:

- DDoS now includes all 12 subtypes.
- DoS includes all 4 subtypes.
- Spoofing includes both DNS spoofing and MITM ARP spoofing.
- Recon and WebBased include their subtype diversity.
- Long flows are capped at 20 packets rather than discarded.

## Current Evaluation Results

Current macro F1:

```text
0.84956285320623
```

Per-class metrics:

```text
Benign:     precision=0.8403, recall=0.8535, f1=0.8468
DDoS:       precision=0.9943, recall=0.9090, f1=0.9497
DoS:        precision=0.9987, recall=0.9798, f1=0.9891
Mirai:      precision=1.0000, recall=0.9968, f1=0.9984
Recon:      precision=0.9068, recall=0.6935, f1=0.7859
Spoofing:   precision=0.8959, recall=0.6715, f1=0.7676
WebBased:   precision=0.5845, recall=0.8283, f1=0.6854
BruteForce: precision=0.7199, recall=0.8357, f1=0.7735
```

Strong classes:

```text
DDoS
DoS
Mirai
```

Weak classes:

```text
Recon
Spoofing
WebBased
BruteForce
Benign
```

The project is still below the methodology target:

```text
Target macro F1: >= 0.97
Current macro F1: 0.84956
```

## DDoS Subtype Observation

DDoS class-level F1 is now:

```text
0.9497
```

This is lower than the earlier inflated DDoS score, but it is now measured across all 12 DDoS subtypes.

The DDoS subtype distribution in `metrics.json` shows `DDoS-SlowLoris` is the weakest DDoS subtype. It is often confused with:

```text
Benign
WebBased
BruteForce
Recon
Spoofing
```

That matches the diagnosis notes in `fixes-2.md`, which warned that SlowLoris may require special attention because its traffic pattern differs from high-rate flood variants.

## OOD and Export

OOD threshold was recalibrated:

```text
0.3982970416545868
```

TorchScript export was regenerated:

```text
artifacts/secureedge_model.ts
```

Export verification passed: traced TorchScript logits matched PyTorch logits within tolerance.

## Verification Completed

Verification checks that passed:

```text
python -m compileall secureedge tests
python tests/smoke_checks.py
python -m secureedge.data.acquire
python -m secureedge.data.preprocess
python -m secureedge.features.pipeline
python -m secureedge.models.train
python -m secureedge.models.evaluate
python -m secureedge.ood.detector
python -m secureedge.export.export
```

Additional checks:

```text
feature_columns.json count: 76
config.INPUT_DIM: 76
src_port/dst_port/protocol present: yes
max bidirectional_packets: 20
train rows: 160000
test rows: 32000
DDoS subtype count in training: 12
TorchScript exists: yes
```

## Problems Encountered During Both Fix Passes

### NFStream Was Not Initially Installed

The first NFStream import failed with:

```text
ModuleNotFoundError: No module named 'nfstream'
```

Resolution:

- Added NFStream to `requirements.txt`.
- Installed dependencies after network permission was granted.

### NFStream Feature Count Differed From Expectations

NFStream `6.6.0` did not initially expose the expected `76` numeric feature count after metadata exclusion. After `src_port`, `dst_port`, and `protocol` were correctly included, the model feature count became:

```text
60 flow/metadata-as-feature columns + 16 temporal columns = 76
```

### NFStream Plugin Parameter Was Version-Specific

The fixes document used:

```text
plugins=[FlowCapper()]
```

NFStream `6.6.0` expects:

```text
udps=[FlowCapper()]
```

Resolution:

- Patched `pcap_flows.py` to use `udps`.

### FlowCapper Method Resolution Order

The first FlowCapper implementation inherited in the wrong order, so `NFPlugin.on_update()` took precedence over the capper logic.

Resolution:

- Changed the runtime plugin class to inherit `FlowCapper` before `NFPlugin`.
- Verified live NFStream output had `max bidirectional_packets = 20`.

### The More Correct Dataset Produced a Lower Macro F1

The latest macro F1 is lower than the first fix pass because the previous dataset was biased toward easier subtype representations, especially in DDoS.

The latest result is more reliable:

- It represents all DDoS subtypes.
- It includes all multi-subtype class variants.
- It no longer discards long flows.
- It includes port and protocol signals.

## Recommended Next Work

1. Add a full confusion matrix artifact to identify class-level confusion patterns.
2. Add per-subtype prediction breakdowns for Recon, Spoofing, WebBased, and BruteForce, not only DDoS.
3. Investigate why Recon recall is low despite strong precision.
4. Investigate Spoofing recall, especially DNS spoofing versus MITM ARP spoofing.
5. Inspect WebBased subtypes individually; Backdoor and Uploading may be flow-level limited without payload features.
6. Consider subtype-balanced training inside each class rather than only subtype-balanced reservoir construction.
7. Consider class/subtype-aware loss weighting or a two-stage classifier.
8. Document that reaching `>=0.97` may require the later graph/payload phase described by the methodology, not only flow-level MLP features.

