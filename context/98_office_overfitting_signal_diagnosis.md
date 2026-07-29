# Office Training Overfitting-Signal Diagnosis

Date: 2026-07-29

## Purpose

List the reasons the office training run shows very high signs of overfitting or overly easy validation, based on the current training history and graph manifests.

This report separates:

- confirmed evidence from the actual run;
- likely causes;
- possible causes that still need audit work;
- causes that are currently ruled out by existing gates.

## Confirmed Training Evidence

Current run artifacts:

```text
artifacts/office_model/office_training_history.json
artifacts/office_model/training_runs/office_run_01_history.json
context/office-training-logs-01.md
```

The restarted GATv2 office run still shows unusually high validation performance immediately:

| Epoch | Train loss | Validation accuracy | Validation macro-F1 | Validation weighted-F1 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0.226048 | 0.995021 | 0.995659 | 0.995021 |
| 2 | 0.001505 | 0.998755 | 0.998914 | 0.998755 |
| 3 | 0.000751 | 0.998589 | 0.998769 | 0.998589 |
| 18 | 0.000165 | 0.999336 | 0.999421 | 0.999336 |

Best validation macro-F1 by epoch 18:

```text
0.999638 at epoch 11
```

The run diagnostics repeatedly flag:

```text
first_epoch_validation_macro_f1_ge_0.98
very_low_train_loss_with_near_perfect_validation_macro_f1
webbased_validation_support_is_low
```

Latest per-class validation metrics at epoch 18 are nearly perfect:

| Class | Validation support | TP | FP | FN | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Benign | 1,949 | 1,945 | 4 | 4 | 0.997948 |
| BruteForce | 2,000 | 2,000 | 0 | 0 | 1.000000 |
| DoS | 2,000 | 2,000 | 0 | 0 | 1.000000 |
| DDoS | 2,000 | 2,000 | 0 | 0 | 1.000000 |
| WebBased | 103 | 103 | 0 | 0 | 1.000000 |
| Bot | 2,000 | 2,000 | 0 | 0 | 1.000000 |
| Infiltration | 1,999 | 1,995 | 4 | 4 | 0.997999 |

The strongest signal is not just high validation accuracy. It is the combination of:

1. Near-perfect validation in epoch 1.
2. Train loss collapsing by epoch 2.
3. Almost every attack class reaching perfect validation F1.
4. Validation staying near-perfect for many epochs.

## Current Split Counts

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

`materialization_incomplete` is `false`.

## Reasons and Risk Factors

### 1. The split is graph/candidate-level, not session-level

The most likely cause is that train, validation, and test are split at the individual graph/candidate level while many samples come from the same capture day, attack campaign, endpoint pair, and attack time window.

This can produce excellent validation scores without proving generalization. The model may only need to learn session-specific patterns that appear in both train and validation.

This is not the same as exact duplicate leakage. It is distribution leakage or near-neighbor leakage.

Risk level: high.

### 2. Attack classes are strongly tied to specific days and windows

The office class mapping is built from CIC-IDS-2018 attack days and time windows:

| Class | Main source |
| --- | --- |
| BruteForce | Wednesday-14-02-2018 |
| DoS | Friday-16-02-2018 |
| DDoS | Wednesday-21-02-2018 |
| Bot | Friday-02-03-2018 |
| Infiltration | Thursday-01-03-2018 |
| WebBased | Thursday-22-02-2018 and Friday-23-02-2018 |

If train and validation both contain flows from the same attack windows, the model may learn capture/window signatures instead of attack behavior that transfers to a different day, subnet, or campaign.

Risk level: high.

### 3. Endpoint and role patterns may be class-identifying

Many CIC-IDS-2018 office attacks have stable attacker and victim endpoint roles. Even if raw IP or MAC feature names are not present in the graph tensors, the generated flow and packet features can still carry endpoint/session artifacts indirectly through:

- ports;
- protocol;
- directionality;
- packet sizes;
- timing;
- flow duration;
- attack-specific traffic volume;
- temporal context features.

Gate 5 confirms tuple context features exist:

```text
src_port
dst_port
protocol
```

The warning does not mean these features are wrong. It means the model may have easy class shortcuts if the same endpoint/port/protocol patterns are shared across train and validation.

Risk level: high.

### 4. Validation contains near-neighbor flows from the same PCAPs

The same raw PCAP/day/window can contribute many similar candidate flows. Even if there are no duplicate graph IDs, validation flows may be adjacent in time or generated from the same burst as training flows.

For bursty attacks like DoS, DDoS, BruteForce, and Bot, adjacent flows can be almost interchangeable. A random graph-level split will make validation easier than a deployment-style split.

Risk level: high.

### 5. The attack classes may be separable by simple flow statistics

Some CIC-IDS-2018 attack classes are naturally very separable:

- DDoS and DoS can have strong packet-rate, duration, protocol, and size signatures.
- BruteForce can have repeated service-port patterns.
- Bot traffic can have distinctive endpoint and timing behavior.
- Infiltration may have a narrow traffic pattern in this selected subset.

If the selected office dataset is highly separable, high validation scores may be partly real. But first-epoch near-perfection still suggests the validation split is too similar to train for research-strength claims.

Risk level: medium-high.

### 6. WebBased validation support is too small

WebBased has only:

```text
train=206
val=103
test=103
```

With only 103 validation graphs, WebBased F1 is high variance. A result of `103/103` correct can happen in a narrow split and still fail to generalize to different web attack captures.

Risk level: high for WebBased conclusions.

### 7. Balanced sampling repeatedly exposes scarce WebBased examples

The training loader uses a weighted random sampler with replacement and roughly equal expected class probability per draw:

```text
expected_class_probability_per_draw = 1/7 per class
```

Since WebBased has only 206 training graphs, those examples are seen repeatedly within and across epochs. This is intentional imbalance handling, but it increases memorization pressure for WebBased.

Risk level: high for WebBased, medium overall.

### 8. Weighted loss makes the scarce class influential

The current train-only WebBased class weight is:

```text
6.13131
```

This is defensible for imbalance, but combined with repeated WebBased sampling it can make the model fit the tiny WebBased training set very aggressively.

Risk level: medium-high for WebBased.

### 9. Validation is used every epoch for checkpoint selection

The trainer selects the checkpoint by validation macro-F1. This is normal, but when validation is very similar to training, repeated validation can encourage tuning to that split over time.

This is not the cause of epoch 1 being too high, because checkpoint selection has not had time to overfit at epoch 1. It is still a risk for later epochs.

Risk level: medium.

### 10. Model capacity is enough to memorize narrow session signatures

The current model uses:

```text
SecureEdgeHGNN + GATv2Conv
```

GATv2 is expressive enough to rapidly memorize stable relation, timing, and packet patterns when train and validation are drawn from the same narrow capture sessions.

This does not mean GATv2 is wrong. It means architecture capacity can amplify weak split design.

Risk level: medium.

### 11. Training loss collapse suggests the task is too easy under this split

The restarted run used the fixed gradient accumulation behavior and still reached:

```text
epoch 2 train_loss = 0.001505
```

That is a direct signal that the training objective is nearly solved almost immediately. This can happen with a very clean dataset, but paired with near-perfect validation it strongly suggests the split is not challenging enough.

Risk level: high.

### 12. Test split may share the same weakness as validation

The test split is held out from training, but it appears to be produced by the same split strategy as validation. If test graphs are also sampled from the same days/windows/sessions as train, then test performance may also be optimistic.

This means a high test score would be useful but not sufficient for a strong thesis claim. A grouped or temporal holdout is still needed.

Risk level: high.

## Causes Currently Ruled Out or Not Proven

### Exact duplicate graph leakage is not currently shown

Gate 7 passes:

```text
status=pass
hard_failure_count=0
warning_count=0
```

Current duplicate/leakage checks report:

| Check | Count |
| --- | ---: |
| Duplicate candidate identity | 0 |
| Cross-split candidate identity overlap | 0 |
| Cross-split flow hash overlap | 0 |
| Cross-split graph ID overlap | 0 |

So the current evidence does not show exact duplicate graph leakage.

### Raw IP/MAC tensor leakage is not currently shown

Gate 5 warns that no raw IP/MAC feature names were found. That suggests raw IP/MAC features are not directly present by name in the graph tensors.

This does not rule out indirect endpoint/session leakage through ports, protocol, timing, packet size, flow statistics, or attack-window context.

### The old gradient accumulation bug is not the cause of the restarted run

The office trainer previously had a gradient accumulation scaling bug. That bug was fixed before the current `office_run_01` history was produced.

The current run uses:

```text
grad_accum_steps=1
```

Therefore the accumulation bug is not the cause of the current overfitting signal. The overfitting signal persisted after that fix.

## Most Likely Explanation

The best current explanation is:

```text
The office split is clean from exact duplicate leakage, but not strict enough from a session/day/window/generalization perspective.
```

The model is probably learning stable capture-session and attack-window signatures that are shared across train and validation. This makes validation look almost solved immediately.

## Recommended Audits Before Trusting Results

### 1. Grouped split audit

Measure overlap by:

- attack day;
- attack subtype;
- time window;
- PCAP source;
- source/destination endpoint pair;
- five-tuple without timestamp;
- nearest-neighbor timestamp distance.

### 2. Grouped evaluation

Run stricter evaluations:

- leave-one-window-out;
- leave-one-day-out when class coverage permits;
- hold out whole PCAPs;
- hold out endpoint pairs;
- evaluate WebBased separately.

### 3. Shortcut-feature ablation

Train/evaluate ablations that remove or mask:

- tuple context features;
- ports;
- protocol;
- temporal context features;
- packet payload bytes;
- high-level flow timing features.

This will show whether the model relies on robust traffic behavior or easy session shortcuts.

### 4. Nearest-neighbor similarity audit

For each validation graph, find the nearest training graph by:

- flow feature distance;
- packet-size/timing summary;
- candidate timestamp proximity;
- same endpoint/service tuple.

If validation graphs have extremely close train neighbors, high validation F1 is expected and not strong evidence of generalization.

### 5. Treat WebBased separately

WebBased should be reported with explicit caveats:

- only 206 train graphs;
- only 103 validation graphs;
- only 103 test graphs;
- oversampled training exposure;
- class weight `6.13131`;
- high variance metrics.

## Immediate Recommendation

Do not present the current validation macro-F1 as final model quality.

Use it as a smoke result showing that:

1. the graph tensors load correctly;
2. GATv2 training runs end-to-end;
3. the model can fit the current office split;
4. the current split is probably too easy for a strong generalization claim.

The next research-quality step is to add a grouped/temporal robustness evaluation before relying on the reported macro-F1.
