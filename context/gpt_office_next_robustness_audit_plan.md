# Office Model — Next Robustness Audit Plan

Date: 2026-08-02

## Purpose

This document defines the next robustness audits to run after the updated subtype-diverse nearest-neighbor similarity rerun.

The current evidence shows two separate issues:

1. **Class diversity improved** after adding newer DoS and DDoS subtypes and the closest defensible FTP-BruteForce attempts.
2. **Train/validation independence is still weak** because the current random graph-level split leaves validation graphs extremely close to training graphs, often from the same subtype, day, window, PCAP, or endpoint/service group.

The next audits therefore shift away from asking whether random train/validation graphs are dissimilar and instead ask:

> Can a completely unseen subtype, window, PCAP, or endpoint/service group still map to the correct broad attack class?

---

## Current Reference Point

The latest stratified nearest-neighbor rerun confirmed that DDoS sampling now includes meaningful subtype diversity:

- DDOS-HOIC
- DDoS-LOIC-HTTP
- DDoS-LOIC-UDP

However, nearest-neighbor distances remain extremely small and same-subtype nearest-neighbor rates remain effectively perfect under the current random graph-level split.

This means that adding subtype diversity was necessary, but it did **not** by itself create an independent validation set.

---

# Audit 1 — Subtype-Stratified Similarity Report

## Objective

Extend the nearest-neighbor audit so that results are reported separately for every attack subtype instead of only at the broad-class level.

## Required per-subtype output

For every subtype, report:

- number of train samples;
- number of validation samples;
- median nearest-neighbor cosine distance;
- P95 nearest-neighbor cosine distance;
- same broad-class nearest-neighbor rate;
- same subtype nearest-neighbor rate;
- same day rate;
- same attack-window rate;
- same source-PCAP rate;
- same endpoint/service rate.

## Required subtype coverage

### BruteForce

- SSH-Bruteforce
- FTP-BruteForce best-attempt subset

### DoS

Include every subtype that currently has materialized graphs, for example:

- DoS-Hulk
- DoS-GoldenEye
- DoS-Slowloris
- DoS-SlowHTTPTest, if a defensible materialized subset exists

### DDoS

- DDOS-HOIC
- DDoS-LOIC-HTTP
- DDoS-LOIC-UDP

### WebBased

- Brute Force-Web
- Brute Force-XSS
- SQL Injection

### Other classes

- Bot
- Infiltration
- Benign by day/source group where useful

## Question answered

This audit tells us which new subtypes actually add feature-space diversity and which remain near-identical to existing traffic.

## Important interpretation

A high same-subtype nearest-neighbor rate is **not automatically bad** under the current random split. It mainly confirms that same-campaign samples are still shared across train and validation.

---

# Audit 2 — Group-Held-Out Nearest-Neighbor Similarity Audit

## Objective

This is the most important next nearest-neighbor audit.

Instead of allowing the query graph to find a training neighbor from the same subtype/window/group, completely remove one group from the reference training set and ask whether the unseen group is still closest to the correct **broad class**.

The desired result becomes:

```text
Unseen attack subtype/window
        ↓
nearest training neighbors
        ↓
other examples from the same broad class
```

This is stronger evidence of generalization than the current random-split nearest-neighbor test.

---

## 2A — DDoS Subtype Holdouts

Run separate nearest-neighbor folds.

### Fold DDoS-1 — Hold out LOIC-HTTP

Reference/train NN pool:

```text
DDOS-HOIC + DDoS-LOIC-UDP + all non-DDoS training classes
```

Query set:

```text
DDoS-LOIC-HTTP only
```

Measure:

- percentage whose nearest neighbor is DDoS;
- top-k DDoS neighbor rate;
- distance to nearest DDoS neighbor;
- distance to nearest non-DDoS neighbor;
- nearest-neighbor margin.

### Fold DDoS-2 — Hold out LOIC-UDP

Reference/train NN pool:

```text
DDOS-HOIC + DDoS-LOIC-HTTP + all non-DDoS training classes
```

Query set:

```text
DDoS-LOIC-UDP only
```

### Fold DDoS-3 — Hold out HOIC

Reference/train NN pool:

```text
DDoS-LOIC-HTTP + DDoS-LOIC-UDP + all non-DDoS training classes
```

Query set:

```text
DDOS-HOIC only
```

This fold may be difficult because HOIC has historically dominated the DDoS class. Report it even if performance is poor.

---

## 2B — DoS Subtype Holdouts

Run only folds where the remaining DoS subtypes retain enough support.

Possible folds:

### Fold DoS-1 — Hold out GoldenEye

Reference pool:

```text
Hulk + Slowloris + SlowHTTPTest (if available)
```

Query:

```text
GoldenEye
```

### Fold DoS-2 — Hold out Slowloris

Reference pool:

```text
Hulk + GoldenEye + SlowHTTPTest (if available)
```

Query:

```text
Slowloris
```

### Fold DoS-3 — Hold out SlowHTTPTest

Run only if the SlowHTTPTest materialized set is methodologically defensible.

Reference pool:

```text
Hulk + GoldenEye + Slowloris
```

Query:

```text
SlowHTTPTest
```

### Fold DoS-4 — Hold out Hulk

Reference pool:

```text
GoldenEye + Slowloris + SlowHTTPTest (if available)
```

Query:

```text
Hulk
```

This is a strong stress test because Hulk was previously the dominant DoS behavior.

---

## 2C — BruteForce Subtype Holdouts

Because the FTP-BruteForce additions are the closest defensible attempts rather than clean successful FTP-BruteForce examples, these folds must be labeled carefully.

### Fold BF-1 — Hold out FTP-BruteForce attempts

Reference pool:

```text
SSH-Bruteforce + all non-BruteForce classes
```

Query:

```text
FTP-BruteForce best-attempt subset
```

Question:

> Do the FTP attempts still map closer to BruteForce behavior than to other broad classes?

### Fold BF-2 — Hold out SSH-Bruteforce

Reference pool:

```text
FTP-BruteForce best-attempt subset + all non-BruteForce classes
```

Query:

```text
SSH-Bruteforce
```

This fold is likely much harder because the FTP subset may be small and not fully representative.

Interpret separately and do not treat failure as proof that the class concept is invalid.

---

## 2D — Infiltration Window Holdouts

Infiltration already has two meaningful windows and is the cleanest current same-class unseen-window test.

### Fold INF-1

Reference pool:

```text
Infiltration window 1 + all other classes
```

Query:

```text
Infiltration window 2
```

### Fold INF-2

Reference pool:

```text
Infiltration window 2 + all other classes
```

Query:

```text
Infiltration window 1
```

---

## 2E — WebBased Holdouts

Use cautiously because sample counts are small.

Possible holdouts:

- Brute Force-Web
- Brute Force-XSS
- SQL Injection
- day-level WebBased window when support allows

For every fold, report the raw number of query graphs alongside percentages.

Do not treat very small folds as stable estimates.

---

# Audit 3 — Top-k Group-Held-Out Neighbor Audit

## Objective

Nearest-neighbor rank 1 can be noisy. Extend Audit 2 to top-k neighbors.

Recommended values:

```text
k = 1, 3, 5, 10
```

For every unseen-group query graph, report:

- whether the top-1 neighbor has the correct broad class;
- fraction of top-3 neighbors with the correct broad class;
- fraction of top-5 neighbors with the correct broad class;
- fraction of top-10 neighbors with the correct broad class;
- mean distance to correct-class neighbors;
- mean distance to closest competing class.

## Why this helps

An unseen LOIC-UDP graph does not need to be nearly identical to HOIC. It only needs its neighborhood to be more DDoS-like than DoS-, Bot-, or Benign-like.

---

# Audit 4 — Nearest-Neighbor Margin Audit

## Objective

Measure whether unseen groups are clearly closer to the correct broad class than to the strongest competing class.

For each query graph compute conceptually:

```text
margin = nearest_wrong_class_distance - nearest_correct_class_distance
```

Interpretation:

```text
positive margin  → correct class is closer
near-zero margin → ambiguous neighborhood
negative margin  → another class is closer
```

Report:

- median margin;
- P5/P50/P95 margin;
- percentage positive;
- percentage near zero;
- strongest competing class.

This is more informative than same-class nearest-neighbor rate alone.

---

# Audit 5 — Targeted Leave-One-Window-Out Model Retraining

## Objective

After the held-out nearest-neighbor audits identify valid folds, retrain the actual HGNN using the same holdout definitions.

Do **not** run every theoretical fold. Only run folds where training retains meaningful support for every broad class.

## Priority folds

### Infiltration

Run both window folds:

1. train on Infiltration window 1, test on window 2;
2. train on Infiltration window 2, test on window 1.

### DDoS

Priority order:

1. hold out LOIC-UDP;
2. hold out LOIC-HTTP;
3. hold out HOIC as a stress test.

### DoS

Run subtype holdouts only after confirming materialized support for the added DoS subtypes.

Suggested order:

1. GoldenEye holdout;
2. Slowloris holdout;
3. SlowHTTPTest holdout, if valid;
4. Hulk holdout as the hardest stress test.

### BruteForce

Run FTP-attempt holdout as an exploratory robustness test.

Do not present FTP-attempt results as equivalent to clean successful FTP-BruteForce evaluation.

---

# Audit 6 — Whole-PCAP Holdout Retraining

## Objective

Use the previously identified runnable PCAP groups and retrain with complete source-PCAP groups excluded.

## Selection policy

Choose approximately 3–5 folds that:

- have enough held-out support;
- do not remove a complete broad class from training;
- cover different attack classes where possible;
- represent meaningfully different capture sources;
- are not tiny fragments with unstable metrics.

## Question answered

> Can the model generalize to traffic from an unseen source capture rather than another graph from a known capture?

---

# Audit 7 — Endpoint/Service Holdout Retraining

## Objective

Hold out complete endpoint/service groups using the key:

```text
source_dataset | day | src_ip | dst_ip | dst_port | protocol
```

The IP values are used only for grouping and never exposed to the model as features.

## Selection policy

Choose approximately 3–5 runnable folds with:

- at least 100 held-out graphs;
- substantial same-class support remaining in training;
- meaningful endpoint/service variation;
- different attack classes where possible.

## Question answered

> Can the model recognize the attack when the endpoint/service combination is unseen?

---

# Audit 8 — Temporal-Context Holdout Audit

## Objective

Specifically test whether the 375-flow temporal context is responsible for group similarity.

## Procedure

For group-held-out folds:

1. construct the split **before** temporal features are generated;
2. maintain separate temporal-window state for train, validation, and test;
3. reset destination windows at group boundaries;
4. ensure no historical flow from a training group contributes to a held-out group's temporal features.

Then compare:

- full model with temporal features;
- same model without temporal features.

## Question answered

> Does the model generalize because of attack behavior, or mainly because held-out graphs share temporal history with training traffic?

---

# Audit 9 — Feature Ablation Audit

## Objective

Identify shortcut feature groups.

Run the same robust holdout split with the following variants.

### Required ablations

1. Full model.
2. No temporal features.
3. Temporal features only.
4. Flow features only.
5. No source port.
6. No source and destination ports.
7. No protocol.
8. No packet payload bytes.
9. Packet-only representation, if implementation cost is reasonable.

## Interpretation

Large performance drops under a robust holdout identify which feature groups the model relies on most.

A feature should not be removed merely because it is predictive. The key question is whether its predictive power survives unseen-group evaluation.

---

# Audit 10 — Group-Balanced Training Audit

## Objective

Test whether dominant campaigns are overpowering smaller subtypes.

Compare:

### Baseline

```text
graph-level sampling
```

### Group-balanced sampling

```text
choose broad class
    ↓
choose subtype
    ↓
choose window/PCAP/session group
    ↓
choose graph
```

Track:

- macro-F1;
- per-class F1;
- per-subtype recall;
- held-out group performance;
- number of unique graphs seen per epoch;
- average repetitions of scarce graphs.

## Important

Do not combine aggressive oversampling and large class weights without checking whether scarce classes are being double-compensated.

---

# Audit 11 — Campaign-Capped Training Audit

## Objective

Reduce domination by huge highly similar groups without deleting the original data.

Create a separate training manifest that caps the number of graphs contributed by one:

- subtype;
- attack window;
- PCAP;
- endpoint/service session;
- short chronological block.

Use diversity-aware selection across the full attack period.

Compare the capped model with the uncapped model on the same group-held-out evaluation.

## Question answered

> Does reducing repeated campaign examples improve unseen-group generalization?

---

# Audit 12 — External/Cross-Dataset Robustness Test

## Objective

Only after the internal group-held-out audits are stable, test one or more attack classes on an external compatible PCAP source.

Priority candidates:

- BruteForce;
- DoS;
- DDoS;
- WebBased if a compatible source is available.

Use the same SecureEdge extraction pipeline so graph schema and feature generation remain consistent.

Report this separately as:

```text
external robustness / cross-dataset evaluation
```

Do not merge external test samples into the primary CIC-IDS-2018 test set.

---

# Recommended Execution Order

Run the audits in this order to minimize wasted training time:

```text
1. Subtype-stratified similarity report
2. Group-held-out nearest-neighbor audit
3. Top-k held-out neighbor audit
4. Nearest-neighbor margin audit
5. Select valid model holdout folds from NN results
6. Targeted Infiltration leave-one-window-out retraining
7. DDoS subtype-held-out retraining
8. DoS subtype-held-out retraining
9. Exploratory BruteForce FTP-attempt holdout
10. Selected whole-PCAP holdouts
11. Selected endpoint/service holdouts
12. Temporal-context holdout audit
13. Feature ablations on the strongest robust split
14. Group-balanced training comparison
15. Campaign-capped training comparison
16. External/cross-dataset evaluation if needed
```

---

# Priority Levels

## Priority A — Run immediately

- Subtype-stratified similarity report.
- Group-held-out nearest-neighbor audit.
- Top-k and margin analysis for held-out groups.
- Infiltration window-held-out NN folds.
- DDoS subtype-held-out NN folds.
- DoS subtype-held-out NN folds where support exists.

These are inexpensive compared with retraining and will identify the most meaningful model folds.

## Priority B — Retraining audits

- Infiltration leave-one-window-out.
- DDoS subtype holdouts.
- DoS subtype holdouts.
- Selected PCAP holdouts.
- Selected endpoint/service holdouts.

## Priority C — Improvement experiments

- Temporal-context isolation.
- Feature ablations.
- Group-balanced sampling.
- Campaign-capped training.

## Priority D — Strongest final robustness evidence

- External/cross-dataset testing.

---

# Success Criteria

The goal is **not** to preserve the previous ~0.999 validation macro-F1.

A successful robustness result is one where:

1. the held-out group was completely absent from training;
2. the model still recognizes the correct broad class at a useful rate;
3. the nearest-neighbor structure for the unseen group points toward the correct broad class rather than the exact same subtype/session;
4. performance remains reasonably stable across multiple independent groups;
5. failure cases can be explained by missing training diversity rather than hidden split overlap.

A lower but credible held-out score is more valuable than a near-perfect random-split score.

---

# Final Decision Rule

After these audits, classify each broad class into one of three categories:

### Strong generalization evidence

The class performs well on unseen subtype/window/PCAP/endpoint groups.

### Limited generalization evidence

The class has some valid holdouts but performance is unstable or support is small.

### Insufficient diversity to evaluate generalization

The class has only one meaningful campaign/group or holding it out removes the class from training.

This final classification should determine whether more data collection is required before further architecture tuning.
