# Office Model Training Plan

Date: 2026-08-02

## Objective

Move from robustness auditing into the first serious HGNN training run using the evidence collected from the office-model audits.

The goal is to improve generalization **without redesigning the current HGNN architecture**.

The main strategy is:

> Expose the model to every legitimate attack subtype, prevent individual campaigns from dominating training, use group-aware train/validation/test splits instead of graph-level random splitting, and preserve the current model architecture.

## 1. Keep the Current Seven Broad Classes

The final classifier should continue predicting:

```text
Benign
BruteForce
DoS
DDoS
WebBased
Bot
Infiltration
```

Do not convert the final task into subtype classification.

However, retain subtype and campaign metadata internally:

```text
broad class
└── subtype
    └── day / attack window / PCAP group
        └── graph
```

Examples:

```text
DDoS
├── HOIC
├── LOIC-HTTP
└── LOIC-UDP
```

```text
DoS
├── Hulk
├── GoldenEye
├── Slowloris
└── SlowHTTPTest
```

Different subtypes do not need to occupy the same region of feature space. The HGNN can learn that multiple different regions all correspond to the same broad attack class.

## 2. Do Not Use Full Subtype Holdout as the Main Training Split

The robustness audits showed that some completely held-out subtypes are very far from the remaining members of their broad class.

Examples included:

- LOIC-UDP
- LOIC-HTTP
- several DoS subtypes
- FTP vs SSH BruteForce

Therefore, completely removing a subtype from training often becomes closer to a zero-shot/generalization stress test than a normal supervised classification problem.

For the main training run:

> Every legitimate subtype should have training representation.

Subtype holdouts remain useful as separate robustness stress tests later, but they should not define the main training/validation/test split.

## 3. Handle Questionable Attempted-Attack Labels Carefully

### FTP-BruteForce

The current FTP samples are closest-attempt examples rather than clean successful FTP-BruteForce behavior.

Recommended policy for the first serious model:

```text
BruteForce training:
✓ SSH-Bruteforce
✗ FTP attempted flows as ordinary successful BruteForce positives
```

Keep the FTP examples separately as:

```text
FTP-BruteForce attempted/stress-test set
```

If later evidence confirms a subset as valid successful BruteForce traffic, those samples can be added.

### SlowHTTPTest

If the SlowHTTPTest samples correspond to the known unsuccessful/misconfigured CIC-IDS-2018 attack attempt, do not treat them as ordinary successful DoS positives.

Use the same rule:

```text
verified successful attack → training candidate
attempted/failed attack     → separate stress-test set
```

This prevents the model from learning artifacts of failed attack execution as if they were canonical attack behavior.

## 4. Replace Random Graph Splitting with Group-Aware Splitting

The current random graph split was the main reason train and validation graphs had extremely close nearest neighbors.

Do not use:

```text
all graphs
    ↓
random shuffle
    ↓
80% train
10% validation
10% test
```

Instead define a group using available metadata such as:

```text
source dataset
+ broad class
+ subtype
+ day
+ attack window
+ source PCAP
```

Then assign entire groups to only one split:

```text
group A → train
group B → train
group C → validation
group D → test
```

Target approximately:

```text
80% train
10% validation
10% test
```

The percentages do not need to be mathematically exact if keeping whole groups intact requires small deviations.

### Critical Rule

No attack-window/PCAP group may appear in more than one split.

At the same time:

> Every legitimate subtype should still be represented in training whenever the available data permits it.

Example:

```text
DDoS / HOIC
├── group A → train
├── group B → train
├── group C → validation
└── group D → test
```

This tests new HOIC groups without asking the model to recognize a subtype it has never seen.

## 5. Cap Repetitive Campaign Groups During Training

Previous audits showed that some classes are dominated by one or two large campaign groups.

Approximate largest-group shares included:

```text
BruteForce ≈ 50%
DDoS       ≈ 45%
DoS        ≈ 32%
```

A single attack campaign should not contribute tens of thousands of nearly repetitive training examples.

Use:

```text
maximum 1,000 training graphs
per class/subtype/window/PCAP group
```

This cap applies only to the **training split**.

Validation and test groups should remain intact whenever possible so their metrics represent the complete held-out group.

### Sampling Inside a Large Group

Do not simply take the first 1,000 graphs.

Sample across the complete attack window:

```text
start ───────────────────────────── end
  ↑    ↑     ↑     ↑     ↑     ↑
     distributed representative samples
```

This maintains temporal and behavioral diversity within the selected subset.

## 6. Use Hierarchical Subtype/Group-Aware Sampling

Training batches should not be created by uniformly selecting individual graphs from the complete manifest.

Preferred conceptual sampling hierarchy:

```text
choose broad class
        ↓
choose subtype
        ↓
choose attack window / PCAP / campaign group
        ↓
choose graph
```

This prevents large subtypes from overwhelming smaller subtypes.

Example for DDoS:

```text
DDoS
├── HOIC
├── LOIC-HTTP
└── LOIC-UDP
```

The sampler should deliberately expose the HGNN to all three instead of allowing HOIC to dominate because it has more graphs.

The same principle applies to:

```text
DoS
├── Hulk
├── GoldenEye
└── Slowloris
```

and any other class with multiple valid subtypes.

## 7. Do Not Aggressively Oversample WebBased

WebBased remains extremely small compared with the other classes.

Repeatedly duplicating the same few hundred WebBased graphs does not create new attack behavior and increases memorization risk.

Recommended approach:

```text
✓ use all available clean WebBased samples
✓ apply moderate loss weighting
✗ do not duplicate them until they match 20k-class sizes
```

WebBased should continue to be reported as a low-support class.

## 8. Use Moderate Weighted Cross-Entropy

Recommended loss:

```python
CrossEntropyLoss(
    weight=class_weights,
    label_smoothing=0.05,
)
```

Use moderate class weights based on:

```text
weight ∝ 1 / sqrt(number_of_training_samples)
```

Then normalize the weights so the average class weight is approximately 1.

Avoid extremely large weights.

Suggested maximum:

```text
4–5
```

Do not combine:

```text
aggressive oversampling
+
aggressive class weighting
```

Use moderate weighting together with the group/subtype-aware sampler.

## 9. Mask the 16 Temporal Features for the First Robust Training Run

The temporal audit showed insufficient provenance to prove that the existing 375-flow temporal context is isolated across split boundaries.

A complete temporal rebuild would require substantial changes to preprocessing and graph generation.

To avoid delaying training, use the current graph files but mask the 16 temporal flow features to zero inside the dataset loader.

Conceptually:

```text
92 flow features
├── ordinary flow features → keep
└── 16 temporal features   → zero
```

Important:

```text
HGNN architecture  → unchanged
input tensor shape → unchanged
graph files        → unchanged
```

This is a temporary conservative measure.

After the robust model is established, temporal features can be rebuilt using split-isolated temporal state and reintroduced.

## 10. Keep Packet Features and Graph Structure

Do not remove:

```text
packet nodes
packet information
flow features
graph edges
GATv2/SAGE structure
```

Previous ablations showed that different classes rely on different modalities.

Examples:

- Infiltration depended strongly on more than packet-only information.
- Hulk showed strong packet-level regularities.

Therefore, the first robust model should preserve the full graph architecture.

Continue excluding direct raw identity features such as:

```text
raw IP addresses
raw MAC addresses
```

from model tensors.

## 11. Keep the HGNN Architecture Unchanged

Do not change the main architecture yet.

Keep the same:

```text
GATv2 / SAGE components
hidden dimensions
attention heads
optimizer
learning rate
packet/flow graph structure
```

The primary problems found by the audits were:

```text
weak split independence
campaign repetition
subtype imbalance
questionable attack labels
```

not insufficient model capacity.

Changing the architecture now would make it impossible to tell whether performance improvements came from the data fixes or the network changes.

## 12. Recommended First Training Configuration

| Setting | Recommendation |
| --- | --- |
| Output classes | 7 |
| Main split | Group-aware |
| Approximate ratio | 80 / 10 / 10 |
| Split unit | subtype + day + window/PCAP |
| Group overlap | none |
| Max train graphs/group | 1,000 |
| Sampling | class → subtype → group → graph |
| Temporal features | mask 16 temporal features |
| Flow features | keep |
| Packet features | keep |
| Graph structure | keep |
| Raw IP/MAC features | exclude |
| Loss | weighted cross-entropy |
| Class weighting | inverse-square-root |
| Weight cap | approximately 4–5 |
| Label smoothing | 0.05 |
| Batch size | keep current 512 if stable |
| Learning rate | keep current working value |
| Architecture | unchanged |
| Maximum epochs | approximately 30 |
| Early stopping | patience 5 |
| Best checkpoint | validation macro-F1 |

The previous model converged very quickly, so long 100–300 epoch runs are unnecessary for this phase.

## 13. Validation Design

Validation should test:

> New groups from known attack subtypes.

It should not simply test random graphs from the same attack campaigns.

Example:

```text
TRAIN DDoS
├── HOIC group A
├── HOIC group B
├── LOIC-HTTP group A
└── LOIC-UDP group A

VALIDATION DDoS
├── HOIC group C
├── LOIC-HTTP group B
└── LOIC-UDP group B
```

This is the correct generalization target for the current dataset.

## 14. Report Broad-Class Metrics and Per-Subtype Recall

The model still predicts only the seven broad classes.

However, evaluation should use subtype metadata to report where failures occur.

Example:

```text
DDoS recall
├── HOIC recall
├── LOIC-HTTP recall
└── LOIC-UDP recall
```

```text
DoS recall
├── Hulk recall
├── GoldenEye recall
└── Slowloris recall
```

Primary metrics:

```text
overall accuracy
macro-F1
weighted-F1
per-class precision
per-class recall
per-class F1
```

Additional diagnostic metric:

```text
per-subtype recall
```

This will show whether a broad class looks strong only because one dominant subtype performs well.

## 15. Training Run Order

### Run 1 — Main Robust Baseline

Use:

```text
group-aware split
campaign cap
subtype/group-aware sampling
moderate weighted CE
temporal features masked
unchanged HGNN
```

This should become the new baseline.

### Run 2 — Only If the Baseline Has Serious Subtype Failures

If results look like:

```text
HOIC       → strong
LOIC-HTTP  → weak
LOIC-UDP   → weak
```

or similar subtype-specific failures, the next training improvement should target representation learning rather than another split audit.

Candidate improvement:

```text
auxiliary supervised contrastive loss
```

The objective would be to encourage different subtypes of the same broad class to share a more useful broad-class embedding while remaining separable from other classes.

Do not add this to Run 1.

## 16. What We Are Not Doing Yet

The following work is intentionally deferred:

```text
full temporal graph rebuild
endpoint/service metadata rebuild
architecture redesign
domain-adversarial training
external dataset integration
large-scale hyperparameter search
complete subtype-holdout training sweep
```

These should only be revisited if the new robust baseline still generalizes poorly.

## 17. Final Training Pipeline

```text
Clean eligible graphs
        ↓
Separate questionable attempted attacks
        ↓
Preserve:
class → subtype → campaign group
        ↓
Group-aware train / validation / test split
        ↓
No group overlap
        ↓
Training split only:
cap large campaign groups at ~1,000 graphs
        ↓
Class → subtype → group → graph sampling
        ↓
Mask the 16 uncertain temporal features
        ↓
Current HGNN architecture
        ↓
Moderately weighted CE
+ label smoothing
        ↓
Early stopping on validation macro-F1
        ↓
Final held-out test
        ↓
Report:
broad-class metrics
+
per-subtype recall
```

## 18. Success Criteria

The new run does **not** need to reproduce the previous near-perfect random-split validation macro-F1.

A lower score can be more scientifically meaningful if the validation groups are genuinely independent from training groups.

The training setup should be considered successful if:

1. Validation performance remains strong under group-aware splitting.
2. No major class is supported only by one subtype.
3. Per-subtype recall is reasonably consistent within each broad class.
4. The validation gap is not caused by random same-campaign similarity.
5. Training remains stable without major changes to the HGNN architecture.
6. The model performs substantially better than chance on genuinely held-out campaign groups.

The objective is no longer:

```text
maximize random-split validation score
```

It is:

```text
maximize credible generalization to unseen traffic groups
while preserving broad attack-class recognition
```
