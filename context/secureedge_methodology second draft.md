# SecureEdge — Implementation Methodology

## Project Context

SecureEdge is an edge-deployed Network Intrusion Detection System. A lightweight deep
learning model runs inference in real-time on a NVIDIA Jetson Orin Nano, classifying
network traffic into attack categories and flagging unknown threats. Training happens
offline on a PC with an NVIDIA RTX 4060 GPU; only the frozen model weights are deployed
to the edge device.

This document is the implementation specification. Work through each phase in order.
The immediate goal is to build the full training and evaluation pipeline on the
CIC-IoT2023 dataset and match or exceed XG-NID's 97% macro F1 score on that dataset.
Deployment to the Jetson Orin Nano comes after the pipeline is validated and results
are satisfactory.

**Reference paper:** XG-NID (Farrukh et al., 2025) — arXiv:2408.16021v2

---

## Phase 1 — Dataset Acquisition

The only dataset used in this phase is **CIC-IoT2023**, developed by the Canadian
Institute for Cybersecurity. It contains 46.7 million records generated from a
large-scale IoT topology of 105 devices, covering 33 distinct attack scenarios
organized into 7 attack classes plus a benign class.

Download the dataset from the CIC website. It is available in two formats: raw PCAP
files and pre-extracted CSV files. Use the CSV files for this phase. The CSV export
contains 47 features extracted using a fixed-size packet window. Place all CSV files
in a dedicated raw data folder before proceeding.

The dataset also provides a list of attacker device MAC addresses. These are needed
in Phase 2 for correct labelling.

---

## Phase 2 — Data Preprocessing

This phase transforms the raw CSVs into a clean, balanced dataset ready for feature
engineering. Follow these steps in order.

### Step 1 — MAC Address Filtering

The CSV files downloaded from CIC do not contain MAC addresses and do not require
MAC-based filtering. The labelling was performed by CIC before the dataset was
released — each row already carries a correct label in the `Attack_type` column
(this is the original column name; some redistributed versions rename it to `label`
or `Label`). Check the column names in your CSV files and identify which one holds
the attack type strings before proceeding.

The MAC filtering step described in the XG-NID paper applied only to their workflow,
where they re-processed the raw PCAP files from scratch and needed MAC addresses to
reconstruct the ground truth labels. Since you are working from the pre-labeled CSV
files, the labels are already trustworthy and no additional filtering is needed.

### Step 1 — Identify and Verify the Label Column

Open one of the CSV files and confirm the label column name. It will contain strings
such as `BenignTraffic`, `DDoS-UDP_Flood`, `Mirai-greeth_flood`, and so on. Print
the unique values in this column before doing anything else. This confirms the data
loaded correctly and shows you the exact strings that need to be normalised in Step 2.

### Step 2 — Label Normalisation

**Before mapping labels, save the original fine-grained sub-type string into a
separate column called `subtype_label`.** Do this for every row before any
normalisation happens. This column is unused during Stage 1 training but is essential
for Stage 2 sub-classifier training later. If it is not saved now the entire
preprocessing pipeline must be rerun. The cost of saving it is zero.

The dataset contains 33 distinct attack sub-types across 7 attack categories. Each
sub-type string must be mapped to one of eight canonical class names. Any row whose
label does not match a known sub-type should be dropped.

| Class Index | Canonical Name | Raw label strings that map to it |
|---|---|---|
| 0 | Benign | `BenignTraffic` |
| 1 | DDoS | Any string starting with `DDoS` or `DDOS` — 12 sub-types |
| 2 | DoS | Any string starting with `DoS` — 4 sub-types |
| 3 | Mirai | Any string starting with `Mirai` — 3 sub-types |
| 4 | Recon | Any string starting with `Recon`, plus `VulnerabilityScan` — 5 sub-types |
| 5 | Spoofing | `DNS_Spoofing`, `MITM-ArpSpoofing` — 2 sub-types |
| 6 | WebBased | `SqlInjection`, `XSS`, `BrowserHijacking`, `CommandInjection`, `Uploading_Attack`, `Backdoor_Malware` — 6 sub-types |
| 7 | BruteForce | `DictionaryBruteForce` — 1 sub-type, no Stage 2 classifier needed |

Use prefix-based mapping for most classes. Handle `VulnerabilityScan` as an explicit
special case mapping to Recon since its name carries no `Recon` prefix.

### Step 3 — Data Cleaning

Replace all infinite values with NaN and drop any row containing NaN in a feature
column. Do not drop rows based on the label column — that was handled in Step 2.
This step removes feature extraction artefacts that would corrupt training.

### Step 4 — Train/Test Split

Before balancing, set aside a test set. For each class, randomly select up to 4,000
samples as the test set. If a class has fewer than 4,000 samples, use all of them.
The remaining samples form the pool from which the training set is drawn.

Do this split before balancing so the test set reflects the natural class distribution
rather than the artificially balanced one.

### Step 5 — Class Balancing

The raw class distribution is severely skewed: DDoS accounts for 72.79% of the data
while BruteForce accounts for only 0.03%. A model trained on unbalanced data learns
to predict the majority class and ignores rare classes.

Balance the training set to exactly 20,000 samples per class using a combination of:
- Random undersampling for classes with more than 20,000 training samples
- Random oversampling for classes with fewer than 20,000 training samples

The test set is NOT balanced — keep it as-is to reflect real-world conditions.

### Step 6 — Normalisation

Fit a StandardScaler (zero mean, unit variance) on the training set feature columns
only. Save the fitted scaler to disk. Apply the same saved scaler to the test set —
never refit the scaler on test data.

---

## Phase 3 — Feature Engineering

This is the most important phase. XG-NID's core methodological contribution is
the combination of standard flow features with temporal sliding-window features.
The temporal features are what pushed XG-NID's performance from roughly 88% to 97%.

The final input to the model is a 96-dimensional vector: 80 standard flow features
plus 16 temporal features.

### Standard Flow Features (80 features)

These are the features already present in the CIC-IoT2023 CSV export. They include
packet counts, byte counts, inter-arrival times, flag counts, flow duration, and
derived statistics (mean, std, max, min) for forward and backward directions. No
additional extraction is needed — these come directly from the preprocessed CSV.

Apply the StandardScaler from Phase 2 to these features.

### Temporal Sliding-Window Features (16 features)

These features capture the behaviour of the network over recent history, not just
within a single flow. They are computed per destination IP by maintaining a rolling
window of the last W flows that arrived at that destination. The optimal window size
W is 375 flows (valid range: 350-400, per XG-NID experimental findings). Using a
larger window reduces accuracy; using a smaller window fails to capture temporal
patterns.

**Critical:** Apply temporal features before shuffling the data. The window must
process flows in chronological arrival order to be meaningful. Shuffling first and
then computing temporal features produces nonsense values.

The 16 temporal features and what each captures:

| Feature Name | What it measures |
|---|---|
| Rolling_UDP_Sum | Count of UDP flows to this destination in the last W flows |
| Rolling_TCP_Sum | Count of TCP flows to this destination in the last W flows |
| Rolling_ACK_Sum | Total ACK flags received at this destination in the last W flows |
| Rolling_FIN_Sum | Total FIN flags received at this destination in the last W flows |
| Rolling_RST_Sum | Total RST flags received at this destination in the last W flows |
| Rolling_fin_Sum | Alias for FIN count (kept for XG-NID parity) |
| Rolling_psh_Sum | Total PSH flags received at this destination in the last W flows |
| Rolling_SYN_Sum | Total SYN flags received at this destination in the last W flows |
| Rolling_ICMP_Sum | Count of ICMP flows to this destination in the last W flows |
| Rolling_http_port | Frequency of access to HTTP ports (80, 443, 8080, 8443) in the last W flows |
| Rolling_Average_Duration | Mean bidirectional flow duration to this destination in the last W flows |
| Rolling_DNS_Sum | Count of DNS requests (port 53) to this destination in the last W flows |
| Rolling_vulnerable_port | Count of flows targeting known vulnerable ports in the last W flows |
| Rolling_packets_Sum | Total packet count (forward + backward) across all W flows |
| Rolling_bipackets_Sum | Total bidirectional packet count across all W flows |
| Unique_Ports_In_SourceDestination | Number of unique source ports communicating with this destination in the last W flows |

The vulnerable ports list to use: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
445, 1433, 1521, 3306, 3389, 5900, 8080, 8443.

**Why these features matter:** A single flow from one IP sending a moderate number of
SYN packets looks ambiguous. But if Rolling_SYN_Sum shows 7,000 SYN packets arriving
at the same destination in the last 375 flows, that is unambiguous evidence of a SYN
flood. The temporal context transforms an ambiguous signal into a clear one. This is
why payload-free flow-level models can detect DDoS and Mirai attacks with high
confidence when temporal features are included.

After appending all 16 temporal features, apply the StandardScaler to them as well
(the same scaler fitted in Phase 2, or a new scaler fitted on the combined 96-feature
training set — be consistent and document the choice).

---

## Phase 4 — Model Architecture

The model is a lightweight Multi-Layer Perceptron (MLP). The architecture is
intentionally simple to enable real-time inference on the Jetson Orin Nano's GPU.

**Input layer:** 96 neurons (one per feature)

**Hidden layers:** Three fully connected layers with the following structure at
each layer: Linear → BatchNorm → ReLU → Dropout. The layer widths are
256 → 128 → 64.

**Output layer:** A single Linear layer with 8 outputs (one per class). Do not
apply softmax inside the model's forward pass — raw logits are needed for the
OOD detection layer and for the loss function during training.

**Dropout rate:** 0.4 at all hidden layers.

**Why BatchNorm:** Without BatchNorm, the extreme range of flow feature values
(some features span several orders of magnitude) causes training instability
even after normalisation. BatchNorm keeps activations in a well-behaved range
throughout training.

An optional CNN variant can be tried if the MLP underperforms. It treats the
96-feature vector as a 1D sequence and applies two convolutional layers before
a fully connected head. The MLP should be the first attempt.

---

## Phase 5 — Training

### Loss Function

Use CrossEntropyLoss. It works directly with raw logits (no softmax needed beforehand)
and handles multi-class classification natively.

### Optimizer and Schedule

Use the Adam optimizer with a learning rate of 1e-3 and weight decay of 1e-5.

**Why 1e-3 and not XG-NID's 0.01:** The XG-NID HGNN was trained on graph objects
with batch sizes of roughly 32 to 64 graphs per batch. Our MLP processes flat feature
vectors with a batch size of 1024. A learning rate is implicitly coupled to batch size
— smaller batches produce noisier gradients and need a higher rate to make progress.
Applying their 0.01 directly to our larger-batch setup would cause instability.
1e-3 is the correct equivalent at this scale.

**Why 1e-5 weight decay:** This matches XG-NID's setting and produced their best
result. Our model already has dropout and BatchNorm providing regularisation, so
the weight decay can be light. If overfitting is observed on any class, increase to
1e-4 as a first adjustment.

Attach a ReduceLROnPlateau scheduler that halves the learning rate when validation
macro F1 stops improving for 5 consecutive epochs. Use a minimum LR floor of 1e-6
to prevent the scheduler from reducing the rate to zero prematurely.

Additionally, apply a 5-epoch linear warmup at the start of training. Begin with a
learning rate of 1e-4 and increase linearly to 1e-3 over the first 5 epochs. This
stabilises the early training phase when the model weights are randomly initialised
and gradients are large and noisy.

### Hyperparameters

| Parameter | Value | Source |
|---|---|---|
| Batch size | 1024 | Appropriate for flat feature vectors at this scale |
| Initial learning rate | 1e-3 | Scaled from XG-NID's 0.01 to match our batch size |
| LR warmup | 5 epochs, linear 1e-4 → 1e-3 | Stabilises early training |
| LR scheduler | ReduceLROnPlateau, factor 0.5, patience 5 | Decays LR when progress stalls |
| Min learning rate | 1e-6 | Floor to prevent over-reduction |
| Weight decay | 1e-5 | Matches XG-NID's successful setting |
| Max epochs | 200 | XG-NID used only 30 — the primary opportunity for improvement |
| Early stopping patience | 20 epochs | Allows multiple LR reductions before stopping |
| Gradient clipping max norm | 1.0 | Prevents exploding gradients |

**Why 200 epochs when XG-NID used 30:** Their 30-epoch limit with a constant 0.01
learning rate and no scheduler almost certainly stopped before full convergence.
The model was not failing to learn — it simply ran out of time. With our decaying
LR schedule, the model will continue refining its weights at smaller scales long
after the initial fast learning phase. Early stopping at patience 20 means training
stops automatically once no further improvement is possible, so the 200 ceiling is
a safety limit, not a target.

### Training Loop

Run a 5-epoch warmup phase first, increasing the learning rate linearly from 1e-4
to 1e-3. After warmup, begin the main training loop.

For each epoch: run a full pass over the training set, computing loss and updating
weights. At the end of each epoch, evaluate on the validation set and compute macro
F1. Pass the validation F1 to the ReduceLROnPlateau scheduler. Save a checkpoint
whenever macro F1 improves over the previous best. Stop training if macro F1 has
not improved for 20 consecutive epochs.

Gradient clipping (max norm 1.0) applies during both the warmup phase and the main
loop. Do not disable it during warmup — gradients are largest in the first few epochs
and clipping is most valuable there.

### What to Track Per Epoch

Log training loss, validation macro F1, and learning rate. These three values are
enough to diagnose whether training is progressing correctly.

### Memory Management

Understanding where your RAM and VRAM actually go prevents wasted debugging time.
The situation is different for each resource, and the phase where overflow is most
likely is not training — it is preprocessing.

**RAM (16 GB) — the real risk is in Phase 2, not Phase 5**

The raw CIC-IoT2023 dataset is 46.7 million rows. If you load all CSV files into
a single DataFrame at once using float64 (pandas default), the in-memory size is
approximately 17–18 GB — enough to overflow 16 GB of RAM before any processing
begins. Do not do this.

The safe approach during preprocessing is to read and process one CSV file at a
time, applying MAC filtering, label normalisation, and cleaning before loading the
next. Release each DataFrame from memory before opening the next file. Specifying
`dtype=float32` when reading CSVs halves the per-file memory footprint compared to
pandas' float64 default. After balancing to 20,000 samples per class across 8
classes, the final training set is only 160,000 rows × 96 features, which is
approximately 58 MB — safe to hold in RAM as a single object.

The temporal feature computation in Phase 3 is also safe. The sliding window state
is just 8 small deques (one per destination IP, each holding at most 375 lightweight
dictionaries). This uses well under 100 MB regardless of dataset size.

During training itself, RAM usage is low. The DataLoader prefetches batches in
background workers — keep `num_workers` at 2 to 4. More workers each hold a copy
of data and prefetch buffers; beyond 4 the RAM cost outweighs the speed benefit
on a 16 GB machine. Set `pin_memory=True` to allow faster CPU-to-GPU transfers
without additional RAM cost.

**VRAM (8 GB) — genuinely not at risk for this architecture**

The MLP is small. The total parameter count across all layers is approximately
67,000 weights and biases, which occupies roughly 0.3 MB of VRAM. The Adam
optimizer doubles this by storing momentum and variance states, bringing the
total model overhead to under 1 MB. A batch of 1,024 samples at 96 features
adds another 0.4 MB for the input tensor plus roughly 2 MB for intermediate
activations during the forward and backward passes.

In practice, the entire training run uses under 10 MB of VRAM. The RTX 4060's
8 GB is nearly fully available for other processes while training is running.
If you switch to the optional CNN variant the VRAM footprint increases but
remains well under 100 MB.

The batch size of 1,024 is chosen for stable gradient estimation, not for memory
reasons. It can be increased to 4,096 or even 16,384 without approaching the VRAM
limit, which may speed up training on the RTX 4060. Do not increase it beyond that
without testing, as very large batch sizes can hurt generalisation even when memory
allows it.

**Summary table**

| Phase | RAM pressure | VRAM pressure | Action needed |
|---|---|---|---|
| Phase 2 — Preprocessing | High (raw data) | None | Read one CSV at a time, use float32 |
| Phase 3 — Temporal features | Low | None | None — window state is tiny |
| Phase 5 — Training | Low (~300 MB total) | Very low (~10 MB) | num_workers ≤ 4 |
| Phase 8 — Edge inference | Low | ~5 MB on Jetson | None |

---

## Phase 6 — Evaluation

Evaluate the best saved checkpoint (highest validation macro F1) on the test set.

### Primary Metric

**Macro F1 score.** This is the metric used by XG-NID for comparison. Macro F1
averages the per-class F1 scores equally regardless of class size, meaning the model
must perform well on rare classes (WebBased, BruteForce) as well as common ones (DDoS).

Target: **≥ 97%** macro F1 on the CIC-IoT2023 test set.

### Full Report

Also compute per-class precision, recall, and F1 for all 8 classes. This breakdown
is essential for diagnosing failure modes. A high overall macro F1 with a low score
on BruteForce (the rarest class) suggests the class balancing or oversampling did
not work correctly.

### Diagnosing Below-Target Performance

If macro F1 is below 97%, check in this order:

1. **Temporal feature ordering** — Were temporal features computed before shuffling?
   If computed after shuffling, the window values are meaningless. This is the most
   common cause of underperformance.

2. **Window size** — Is the window set to a value between 350 and 400? Values
   outside this range degrade performance noticeably.

3. **Scaler leakage** — Was the scaler fitted on training data only? If fitted on
   the combined train+test set, performance will appear inflated during evaluation
   but the model will not generalise.

4. **Class balancing** — Are all 8 classes represented at 20,000 samples in training?
   Print the class distribution before training to verify.

5. **Label mapping** — Are all label strings correctly mapped to class indices?
   Any unmapped strings silently become NaN and get dropped, reducing training data.

6. **Premature stopping** — Did the model stop before the learning rate had a chance
   to decay? With patience 20 and a scheduler patience of 5, the LR should reduce
   at least three or four times before early stopping triggers. If training stopped
   after fewer than 40 epochs, the patience may be too short or the warmup too long.

---

## Phase 7 — OOD Detection

After the model achieves target performance, add a confidence threshold to the
inference path. This allows the system to output "Unknown Attack" when it encounters
traffic that does not confidently match any known class.

### Method: Maximum Softmax Probability (MSP)

At inference, apply softmax to the model's raw logits and take the maximum probability
across all 8 classes. If this maximum confidence score falls below a threshold θ,
classify the sample as "Unknown Attack" instead of the predicted class.

### Threshold Calibration

Find θ by running the model on the CIC-IoT2023 test set and collecting all maximum
softmax scores for correctly classified samples. Set θ at the 5th percentile of this
distribution. This ensures 95% of in-distribution samples still pass through correctly,
while samples with unusual confidence profiles — which novel attacks tend to produce —
get flagged.

Save θ to disk alongside the model weights so it can be loaded at inference time.

---

## Phase 8 — Edge Deployment

Only begin this phase once Phase 6 confirms ≥ 97% macro F1.

### Model Export

Export the trained model to TorchScript format using `torch.jit.trace`. This
produces a portable, optimised model file that does not require the Python class
definition to load. Verify the exported model produces identical predictions to the
original PyTorch model on a small batch before deploying.

### Files to Deploy to the Jetson Orin Nano

The Jetson only needs: the TorchScript model file, the saved StandardScaler, the
saved OOD threshold value, and the temporal feature extractor module. Nothing else
from the training codebase is needed on the edge device.

### Real-Time Pipeline on the Jetson

The edge inference loop has four steps that run continuously:

1. Capture live packets using Scapy on the network interface.
2. Aggregate packets into flows. A flow is complete when it reaches 20 packets
   or 120 seconds pass with no new packets (idle timeout).
3. Compute 80 flow features from the completed flow, then append 16 temporal
   features using the same sliding window logic from Phase 3. Apply the saved
   scaler. Concatenate into a 96-dimensional input vector.
4. Run inference. Apply the OOD threshold. If the result is not Benign, serialize
   the alert as JSON and send it to the cloud API.

The temporal feature extractor on the Jetson maintains its own per-destination
window that updates in real-time as flows complete, exactly as in offline processing.

---

## Project Structure

Organise the codebase into these modules. Each module corresponds to one or more
phases above:

```
secureedge/
├── config.py              — all constants and hyperparameters (single source of truth)
├── data/
│   ├── preprocess.py      — Phase 2: filtering, cleaning, balancing, splitting
│   └── dataset.py         — PyTorch Dataset class wrapping the processed CSVs
├── features/
│   ├── temporal.py        — Phase 3: TemporalFeatureExtractor class
│   └── pipeline.py        — Phase 3: apply temporal features to processed CSVs
├── models/
│   ├── architecture.py    — Phase 4: MLP and optional CNN class definitions
│   ├── train.py           — Phase 5: training loop
│   └── evaluate.py        — Phase 6: metrics and reporting
├── ood/
│   └── detector.py        — Phase 7: OOD scoring and threshold calibration
├── export/
│   └── export.py          — Phase 8: TorchScript export
└── edge/
    ├── capture.py         — Phase 8: Scapy packet capture
    ├── flow_builder.py    — Phase 8: packet-to-flow aggregation
    └── inference.py       — Phase 8: real-time inference loop
```

**config.py is the single source of truth.** All constants — window size, class
mappings, feature column names, hyperparameters, file paths — must be defined there
and imported everywhere else. Never hardcode these values in individual modules.

---

## Execution Order

```
Phase 2:   python data/preprocess.py
Phase 3:   python features/pipeline.py
Phase 5:   python models/train.py
Phase 6:   python models/evaluate.py
Phase 7:   python ood/detector.py     (calibrates and saves threshold)
Phase 8:   python export/export.py    (only after Phase 6 confirms ≥ 97% F1)
```

Phases 4 and 8 do not have standalone scripts — the model architecture is defined
in a module imported by train.py, and edge deployment is configured before running
edge/inference.py on the Jetson.

---

## Success Criteria

The pipeline is complete and ready for the next stage (benchmarking datasets and
Gotham 2025 evaluation) when all three of the following are true:

1. The model achieves ≥ 97% macro F1 on the CIC-IoT2023 test set.
2. Per-class F1 is above 90% for all 8 classes, including BruteForce and WebBased.
3. The OOD detector is calibrated and the threshold is saved to disk.
