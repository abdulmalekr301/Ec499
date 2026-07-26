# CIC-IDS-2018 Office Model: Required Fixes and Implementation Plan

**Repository:** `abdulmalekr301/Ec499`  
**Target branch reviewed:** `main`  
**Review date:** 2026-07-26  
**Scope:** CIC-IDS-2018 preprocessing, temporal features, compact graph materialization, PyTorch Geometric conversion, training, evaluation, reproducibility, and class imbalance.

---

## 1. Purpose

This document converts the current code review into an actionable repair plan.

The office pipeline already contains several strong improvements, including:

- an external YAML configuration;
- cumulative compact manifests;
- an append-only completed-candidate registry;
- compact graph validation;
- office compact-to-PyG graph conversion;
- configuration hashing and provenance;
- per-destination temporal windows.

However, the project is **not ready for final office-model training**. Several issues can produce misleading temporal features, distorted flow statistics, incorrect class dimensions, or test-set leakage.

The fixes are divided into:

- **P0 — Blocking:** must be completed before generating the final graph dataset or training the office model;
- **P1 — High priority:** required for trustworthy experiments and reproducibility;
- **P2 — Improvement:** important after the baseline pipeline is correct and stable.

---

## 2. Most Important Findings

| Priority | Finding | Main risk |
|---|---|---|
| P0 | Candidate-specific PCAP slices can calculate temporal features from incomplete traffic history | Temporal features may describe the slice rather than the real destination history |
| P0 | A new temporal extractor can be created for each `iter_flow_records()` call | The 375-flow destination window can reset between PCAPs, slices, batches, or workers |
| P0 | `FlowCapper` expires the entire NFStream flow after 20 packets | Long office flows are split/truncated, so flow statistics no longer describe the complete flow |
| P0 | The current training code assumes the original eight-class dataset | The office model has seven classes and a different class order |
| P0 | Training evaluates every epoch on the test split | Test information influences early stopping and checkpoint selection |
| P0 | Office YAML and hard-coded `office_pipeline.py` values coexist | Two sources of truth can silently disagree |
| P0 | Office graph conversion exists, but the regular trainer still loads original manifests and paths | Office graphs cannot be trained safely through the current generic command |
| P1 | WebBased has very few unique native examples | Oversampling can cause memorization and unstable evaluation |
| P1 | Candidate matching can produce ambiguous or duplicate matches | Wrong packets or duplicate graphs may be assigned to a labeled candidate |
| P1 | The office pipeline remains monolithic | High risk of accidental regressions and difficult testing |

---

# Part I — Blocking Fixes

## 3. Fix P0-1: Separate Temporal Context Extraction From Candidate Packet Slicing

### Current problem

The temporal extractor correctly keeps one window for each destination IP. That part is good.

The problem is that office materialization may run NFStream on small candidate-specific PCAP slices. These slices can contain only the candidate tuple or a narrow subset of the destination traffic.

This can cause the feature vector to answer:

> What happened in this filtered slice before the candidate?

instead of:

> What were the previous 375 flows received by this destination in the original capture?

### Why it matters

Suppose the full capture contains:

```text
300 benign flows to Server A
50 background service flows to Server A
25 DDoS flows to Server A
```

A tuple-filtered slice may contain only the 25 DDoS flows. The temporal vector then becomes artificially attack-heavy and deployment-unrealistic.

This creates a form of preprocessing bias. The model may achieve strong results because the candidate extraction process has already removed normal context.

### Required design

Use a **two-pass pipeline**.

```text
Pass 1: Full chronological flow metadata
    -> calculate per-destination temporal context
    -> save temporal vectors in a lightweight index

Pass 2: Candidate-specific PCAP slices
    -> recover packet payloads and edge information
    -> match the candidate
    -> attach its precomputed temporal vector
    -> build the compact graph
```

### Recommended new modules

```text
secureedge/office/temporal_index.py
secureedge/office/flow_identity.py
```

### Recommended interface

```python
@dataclass(frozen=True)
class CanonicalFlowKey:
    day: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    first_seen_ms: int


def build_temporal_index(
    pcap_paths: list[Path],
    *,
    window_size: int,
    output_path: Path,
) -> dict[str, object]:
    """Process complete flow metadata chronologically and save temporal vectors."""


def lookup_temporal_features(
    index: TemporalIndex,
    candidate_key: CanonicalFlowKey,
    tolerance_ms: int,
) -> dict[str, float]:
    """Return the nearest unambiguous precomputed temporal vector."""
```

### Important requirements

- Process flows in chronological order.
- Keep independent windows per destination.
- Preserve a window across all sequential files belonging to the same logical capture/day.
- Do not carry a window from one capture day into another.
- Do not calculate destination history from a tuple-only slice.
- Record whether the context was full, partial, or missing.
- Fail or quarantine candidates with missing temporal context; do not silently fill them with zeros.

### Validation

Create a test capture containing benign and attack flows to one destination.

Verify that:

1. the candidate’s temporal vector is identical whether its packets are extracted from the full PCAP or a candidate slice;
2. unrelated destinations do not enter its history;
3. the current flow does not count itself;
4. the 376th previous flow causes the oldest entry to leave the window;
5. processing the capture in sequential chunks gives the same result as processing it as one file.

### Done when

- Temporal vectors are produced from complete chronological destination traffic.
- Candidate slicing is used only for packet recovery and matching.
- Full-PCAP and sliced materialization produce identical temporal features for the same candidate.

---

## 4. Fix P0-2: Prevent Accidental Temporal Window Resets

### Current problem

`iter_flow_records()` creates a new `TemporalFeatureExtractor` when no extractor is supplied.

Therefore, code like this resets all destination histories:

```python
for slice_path in candidate_slices:
    for flow in iter_flow_records(slice_path, subtype):
        ...
```

Every call may begin with an empty set of destination windows.

### Required fix

Do not allow implicit temporal state creation in office production materialization.

Recommended change:

```python
def iter_flow_records(
    path: Path,
    subtype_label: str,
    extractor: TemporalFeatureExtractor | None = None,
    *,
    require_external_extractor: bool = False,
):
    if extractor is None and require_external_extractor:
        raise ValueError(
            "Office materialization requires an explicitly managed temporal extractor."
        )
```

For the two-pass solution, packet recovery should not calculate temporal values at all:

```python
def iter_flow_records(
    path: Path,
    subtype_label: str,
    *,
    temporal_mode: Literal["calculate", "disabled"] = "calculate",
    extractor: TemporalFeatureExtractor | None = None,
):
    ...
```

### State boundaries

Reset temporal state only when one of these changes:

- capture day;
- independent network capture domain;
- explicit experiment boundary.

Do not reset it merely because:

- a PCAP was split into chunks;
- a new candidate batch began;
- a worker restarted;
- a candidate slice was opened.

### Done when

- Temporal reset behavior is explicit and documented.
- Tests verify context continuity across sequential chunks.
- No office production call relies on the implicit extractor default.

---

## 5. Fix P0-3: Do Not Expire the Entire Flow at 20 Packets

### Current problem

`PacketCapture` already stops storing packet records after `FLOW_PACKET_LIMIT`.

However, `FlowCapper` also sets:

```python
flow.expiration_id = -1
```

when the flow reaches the same packet limit.

This means the limit does not only control packet-node count. It can terminate the NFStream flow itself.

### Why this is serious for office traffic

A video call, file transfer, HTTPS session, database connection, or server session may contain thousands of packets.

The intended graph design can reasonably use:

- the complete flow statistics;
- only the first 20 packet payload nodes.

The current cap can instead create:

```text
One real connection
    -> segment 1 with 20 packets
    -> segment 2 with 20 packets
    -> segment 3 with 20 packets
    -> ...
```

The resulting duration, byte totals, packet counts, active/idle statistics, and temporal history no longer describe the original flow.

### Required fix

Remove `NFStreamFlowCapper()` from normal office extraction.

Keep this behavior:

```python
if len(records) >= FLOW_PACKET_LIMIT:
    return
```

inside `PacketCapture`, because that limits only stored packet-node evidence.

Recommended streamer configuration:

```python
udps=[
    NFStreamActiveIdlePlugin(),
    NFStreamPacketCapture(),
]
```

### Optional controlled segmentation

If forced expiration is required for resource safety, make it a separate documented mode:

```text
SECUREEDGE_FLOW_SEGMENT_PACKET_LIMIT=0   # disabled by default
```

Every segmented graph must then record:

- `is_segmented_flow`;
- `segment_index`;
- `segment_reason`;
- `original_or_reconstructed_flow_identity`;
- whether flow statistics represent a full flow or a segment.

Do not call segmented records complete flows.

### Validation

Use a synthetic PCAP with one connection containing more than 100 packets.

Verify that after the fix:

- NFStream emits one complete flow under normal timeout behavior;
- `packet_records` contains at most 20 packets;
- the flow packet count remains greater than 20;
- duration and byte totals describe the complete connection;
- graph packet nodes remain bounded at 20.

### Done when

The packet-node limit and flow lifetime are independent concepts.

---

## 6. Fix P0-4: Make YAML the Only Office Configuration Source

### Current problem

The repository contains `configs/office_cic_ids_2018.yaml` and a typed loader, but `secureedge/data/office_pipeline.py` still contains office paths and constants directly.

This creates two sources of truth.

### Required fix

At program startup:

```python
office_config = load_office_config(args.config)
```

Then replace direct constants with values read from `OfficeConfig`.

### Values that must come from YAML

- dataset paths;
- class names and class order;
- attack windows;
- attacker and victim IP lists;
- timestamp offset;
- tuple matching tolerance;
- reverse-direction policy;
- preslice classes;
- slice width and maximum size;
- materialization batch size;
- retry count;
- worker memory cap;
- split targets;
- WebBased augmentation policy;
- graph dimensions;
- feature version;
- architecture policy.

### Recommended `OfficeConfig` properties

Add typed accessors instead of repeatedly indexing nested dictionaries:

```python
@property
def matching_tolerance_seconds(self) -> float: ...

@property
def attack_windows(self) -> list[AttackWindow]: ...

@property
def compact_root(self) -> Path: ...

@property
def split_targets(self) -> SplitTargets: ...
```

### Provenance requirement

Every generated artifact must contain:

```json
{
  "config_path": "...",
  "config_hash": "...",
  "config_schema_version": 1
}
```

### Done when

- Changing a YAML value changes all office pipeline stages.
- No duplicated day, path, class, window, or split constant remains in `office_pipeline.py`.
- A test compares the loaded configuration with generated manifest provenance.

---

## 7. Fix P0-5: Create an Office-Aware Training Entry Point

### Current problem

The current generic trainer is tied to the original SecureEdge configuration:

- original graph manifest path;
- original graph directories or shard manifest;
- original eight class names;
- original expected training count;
- default model output dimension from `config.N_CLASSES`.

The office model has seven classes:

```text
Benign, BruteForce, DoS, DDoS, WebBased, Bot, Infiltration
```

### Required fix

Make the trainer manifest-driven, or create a dedicated office wrapper around a generic trainer.

Recommended structure:

```text
secureedge/training/engine.py       # dataset-independent loop
secureedge/models/train.py          # original pipeline wrapper
secureedge/office/train.py          # office wrapper
```

### Manifest-driven training context

```python
@dataclass(frozen=True)
class TrainingContext:
    graph_manifest_path: Path
    shard_manifest_path: Path | None
    class_names: list[str]
    graph_dirs: dict[str, Path]
    feature_dimensions: dict[str, int]
    checkpoint_path: Path
    metrics_path: Path
    config_hash: str
```

### Model construction

Do not use the root default class count for office training:

```python
model = SecureEdgeHGNN(
    num_classes=len(training_context.class_names)
).to(device)
```

### Required checks

Before training:

- graph manifest class names exactly match YAML class names and order;
- all labels are in `0..N-1`;
- all seven classes exist in train and validation;
- test exists but is not loaded during training;
- feature dimensions match the model;
- manifest hash is recorded in the checkpoint;
- the dataset is not marked `materialization_incomplete`.

### Done when

The office model can be trained without changing the original global `secureedge/config.py` class list.

---

## 8. Fix P0-6: Use Validation for Model Selection, Not Test

### Current problem

The current training loop evaluates each epoch using the test split and uses that result for:

- best-checkpoint selection;
- learning-rate scheduling;
- early stopping;
- reported best macro-F1.

This leaks test-set information into model development.

### Correct split responsibilities

```text
Train:
- gradient updates
- oversampling/balancing
- scaler fitting

Validation:
- early stopping
- checkpoint selection
- scheduler decisions
- hyperparameter comparison

Test:
- one final evaluation after all choices are frozen
```

### Required code change

Replace training-time test loading with validation loading:

```python
val_dataset = load_graph_dataset("val", ...)
```

or use validation shards.

The test set must not be loaded by the training process.

### Required final workflow

```bash
python -m secureedge.office.train
python -m secureedge.office.evaluate --split test
```

### Checkpoint metadata

Save:

- best validation macro-F1;
- best validation epoch;
- validation confusion matrix;
- graph manifest hash;
- training config hash;
- class order.

Do not label validation metrics as final test performance.

### Done when

- Training logs say `validation`, not `test`, for epoch metrics.
- Test metrics are created only by a separate final evaluation command.
- Repeated training runs cannot access test labels.

---

## 9. Fix P0-7: Make Evaluation Office-Aware

### Current problem

The current evaluation code contains original dataset class assumptions and a hard-coded XG-NID class order containing classes that do not exist in the office model.

### Required fix

Read class names directly from the checkpoint and verify them against the graph manifest:

```python
class_names = checkpoint["class_names"]
assert class_names == manifest["class_names"]
```

Remove hard-coded class-order conversion for office evaluation.

### Required office metrics

- accuracy;
- macro precision, recall, and F1;
- weighted F1;
- per-class precision, recall, F1, and support;
- confusion matrix;
- false-positive and false-negative rates;
- source-stratified WebBased metrics;
- bootstrap confidence intervals for small classes;
- number of unique real graphs, separately from oversampled references.

### Output

```text
artifacts/office_model/metrics.json
artifacts/office_model/classification_report.json
artifacts/office_model/confusion_matrix.csv
artifacts/office_model/evaluation_report.md
```

### Done when

All metric labels and matrix axes use the exact seven-class office order.

---

## 10. Fix P0-8: Complete Materialization With Safe, Resumable Batches

### Current problem

BruteForce, DoS, and DDoS recovery has proven that narrow slicing works, but full target materialization remains incomplete.

### Required processing strategy

```text
Candidate manifest
    -> group by day, class, endpoint PCAP, and nearby time
    -> process deterministic batches
    -> create bounded PCAP slices
    -> extract in isolated worker
    -> validate compact graph
    -> atomically save graph
    -> append completion event
    -> rebuild cumulative manifest
```

### Required safety controls

- maximum candidates per batch;
- maximum slice size;
- maximum worker RSS;
- hard worker timeout;
- retry count;
- failure reason code;
- temporary-file cleanup;
- atomic graph writes;
- deterministic candidate ordering;
- skip completed candidate identities;
- no full-run override without passing preflight gates.

### Failure reason taxonomy

Use stable reason codes such as:

```text
NO_PCAP_FOR_DAY
SLICE_EMPTY
SLICE_TOO_LARGE
NFSTREAM_ERROR
WORKER_MEMORY_LIMIT
WORKER_TIMEOUT
NO_TUPLE_MATCH
TIMESTAMP_OUTSIDE_TOLERANCE
AMBIGUOUS_MATCH
NO_PACKET_RECORDS
TEMPORAL_CONTEXT_MISSING
GRAPH_SCHEMA_INVALID
OUTPUT_WRITE_FAILED
```

### Done when

Every requested real candidate is in exactly one state:

- materialized;
- permanently rejected with a documented reason;
- deferred for a documented recoverable reason.

---

# Part II — High-Priority Data Integrity Fixes

## 11. Fix P1-1: Strengthen Candidate-to-PCAP Flow Matching

### Required canonical identity

Use:

- capture day;
- protocol;
- source IP and port;
- destination IP and port;
- CSV start timestamp;
- source dataset;
- source row identity.

Allow reverse direction only as an explicit matching rule, not by silently sorting every field without preserving observed direction.

### Matching order

1. exact protocol;
2. exact directed five-tuple;
3. timestamp distance within tolerance;
4. reverse tuple when allowed;
5. packet/byte/duration similarity as a tie-breaker;
6. require a unique best match.

### Do not use arbitrary first-match behavior

If multiple flows have a similar score, mark the candidate as `AMBIGUOUS_MATCH`.

### Match report fields

Each compact graph should record:

```json
{
  "candidate_identity": "...",
  "matched_flow_identity": "...",
  "match_direction": "forward",
  "timestamp_delta_ms": 320,
  "match_score": 0.97,
  "match_candidate_count": 1,
  "source_pcap": "...",
  "slice_path": "..."
}
```

### Validation

Manually inspect a sample from every class and day, including reverse-direction matches.

---

## 12. Fix P1-2: Deduplicate Endpoint Capture Views

### Problem

The same network flow can appear in multiple endpoint or mirrored captures.

If both copies enter the graph pool or temporal history, the project can:

- double-count flows;
- inflate attack counts;
- repeat the same payload in multiple splits;
- distort the 375-flow history.

### Required fix

Calculate a canonical flow hash using direction-normalized endpoints plus stable timing/statistical evidence.

Example inputs:

- day;
- protocol;
- normalized endpoint pair;
- rounded first-seen timestamp;
- rounded last-seen timestamp;
- packet counts;
- byte counts;
- first packet payload hash when available.

Store both:

- `candidate_identity` — identity of the labeled CSV request;
- `flow_hash` — identity of the materialized network flow.

Reject cross-split duplicate `flow_hash` values.

---

## 13. Fix P1-3: Enforce Chronological Processing

Temporal features are valid only when flows are processed in time order.

### Required checks

- sort PCAP chunks by their real capture sequence;
- validate each chunk’s minimum and maximum timestamp;
- detect overlaps and gaps;
- sort extracted flow summaries by first-seen timestamp before updating windows;
- define deterministic ordering for equal timestamps;
- record the time range in the temporal index manifest.

### Equal-time tie-breaker

Use a stable tuple such as:

```python
(first_seen_ms, protocol, src_ip, src_port, dst_ip, dst_port, source_order)
```

---

## 14. Fix P1-4: Validate Timestamp Conversion and the Four-Hour Offset

### Risk

An incorrect timestamp offset can make candidate rows search the wrong section of a PCAP while still occasionally finding misleading near matches.

### Required fix

Create unit and integration tests around known attack examples from every selected day.

The timestamp audit must report:

- raw CSV timestamp;
- parsed timezone assumption;
- applied offset;
- converted epoch time;
- nearest PCAP packet time;
- resulting delta.

Do not hard-code the offset inside matching functions. Read it from YAML.

---

## 15. Fix P1-5: Preserve and Integrate Cumulative Manifests

### Current positive state

The repository now contains cumulative-manifest and completed-candidate registry support. This must become mandatory in the active materialization path.

### Required behavior

After every successful batch:

1. write each graph atomically;
2. append completed candidates to the done registry;
3. write an immutable run manifest;
4. rebuild or incrementally update the cumulative manifest;
5. validate manifest counts against the filesystem;
6. save the configuration and input-manifest hashes.

### Do not overwrite history

Keep:

```text
artifacts/office_model/runs/<run_id>.json
artifacts/office_model/office_compact_cumulative_manifest.json
artifacts/office_model/done_candidates.jsonl
```

### Cumulative consistency checks

- no duplicate candidate identity;
- no duplicate compact tensor hash unless explicitly oversampled by reference;
- no cross-split flow hash;
- class label matches class name;
- recorded file exists;
- file size and hash match;
- all files on disk appear in the manifest;
- all manifest files exist on disk.

---

## 16. Fix P1-6: Split Real Examples Before Any Oversampling

### Required sequence

```text
Unique real candidates
    -> deduplicate
    -> assign train/validation/test
    -> materialize and validate
    -> oversample training references only
```

### Never do this

```text
Oversample candidate list
    -> random split
```

That can place copies of the same graph in training, validation, and test.

### Required split identity audits

Check overlap using:

- candidate identity;
- flow hash;
- compact tensor hash;
- payload hash;
- capture day and source grouping.

### Oversampling storage

Prefer an oversampled training sampler or manifest references instead of copying the same `.pt` file thousands of times.

---

## 17. Fix P1-7: Use a Defensible WebBased Strategy

### Current challenge

The native CIC-IDS-2018 WebBased pool is small. Oversampling increases training frequency but not unique information.

### Required baseline policy

- use every valid native CIC-IDS-2018 WebBased graph;
- keep CICIDS2017 augmentation in training only;
- never place CICIDS2017 graphs in the native CIC-IDS-2018 validation or test split;
- record `source_dataset` on every graph;
- report native and external-source performance separately;
- report unique count and oversampled count separately.

### Recommended training experiments

Run controlled comparisons:

1. native data + random training oversampling;
2. native data + class-weighted loss;
3. native data + focal loss;
4. CICIDS2017 pretraining then native fine-tuning;
5. mixed train-only augmentation with source-balanced batches.

Do not run all methods simultaneously in the first baseline because the effect of each method becomes impossible to interpret.

### Evaluation warning

With roughly one hundred native examples in validation or test, report confidence intervals and avoid strong claims from small score differences.

---

## 18. Fix P1-8: Make Compact Validation a Mandatory Gate

Every compact record must pass validation before it is registered as done.

### Required checks

- class is one of the seven configured classes;
- label index matches class order;
- feature version matches YAML;
- flow vector has exactly 92 entries;
- packet count is between 1 and 20;
- packet feature width is 1,500;
- containment edge width is correct;
- packet-link edge width is correct;
- all numeric values are finite;
- packet edges reference valid packet nodes;
- packet-link edges follow sequence order;
- no raw IP or MAC is present in the model feature vector;
- candidate identity and flow hash are present;
- split and source dataset are present;
- temporal context provenance is present.

### Invalid graph handling

Move invalid files to a quarantine directory rather than silently ignoring them:

```text
data/graphs/office_quarantine/<reason>/...
```

---

## 19. Fix P1-9: Add Office Graph Sharding

The office converter creates `office_train`, `office_val`, and `office_test`, but the regular shard and training paths are still designed around the original graph dataset.

### Required fix

Create a manifest-driven sharder:

```bash
python -m secureedge.data.create_shards \
  --graph-manifest artifacts/office_model/office_graph_dataset_manifest.json \
  --output-root data/graphs/office_shards \
  --manifest-path artifacts/office_model/office_graph_shard_manifest.json
```

### Requirements

- preserve split boundaries;
- preserve class counts;
- record graph file hashes or manifest hash;
- reject incomplete datasets unless `--allow-incomplete-development-run` is explicit;
- never mix original and office graphs.

---

## 20. Fix P1-10: Prevent Original and Office Artifact Collisions

Use separate paths for:

- graph directories;
- shard directories;
- model checkpoint;
- training logs;
- metrics;
- scalers;
- OOD detector;
- export artifact.

Recommended office paths:

```text
artifacts/office_model/checkpoints/best_hgnn.pt
artifacts/office_model/training_runs/
artifacts/office_model/metrics.json
artifacts/office_model/office_graph_dataset_manifest.json
artifacts/office_model/office_graph_shard_manifest.json
data/graphs/office_train/
data/graphs/office_val/
data/graphs/office_test/
data/graphs/office_shards/
```

---

# Part III — Code Structure and Testing

## 21. Fix P1-11: Break Up `office_pipeline.py`

The large office pipeline should become orchestration code rather than a 4,000-line implementation file.

### Recommended package structure

```text
secureedge/office/
├── config.py
├── registry.py
├── labels.py
├── attack_windows.py
├── candidates.py
├── flow_identity.py
├── matching.py
├── slicing.py
├── temporal_index.py
├── materialize.py
├── manifests.py
├── validate.py
├── build_graphs.py
├── create_shards.py
├── train.py
├── evaluate.py
└── cli.py
```

### Migration approach

Move one responsibility at a time while keeping compatibility wrappers in `office_pipeline.py`.

Do not perform a complete rewrite before tests exist.

---

## 22. Fix P1-12: Expand Automated Tests

### Unit tests

- configuration schema and reference expansion;
- class order and label mapping;
- timestamp conversion;
- bidirectional tuple normalization;
- candidate identity stability;
- flow hash stability;
- temporal window per destination;
- temporal continuity across chunks;
- packet cap without flow expiration;
- ambiguity rejection;
- split overlap detection;
- compact schema validation.

### Integration tests

Use small synthetic PCAPs to test:

- full-PCAP versus slice temporal equivalence;
- long flow with more than 20 packets;
- reverse-direction candidate match;
- multiple candidates in one time slice;
- duplicate endpoint capture views;
- worker crash and resume;
- graph conversion and scaler fitting;
- validation-only checkpoint selection;
- final test evaluation.

### Regression tests

Keep one known graph per office class and verify:

- dimensions;
- label;
- edge types;
- deterministic identity;
- expected temporal feature values.

---

## 23. Fix P1-13: Add an Office Runbook

Create:

```text
docs/OFFICE_CIC_IDS_2018_RUNBOOK.md
```

It should explain:

- environment setup;
- required dataset directory structure;
- checksum gate;
- configuration inspection;
- candidate creation;
- temporal index generation;
- compact materialization;
- cumulative validation;
- graph conversion;
- sharding;
- training;
- validation-based checkpointing;
- final test evaluation;
- recovery after interruption;
- expected artifacts after every command.

The root README should clearly distinguish the original CIC-IoT2023 pipeline from the office pipeline.

---

# Part IV — Model and Experiment Improvements

## 24. Fix P2-1: Validate Edge-Feature Use in Both GAT Layers

The first heterogeneous GAT layer uses edge attributes. The second layer currently performs message passing without edge attributes.

This may be intentional, but it must be an explicit architectural decision.

### Required experiment

Compare:

1. edge attributes in layer 1 only;
2. edge attributes in both layers;
3. no edge attributes as an ablation.

Do this only after the preprocessing baseline is stable.

---

## 25. Fix P2-2: Defer GATv2 Until the Dataset Is Stable

The configuration correctly reserves `GATv2Conv` for a later architecture phase and rejects `SAGEConv` for the current attention-based design.

Do not change the convolution type while the preprocessing pipeline is still changing.

Recommended experiment order:

1. stable GATConv baseline;
2. identical training setup with GATv2Conv;
3. compare macro-F1 and minority-class metrics;
4. report parameter count and training cost;
5. keep the better validated model.

---

## 26. Fix P2-3: Validate the 375-Flow Window Rather Than Changing It Blindly

The per-destination implementation makes 375 a reasonable baseline.

After temporal context is calculated correctly, compare:

```text
100, 250, 375, 500, 750 flows
```

Evaluate:

- macro-F1;
- BruteForce recall;
- DoS and DDoS false positives;
- Infiltration recall;
- performance by busy versus quiet destination.

A later hybrid policy may use:

```text
up to the previous 375 destination flows,
subject to a maximum real-time age
```

Do not add multi-window features before the current single-window baseline is verified.

---

## 27. Fix P2-4: Use Class-Balancing Methods as Controlled Experiments

The existing trainer uses plain `CrossEntropyLoss()`.

After the pipeline is correct, add configuration options for:

- plain cross-entropy baseline;
- class-weighted cross-entropy;
- focal loss;
- balanced batch sampler.

Log the exact method and weights in every training run.

Never use validation or test counts to calculate training class weights.

---

## 28. Fix P2-5: Add Source and Day Robustness Experiments

Random flow-level splits can overestimate deployment performance when very similar flows from one attack session appear across all splits.

After the main baseline, run stricter evaluations:

- grouped by attack session;
- grouped by time block;
- leave-one-day-out when class availability permits;
- source-stratified evaluation for CICIDS2017 augmentation;
- endpoint robustness checks.

These are research-strengthening experiments, not replacements for fixing the main pipeline.

---

# Part V — Recommended Implementation Order

## 29. Phase A: Correct Flow and Temporal Semantics

Complete in this order:

1. Remove normal flow expiration at 20 packets.
2. Add a packet-only extraction mode with temporal calculation disabled.
3. Build a full chronological temporal-index pass.
4. Attach indexed temporal features during candidate materialization.
5. Test chunk continuity and full-PCAP/slice equivalence.
6. Centralize timestamp conversion.

**Do not continue full graph generation until this phase passes.**

---

## 30. Phase B: Make Materialization Reliable

1. Load all values from YAML.
2. Strengthen canonical identities and match scoring.
3. Add deterministic candidate batches.
4. Enforce worker memory and time limits.
5. Integrate the done registry and cumulative manifest.
6. Add reason-coded failures and quarantine.
7. Deduplicate endpoint capture copies.
8. Materialize development samples from all seven classes.
9. Validate them automatically and manually.

---

## 31. Phase C: Complete the Real Graph Pool

1. Freeze candidate split assignments.
2. Materialize unique real candidates.
3. Rebuild cumulative manifest.
4. Run compact graph gate.
5. Confirm class, split, day, and source counts.
6. Decide and document the final WebBased policy.
7. Preserve real-count versus oversampled-reference counts.

---

## 32. Phase D: Build the Office PyG Dataset

1. Fit normalizers on training only.
2. Convert train, validation, and test compact graphs.
3. Run graph structural validation.
4. Audit cross-split identity, flow-hash, and tensor-hash overlap.
5. Build office-specific shards.
6. Freeze and hash all manifests.

---

## 33. Phase E: Train and Evaluate Correctly

1. Create office-aware training context.
2. Instantiate a seven-output model.
3. Train on train only.
4. Select checkpoints with validation only.
5. Freeze architecture and hyperparameters.
6. Evaluate test once.
7. Save metrics, confusion matrix, and class reports.
8. Run WebBased source-stratified analysis.
9. Only then begin GATv2 or multi-window experiments.

---

# Part VI — Required Gates

## 34. Gate 1: Raw Dataset Integrity

Must pass:

- all configured CSV and PCAP files exist;
- checksums are recorded;
- PCAP readability passes;
- timestamp ranges are plausible;
- selected-day inventory is complete.

---

## 35. Gate 2: Candidate Integrity

Must pass:

- stable candidate IDs;
- correct class mapping;
- valid timestamps;
- no candidate cross-split overlap;
- CICIDS2017 absent from native validation/test;
- class and source counts documented.

---

## 36. Gate 3: Temporal Context Integrity

Must pass:

- per-destination windows;
- chronological ordering;
- continuity across chunks;
- no context from future flows;
- no candidate-slice-only history;
- full-PCAP/slice equivalence test;
- missing context is explicitly rejected.

---

## 37. Gate 4: Compact Graph Integrity

Must pass:

- dimensions and finite values;
- one correct label per graph;
- 1–20 packet nodes;
- valid edges;
- source and split metadata;
- temporal provenance;
- no identity features;
- no cross-split duplicate flow or tensor hash.

---

## 38. Gate 5: PyG Dataset Integrity

Must pass:

- train, validation, and test are all non-empty;
- all seven classes appear where methodologically expected;
- training-only scaler fit is proven;
- manifest and filesystem counts agree;
- graph and shard hashes are recorded;
- `materialization_incomplete` is false for the final run.

---

## 39. Gate 6: Training Integrity

Must pass:

- seven-class output dimension;
- office class order from manifest;
- validation used for early stopping;
- test not loaded by the trainer;
- checkpoint includes manifest/config hashes;
- loss and balancing method are recorded.

---

## 40. Gate 7: Final Evaluation Integrity

Must pass:

- test evaluated only after model selection;
- class order verified;
- macro and per-class metrics saved;
- confusion matrix saved;
- WebBased uncertainty reported;
- unique graph counts reported;
- native and augmented sources reported separately.

---

# Part VII — Suggested Commands After Implementation

The exact command names can be adjusted, but the workflow should look like this:

```bash
# 1. Inspect and hash configuration
python -m secureedge.office.config --print-hash

# 2. Verify raw data
python -m secureedge.office.registry --config configs/office_cic_ids_2018.yaml

# 3. Build candidate manifest and split assignments
python -m secureedge.office.candidates --config configs/office_cic_ids_2018.yaml

# 4. Build complete chronological temporal context index
python -m secureedge.office.temporal_index --config configs/office_cic_ids_2018.yaml

# 5. Materialize compact graphs in resumable batches
python -m secureedge.office.materialize --config configs/office_cic_ids_2018.yaml

# 6. Rebuild cumulative compact manifest
python -m secureedge.office.manifests --config configs/office_cic_ids_2018.yaml

# 7. Validate compact graphs
python -m secureedge.office.validate --stage compact

# 8. Convert compact graphs to PyG
python -m secureedge.office.build_graphs --overwrite

# 9. Validate final graph dataset
python -m secureedge.office.validate --stage graphs

# 10. Create office graph shards
python -m secureedge.office.create_shards --overwrite

# 11. Train using train and validation only
python -m secureedge.office.train

# 12. Perform one final test evaluation
python -m secureedge.office.evaluate --split test
```

---

# Part VIII — Final Completion Checklist

## Preprocessing

- [ ] Office pipeline reads all operational values from YAML.
- [ ] Timestamp offset is validated against known flows.
- [ ] Full chronological temporal index exists.
- [ ] Per-destination window continuity survives PCAP chunking.
- [ ] Candidate slices do not calculate their own isolated temporal context.
- [ ] The 20-packet cap limits packet nodes only, not whole-flow lifetime.
- [ ] Candidate matching rejects ambiguous results.
- [ ] Endpoint capture duplicates are removed.

## Materialization

- [ ] Every candidate has a stable identity.
- [ ] Every graph has a stable flow hash.
- [ ] Materialization is resumable.
- [ ] Failures have reason codes.
- [ ] Cumulative manifest matches the filesystem.
- [ ] All compact records pass schema validation.
- [ ] Real examples are split before oversampling.

## Graph generation

- [ ] Training-only scalers are fitted.
- [ ] Office graph manifest contains seven ordered classes.
- [ ] Train, validation, and test directories are distinct.
- [ ] Office shards are separate from original shards.
- [ ] Cross-split leakage audit passes.

## Training

- [ ] Model output size is seven.
- [ ] Class names come from the office graph manifest.
- [ ] Validation controls early stopping and checkpoint selection.
- [ ] Test is not touched during training.
- [ ] Checkpoint stores config and manifest hashes.

## Evaluation

- [ ] Test is evaluated once after selection.
- [ ] Macro-F1 and every class metric are saved.
- [ ] WebBased results include confidence intervals.
- [ ] Native CIC-IDS-2018 and CICIDS2017 augmentation are reported separately.
- [ ] Final `metrics.json` exists under `artifacts/office_model/`.

## Documentation and reproducibility

- [ ] Office runbook exists.
- [ ] Root README clearly separates both pipelines.
- [ ] All source code and configuration are committed.
- [ ] Raw data remain excluded from Git.
- [ ] Dataset checksums, configuration hashes, and run manifests are preserved.

---

# 41. Final Recommendation

The first implementation sprint should focus on four corrections only:

1. **Stop expiring flows at 20 packets.**
2. **Build temporal features from complete chronological per-destination traffic, not candidate slices.**
3. **Make the office trainer seven-class and manifest-driven.**
4. **Use validation for checkpoint selection and reserve test for final evaluation.**

These four changes correct the meaning of the input data and the validity of the experiment. Completing large-scale materialization before fixing them would risk generating thousands of graphs that later need to be discarded and rebuilt.

After these blockers are fixed, continue with safe materialization, cumulative validation, office sharding, WebBased handling, and final training.
