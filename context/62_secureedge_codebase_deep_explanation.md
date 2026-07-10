# SecureEdge Codebase Deep Explanation

This document explains the SecureEdge codebase at a module and function level.
It is meant to be a guide you can read before modifying the pipeline, debugging
training, or explaining the implementation in a report or presentation.

## Big Picture Analogy

Think of SecureEdge as a factory that turns network traffic into decisions.

- PCAP files are the raw material.
- NFStream is the intake machine that separates traffic into flows.
- `PacketCapture` is the small camera mounted on the machine; it keeps packet bytes.
- Temporal features are the factory's short-term memory.
- Compact graph records are boxed intermediate products.
- PyTorch Geometric heterographs are the finished parts sent to the model.
- The HGNN is the inspector that looks at both the flow summary and packet details.
- Training logs and audits are the quality-control paperwork.

The central design is XG-NID-style heterogeneous graph learning: each flow becomes
one graph with one flow node, multiple packet nodes, and typed edges between them.

## Data Shape

Each completed flow becomes a graph:

- `flow` node: 92 features
  - 76 flow/statistical features
  - 16 temporal features
- `packet` nodes: up to 20 packet nodes per flow
  - each packet node has 1500 payload-byte features
- `flow -> packet` edges: contain edges
  - 4 edge features: direction, IP size, transport size, payload size
- `packet -> flow` edges: reverse contain edges
  - same 4 edge features
- `packet -> packet` edges: link edges
  - 1 feature: inter-packet time delta
- target: one of 8 classes
  - `Benign`, `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`, `WebBased`, `BruteForce`

## `secureedge/config.py`

This is the codebase's control panel.

### Path constants

The top of the file defines canonical project paths:

- `PCAP_DIR`: raw PCAP directory.
- `RAW_DATA_DIR`: raw extracted/split data.
- `GRAPH_DIR`: generated graph files.
- `GRAPH_RESERVOIR_DIR`: compact graph reservoir.
- `ARTIFACTS_DIR`: manifests, metrics, checkpoints, scalers.
- `CONTEXT_DIR`: markdown documentation and logs.

Analogy: these constants are the labeled shelves in the workshop.

### MAC helpers

- `normalize_mac_address(value)`: normalizes MAC addresses into a consistent
  lowercase colon-separated form.
- `parse_mac_set(raw)`: parses a comma/space/semicolon separated list of MACs.
- `parse_mac_file(path_value)`: reads attacker MACs from a file.

Why this matters: MAC filtering is used to remove background traffic from attack
classes while preserving benign traffic logic.

### Class configuration

- `CLASS_NAMES`: the eight output labels.
- `CLASS_TO_INDEX`: converts class names into integer targets.
- `SUBTYPE_TO_CLASS`: maps fine-grained CIC-IoT2023 subtype filenames to the eight
  canonical classes.
- `MAC_FILTERED_CLASSES`: every class except `Benign`.

Analogy: `SUBTYPE_TO_CLASS` is a translation dictionary between the dataset's
detailed folder/file names and the model's eight answer choices.

### Split configuration

- `TRAIN_SAMPLES_PER_CLASS`: default `20000`.
- `VAL_SAMPLES_PER_CLASS`: default `2000`.
- `TEST_SAMPLES_PER_CLASS`: default `2000`.
- `PROPORTIONAL_SPLIT_THRESHOLD`: default `24000`.

When a class has at least 24000 real records, it keeps fixed 2000/2000 val/test
targets. Below that threshold, validation and test shrink proportionally so scarce
classes keep more real data in training.

### Feature configuration

- `TEMPORAL_FEATURES`: 16 rolling-window features.
- `NFSTREAM_STAT_FEATURES`: flow statistics from NFStream.
- `DERIVED_FLOW_FEATURES`: extra rate/ratio features.
- `FLOW_FEATURE_ORDER`: the final ordered 76 flow feature list.
- `N_FLOW_NODE_FEATURES`: 92 after adding temporal features.
- `N_PACKET_FEATURES`: 1500.
- `FLOW_PACKET_LIMIT`: 20.

Feature order is critical because a model checkpoint only makes sense if feature
position 17 means the same thing during training and inference.

### Training configuration

The training defaults are mostly environment-variable driven:

- device selection
- batch size
- gradient accumulation
- scheduler
- learning rates
- early stopping
- AMP on/off
- graph sharding
- resume behavior

This lets us run the same Python code in different modes without editing source.

## `secureedge/utils.py`

Small utility module.

- `ensure_directories()`: creates expected output directories.
- `write_context(filename, title, lines)`: writes a markdown note into `context/`.
- `write_json(path, payload)`: writes formatted JSON.
- `read_json(path)`: reads JSON.

Analogy: this is the stationery drawer: folders, notebooks, and JSON forms.

## `secureedge/data/pcap_flows.py`

This module converts raw PCAP traffic into flow records.

### `_packet_bytes_from_attr(value)`

Normalizes possible packet-byte containers into `bytes`.

It accepts:

- `bytes`
- `bytearray`
- `memoryview`
- lists/tuples of byte-like integers

If the value cannot be interpreted as bytes, it returns `b""`.

### `packet_payload_bytes(packet)`

Searches an NFStream packet object for usable payload bytes.

The order is:

1. `ip_payload_bytes`
2. `payload`
3. `ip_packet`, parsed by `application_payload_from_ip_packet`
4. `transport_payload`
5. `packet`

This exists because NFStream exposes different packet attributes depending on
version and dissection settings.

### `application_payload_from_ip_packet(ip_packet)`

Strips IPv4, TCP, and UDP headers from a raw IP packet when possible.

Analogy: if `ip_packet` is a shipping box, this function removes the outer label
and inner packaging so the model sees the actual item inside.

### `pad_payload(payload)`

Truncates or pads payload bytes to exactly 1500 values.

This is needed because neural networks require fixed-size vectors.

### `PacketCapture`

NFStream plugin that stores up to `FLOW_PACKET_LIMIT` packet records inside each
flow.

Methods:

- `on_init(packet, flow)`: initializes `flow.udps.packet_records`.
- `on_update(packet, flow)`: appends one packet record if the limit has not been
  reached.

Each packet record includes:

- payload bytes
- direction
- IP size
- transport size
- payload size
- timestamp

### `FlowCapper`

NFStream plugin that expires a flow once it reaches the packet limit.

Why: XG-NID only uses up to 20 packets per graph. Keeping longer flows open wastes
memory and increases extraction cost.

### `ActiveIdlePlugin`

Computes active/idle burst statistics.

Methods:

- `on_init`: starts tracking packet timing.
- `on_update`: detects idle gaps larger than 1000 ms.
- `on_expire`: writes active/idle summary features into `flow.udps`.

Analogy: it records whether a conversation was continuous or had long awkward
pauses. Some attacks, like slow-rate attacks, are defined by those pauses.

### `flow_to_dict(flow)`

Converts an NFStream flow object into a normal Python dictionary.

### `is_number(value)`

Returns whether a value is safe to convert to float and should be considered a
numeric feature.

### `nfstream_feature_dict(flow_data)`

Extracts numeric NFStream features while excluding identity and metadata columns.

This is one of the core anti-leakage functions: IPs, MACs, filenames, timestamps,
and other identifiers should not become model features.

### `active_idle_feature_dict(flow)`

Extracts active/idle features produced by `ActiveIdlePlugin`.

### `flow_mac_pair(flow_data)`

Returns normalized source/destination MACs.

Used by MAC-filter auditing and preprocessing.

### `nfstream_to_temporal_dict(flow_data)`

Converts NFStream field names into the field names expected by the temporal feature
extractor.

### `iter_flow_records(path, subtype_label, extractor)`

The main generator for PCAP extraction.

It configures `NFStreamer` with:

- statistical analysis enabled
- tunnel decoding disabled
- packet capture plugin
- flow capper plugin
- active/idle plugin

For each completed flow, it yields a record containing:

- `flow_features`
- `temporal_features`
- `packet_records`
- label metadata
- source file/order metadata
- MAC metadata for filtering

Analogy: this is the conveyor belt from raw PCAPs to model-ready ingredients.

## `secureedge/features/temporal.py`

This module computes the 16 rolling temporal features.

### Helper functions

- `first_present(row, candidates, default)`: returns the first available field
  from a set of possible names.
- `destination_key(row)`: chooses the destination key, usually destination IP.
- `source_port(row)`: extracts source port.
- `destination_port(row)`: extracts destination port.
- `numeric(row)`: safely converts row fields into numeric values.
- `numeric_sum(row)`: sums numeric fields.
- `snapshot(row)`: creates the normalized flow event stored in the rolling window.

### `TemporalFeatureExtractor`

Keeps a per-destination rolling window of recent flows.

Methods:

- `transform_row(row)`: updates the window for one flow and returns 16 temporal
  features.
- `transform_frame(frame)`: applies `transform_row` to a dataframe-like batch.

Analogy: if the flow node is a single sentence, temporal features are the previous
paragraph. They tell the model whether this flow is isolated or part of a recent
pattern.

## `secureedge/data/graph_builder.py`

This module turns flow records into graph records and PyG heterographs.

### `safe_divide(numerator, denominator)`

Division helper that returns `0.0` for zero, NaN, or infinite denominators.

### `compute_derived_features(flow_features)`

Computes rate and ratio features such as:

- bytes per second
- packets per second
- down/up byte ratio
- average packet size

These derived features caused fp16 overflow in raw mode until log1p handling and
AMP disabling were added.

### `require_pyg()`

Imports PyTorch Geometric and gives a clear error if it is missing.

### `graph_value_mode()`

Validates whether graph values should be `scaled` or `raw`.

The active methodology uses `raw` with log1p on derived flow features.

### `raw_derived_flow_transform()`

Validates whether raw derived features should use `log1p` or no transform.

### `transform_raw_flow_values(flow_values, feature_names)`

Applies `log1p` to derived rate/ratio features in raw mode.

Analogy: it compresses skyscraper-sized numbers into a scale the model can survive,
while preserving their order.

### `ordered_flow_vector(flow_features, temporal_features)`

Combines flow, derived, and temporal features in the exact configured order.

### `build_compact_graph_record(...)`

Builds a compact dictionary representation of one graph:

- flow feature array
- packet byte matrix
- contain edge features
- packet-link delta features
- class label
- subtype/source metadata

It returns `None` for flows with no packet records.

Why compact records exist: storing compact NumPy arrays is cheaper and safer during
preprocessing than immediately materializing PyG objects for everything.

### `compact_to_hetero_graph(compact)`

Converts a compact graph dictionary into a `torch_geometric.data.HeteroData` object.

It creates:

- `data["flow"].x`
- `data["packet"].x`
- `data["flow", "contains", "packet"]`
- `data["packet", "rev_contains", "flow"]`
- `data["packet", "linked_to", "packet"]`
- `data.y`

### `build_hetero_graph(...)`

Convenience wrapper that builds compact form and immediately converts it to a PyG
heterograph.

### `load_graph_ref(graph_ref)`

Loads either:

- compact `.pkl`
- PyTorch `.pt`
- already-loaded graph object

### `is_compact_graph(graph)`

Checks whether an object is a compact graph dictionary.

### `graph_class_name(graph_ref)`

Gets the canonical class name from a compact or PyG graph.

### Matrix helpers

- `graph_flow_matrix(graphs)`
- `graph_contain_edge_matrix(graphs)`
- `graph_link_delta_vector(graphs)`

These collect feature matrices for scaler fitting or diagnostics.

### Normalization helpers

- `normalize_graph(graph, flow_scaler, contain_scaler, link_norm_value)`
- `fit_graph_normalizers(train_graphs)`

These are used for scaled graph mode. In current raw mode, scalers are recorded as
disabled to avoid train/test leakage concerns.

### Dataset saving

- `clear_pt_files(directory)`: removes old `.pt` graph files.
- `save_graph_split(...)`: writes one split.
- `save_graph_dataset(train_graphs, val_graphs, test_graphs)`: writes graph files
  and the graph manifest.

## `secureedge/data/extract_worker.py`

This module runs bounded extraction in a subprocess-style worker.

### `split_pcap_if_needed(path, chunk_threshold_mb, chunk_size_mb)`

Refuses large direct PCAP processing unless automatic splitting is explicitly
enabled.

This guard exists because earlier extraction attempts exhausted memory/swap.

### `memory_ok(max_rss_gb, min_available_gb)`

Checks both process RSS and system available memory.

### `save_compact_record(record, directory, subtype, index)`

Writes one compact graph record to disk.

### `mac_filter_decision(flow_record, class_name)`

Applies class-aware MAC filtering:

- Benign traffic can be kept unless attacker-MAC enforcement says otherwise.
- Attack traffic is kept only when an attacker MAC is involved.
- Missing MACs can be kept with a reason label.

### `extract(args)`

The extraction worker's main function.

It:

1. checks memory
2. creates a temporal extractor
3. iterates PCAP chunks
4. streams NFStream flow records
5. applies MAC filtering
6. builds compact graph records
7. maintains a reservoir sample
8. stops at target or memory limit
9. returns a JSON-style summary

Analogy: it is a careful miner that only carries a fixed-size basket and checks
oxygen levels before going deeper.

### `parse_args()` and `main()`

CLI interface for worker execution.

## `secureedge/data/preprocess.py`

This is the orchestration layer for preprocessing.

### Label and PCAP discovery

- `canonical_label(raw)`: maps a raw subtype/label to one of 8 classes.
- `subtype_from_pcap(path)`: derives subtype from PCAP filename or chunk folder.
- `chunk_sort_key(path)`: sorts chunks in natural capture order.
- `discover_pcap_groups()`: finds PCAPs and chooses pre-split chunks when needed.
- `discover_pcap_files()`: flattens group discovery into a file list.
- `expected_subtypes()`: lists required subtype names.
- `validate_pcap_class_coverage(pcap_files)`: fails if classes/subtypes are missing.

### Sampling targets

- `subtypes_for_class(class_name)`: returns subtypes belonging to a class.
- `per_subtype_target(class_name)`: computes reservoir target per subtype.
- `total_requested_graphs()`: computes total planned graph count.
- `assert_full_run_is_allowed(pcap_files)`: prevents accidental full-scale extraction.

### Reservoir management

- `clear_reservoir_dir()`: resets reservoir output.
- `save_reservoir_graph(...)`: writes compact graph records.
- `update_subtype_reservoir(...)`: reservoir-samples a subtype stream.
- `reservoir_is_full(...)`: checks target fill status.
- `load_existing_subtype_reservoirs()`: reloads existing compact records.
- `compact_manifest_source_from_existing()`: documents source metadata for resplits.

Reservoir sampling analogy: imagine a bucket that can hold only N marbles from a
stream. Every new marble has a fair chance to replace an old one, so the bucket is
representative without storing the entire stream.

### Balancing and splitting

- `sample_graphs(...)`: samples paths with or without replacement.
- `compact_content_hash(path)`: hashes compact graph contents to prevent leakage.
- `compact_subtype_label(path)`: reads subtype metadata.
- `balance_to_target(records, target, rng)`: over/undersamples train to target.
- `capped_floor_subtype_allocations(...)`: allocates WebBased train slots with
  subtype floors and ceilings.
- `balance_webbased_subtypes(...)`: balances WebBased subtypes within train.
- `split_targets_for_class(pool_size)`: applies fixed or proportional split rules.
- `split_without_cross_split_duplicates(records, rng, class_name)`: content-hash
  split before train-only oversampling.
- `build_balanced_splits(subtype_reservoirs, rng)`: builds global train/val/test.

The most important guarantee: validation/test records are separated before train
oversampling, so duplicated train samples do not leak into evaluation.

### Worker orchestration and manifests

- `assert_memory_available(context)`: blocks unsafe stages.
- `worker_limits()`: provides memory limits to extraction workers.
- `output_tag_for_pcap(path)`: creates safe output tags.
- `run_extraction_worker(...)`: invokes `extract_worker`.
- `write_compact_manifest(...)`: writes `artifacts/compact_reservoir_manifest.json`
  and preprocessing context.

### Entrypoints

- `resplit_existing_reservoir()`: rebuilds splits without re-extracting PCAPs.
- `regenerate_selected_subtype_reservoirs(selected_subtypes)`: re-extracts selected
  subtypes.
- `preprocess()`: main pipeline.
- `main()`: CLI entrypoint.

## `secureedge/data/build_graphs.py`

Converts compact manifest paths into PyG graph files.

- `load_compact_manifest()`: reads compact manifest.
- `paths_from_manifest(manifest, split)`: gets compact paths for a split.
- `validate_compact_feature_version(paths)`: checks feature schema consistency.
- `build_graphs()`: loads compact records, converts them with `compact_to_hetero_graph`,
  and saves graph dataset.
- `main()`: CLI entrypoint.

Analogy: if compact records are dehydrated meals, `build_graphs.py` adds water and
turns them into full graph objects.

## `secureedge/data/create_shards.py`

Groups individual graph files into shard files for faster, safer training.

- `parse_args()`: reads CLI flags.
- `split_manifest_paths(manifest, split)`: fetches graph paths.
- `prepare_output_dir(path, overwrite)`: creates/clears shard directory.
- `create_split_shards(paths, output_dir, shard_size, seed, overwrite)`: writes one
  split's shards.
- `create_shards(shard_size, seed, overwrite)`: creates all split shards.
- `main()`: CLI entrypoint.

Analogy: instead of carrying 160000 loose sheets of paper, sharding binds them into
160 notebooks.

## `secureedge/data/dataset.py`

Dataset loading utilities.

- `GraphFileDataset`: lazy dataset that loads graph files by path.
  - `__init__`: stores paths.
  - `__len__`: returns graph count.
  - `__getitem__`: loads one graph.
- `load_graph_manifest()`: reads graph manifest.
- `split_paths(split, limit_per_class)`: returns graph paths, optionally limited.
- `load_graph_dataset(split, limit_per_class)`: returns `GraphFileDataset`.

## `secureedge/data/leakage_audit.py`

Verifies that train/val/test are cleanly separated.

- `graph_hash(data)`: exact graph hash.
- `rounded_graph_fingerprint(data, decimals)`: near-duplicate fingerprint.
- `compact_row_hash(path)`: exact compact-record hash.
- `hash_graph_split(shards, decimals)`: hashes all graphs in a split.
- `compact_hash_split(paths)`: hashes compact rows.
- `overlap_count(left, right)`: counts overlap.
- `audit(args)`: runs all leakage checks and asserts failure if leakage appears.
- `write_report(path, results)`: writes markdown report.

Analogy: it is the border guard between train and evaluation.

## `secureedge/data/mac_filter_audit.py`

Explains MAC filtering outcomes before or after preprocessing.

- `mac_pair(flow_record)`: extracts normalized pair.
- `pair_label(pair)`: classifies pair readability.
- `audit_subtype(...)`: samples flows for a subtype.
- `summarize_by_class(...)`: aggregates subtype summaries.
- `interpret(class_summary)`: adds human interpretation.
- `write_markdown_report(payload)`: writes audit report.

## `secureedge/data/payload_diagnostic.py`

Measures whether packet payload features contain signal.

- `graph_paths` and `shard_paths`: choose inputs.
- `packet_stats(graph)`: computes payload density stats.
- `diagnose_graphs` and `diagnose_shards`: inspect graph files or shards.
- `summarize` and `summarize_per_class`: aggregate results.

## `secureedge/data/verify_packet_capture.py`

Debug tool for NFStream packet byte attributes.

- `PacketAttributeProbe`: probes packet attributes inside NFStream.
- `inspect_pcap(...)`: runs probe on a PCAP.
- `summarize_records(records)`: reports which attributes contain bytes.

This is how we verified `packet.ip_packet` was usable.

## `secureedge/data/verify_flow_window.py`

Inspects compact paths to verify temporal-window consistency.

- `compact_paths(limit)`: selects compact records.
- `inspect_compact(path)`: reads one compact record.
- `verify(limit)`: aggregates checks.

## `secureedge/models/hgnn.py`

Defines the graph model.

### `require_pyg_layers()`

Imports PyG layers:

- `GATConv`
- `HeteroConv`
- `global_mean_pool`

### `SecureEdgeHGNN`

The main model class.

Constructor:

- optional packet payload CNN encoder
- first heterogeneous GAT layer
- BatchNorm for flow and packet nodes
- second heterogeneous GAT layer
- BatchNorm again
- graph readout
- classifier head

Important architecture details:

- attention size: 32
- heads: 2
- concat: true
- output hidden size: 64
- edge attributes are used on all edge types
- BatchNorm epsilon: 1.0
- readout can concatenate flow and packet pooled embeddings

Analogy: the model has two specialists: one reads flow statistics, the other reads
packet payloads. Multi-head attention lets them ask different questions about the
same graph instead of forcing one blended question.

Methods:

- `forward(...)`: accepts PyG dictionaries and returns logits.
- `forward_batch(batch)`: convenience wrapper for a PyG batch.

### `document_architecture()`

Writes architecture summary into `context/04_model_architecture.md`.

## `secureedge/models/train.py`

Training loop and logging.

### Device and AMP helpers

- `training_device()`: chooses/validates CPU or CUDA.
- `amp_disabled_reason(device)`: explains why AMP is disabled.
- `amp_is_enabled(device)`: final AMP decision.

Raw graph mode disables AMP because large raw rate features can overflow fp16.

### DataLoader helpers

- `require_pyg_dataloader()`: imports PyG DataLoader.
- `make_loader_kwargs(device, num_workers)`: sets workers and pin memory.
- `move_batch(batch, device)`: moves batch to target device.
- `logits_for_batch(model, batch)`: calls the HGNN.

### Shard helpers

- `load_shard_manifest()`: reads shard manifest.
- `shard_entries(manifest, split)`: validates shard paths.
- `load_shard_graphs(path)`: loads one shard list.
- `epoch_batch_count_from_shards(entries)`: computes batches per epoch.

### Metrics

- `compute_class_metrics(predictions, targets)`: computes TP, FP, FN, TN, precision,
  recall, F1, false-positive rate, and false-negative rate per class.
- `evaluate_metrics_on_loader(...)`: collects predictions from a loader.
- `evaluate_metrics(...)`: evaluates either shards or regular loaders.
- `evaluate_macro_f1(...)`: convenience macro-F1 evaluator.

### Checkpoint and resume

- `model_signature()`: describes architecture-sensitive settings.
- `checkpoint_signature_compatible(checkpoint)`: prevents incompatible resume.
- `checkpoint_macro_f1(path)`: reads best F1 from a checkpoint.
- `load_resume_state(...)`: restores model, optimizer, and scheduler if requested.

### Scheduler and history

- `cosine_cycle(epoch_index_after_warmup)`: tracks cosine-restart cycle.
- `current_lr(optimizer)`: returns current learning rate.
- `write_training_history_csv(path, history)`: writes machine-readable CSV.
- `write_run_markdown(...)`: writes `context/logs-N.md`.

### `train()`

The main training pipeline:

1. validates graph manifest
2. selects device
3. chooses run id
4. loads train/val shards or graph files
5. builds `SecureEdgeHGNN`
6. configures loss, optimizer, scheduler
7. optionally resumes checkpoint
8. trains by epoch
9. evaluates on validation split
10. saves best checkpoint by validation macro F1
11. writes JSON, CSV, and markdown logs
12. stops on max epochs or early stopping

Analogy: this is the pilot checklist and flight recorder for the model.

## `secureedge/models/evaluate.py`

Final evaluation helpers.

- `load_checkpoint()`: loads compatible best checkpoint.
- `predict(model, loader, device)`: gets predictions, targets, subtypes, classes.
- `ddos_subtype_distribution(...)`: checks DDoS subtype behavior.
- `named_confusion_matrix(...)`: writes confusion matrix in chosen class order.
- `evaluate()`: evaluates test split and writes metrics.

## `secureedge/ood/detector.py`

Calibrates simple OOD detection.

- `calibrate_threshold()`: uses correctly classified samples and maximum softmax
  probability to set threshold.
- `main()`: CLI entrypoint.

## `secureedge/export/export.py`

Exports the trained HGNN.

- `TraceableHGNN`: wrapper that makes dictionary inputs traceable.
- `export_torchscript()`: traces one sample batch and verifies logits.
- `main()`: CLI entrypoint.

## `secureedge/visualize/graph_view.py`

Creates SVG/HTML graph samples.

Important helpers:

- `graph_paths_from_split(...)`: selects graph files.
- `load_graph(path)`: loads graph.
- `edge_count(graph, edge_type)`: counts typed edges.
- `packet_color(packet_values)`: colors packets by payload signal.
- SVG helpers: `text`, `line`, `rect`, `circle`.
- `flow_feature_rows(graph, show_values)`: displays flow features.
- `render_graph_svg(path, graph, show_values)`: creates one SVG.
- `write_index(output_dir, rendered)`: creates HTML gallery.

Analogy: this is the microscope. It does not train anything, but it lets us see
what the graph objects look like.

## Legacy/Parallel Modules

### `secureedge/models/architecture.py`

Contains the older flat MLP implementation. It is not the final methodology model,
but it remains in the repo from the earlier CSV/MLP phase.

### `secureedge/features/pipeline.py`

Now mainly validates graph features.

### `secureedge/data/acquire.py`

Legacy CSV acquisition helper from the early CSV phase.

## `tests/smoke_checks.py`

One-file smoke suite for high-risk assumptions:

- label mapping
- balancing behavior
- temporal extractor output
- model forward shape
- OOD threshold artifact behavior
- export compatibility behavior

Smoke checks are not a full unit-test suite, but they are useful before heavy
preprocessing or training runs.

## Mental Model for Debugging

When something fails, locate the pipeline stage:

1. PCAP/NFStream problem: inspect `pcap_flows.py`, `extract_worker.py`, packet
   verification, and MAC filtering.
2. Wrong class counts: inspect `preprocess.py`, compact manifest, and class
   distribution reports.
3. Graph shape problem: inspect `graph_builder.py`, `build_graphs.py`, and
   `features.pipeline`.
4. Slow or memory-heavy training: inspect `create_shards.py`, `dataset.py`,
   `train.py`, batch size, workers, and AMP.
5. Bad metrics: inspect `logs-N.md`, per-class FP/FN rates, class distribution,
   and leakage audit.
6. Export problem: inspect checkpoint compatibility and `export.py`.

