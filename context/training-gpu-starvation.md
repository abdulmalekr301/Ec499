# Training GPU Starvation Report

> Generated: 2026-06-15  
> Scope: Explains why SecureEdge HGNN training showed very low GPU utilization,
> why it was not actually CPU-only, and what fixes have been applied so far.

## Summary

During HGNN training, GPU utilization appeared to sit around 1-5% while CPU usage
was around 20%. This looked like the model might be training on CPU, but process
inspection showed that the training process was attached to the RTX 4060 and was
executing CUDA kernels.

The real issue is GPU starvation: the GPU is waiting for the CPU/DataLoader to
load, deserialize, batch, and transfer many small graph files.

## Evidence Collected

The active training process was:

```text
PID 196122: .venv/bin/python -m secureedge.models.train
```

The process environment was:

```text
SECUREEDGE_DEVICE=cuda
SECUREEDGE_BATCH_SIZE=128
SECUREEDGE_NUM_WORKERS=2
SECUREEDGE_MAX_EPOCHS=200
```

`nvidia-smi` showed the training process attached to the GPU:

```text
PID 196122
Type C
Process .venv/bin/python
GPU memory about 206 MiB
```

`nvidia-smi pmon` showed CUDA activity from that process:

```text
PID 196122
SM utilization about 2%
GPU memory about 206 MiB
```

So training was not CPU-only. It was running on CUDA, but the GPU was mostly idle.

## Why GPU Utilization Was Low

### 1. The dataset is stored as many small files

The graph dataset currently contains:

```text
data/graphs/train/*.pt  -> 160,000 files
data/graphs/test/*.pt   -> 32,000 files
```

Each training sample is an individual PyTorch Geometric `HeteroData` object saved
with `torch.save()`. Every batch therefore requires many small file reads and many
`torch.load()` deserialization calls.

This creates high Python and filesystem overhead before the GPU receives a batch.

### 2. PyG batching is CPU-side work

`torch_geometric.loader.DataLoader` merges many small heterogeneous graph objects
into one disconnected batched graph. That collation work happens on CPU.

For this project, every graph has:

- one `flow` node with 92 features
- up to 20 `packet` nodes with 1,500 features each
- flow-to-packet contain edges
- packet-to-flow reverse contain edges
- packet-to-packet temporal edges

The GPU computation per graph is small, but the CPU work to load and collate each
graph is non-trivial.

### 3. The HGNN is relatively small

The current HGNN has:

- two heterogeneous GAT layers
- hidden size 64
- small graph-level classifier

The RTX 4060 can finish these batches quickly. If the next batch is not ready,
GPU utilization drops.

### 4. CPU usage was partly unrelated

During inspection, there was also an unrelated `git add` process using nearly a
full CPU core. That contributed to the observed CPU load but was not the training
process itself.

Training also had two `pt_data_worker` processes doing DataLoader work:

```text
pt_data_worker
pt_data_worker
```

Those workers were doing the graph file loading and batch preparation.

## Fixes Applied So Far

### 1. Explicit device logging at training startup

`secureedge/models/train.py` now prints the active runtime device and CUDA state
at the beginning of training:

```json
{
  "device": "cuda",
  "torch_cuda_available": true,
  "torch_cuda_version": "13.0",
  "cuda_device_count": 1,
  "cuda_device_name": "NVIDIA GeForce RTX 4060",
  "batch_size": 128,
  "train_limit_per_class": 0,
  "eval_limit_per_class": 0,
  "max_epochs": 200
}
```

This prevents confusion between CPU runs, sandboxed runs, and real CUDA runs.

### 2. Explicit `SECUREEDGE_DEVICE` handling

Training now supports:

```text
SECUREEDGE_DEVICE=auto
SECUREEDGE_DEVICE=cpu
SECUREEDGE_DEVICE=cuda
```

If `SECUREEDGE_DEVICE=cuda` is requested but PyTorch cannot see CUDA, training now
fails clearly instead of silently falling back to CPU.

### 3. Configurable batch size and worker count

The following environment variables are now supported:

```text
SECUREEDGE_BATCH_SIZE
SECUREEDGE_NUM_WORKERS
SECUREEDGE_PREFETCH_FACTOR
```

This allows tuning without editing code.

### 4. Persistent DataLoader workers

When `SECUREEDGE_NUM_WORKERS > 0`, the trainer now uses:

```python
persistent_workers=True
```

This keeps worker processes alive between epochs instead of constantly creating
and destroying them.

### 5. DataLoader prefetching

When worker processes are enabled, the trainer now uses:

```python
prefetch_factor=config.PREFETCH_FACTOR
```

The default is:

```text
SECUREEDGE_PREFETCH_FACTOR=2
```

This lets each worker prepare future batches while the GPU works on the current
batch.

### 6. Pinned host memory for CUDA

For CUDA runs, the trainer and evaluator use:

```python
pin_memory=True
```

This can improve CPU-to-GPU transfer speed.

### 7. Non-blocking CUDA batch transfer

Batch transfer now uses:

```python
batch.to(device, non_blocking=True)
```

This allows asynchronous transfer from pinned CPU memory to GPU where possible.

### 8. Evaluation loader updated consistently

`secureedge/models/evaluate.py` now uses the same worker, prefetch, and pinned
memory settings as training.

## Current Recommended Training Command

For the RTX 4060 with 8 GB VRAM, the next recommended restart is:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_NUM_WORKERS=2 \
SECUREEDGE_PREFETCH_FACTOR=2 \
SECUREEDGE_MAX_EPOCHS=200 \
.venv/bin/python -m secureedge.models.train
```

If VRAM usage is still low and the system remains stable, try:

```bash
SECUREEDGE_BATCH_SIZE=512
```

Do not increase worker count aggressively yet. Each worker was observed using a
large amount of memory, so increasing workers may increase RAM pressure more than
it helps GPU utilization.

## How to Confirm CUDA Is Being Used

At training startup, look for:

```text
"device": "cuda"
"torch_cuda_available": true
"cuda_device_name": "NVIDIA GeForce RTX 4060"
```

During training, run:

```bash
nvidia-smi
```

The training process should appear as:

```text
.venv/bin/python
Type C
```

For per-process GPU utilization:

```bash
nvidia-smi pmon -s um
```

Look for the training PID and nonzero `sm` utilization.

## Remaining Root Cause

The largest remaining bottleneck is the dataset storage format:

```text
192,000 individual .pt files
```

This causes:

- many tiny filesystem reads
- repeated Python deserialization
- expensive CPU-side PyG collation
- low GPU occupancy because batches are not ready fast enough

## Recommended Future Fix

The next substantial performance improvement should be to pack graph samples into
larger training shards instead of individual `.pt` files.

Good options:

1. PyG `InMemoryDataset` files
2. chunked `.pt` shard files, for example 1,000-5,000 graphs per shard
3. memory-mapped feature arrays with graph metadata indices

The safest next implementation is probably chunked graph shards because it keeps
the current graph objects intact while reducing file-open and deserialization
overhead dramatically.

## Current Status

The trainer is CUDA-capable and has been confirmed to run on the RTX 4060. The
low GPU percentage is a data pipeline throughput problem, not proof of CPU-only
training.

The first round of fixes has been applied:

- explicit CUDA/device logging
- strict CUDA device selection
- configurable training limits and batch size
- persistent DataLoader workers
- DataLoader prefetching
- pinned memory for CUDA
- non-blocking CUDA transfers

The next major optimization is graph dataset sharding.
