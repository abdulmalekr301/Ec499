# PCAP Crash Root Cause and Guardrails

## What Happened

During repeated full PCAP preprocessing attempts, the workstation became unstable and crashed while extracting graph samples from large CIC-IoT2023 PCAP files. The failures happened during the PCAP extraction stage, before model training.

The latest run used per-PCAP subprocess workers, compact pickle reservoirs, and PCAP chunking through `tcpdump`, but the machine still exhausted memory and swap during the large PCAP phase. After the crash, no SecureEdge extraction process remained active and the system memory recovered.

## Root Causes Found

- The raw PCAP corpus is large for an interactive 16 GiB workstation. A full methodology run targets 192,000 graph samples from tens of GiB of packet captures.
- NFStream extraction can create high transient memory pressure while parsing large PCAPs, independent of the compact graph records stored by SecureEdge.
- Chunking with `tcpdump` reduces per-file size, but still performs large sequential reads/writes and can create heavy page-cache and swap pressure.
- A plain `python -m secureedge.data.preprocess` previously started the full run immediately, which made it too easy to repeat a known unsafe workload.
- `secureedge/data/preprocess.py` contained an unreachable memory check after a `return` statement in `run_extraction_worker`, so the parent process did not perform the intended post-worker memory validation.

## Fixes Applied

- Added a hard full-run lock in `secureedge/data/preprocess.py`.
- Full PCAP preprocessing now refuses to start unless `SECUREEDGE_ALLOW_FULL_PREPROCESS=1` is set.
- Added environment-controlled development sample counts:
  - `SECUREEDGE_TRAIN_SAMPLES_PER_CLASS`
  - `SECUREEDGE_TEST_SAMPLES_PER_CLASS`
- Lowered default memory-risk settings:
  - `SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4`
  - `SECUREEDGE_MAX_PROCESS_RSS_GB=2`
  - `SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64`
  - `SECUREEDGE_PCAP_CHUNK_SIZE_MB=16`
  - `SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL=50`
- Disabled automatic large-PCAP splitting by default with `SECUREEDGE_ALLOW_AUTOMATIC_PCAP_SPLITTING=0`.
- Added a hard worker address-space limit with `resource.RLIMIT_AS` unless `SECUREEDGE_ALLOW_UNSAFE_PREPROCESS=1` is set.
- Limited worker math/thread allocator behavior with:
  - `MALLOC_ARENA_MAX=2`
  - `OMP_NUM_THREADS=1`
  - `OPENBLAS_NUM_THREADS=1`
  - `MKL_NUM_THREADS=1`
- Fixed the unreachable parent memory check after worker completion.
- Added pre-extraction and per-chunk memory checks inside `secureedge/data/extract_worker.py`.
- Updated `README.md` with safe development commands and full-run override instructions.

## Safe Development Command

Use this first on the current workstation:

```bash
SECUREEDGE_TRAIN_SAMPLES_PER_CLASS=200 SECUREEDGE_TEST_SAMPLES_PER_CLASS=50 python -m secureedge.data.preprocess
```

## Full Run Warning

The full final-methodology extraction should not be run interactively on this machine again. If it must be run, use a larger machine or a controlled batch session, pre-split the PCAPs into smaller files first, then start it explicitly:

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 python -m secureedge.data.preprocess
```

Automatic in-pipeline splitting remains locked unless this is also set:

```bash
SECUREEDGE_ALLOW_AUTOMATIC_PCAP_SPLITTING=1
```

## Current Recommendation

Proceed with bounded development extraction first, verify the graph build/training/evaluation path end to end, and reserve the full 192,000-sample extraction for a machine with substantially more memory or a controlled non-desktop environment.
