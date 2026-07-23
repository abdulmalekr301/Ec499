# Office Model Graph Generation Preflight

Generated: `2026-07-13T02:54:42+00:00`

## Action
- Added the office-network graph generation preflight pipeline.
- Registered the final seven-class office taxonomy: `Benign`, `BruteForce`, `DoS`, `DDoS`, `WebBased`, `Bot`, `Infiltration`.
- Verified the improved CIC-IDS2018 CSV directory and per-day raw PCAP directory layout.
- Built per-day IP-to-capture-file lookup counts from `datasets/cic_ids_2018/raw_pcaps/<day>/pcap`.
- Added streaming improved-CSV scanning with corrected-label exclusion handling for `Attempted` labels and documented BruteForce contamination rules.
- Did not start full PCAP graph extraction; that remains gated by the missing machine-readable IP/time-window table and by memory/runtime controls.

## Preflight Manifest
- JSON: `/var/home/alucard-00/EC499/artifacts/office_model/preflight_manifest.json`

## Per-Day Summary

| Day | PCAP files | PCAP IPs | Rows scanned | Limited | Accepted by class | Excluded by class |
|---|---:|---:|---:|---|---|---|
| Wednesday-14-02-2018 | 449 | 449 | 250000 | `True` | `{"Benign": 250000}` | `{}` |
| Friday-16-02-2018 | 442 | 442 | 250000 | `True` | `{"Benign": 250000}` | `{}` |
| Wednesday-21-02-2018 | 445 | 445 | 250000 | `True` | `{"Benign": 250000}` | `{}` |
| Friday-23-02-2018 | 446 | 446 | 250000 | `True` | `{"Benign": 250000}` | `{}` |
| Friday-02-03-2018 | 439 | 439 | 250000 | `True` | `{"Benign": 250000}` | `{}` |
| Thursday-01-03-2018 | 439 | 439 | 250000 | `True` | `{"Benign": 250000}` | `{}` |

## Blocking Items Before Full Extraction

- Provide the IP/time-window ground-truth table referenced by `office-model-graph-generation-pipeline.md` as JSON or CSV.
- Decide the private/public endpoint matching rule after inspecting the pilot day manifest.
- Run a bounded extraction pilot for one day/class before any full six-day run.
- Keep CICIDS2017 WebBased augmentation source-tagged and train-only.
