# Office Config Hashing and Architecture Policy

Date: 2026-07-17

## Action

Implemented the next recovery-plan step after the cumulative manifest baseline:

- Installed `PyYAML==6.0.3` into `.venv`.
- Added `PyYAML>=6.0.3` to `requirements.txt`.
- Added `configs/office_cic_ids_2018.yaml`.
- Added `secureedge/office/config.py`.
- Updated `secureedge/office/manifests.py` so cumulative manifests include config provenance.

## Config provenance

Command:

```bash
.venv/bin/python -m secureedge.office.config
```

Output:

```json
{
  "config_hash": "2ded866b30fca73462ac448fa1967336c528cf245708d3756f49736efc524538",
  "config_path": "/var/home/alucard-00/EC499/configs/office_cic_ids_2018.yaml",
  "config_schema_version": 1
}
```

The config loader:

- Uses `yaml.safe_load`.
- Fails on unknown or missing top-level keys.
- Expands the shared DDoS rotating attacker list and Bot victim list into attack-window entries.
- Computes a stable SHA-256 hash over canonicalized config content.
- Resolves relative paths against the repository root.

## Behavior preservation

The YAML values were lifted from the current office pipeline constants. Validation confirmed:

```text
config matches live office constants
```

Checked:

- office class names
- day-spec count
- CIC-IDS-2018 attack-window count
- CICIDS2017 WebBased attack-window count
- current WebBased train target
- current preslice window seconds

This step does not change candidate selection, materialization behavior, graph schema, or split behavior.

## Manifest provenance

After rerunning:

```bash
.venv/bin/python -m secureedge.office.manifests --reconcile
```

the cumulative manifest retained the same compact graph counts:

```text
record_count: 49242
rejected_count: 0
Benign: 10764
Bot: 14172
BruteForce: 200
DDoS: 20
DoS: 165
Infiltration: 23509
WebBased: 412
```

and now includes:

```text
config_path: /var/home/alucard-00/EC499/configs/office_cic_ids_2018.yaml
config_hash: 2ded866b30fca73462ac448fa1967336c528cf245708d3756f49736efc524538
config_schema_version: 1
```

## Architecture policy

The project owner explicitly chose attention-based aggregation:

- Do not switch to `SAGEConv`.
- Keep the current attention-based `GATConv` path for now.
- When the architectural-change phase begins, switch from `GATConv` to `GATv2Conv`.

This is recorded in `configs/office_cic_ids_2018.yaml`:

```yaml
architecture_policy:
  current_attention_conv: GATConv
  future_attention_conv: GATv2Conv
  do_not_use: SAGEConv
```

## Verification

Commands run:

```bash
.venv/bin/python -m py_compile secureedge/office/config.py secureedge/office/manifests.py secureedge/data/office_pipeline.py
.venv/bin/python -m secureedge.office.config
.venv/bin/python -m secureedge.office.manifests --reconcile
.venv/bin/python tests/smoke_checks.py
```

All checks passed.

## Next recovery-plan step

Implement the raw dataset registry and Gate 1 validation:

- file existence
- file sizes
- SHA-256 checksums
- CSV row/header checks
- PCAP readability metadata where tooling is available

