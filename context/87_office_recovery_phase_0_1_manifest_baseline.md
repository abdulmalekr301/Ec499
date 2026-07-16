# Office Recovery Phase 0/1 Manifest Baseline

Date: 2026-07-16

## Action

Implemented the first durable-state step from `context/PROJECT_RECOVERY_AND_IMPLEMENTATION_PLAN.md`:

- Added `secureedge/office/manifests.py`.
- Added `secureedge/office/__init__.py`.
- Wired `secureedge/data/office_pipeline.py` to pre-filter already-materialized candidate identities from the cumulative manifest before density-aware pending-candidate selection.
- Created a reconcile command:

```bash
.venv/bin/python -m secureedge.office.manifests --reconcile
```

The command rebuilds a cumulative office compact graph manifest from the current filesystem and backfills an append-only done-registry keyed by `candidate_identity`.

## Generated artifacts

| Artifact | Purpose |
| --- | --- |
| `artifacts/office_model/office_compact_cumulative_manifest.json` | Current authoritative cumulative compact-graph manifest |
| `artifacts/office_model/done_candidates.jsonl` | Append-only materialized-candidate registry |
| `artifacts/office_model/runs/reconcile_*.json` | Per-run reconcile manifests |

## Baseline reconcile result

Second reconcile run:

```text
run_id: reconcile_20260716T205652Z
record_count: 49242
rejected_count: 0
per_class:
  Benign: 10764
  Bot: 14172
  BruteForce: 200
  DDoS: 20
  DoS: 165
  Infiltration: 23509
  WebBased: 412
done_registry_registered: 49242
```

Manifest verification:

```text
duplicate_candidate_identity_count: 0
newly_registered_from_reconcile: 0
done_registry lines: 49242
```

The second reconcile registering zero new candidates verifies the initial idempotency requirement for the done-registry.

## Registry-aware planner check

Non-writing check:

```bash
.venv/bin/python - <<'PY'
from secureedge.data.office_pipeline import load_office_materialization_candidates, load_office_materialized_identity_index, materialization_identity
idx = load_office_materialized_identity_index()
selected = load_office_materialization_candidates(limit_unique=25, target_classes={'DDoS'}, materialized_identities=set(idx))
overlap = [materialization_identity(candidate) for candidate in selected if materialization_identity(candidate) in idx]
print('selected', len(selected))
print('overlap_with_materialized', len(overlap))
assert not overlap
PY
```

Output:

```text
selected 25
overlap_with_materialized 0
```

This verifies future bounded materialization runs can spend their candidate budget on pending records instead of already-materialized records.

## Office CLI verification

Confirmed with:

```bash
.venv/bin/python -m secureedge.data.office_pipeline --help
```

Available modes:

- `preflight`
- `candidate-manifest`
- `ip-time-crosscheck`
- `pilot-extract`
- `webbased-attempted-check`
- `cicids2017-webbased-augment`
- `office-final-splits`
- `office-materialize-compact`
- `office-materialize-pcap-worker`
- `office-open-flow-diagnostic`
- `office-nfstream-rss-diagnostic`
- `office-infiltration-payload-audit`
- `office-readable-graph-samples`

## Remaining recovery-plan work

This step does not change materialization behavior and does not complete full office graph generation. The next implementation steps are:

1. Add YAML configuration and config hashing.
2. Implement dataset registry and validation gates.
3. Build the office compact-to-PyG graph conversion command.
4. Extend the materialization worker to append per-run manifests into the cumulative manifest after each successful batch.
