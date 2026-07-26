# Graph Sharding

Generated: `2026-07-26T05:17:59+00:00`

## Action
- Packed individual graph files into shard files of up to `1000` graphs.
- Train shards: `112`.
- Validation shards: `12`.
- Test shards: `12`.
- Source graph manifest: `artifacts/office_model/office_graph_dataset_manifest.json`.
- Saved shard manifest to `artifacts/office_model/office_graph_shard_manifest.json`.

## Counts
```json
{
  "train_graphs": 111376,
  "val_graphs": 11235,
  "test_graphs": 11205,
  "train_shards": 112,
  "val_shards": 12,
  "test_shards": 12
}
```
