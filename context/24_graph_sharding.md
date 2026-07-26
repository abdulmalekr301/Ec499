# Graph Sharding

Generated: `2026-07-26T03:29:41+00:00`

## Action
- Packed individual graph files into shard files of up to `1000` graphs.
- Train shards: `76`.
- Validation shards: `6`.
- Test shards: `6`.
- Source graph manifest: `artifacts/office_model/office_graph_dataset_manifest.json`.
- Saved shard manifest to `artifacts/office_model/office_graph_shard_manifest.json`.

## Counts
```json
{
  "train_graphs": 75035,
  "val_graphs": 5475,
  "test_graphs": 5441,
  "train_shards": 76,
  "val_shards": 6,
  "test_shards": 6
}
```
