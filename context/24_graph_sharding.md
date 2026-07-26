# Graph Sharding

Generated: `2026-07-26T20:35:39+00:00`

## Action
- Packed individual graph files into shard files of up to `1000` graphs.
- Train shards: `120`.
- Validation shards: `13`.
- Test shards: `13`.
- Source graph manifest: `artifacts/office_model/office_graph_dataset_manifest.json`.
- Saved shard manifest to `artifacts/office_model/office_graph_shard_manifest.json`.

## Counts
```json
{
  "train_graphs": 119700,
  "val_graphs": 12051,
  "test_graphs": 12054,
  "train_shards": 120,
  "val_shards": 13,
  "test_shards": 13
}
```
