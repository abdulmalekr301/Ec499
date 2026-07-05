# Graph Sharding

Generated: `2026-07-04T21:52:58+00:00`

## Action
- Packed individual graph files into shard files of up to `1000` graphs.
- Train shards: `160`.
- Validation shards: `32`.
- Test shards: `32`.
- Saved shard manifest to `/var/home/alucard-00/EC499/artifacts/graph_shard_manifest.json`.

## Counts
```json
{
  "train_graphs": 160000,
  "val_graphs": 32000,
  "test_graphs": 32000,
  "train_shards": 160,
  "val_shards": 32,
  "test_shards": 32
}
```
