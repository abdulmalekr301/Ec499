# Graph Sharding

Generated: `2026-07-07T00:38:29+00:00`

## Action
- Packed individual graph files into shard files of up to `1000` graphs.
- Train shards: `160`.
- Validation shards: `12`.
- Test shards: `12`.
- Saved shard manifest to `/var/home/alucard-00/EC499/artifacts/graph_shard_manifest.json`.

## Counts
```json
{
  "train_graphs": 160000,
  "val_graphs": 11843,
  "test_graphs": 11841,
  "train_shards": 160,
  "val_shards": 12,
  "test_shards": 12
}
```
