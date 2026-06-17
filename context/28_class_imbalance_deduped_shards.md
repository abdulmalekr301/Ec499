# Class Imbalance Deduped Shards

Generated: `2026-06-16T18:08:09+00:00`

## Action
- Streamed original train shards from `/var/home/alucard-00/EC499/data/graphs/train_shards`.
- Removed duplicate graph identities using class, subtype, source PCAP, and source flow order.
- Wrote deduped training shards to `/var/home/alucard-00/EC499/data/graphs/train_shards_deduped`.
- Saved manifest to `/var/home/alucard-00/EC499/artifacts/deduped_manifest.json`.

## Counts
```json
{
  "total_original_train_graphs": 160000,
  "total_deduped_train_graphs": 130242,
  "removed_duplicate_graphs": 29758,
  "duplicate_fraction_removed": 0.1859875,
  "class_counts": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 11882,
    "Spoofing": 20000,
    "WebBased": 11691,
    "BruteForce": 6669
  },
  "class_weights": {
    "Benign": 1.0,
    "DDoS": 1.0,
    "DoS": 1.0,
    "Mirai": 1.0,
    "Recon": 1.6832183134152499,
    "Spoofing": 1.0,
    "WebBased": 1.710717646052519,
    "BruteForce": 2.99895036737142
  },
  "shard_count": 131
}
```
