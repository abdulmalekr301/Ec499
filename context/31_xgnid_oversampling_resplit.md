# XG-NID Oversampling Resplit

Generated: `2026-06-17T17:02:18+00:00`

## Action
- Rebuilt `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json` from the existing compact reservoir.
- Balanced each canonical class to 24,000 records using random undersampling/oversampling.
- Split each balanced class pool into 20,000 train and 4,000 test records.

## Oversampling Summary
```json
{
  "Benign": {
    "real_available": 24000,
    "target_total": 24000,
    "unique_in_balanced_pool": 24000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "train_count": 20000,
    "test_count": 4000
  },
  "DDoS": {
    "real_available": 24000,
    "target_total": 24000,
    "unique_in_balanced_pool": 24000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "train_count": 20000,
    "test_count": 4000
  },
  "DoS": {
    "real_available": 24000,
    "target_total": 24000,
    "unique_in_balanced_pool": 24000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "train_count": 20000,
    "test_count": 4000
  },
  "Mirai": {
    "real_available": 24000,
    "target_total": 24000,
    "unique_in_balanced_pool": 24000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "train_count": 20000,
    "test_count": 4000
  },
  "Recon": {
    "real_available": 21426,
    "target_total": 24000,
    "unique_in_balanced_pool": 21426,
    "oversampled_count": 2574,
    "oversampled_fraction": 0.10725,
    "train_count": 20000,
    "test_count": 4000
  },
  "Spoofing": {
    "real_available": 24000,
    "target_total": 24000,
    "unique_in_balanced_pool": 24000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "train_count": 20000,
    "test_count": 4000
  },
  "WebBased": {
    "real_available": 20855,
    "target_total": 24000,
    "unique_in_balanced_pool": 20855,
    "oversampled_count": 3145,
    "oversampled_fraction": 0.13104166666666667,
    "train_count": 20000,
    "test_count": 4000
  },
  "BruteForce": {
    "real_available": 11043,
    "target_total": 24000,
    "unique_in_balanced_pool": 11043,
    "oversampled_count": 12957,
    "oversampled_fraction": 0.539875,
    "train_count": 20000,
    "test_count": 4000
  }
}
```
