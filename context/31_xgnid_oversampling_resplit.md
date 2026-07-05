# XG-NID Oversampling Resplit

Generated: `2026-07-04T21:45:00+00:00`

## Action
- Rebuilt `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json` from the existing compact reservoir.
- Rebuilt train/validation/test splits without allowing compact record references to overlap across splits.
- Oversampled train only to 20,000 records per class; validation/test remain held-out unique records and may be smaller for underrepresented classes.

## Oversampling Summary
```json
{
  "Benign": {
    "real_available": 16000,
    "target_total": 20000,
    "unique_in_balanced_pool": 16000,
    "oversampled_count": 4000,
    "oversampled_fraction": 0.2,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 24000,
    "content_hash_group_count": 23986,
    "train_seed_count": 16000,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "DDoS": {
    "real_available": 16000,
    "target_total": 20000,
    "unique_in_balanced_pool": 16000,
    "oversampled_count": 4000,
    "oversampled_fraction": 0.2,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 24000,
    "content_hash_group_count": 24000,
    "train_seed_count": 16000,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "DoS": {
    "real_available": 16000,
    "target_total": 20000,
    "unique_in_balanced_pool": 16000,
    "oversampled_count": 4000,
    "oversampled_fraction": 0.2,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 24000,
    "content_hash_group_count": 24000,
    "train_seed_count": 16000,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Mirai": {
    "real_available": 16000,
    "target_total": 20000,
    "unique_in_balanced_pool": 16000,
    "oversampled_count": 4000,
    "oversampled_fraction": 0.2,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 24000,
    "content_hash_group_count": 24000,
    "train_seed_count": 16000,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Recon": {
    "real_available": 11943,
    "target_total": 20000,
    "unique_in_balanced_pool": 11943,
    "oversampled_count": 8057,
    "oversampled_fraction": 0.40285,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 19943,
    "content_hash_group_count": 19943,
    "train_seed_count": 11943,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Spoofing": {
    "real_available": 6151,
    "target_total": 20000,
    "unique_in_balanced_pool": 6151,
    "oversampled_count": 13849,
    "oversampled_fraction": 0.69245,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 14151,
    "content_hash_group_count": 14150,
    "train_seed_count": 6151,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "WebBased": {
    "real_available": 15126,
    "target_total": 20000,
    "unique_in_balanced_pool": 15126,
    "oversampled_count": 4874,
    "oversampled_fraction": 0.2437,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 23126,
    "content_hash_group_count": 23108,
    "train_seed_count": 15126,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "BruteForce": {
    "real_available": 3043,
    "target_total": 20000,
    "unique_in_balanced_pool": 3043,
    "oversampled_count": 16957,
    "oversampled_fraction": 0.84785,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 11043,
    "content_hash_group_count": 11038,
    "train_seed_count": 3043,
    "requested_train_count": 20000,
    "requested_val_count": 4000,
    "requested_test_count": 4000,
    "train_count": 20000,
    "val_count": 4000,
    "test_count": 4000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  }
}
```
