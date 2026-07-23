# XG-NID Oversampling Resplit

Generated: `2026-07-07T00:31:11+00:00`

## Action
- Rebuilt `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json` from the existing compact reservoir.
- Rebuilt train/validation/test splits without allowing compact record references to overlap across splits.
- Oversampled train only to 20,000 records per class; validation/test remain held-out unique records and may be smaller for underrepresented classes.

## Oversampling Summary
```json
{
  "Benign": {
    "real_available": 24000,
    "target_total": 20000,
    "unique_in_balanced_pool": 20000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 28000,
    "content_hash_group_count": 27983,
    "split_target_mode": "fixed_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 24000,
    "requested_train_real_count": 24000,
    "requested_train_count": 20000,
    "requested_val_count": 2000,
    "requested_test_count": 2000,
    "train_count": 20000,
    "val_count": 2000,
    "test_count": 2000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "DDoS": {
    "real_available": 24008,
    "target_total": 20000,
    "unique_in_balanced_pool": 20000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 28008,
    "content_hash_group_count": 28008,
    "split_target_mode": "fixed_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 24008,
    "requested_train_real_count": 24008,
    "requested_train_count": 20000,
    "requested_val_count": 2000,
    "requested_test_count": 2000,
    "train_count": 20000,
    "val_count": 2000,
    "test_count": 2000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "DoS": {
    "real_available": 24000,
    "target_total": 20000,
    "unique_in_balanced_pool": 20000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 28000,
    "content_hash_group_count": 28000,
    "split_target_mode": "fixed_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 24000,
    "requested_train_real_count": 24000,
    "requested_train_count": 20000,
    "requested_val_count": 2000,
    "requested_test_count": 2000,
    "train_count": 20000,
    "val_count": 2000,
    "test_count": 2000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Mirai": {
    "real_available": 24002,
    "target_total": 20000,
    "unique_in_balanced_pool": 20000,
    "oversampled_count": 0,
    "oversampled_fraction": 0.0,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 28002,
    "content_hash_group_count": 28002,
    "split_target_mode": "fixed_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 24002,
    "requested_train_real_count": 24002,
    "requested_train_count": 20000,
    "requested_val_count": 2000,
    "requested_test_count": 2000,
    "train_count": 20000,
    "val_count": 2000,
    "test_count": 2000,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Recon": {
    "real_available": 19286,
    "target_total": 20000,
    "unique_in_balanced_pool": 19286,
    "oversampled_count": 714,
    "oversampled_fraction": 0.0357,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 23143,
    "content_hash_group_count": 23143,
    "split_target_mode": "proportional_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 19286,
    "requested_train_real_count": 19286,
    "requested_train_count": 20000,
    "requested_val_count": 1929,
    "requested_test_count": 1928,
    "train_count": 20000,
    "val_count": 1929,
    "test_count": 1928,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "Spoofing": {
    "real_available": 13459,
    "target_total": 20000,
    "unique_in_balanced_pool": 13459,
    "oversampled_count": 6541,
    "oversampled_fraction": 0.32705,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 16151,
    "content_hash_group_count": 16150,
    "split_target_mode": "proportional_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 13459,
    "requested_train_real_count": 13459,
    "requested_train_count": 20000,
    "requested_val_count": 1346,
    "requested_test_count": 1346,
    "train_count": 20000,
    "val_count": 1346,
    "test_count": 1346,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "WebBased": {
    "real_available": 3856,
    "target_total": 20000,
    "unique_in_balanced_pool": 3856,
    "oversampled_count": 16144,
    "oversampled_fraction": 0.8072,
    "webbased_subtype_balancing": "capped_floor",
    "webbased_subtype_floor_fraction": 0.1,
    "webbased_subtype_ceiling_fraction": 0.3,
    "webbased_subtype_allocations": {
      "Backdoor_Malware": 2545,
      "BrowserHijacking": 4144,
      "CommandInjection": 2614,
      "SqlInjection": 6000,
      "Uploading_Attack": 2197,
      "XSS": 2500
    },
    "webbased_subtype_summary": {
      "Backdoor_Malware": {
        "real_available_in_train_seed": 205,
        "target_slots": 2545,
        "unique_in_balanced_subtype": 205,
        "oversampled_count": 2340,
        "oversampled_fraction": 0.9194499017681729
      },
      "BrowserHijacking": {
        "real_available_in_train_seed": 807,
        "target_slots": 4144,
        "unique_in_balanced_subtype": 807,
        "oversampled_count": 3337,
        "oversampled_fraction": 0.8052606177606177
      },
      "CommandInjection": {
        "real_available_in_train_seed": 231,
        "target_slots": 2614,
        "unique_in_balanced_subtype": 231,
        "oversampled_count": 2383,
        "oversampled_fraction": 0.9116296863045141
      },
      "SqlInjection": {
        "real_available_in_train_seed": 2351,
        "target_slots": 6000,
        "unique_in_balanced_subtype": 2351,
        "oversampled_count": 3649,
        "oversampled_fraction": 0.6081666666666666
      },
      "Uploading_Attack": {
        "real_available_in_train_seed": 74,
        "target_slots": 2197,
        "unique_in_balanced_subtype": 74,
        "oversampled_count": 2123,
        "oversampled_fraction": 0.9663177059626764
      },
      "XSS": {
        "real_available_in_train_seed": 188,
        "target_slots": 2500,
        "unique_in_balanced_subtype": 188,
        "oversampled_count": 2312,
        "oversampled_fraction": 0.9248
      }
    },
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 4627,
    "content_hash_group_count": 4627,
    "split_target_mode": "proportional_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 3856,
    "requested_train_real_count": 3856,
    "requested_train_count": 20000,
    "requested_val_count": 386,
    "requested_test_count": 385,
    "train_count": 20000,
    "val_count": 386,
    "test_count": 385,
    "val_shortfall": 0,
    "test_shortfall": 0,
    "cross_split_duplicate_reference_counts": {
      "train_val": 0,
      "train_test": 0,
      "val_test": 0
    }
  },
  "BruteForce": {
    "real_available": 1820,
    "target_total": 20000,
    "unique_in_balanced_pool": 1820,
    "oversampled_count": 18180,
    "oversampled_fraction": 0.909,
    "split_order": "split_first_then_oversample_train_only",
    "raw_unique_available": 2184,
    "content_hash_group_count": 2184,
    "split_target_mode": "proportional_targets",
    "proportional_split_threshold": 24000,
    "train_seed_count": 1820,
    "requested_train_real_count": 1820,
    "requested_train_count": 20000,
    "requested_val_count": 182,
    "requested_test_count": 182,
    "train_count": 20000,
    "val_count": 182,
    "test_count": 182,
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
