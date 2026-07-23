# Office Final Candidate Splits

Generated: `2026-07-13T22:13:28+00:00`

## Action
- Built final office-model candidate split JSONLs before graph materialization.
- Used 24,000 real candidates for each standard class: 20,000 train, 2,000 validation, 2,000 test.
- Split native WebBased 50/25/25, added CICIDS2017 only to train, then oversampled WebBased train references to 6,000.
- Saved split manifest to `/var/home/alucard-00/EC499/artifacts/office_model/final_candidate_split_manifest.json`.

## Counts
```json
{
  "counts": {
    "train_real": 120373,
    "train": 126000,
    "val": 12103,
    "test": 12103,
    "materialization_unique": 144579
  },
  "per_class": {
    "Benign": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "BruteForce": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "DoS": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "DDoS": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "Bot": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "Infiltration": {
      "candidate_pool": 24000,
      "train_real": 20000,
      "train_target": 20000,
      "val": 2000,
      "test": 2000,
      "oversampled_train_references": 0
    },
    "WebBased": {
      "native_pool": 412,
      "cicids2017_train_only_pool": 167,
      "train_native_real": 206,
      "train_cicids2017_real": 167,
      "train_real": 373,
      "train_target": 6000,
      "val": 103,
      "test": 103,
      "oversampled_train_references": 5627
    }
  },
  "leakage_guards": {
    "cicids2017_in_val": 0,
    "cicids2017_in_test": 0,
    "real_candidate_cross_split_identity_overlap": 0
  }
}
```
