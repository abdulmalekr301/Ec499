# Data Strategy MAC Filter Audit

Generated: `2026-07-04T21:54:11+00:00`

## Action
- Streamed selected PCAP flows to audit attacker-MAC filtering attrition.
- Counted current filter keep/drop decisions by subtype and class.
- Compared WebBased/BruteForce against representative DDoS subtypes.
- JSON report: `artifacts/mac_filter_audit_class_conditional.json`.

## Class Summary
```json
{
  "BruteForce": {
    "flows_examined": 11043,
    "kept": 11043,
    "dropped": 0,
    "kept_fraction": 1.0,
    "reasons": {
      "class_conditional_unfiltered": 11043
    }
  },
  "DDoS": {
    "flows_examined": 36000,
    "kept": 35099,
    "dropped": 901,
    "kept_fraction": 0.9749722222222222,
    "reasons": {
      "attack_background_dropped": 901,
      "attack_attacker_kept": 35099
    }
  },
  "WebBased": {
    "flows_examined": 25601,
    "kept": 25601,
    "dropped": 0,
    "kept_fraction": 1.0,
    "reasons": {
      "class_conditional_unfiltered": 25601
    }
  }
}
```

## Interpretation
Class-conditional filtering is active: WebBased/BruteForce are being retained by filename/subtype labeling while DDoS remains validated by attacker-MAC filtering.
