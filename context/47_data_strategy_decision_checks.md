# Data Strategy Decision Checks

Generated: `2026-07-04`

## Source Instructions

Checks were performed from:

```text
context/data-strategy-decision.md
```

The file asked whether WebBased/BruteForce scarcity should be handled by external data or by accepting heavier oversampling. Its recommendation was to run a MAC-filter audit first, because the scarcity might be artificial.

## Check Implemented

Added:

```text
secureedge/data/mac_filter_audit.py
```

The audit streams selected PCAP flows and records:

- total flows examined
- current attacker-MAC filter keep/drop decisions
- keep fraction by class and subtype
- top MAC pairs
- top kept pairs
- top dropped pairs
- attacker MAC hit counts

The script does not build graphs and does not write training data. It only audits filtering behavior.

## Command Run

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.mac_filter_audit \
  --max-flows-per-subtype 12000 \
  --max-files-per-subtype 3 \
  --report artifacts/mac_filter_audit.json
```

Full JSON report:

```text
artifacts/mac_filter_audit.json
```

Auto-generated context summary:

```text
context/46_data_strategy_mac_filter_audit.md
```

## Class-Level Result

```json
{
  "BruteForce": {
    "flows_examined": 11043,
    "kept": 2184,
    "dropped": 8859,
    "kept_fraction": 0.197772344471611
  },
  "DDoS": {
    "flows_examined": 36000,
    "kept": 35099,
    "dropped": 901,
    "kept_fraction": 0.9749722222222222
  },
  "WebBased": {
    "flows_examined": 25601,
    "kept": 4627,
    "dropped": 20974,
    "kept_fraction": 0.1807351275340807
  }
}
```

## Interpretation

The current attacker-MAC list works very well for the DDoS control sample:

```text
DDoS kept fraction: 97.5%
```

But it removes most audited WebBased and BruteForce flows:

```text
WebBased kept fraction:   18.1%
BruteForce kept fraction: 19.8%
```

This strongly supports the concern in `data-strategy-decision.md`: the current WebBased/BruteForce scarcity is mostly filter-induced, not proof that the source PCAPs lack data.

## Subtype-Level Evidence

WebBased examples:

```text
Backdoor_Malware: 244 / 3236 kept = 7.5%
BrowserHijacking: 972 / 4763 kept = 20.4%
CommandInjection: 275 / 5470 kept = 5.0%
SqlInjection: 2830 / 6243 kept = 45.3%
Uploading_Attack: 84 / 1619 kept = 5.2%
XSS: 222 / 4270 kept = 5.2%
```

BruteForce:

```text
DictionaryBruteForce: 2184 / 11043 kept = 19.8%
```

DDoS controls:

```text
DDoS-HTTP_Flood: 11228 / 12000 kept = 93.6%
DDoS-SYN_Flood: 11993 / 12000 kept = 99.9%
DDoS-UDP_Flood: 11878 / 12000 kept = 99.0%
```

## Decision

Do not add external data yet.

Do not solve this by increasing oversampling.

The evidence points to a class-specific filtering problem. The next correction should be one of:

1. Expand/fix the attacker MAC list for WebBased and BruteForce if the missing attack-source MACs can be verified.
2. Apply class-conditional filtering:
   - use attacker-MAC filtering for classes where it is validated, such as DDoS/DoS/Mirai/Recon/Spoofing
   - use filename/subtype labeling for WebBased and BruteForce
   - keep benign filtering strict so attacker-involved benign flows are excluded

Option 2 is the more practical next step unless a verified class-specific MAC list is available.

## Current Dataset Status

The current graph artifacts still reflect the previous universal attacker-MAC filter and leakage-safe split:

```text
train: 160000
val:   27404
test:  27405
```

These artifacts are clean from exact train/val/test leakage, but WebBased and BruteForce remain underrepresented because of the universal attacker-MAC filter.

## Recommendation Before Next Training

Do not start a major new training run on the current artifacts if the goal is to maximize WebBased/BruteForce validity.

Recommended next action:

```text
Implement class-conditional filtering, regenerate preprocessing artifacts, rerun leakage audit, then train.
```

If training must proceed immediately for comparison, label it explicitly as:

```text
Run using universal attacker-MAC filter with known WebBased/BruteForce attrition.
```
