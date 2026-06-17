# SecureEdge — Implementation Fixes v2

> **Generated:** 2026-06-13
> **Reference:** Progress report after fixes v2026-06-13, current macro F1 = 0.871 vs target ≥ 0.97
> **Prerequisite:** fixes.md has been fully applied. NFStream is installed and temporal
> features are computed before sampling. All artifacts from the previous fix pass are
> stale and must be regenerated after applying these fixes.

This document covers the three remaining issues preventing the model from reaching the
0.97 macro F1 target. The issues from fixes.md are resolved. What remains is a
fundamental problem with how flows longer than 20 packets are handled, a training
data bias introduced by the PCAP prioritisation change, and a feature set that
excludes discriminative fields it should include.

---

## 0. Summary of Remaining Issues

| # | Issue | Severity | Effect on results |
|---|---|---|---|
| 1 | 20-packet cap is a discard filter, not a flow window | **Critical** | Loses data, statistics computed over wrong packet window, weakens temporal features |
| 2 | Class reservoir fills from one sub-type per PCAP, biasing training | **Critical** | DDoS F1 is artificially inflated; Mirai, Spoofing, WebBased underperform |
| 3 | Port numbers and protocol excluded from model features | **Moderate** | Loses destination-port and protocol signals that are in XG-NID's feature set |

**Expected macro F1 after all fixes:** 0.93–0.96. WebBased and BruteForce will
remain the weakest classes until packet payload features are added in the graph phase,
but all other classes should exceed 0.90 and the overall macro F1 should approach the
target closely.

---

## Fix 1 — 20-packet Cap Must Be a Flow Window, Not a Discard Filter (Critical)

### What XG-NID actually does

The XG-NID paper states: *"we set a maximum limit of 20 packets per flow. The
decision to limit the flow to 20 packets is driven by our objective to enable
real-time inference; allowing flows to accumulate based on default parameters could
result in flow durations of up to 30 minutes."*

The word *limit* here means the flow is **closed and emitted after the 20th packet
arrives**, and any further packets from the same five-tuple start a new flow record.
A 10-minute DDoS flood that contains 50,000 packets becomes 2,500 separate 20-packet
flow records. Each record's statistics — duration, IAT values, byte counts, flag
ratios — are computed over exactly its 20 packets.

### What the current implementation does and why it is wrong

NFStream is allowed to run until a flow reaches its natural end via idle timeout or
active timeout. It then computes all statistics over the complete flow. A
post-processing filter discards any flow whose `bidirectional_packets > 20`.

This is wrong in three independent ways.

**It loses data.** A DDoS flood that runs for 10 minutes produces one or a few
long-lived NFStream flows. All of them are discarded by the post-filter. XG-NID
would have produced thousands of 20-packet records from the same traffic. The current
approach silently throws away the majority of useful long-running attack traffic.

**The surviving flows have wrong statistics.** The post-filter does not give you
"statistics over the first 20 packets of a session." It gives you "statistics over
sessions that happened to terminate within 20 packets." A flow ending at 18 packets
has correct statistics over 18 packets. But a 200-packet session, had it been allowed
to complete, would produce an NFStream record with duration, IAT, and byte statistics
computed over all 200 packets. Discarding that record does not retroactively produce
a record with statistics over the first 20 packets — that record was never created.

**The temporal feature signal is severely degraded.** With natural flow completion, a
10-minute DDoS SYN flood might produce only one or two long-lived NFStream flows from
the entire capture before the idle timeout. The temporal extractor advances its window
by one or two steps. The `Rolling_SYN_Sum` reflects one or two flows, not thousands,
so it looks nearly the same as Benign. With proper 20-packet windowing, the same
attack produces 2,500 flow records, advancing the temporal window 2,500 times and
building up the high `Rolling_SYN_Sum` values that make DDoS clearly anomalous.
Fix 1 therefore also strengthens the temporal feature signal that Fix 2 from the
previous pass was designed to provide.

### The fix: NFStream plugin to close flows at 20 packets

NFStream 6.x supports custom plugins via the `NFPlugin` class. A plugin's
`on_update` method is called every time a new packet is associated with a flow. If
the plugin sets `flow.expiration_id = -1`, NFStream immediately expires that flow,
emits the completed record, and starts a fresh flow entry for subsequent packets on
the same five-tuple.

The entire fix is a short plugin class added to `secureedge/data/pcap_flows.py`:

```
CLASS FlowCapper (extends NFPlugin):

    METHOD on_update(packet, flow):
        IF flow.bidirectional_packets >= 20:
            SET flow.expiration_id = -1
            # NFStream will emit this flow immediately after on_update returns
            # and will start a new entry for the next packet on the same 5-tuple
```

Pass this plugin when constructing the NFStreamer:

```
NFStreamer(
    source               = pcap_path,
    statistical_analysis = True,
    splt_analysis        = 0,
    n_dissections        = 0,
    idle_timeout         = 120,
    active_timeout       = 1800,
    plugins              = [FlowCapper()]
)
```

With this plugin active, NFStream will never emit a flow with more than 20 packets.
Every emitted flow has statistics computed over at most 20 packets. This matches
XG-NID's behaviour exactly.

### Remove the post-filter

The post-processing line that discards flows with `bidirectional_packets > 20` must
be removed from `pcap_flows.py` and `preprocess.py`. With the plugin active, no flow
exceeding 20 packets will ever reach that filter. Keeping the filter is harmless but
misleading — remove it so the intent is clear.

### Expected data volume change

Before Fix 1, long-running attack sessions were discarded. After Fix 1, each session
generates many 20-packet sub-flow records. The raw usable flow counts per class
should increase substantially for flood-type attacks:

- **DDoS and DoS:** flood traffic runs continuously for many seconds. Expect a large
  increase in raw flow count. The reservoir fills faster from each PCAP, meaning
  less total PCAP reading time.
- **Mirai:** scanning probes tend to be short-lived (a few packets each). Flow count
  increase may be modest.
- **BruteForce:** each login attempt is a short session. Moderate count increase.
- **WebBased:** HTTP requests vary. Some application-layer attacks have longer sessions
  that will now be windowed.

### Verification checkpoint for Fix 1

After running preprocessing with Fix 1 applied, before proceeding to training:

1. Print the maximum `bidirectional_packets` value across all records in
   `train_standard.csv`. It must be `20` or less. If any value exceeds 20, the
   plugin is not active or `expiration_id` assignment is not working.

2. Print the raw usable flow count per class before the 20,000 training cap is
   applied. DDoS and DoS counts should be substantially higher than the previous
   run's values of 25,000. If counts are unchanged, NFStream is not splitting
   long flows.

3. Print `Rolling_SYN_Sum` mean per class. With many more DDoS sub-flows advancing
   the temporal window per PCAP, the DDoS mean should be higher than the current
   5,280. Benign should remain near its current 18.97.

---

## Fix 2 — Replace Class-Level Reservoir with Per-Subtype Reservoir (Critical)

### Why the current reservoir produces a biased model

After the PCAP prioritisation change in the previous fix pass, the DDoS reservoir
is filled from `DDoS-SYN_Flood1.pcap` first. Once the DDoS class reservoir reaches
its limit (approximately 25,000 samples), all remaining DDoS PCAPs are skipped:

```
DDoS-SYN_Flood1.pcap        → fills reservoir → reservoir full
DDoS-ACK_Fragmentation1.pcap → skipped
DDoS-HTTP_Flood-.pcap        → skipped
DDoS-ICMP_Flood1.pcap        → skipped
... nine other DDoS sub-types → all skipped
```

The DDoS training set is almost entirely SYN flood samples. The DDoS test set has
the same bias. The reported DDoS F1 of 0.9979 does not measure whether the model
can detect DDoS attacks — it measures whether the model can detect SYN floods when
trained and evaluated on SYN floods. In real deployment, the model would encounter
ICMP floods, UDP floods, HTTP floods, ACK fragmentation, SlowLoris, and nine other
DDoS variants it has almost never seen.

The same problem affects every multi-subtype class:

- **Mirai (3 sub-types, 21,792 total flows):** barely enough for all three to be
  represented. One sub-type will dominate if reservoir filling is not subtype-aware.
- **Spoofing (2 sub-types):** DNS_Spoofing and MITM-ArpSpoofing have different flow
  characteristics. Both must appear in training.
- **Recon (5 sub-types):** HostDiscovery, OSScan, PingSweep, PortScan, and
  VulnerabilityScan each have distinctive patterns the model needs to see.
- **WebBased (6 sub-types):** SQL injection, XSS, BrowserHijacking, CommandInjection,
  Uploading_Attack, and Backdoor_Malware all look different at the flow level.
  Currently, training may be dominated by whichever WebBased PCAP is processed first.

### The fix: two-level reservoir with proportional subtype allocation

Replace the single class-level reservoir with a two-level structure.

**Level 1 — Subtype reservoirs:** each of the 33 attack sub-types plus Benign gets
its own bounded reservoir. Fill it from the corresponding PCAP file until the
per-subtype target is reached, then stop.

**Level 2 — Class aggregation:** after all subtype reservoirs are filled, merge the
sub-types belonging to each class into a class pool. Oversample if any sub-type came
up short, then split into train and test.

### Per-subtype target calculation

The total samples needed per class is 24,000 (20,000 train + 4,000 test). The
per-subtype target is the ceiling of this divided by the number of sub-types in
the class:

```
Class          Sub-types    Per-subtype target    Class total
-----------    ---------    ------------------    -----------
DDoS              12              2,000             24,000
DoS                4              6,000             24,000
Mirai              3              8,000             24,000
Recon              5              4,800             24,000
Spoofing           2             12,000             24,000
WebBased           6              4,000             24,000
BruteForce         1             24,000             24,000
Benign             1             24,000             24,000
```

For sub-types where fewer flows are available than the per-subtype target (e.g.,
DictionaryBruteForce had only 5,365 usable flows), take all available flows and
compensate at the class aggregation stage with oversampling to reach the class total.

### Changes to `config.py`

Add a `SUBTYPE_TO_CLASS` dictionary mapping every sub-type name to its canonical
class. The sub-type name is inferred from the PCAP filename by stripping the
trailing digit and extension:

```
SUBTYPE_TO_CLASS = {
    # DDoS — 12 sub-types
    "DDoS-ACK_Fragmentation":  "DDoS",
    "DDoS-HTTP_Flood":         "DDoS",
    "DDoS-ICMP_Flood":         "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-PSHACK_Flood":       "DDoS",
    "DDoS-RSTFINFlood":        "DDoS",
    "DDoS-SYN_Flood":          "DDoS",
    "DDoS-SlowLoris":          "DDoS",
    "DDoS-SynonymousIP_Flood": "DDoS",
    "DDoS-TCP_Flood":          "DDoS",
    "DDoS-UDP_Flood":          "DDoS",
    "DDoS-UDP_Fragmentation":  "DDoS",

    # DoS — 4 sub-types
    "DoS-HTTP_Flood":  "DoS",
    "DoS-SYN_Flood":   "DoS",
    "DoS-TCP_Flood":   "DoS",
    "DoS-UDP_Flood":   "DoS",

    # Mirai — 3 sub-types
    "Mirai-greeth_flood": "Mirai",
    "Mirai-greip_flood":  "Mirai",
    "Mirai-udpplain":     "Mirai",

    # Recon — 5 sub-types
    "Recon-HostDiscovery": "Recon",
    "Recon-OSScan":        "Recon",
    "Recon-PingSweep":     "Recon",
    "Recon-PortScan":      "Recon",
    "VulnerabilityScan":   "Recon",

    # Spoofing — 2 sub-types
    "DNS_Spoofing":    "Spoofing",
    "MITM-ArpSpoofing": "Spoofing",

    # WebBased — 6 sub-types
    "SqlInjection":    "WebBased",
    "XSS":             "WebBased",
    "BrowserHijacking": "WebBased",
    "CommandInjection": "WebBased",
    "Uploading_Attack": "WebBased",
    "Backdoor_Malware": "WebBased",

    # BruteForce — 1 sub-type
    "DictionaryBruteForce": "BruteForce",

    # Benign — 1 sub-type
    "Benign_Final": "Benign",
}
```

The sub-type name is extracted from the PCAP filename using the following rule:
strip all trailing digits and the `.pcap` extension, then strip any remaining
trailing hyphens or underscores. For example:
- `DDoS-SYN_Flood1.pcap` → `DDoS-SYN_Flood`
- `Mirai-greeth_flood1.pcap` → `Mirai-greeth_flood`
- `VulnerabilityScan.pcap` → `VulnerabilityScan`
- `DNS_Spoofing1.pcap` → `DNS_Spoofing`

### Changes to `preprocess.py`

Replace the current class-level reservoir logic with the following two-level
procedure:

```
PROCEDURE build_subtype_reservoirs(all_pcap_files):

    subtype_reservoirs = {subtype: [] for subtype in SUBTYPE_TO_CLASS}

    FOR each pcap_file in all_pcap_files (in natural order — no priority ordering):
        subtype = extract_subtype_from_filename(pcap_file)
        class   = SUBTYPE_TO_CLASS[subtype]

        per_subtype_target = ceil(24000 / num_subtypes_in_class(class))

        IF len(subtype_reservoirs[subtype]) >= per_subtype_target:
            SKIP this PCAP

        FOR each enriched_flow from NFStream(pcap_file) [with temporal features]:
            IF len(subtype_reservoirs[subtype]) < per_subtype_target:
                ADD enriched_flow to subtype_reservoirs[subtype]
            ELSE:
                STOP reading this PCAP

    RETURN subtype_reservoirs


PROCEDURE build_class_pools(subtype_reservoirs):

    class_pools = {}

    FOR each class in CANONICAL_CLASSES:
        subtypes = [s for s in SUBTYPE_TO_CLASS if SUBTYPE_TO_CLASS[s] == class]
        merged   = concatenate subtype_reservoirs[s] for s in subtypes

        IF len(merged) < 24000:
            merged = oversample(merged, target=24000)
        ELIF len(merged) > 24000:
            merged = random_subsample(merged, n=24000)

        class_pools[class] = merged

    RETURN class_pools


PROCEDURE split_and_save(class_pools):

    FOR each class, pool in class_pools:
        shuffle pool
        test  = pool[:4000]
        train = pool[4000:24000]   # 20,000 samples

    save train rows → train_standard.csv
    save test rows  → test_standard.csv
```

### Revert the PCAP discovery priority ordering

The `discover_pcap_files()` function was modified in the previous fix pass to
process `DDoS-SYN_Flood1.pcap` and `DoS-SYN_Flood1.pcap` before other PCAPs.
This priority must be reverted. With per-subtype reservoirs, all sub-types get
their own capped reservoir, so processing order within a class no longer matters.

Return `discover_pcap_files()` to natural filesystem order or alphabetical order.
Remove any special-case sorting by filename.

### Temporal extractor behaviour with per-subtype reservoirs

The temporal extractor is already reset between PCAP files. Per-subtype reservoirs
do not change this behaviour. Each PCAP gets its own temporal extractor state, and
the 375-flow window reflects the real traffic density within that specific capture.
A DDoS-HTTP_Flood PCAP will produce high `Rolling_http_port` values. A DDoS-SYN_Flood
PCAP will produce high `Rolling_SYN_Sum` values. Both sets of enriched records go
into the DDoS class pool, and the model learns to recognise both temporal patterns.

### Verification checkpoint for Fix 2

After preprocessing with Fix 2 applied:

1. Print the `subtype_label` distribution within the DDoS class in
   `train_standard.csv`. All 12 DDoS sub-type names must appear. No single sub-type
   should account for more than approximately 13% (2,000 / 16,000 DDoS train
   records) of DDoS training samples. If one sub-type accounts for more than 80%,
   the per-subtype reservoir logic is not working.

2. Confirm `subtype_label` diversity for Mirai (3 sub-types), Spoofing (2), Recon
   (5 including VulnerabilityScan), and WebBased (6 including Backdoor_Malware).

3. Confirm total row counts remain: `train_standard.csv` = 160,000 rows,
   `test_standard.csv` = 32,000 rows.

4. For BruteForce, confirm 100% of training rows have `subtype_label` of
   `DictionaryBruteForce` — this is correct since BruteForce has only one sub-type.

---

## Fix 3 — Include Port Numbers and Protocol in Model Features (Moderate)

### Why these fields are currently excluded but should be included

`dst_port`, `src_port`, and `protocol` are currently in `NFSTREAM_METADATA_COLUMNS`
and are therefore excluded from the model input features. They are used internally by
the temporal extractor (via `nfstream_to_temporal_dict`) but do not appear in the
feature vector passed to the MLP.

This exclusion is incorrect. These three fields are discriminative features included
in CICFlowMeter's 80-feature output, in the CIC-IoT2023 CSV's 47-feature export, and
almost certainly in the 76 features reported by XG-NID. The distinction between
"flow identifier metadata" (IP addresses, MAC addresses, timestamps) and "flow
characteristic features" (ports, protocol, statistics) is clear: IP addresses and
timestamps should not be features because they identify the specific source and
destination, which would not generalise. Port numbers and protocol are characteristics
of the communication type, not the specific endpoints.

**Why each field matters:**

- `dst_port`: DDoS-HTTP_Flood targets port 80. DNS_Spoofing targets port 53.
  Recon-PortScan sweeps many ports. The destination port is one of the strongest
  single discriminating features available at the flow level.

- `protocol`: UDP-based attacks (DDoS-UDP_Flood, DoS-UDP_Flood) use protocol 17.
  TCP floods use protocol 6. ICMP attacks use protocol 1. Without protocol in the
  feature vector, the model must infer it from indirect signals like flag counts,
  which is harder and less reliable.

- `src_port`: Port-scanning attacks use sequential or random source ports. Brute
  force attacks repeatedly contact a fixed destination port from varied source ports.
  Benign traffic shows a different source-port distribution. This is signal the
  model should not have to rediscover indirectly.

### The fix

In `config.py`, remove `src_port`, `dst_port`, and `protocol` from
`NFSTREAM_METADATA_COLUMNS`.

Ensure they are extracted as numerical values (not strings) and included in the
per-flow feature dictionary that is passed to the scaler and stored in
`train_standard.csv`. They should appear in `feature_columns.json` after this fix.

Update `N_FLOW_FEATURES` and `INPUT_DIM` in `config.py` to reflect the addition:

```
N_FLOW_FEATURES:  57 → 60
INPUT_DIM:        73 → 76
```

Note: if Fix 3 is applied alongside any change in active/idle statistics (see below),
the final count will differ. Use the actual count from the live NFStream output.

### Check for active and idle time statistics

NFStream 6.x with `statistical_analysis=True` computes active and idle time
statistics for flows that contain bursts of activity separated by idle gaps. These
fields appear with the words `active` or `idle` in their names:

```
bidirectional_mean_active_ms
bidirectional_std_active_ms
bidirectional_max_active_ms
bidirectional_min_active_ms
bidirectional_mean_idle_ms
bidirectional_std_idle_ms
bidirectional_max_idle_ms
bidirectional_min_idle_ms
```

These 8 fields are included in CICFlowMeter and are likely part of XG-NID's 76
features. They are particularly useful for attacks with distinctive pause-and-burst
patterns such as DDoS-SlowLoris and for distinguishing scanning (bursty) from
continuous flooding (no idle periods).

Run this diagnostic to check whether NFStream 6.6.0 includes these fields:

```
PROCEDURE check_active_idle_fields():
    Stream one small PCAP file through NFStreamer
    Print all field names from one emitted flow object
    Filter for names containing "active" or "idle"
    If found:
        Confirm they are NOT listed in NFSTREAM_METADATA_COLUMNS
        Confirm they are being included in the model feature set
        Note: for short flows with no idle period, these fields may be NaN or 0.
              Fill NaN with 0 — a flow with no idle period has idle statistics of 0,
              which is meaningful, not missing.
    If not found:
        NFStream 6.6.0 does not compute these under the current settings.
        Document this as a known difference from XG-NID and proceed without them.
```

If active/idle fields are present, include them. The updated feature count would be:

```
N_FLOW_FEATURES:  57 + 3 (ports/protocol) + 8 (active/idle) = 68
INPUT_DIM:        68 + 16 temporal = 84
```

If directional variants also exist (`src2dst_mean_active_ms`, `dst2src_mean_idle_ms`,
etc.), include those too and update the count accordingly. Whatever the live NFStream
output produces for a given PCAP, that count is the correct `N_FLOW_FEATURES`.

### Verification checkpoint for Fix 3

1. Confirm `dst_port`, `src_port`, and `protocol` appear as column names in
   `feature_columns.json` after regeneration.

2. Confirm `N_FLOW_FEATURES` in `config.py` equals the actual count of NFStream
   statistic fields plus the three newly included identifier fields (plus any
   active/idle fields if present).

3. Confirm `INPUT_DIM` equals `N_FLOW_FEATURES + 16`.

4. Instantiate `SecureEdgeMLP()` with no arguments and confirm that
   `model.net[0].in_features == INPUT_DIM`. This verifies the architecture is
   aligned with the config.

---

## Complete Artifact Regeneration Sequence

Apply all three fixes before regenerating any artifact. Running intermediate steps
with only some fixes in place will require re-deletion and re-generation.

### Step 1 — Delete all stale artifacts

```
data/processed/train_standard.csv
data/processed/test_standard.csv
data/processed/train_features.csv
data/processed/test_features.csv
artifacts/standard_scaler.joblib
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
artifacts/best_model.pt
artifacts/metrics.json
artifacts/ood_threshold.json
artifacts/secureedge_model.ts
```

### Step 2 — Verify FlowCapper is active before full preprocessing

Stream one small PCAP file with the FlowCapper plugin active and print the
`bidirectional_packets` value of every emitted flow. All values must be ≤ 20.
Confirm that a session with many packets (e.g., from any DDoS PCAP) now emits
multiple flow records rather than one long record.

### Step 3 — Run Phase 2 preprocessing

```
python -m secureedge.data.preprocess
```

This run incorporates all three fixes: FlowCapper plugin (Fix 1), per-subtype
reservoir management (Fix 2), and port/protocol inclusion (Fix 3). Generates:

```
data/processed/train_standard.csv
data/processed/test_standard.csv
artifacts/standard_scaler.joblib
context/02_preprocessing.md
```

Run all three verification checkpoints before proceeding.

### Step 4 — Run Phase 3 feature pipeline

```
python -m secureedge.features.pipeline
```

Scales the updated feature set. Generates:

```
data/processed/train_features.csv
data/processed/test_features.csv
artifacts/feature_scaler.joblib
artifacts/feature_columns.json
context/03_feature_engineering.md
```

Confirm `feature_columns.json` contains the expected number of entries, that all
16 temporal column names are present, and that `dst_port`, `src_port`, and
`protocol` are among the columns.

### Step 5 — Run Phase 5 training

```
python -m secureedge.models.train
```

All hyperparameters remain unchanged:
- Adam, lr warmup 1e-4 → 1e-3, weight decay 1e-5
- ReduceLROnPlateau, scheduler patience 5, min lr 1e-6
- Batch size 1024, max 200 epochs, early stopping patience 20
- Gradient clipping max norm 1.0

With the 20-packet windowing fix generating more sub-flow records from long attack
sessions, and with all sub-types now represented in each class, the model should
converge to a higher plateau. Expect fewer epochs to reach a good validation F1
compared to the previous run (which took 142 epochs), because the feature quality
is substantially higher.

### Step 6 — Run Phase 6 evaluation

```
python -m secureedge.models.evaluate
```

In addition to the standard macro F1 report, generate a per-subtype breakdown for
the DDoS class: for each of the 12 DDoS sub-types present in the test set, report
the prediction distribution. All 12 sub-types should predict DDoS at a high rate.
If any sub-type (e.g., DDoS-SlowLoris or DDoS-HTTP_Flood) is confused with DoS or
Benign at a high rate, that sub-type needs more training representation.

### Step 7 — Run Phase 7 OOD calibration

```
python -m secureedge.ood.detector
```

Recalibrate the MSP threshold on the new model. The threshold will shift again
because the new model has different confidence profiles.

### Step 8 — Run Phase 8 TorchScript export

```
python -m secureedge.export.export
```

The dummy input tensor must have shape `(1, INPUT_DIM)` using the updated value
from `config.py`. Confirm `export.py` reads `INPUT_DIM` from config rather than
hardcoding a tensor shape.

---

## Expected Per-Class Results After All Fixes

These are estimates based on the nature of each fix. Actual values depend on PCAP
content and sub-type flow availability.

| Class | Before fixes | After fixes | Explanation |
|---|---|---|---|
| DDoS | 0.9979 | 0.97–0.99 | May adjust slightly as all 12 sub-types are tested; should remain very high |
| DoS | 0.9193 | 0.96–0.98 | 20-packet windowing generates more sub-flows with accurate statistics |
| Mirai | 0.8529 | 0.93–0.96 | All 3 sub-types now proportionally represented in training |
| Recon | 0.9888 | 0.98–0.99 | Already strong; all 5 sub-types including VulnerabilityScan now covered |
| Benign | 0.8803 | 0.92–0.95 | Better temporal context from proper sub-flow windowing |
| Spoofing | 0.8688 | 0.92–0.95 | Both DNS_Spoofing and MITM-ArpSpoofing now in training |
| WebBased | 0.7134 | 0.77–0.83 | All 6 sub-types represented; ceiling limited without packet payload |
| BruteForce | 0.7461 | 0.80–0.87 | Improved temporal patterns from proper windowing; ceiling without payload |
| **Macro F1** | **0.871** | **0.93–0.96** | |

WebBased and BruteForce will remain the weakest classes. The 0.94 payload-specific
F1 in XG-NID Table 5 reflects packet-level payload inspection unavailable to the
current MLP. The ceiling for the flow-only approach is approximately 0.94–0.96
overall. Crossing 0.97 requires the graph-based phase with packet payload nodes.

---

## Diagnosis Guide — If Results Remain Below Target After All Fixes

### If DDoS F1 drops significantly below 0.95 after Fix 2

A modest drop from 0.9979 to 0.97–0.98 is expected — the previous metric was
inflated by single-subtype bias. A drop below 0.93 indicates some DDoS sub-types
have too few samples after the 2,000-per-subtype allocation. Print the per-subtype
test count for DDoS and the per-subtype F1. If one sub-type (e.g., DDoS-SlowLoris,
which generates short flows with distinctive slow-send patterns) consistently fails,
that sub-type needs more training samples or a lower per-subtype training target
with compensating oversampling.

### If Mirai does not improve above 0.89

Mirai had only 21,792 total usable flows across 3 sub-types. With Fix 1, more
Mirai sub-flows should be generated from each capture. If the count increase is
small (because Mirai scanning probes are already short), the 8,000-per-subtype
target may be unachievable for some sub-types. Check the raw available count per
Mirai sub-type after preprocessing. If one sub-type has fewer than 4,000 flows
available (meaning even the test set cannot be fully populated from real data),
document this as a data limitation rather than a pipeline error.

### If the `Rolling_SYN_Sum` diagnostic for DDoS is lower than expected after Fix 1

With 20-packet windowing, each DDoS flood session generates many sub-flows that
advance the temporal window. If `Rolling_SYN_Sum` for DDoS is not significantly
higher than the current 5,280, the FlowCapper plugin may not be splitting long
sessions. Confirm by printing the `bidirectional_packets` distribution in
`train_standard.csv`. If the maximum is still well above 20 for some records, the
plugin is not being applied during the relevant PCAP reads.

### If WebBased or BruteForce F1 is below 0.75 after all fixes

These classes are fundamentally limited without packet payload features. If WebBased
drops below 0.75, check the sub-type distribution: Backdoor_Malware in particular
may produce flow-level characteristics that look identical to Benign (the malware
communicates over normal-looking HTTPS sessions). A Backdoor_Malware F1 below 0.50
is expected and should be documented as a payload-dependent limitation, not a
pipeline error. If SQL injection and XSS are also below 0.70, check the WebBased
temporal features: HTTP-targeting attacks should show elevated `Rolling_http_port`
values.
