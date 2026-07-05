# SecureEdge — XG-NID Parity Fix Plan (for the Coding Agent)

> **Generated:** 2026-06-24
> **Source:** Deep comparison `XGNID-mine.md` + prior codebase audit
> **Baseline to beat:** macro F1 = 0.8966 (Run 10)
> **Two hard constraints from the project owner:**
> 1. **KEEP all 92 flow features.** Do NOT revert to XG-NID's 82. No 82-feature mode is required.
> 2. **KEEP batch size 512.** Do NOT change it. (Batch 64 was already tested in Runs 7–8 and was worse.)

---

## 0. Reconciling Two Diagnoses (read first)

Two separate analyses now exist. They point in different directions, and the coding
agent must understand why the order below is what it is.

**Prior codebase audit** said the primary cause was the payload path (raw bytes into a
linear GAT projection) and the averaged readout.

**The new XG-NID comparison** says the primary cause is **data parity** — specifically
label noise from PCAP-filename labeling instead of attacker-MAC filtering, plus a
possible 20-packet window mismatch — with the averaged-vs-concatenated readout as a
secondary architecture issue.

**The comparison is more likely correct about the primary cause, and here is the
reasoning:** XG-NID reaches 97% while feeding the *same* raw 1,500-byte packet vectors
into a SAGEConv layer (also a linear projection of node features) and concatenating the
pooled embeddings. If a linear projection of raw bytes were the fundamental blocker,
XG-NID could not reach 97% either. That it does means the raw-byte representation is
*sufficient on this dataset* when (a) the labels are clean and (b) the two modalities
are concatenated, not averaged. So label noise and pooling move ahead of the payload
encoder in priority. The payload encoder stays on the list as a later enhancement, not
the first move.

**Order of work:** fix data parity first (Tier 1), then the cheap architecture changes
(Tier 2), then optional experiments (Tier 3). Do not tune hyperparameters — Runs 1–10
already proved they are not the bottleneck, and the two constraints above lock the two
parameters most often mistuned.

---

## 1. Tier 1 — Data Parity (do first; requires dataset regeneration)

### Fix 1 — Attacker-MAC Filtering (highest expected impact)

**Objective.** Stop labeling every flow in an attack PCAP as that attack. Keep a flow
as an attack sample only if it actually involves the attacker device.

**Why this is real here (not hypothetical).** The current pipeline
(`preprocess.py` → `subtype_from_pcap`) assigns the class purely from the PCAP
filename. `config.py`'s `NFSTREAM_METADATA_COLUMNS` already lists `src_mac`, `dst_mac`,
`src_oui`, `dst_oui` — NFStream is extracting MACs and the pipeline is throwing them
away. An earlier methodology note argued MAC filtering was unnecessary, but that note
assumed the *pre-labeled CSV* workflow. The final pipeline processes *raw PCAPs*, so
that reasoning does not apply and the filtering was never added. This is a genuine gap.

**Impact target.** Background, DNS, scanning, and benign device flows currently
mislabeled inside attack PCAPs are the most plausible reason WebBased, Recon, Spoofing,
and Benign lag while DoS/Mirai (whose PCAPs are almost pure attack traffic) score 0.98.

**Files to touch.** `secureedge/data/extract_worker.py` (or wherever the NFStream flow
loop emits records), `secureedge/config.py`, `secureedge/data/preprocess.py`.

**Implementation steps.**
1. Obtain the CIC-IoT2023 attacker device MAC address list from the official dataset
   documentation. Add it to `config.py`:
   ```python
   ATTACKER_MACS = { "aa:bb:cc:...", ... }   # normalize to lowercase, colon-separated
   BENIGN_ONLY_ENFORCE = True                 # gate the filter so it can be toggled
   ```
2. In the NFStream flow loop, read `flow.src_mac` and `flow.dst_mac` (normalize case
   and separators to match `ATTACKER_MACS`).
3. Apply per-PCAP-type filtering:
   - **Attack PCAP** (class != Benign): keep the flow only if
     `src_mac ∈ ATTACKER_MACS or dst_mac ∈ ATTACKER_MACS`. Drop all others.
   - **Benign PCAP**: keep the flow only if
     `src_mac ∉ ATTACKER_MACS and dst_mac ∉ ATTACKER_MACS`. Drop any attacker-involved
     flow that leaked into the benign capture.
4. Log, per PCAP, how many flows were kept vs dropped. A healthy attack PCAP should
   retain most of its high-rate flows and drop background noise; if it drops ~everything
   or ~nothing, the MAC list or field parsing is wrong — stop and inspect.
5. Regenerate reservoirs → balanced pool → graphs → shards. The 20k/4k balanced split
   and 92-feature layout are unchanged.

**Guardrails.**
- If a PCAP has no L2/MAC info (rare for CIC-IoT2023 Ethernet captures), skip filtering
  for that file and log a warning rather than dropping everything.
- Verify a MAC is actually present on a sample flow before trusting the filter; print
  `src_mac/dst_mac` for the first 5 flows of one attack PCAP.

**Regeneration required:** YES (full).

---

### Fix 2 — 20-Packet Window Consistency (verify, then enforce if needed)

**Objective.** Ensure the flow-node statistics and the packet nodes describe the *same*
≤20-packet window, so the graph is internally consistent.

**Current state to verify first.** `FlowCapper` sets `flow.expiration_id = -1` at
`bidirectional_packets >= 20`, and `PacketCapture` records up to 20 packets. Because
both cap at 20 in the same NFStream pass, the flow may already be consistent. **Do not
change anything until you confirm the mismatch exists.**

**Verification.** For a handful of long flows, print: (a) the packet count the flow-node
statistics were computed over, and (b) the number of packet nodes. If (a) > (b) — i.e.
stats were computed over a longer flow than the 20 captured packets — the mismatch the
comparison describes is real and Fix 2 applies. If (a) ≈ (b) ≤ 20, FlowCapper already
handles it and Fix 2 is a no-op; record that and move on.

**If the mismatch is confirmed — enforce subflow segmentation.** Match XG-NID: split
each long flow into consecutive 20-packet subflows, recompute flow statistics *per
subflow*, and build one graph per subflow from that subflow's own 20 packets. Do not
pair full-flow statistics with a truncated first-20 packet set.

**Files to touch.** `secureedge/data/extract_worker.py`, `secureedge/data/pcap_flows.py`,
`secureedge/data/graph_builder.py`.

**Regeneration required:** YES, only if the mismatch is confirmed.

---

## 2. Tier 2 — Architecture (cheap, no regeneration; do after Tier 1)

### Fix 3 — Concatenate Flow and Packet Embeddings (replace averaging)

**Both analyses agree on this and XG-NID uses concatenation.**

**Change in `secureedge/models/hgnn.py`:**
```python
# OLD
graph_embedding = (flow_pooled + packet_pooled) / 2.0        # [B, 64]
self.classifier = nn.Sequential(
    nn.Linear(64, 32), nn.ReLU(),
    nn.Linear(32, 16), nn.ReLU(),
    nn.Linear(16, 8),
)

# NEW
graph_embedding = torch.cat([flow_pooled, packet_pooled], dim=1)   # [B, 128]
self.classifier = nn.Sequential(
    nn.Linear(128, 64), nn.ReLU(),
    nn.Linear(64, 32),  nn.ReLU(),
    nn.Linear(32, 8),
)
```
Averaging forces a fixed 50/50 blend and halves the flow signal; concatenation lets the
classifier learn the weighting and preserves both modalities. Delete
`artifacts/best_hgnn.pt` before retraining (classifier dims changed).

**Regeneration required:** NO.

---

### Fix 4 — Pass Edge Attributes Through conv2

`conv1` uses `edge_dim` and receives `edge_attr`; `conv2` does not, so inter-packet
timing (the SlowLoris signature) only reaches layer 1. Give `conv2` the same `edge_dim`
arguments as `conv1` and pass `edge_attr_dict` in the `conv2` call. Small, cheap
correctness fix.

**Regeneration required:** NO.

---

## 3. Tier 3 — Optional Diagnostics (only if Tier 1+2 still short of target)

### Fix 5 — SAGEConv Comparison Arm

The public XG-NID defaults to SAGEConv, not GAT. Build a parallel
`SecureEdgeHGNN_SAGE` (HeteroConv over SAGEConv, mean aggregation, BatchNorm,
LeakyReLU, concat pooling, classifier 128→64→16→8) as a *comparison model*, not a
replacement. Run it against the edge-aware GAT on the same data to isolate whether the
GAT choice costs anything. Keep the edge-aware GAT as the primary model unless SAGE
clearly wins.

### Fix 6 — 1D-CNN Payload Encoder (enhancement, deferred)

Only pursue if, after Fixes 1–3, WebBased/BruteForce still lag. Add a small 1D-CNN that
turns each packet's 1,500-byte sequence into a compact embedding before the graph
layers (detects byte n-grams regardless of position). This is an *improvement over*
XG-NID, not a parity fix — it is deliberately last because XG-NID reaches 97% without
it.

---

## 4. Evaluation Correctness — Class-Index Remapping

SecureEdge and XG-NID use different class-index orders, so per-class F1 and confusion
matrices are not directly comparable.

| Index | XG-NID | SecureEdge |
|---|---|---|
| 0 | Benign | Benign |
| 1 | WebBased | DDoS |
| 2 | Spoofing | DoS |
| 3 | Recon | Mirai |
| 4 | Mirai | Recon |
| 5 | DoS | Spoofing |
| 6 | DDoS | WebBased |
| 7 | BruteForce | BruteForce |

**Do not renumber SecureEdge's classes** (that would churn the whole codebase). Instead,
add a reporting helper in `evaluate.py` that maps both systems onto a shared,
name-keyed order before printing per-class tables and confusion matrices, so comparisons
are by class *name*, never by raw index.

---

## 5. Ordered Experiment Protocol (one variable per run)

Keep batch 512, 92 features, cosine schedule, lr 0.003 constant across all runs (per the
constraints and prior evidence). Baseline: 0.8966.

| Run | Single change | Regen? | Tests |
|---|---|---|---|
| 11 | Fix 1 (attacker-MAC filtering) | YES | Is label noise the main gap? |
| 12 | Fix 2 (20-packet consistency) — only if mismatch confirmed | YES | Graph internal consistency |
| 13 | Fix 3 (concat readout) | NO | Modality preservation |
| 14 | Fix 4 (edge_attr in conv2) | NO | Timing-attack signal |
| 15 | Fix 5 (SAGE arm) / Fix 6 (CNN encoder) | NO | Architecture headroom |

**Decision rule after each run:**
- ≥ 0.97 → stop, target reached.
- improves prior best by ≥ 0.005 → keep the change, continue.
- within ±0.005 → revert (prefer the simpler pipeline), continue.
- worse by > 0.005 → revert, continue.

Log per-class F1 every 10 epochs. WebBased, Recon, Spoofing, and Benign are the
diagnostic classes for Fix 1 — if attacker-MAC filtering is working, those four rise
together while DoS/Mirai stay flat.

---

## 6. Honest Expectations

- **Fix 1** is the one most likely to produce a real jump, and it targets exactly the
  weak classes. A plausible outcome is those four classes rising several points each and
  macro F1 moving into the low-0.90s. It is not guaranteed — the size depends on how
  much background traffic actually contaminates each attack PCAP.
- **Fix 3** typically adds a smaller, steadier gain once labels are clean.
- Reaching **exactly 0.97** may still require the full 46.7M-flow corpus XG-NID used;
  our selective PCAPs (BruteForce ~one session, 54% oversample) impose a diversity
  ceiling no code change removes. Low-0.90s to mid-0.90s on this dataset would already
  be a strong, defensible result.
- Do not re-litigate learning rate, scheduler, batch size, or the 82-feature question —
  the first three are settled by Runs 1–10 and the constraints, and the feature count is
  fixed at 92 by decision.

---

## 7. Fixed Decisions (do not revisit)

- **92 flow features** — keep. No 82-feature mode.
- **Batch size 512** — keep. Batch 64 was worse (Runs 7–8).
- **lr 0.003 cosine** — keep. lr 0.01 was worse (Run 7).
- **`HGNN_LEAKY_RELU_SLOPE = 0.01`** — keep. Never set to 1.0 (would make the activation
  the identity function and collapse the model).
