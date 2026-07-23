# Office Materialization — Second Diagnostic Round

> **Generated:** 2026-07-14
> **Context:** Follow-up to `office-materialization-memory-diagnosis.md`.
> The open-flow diagnostic refuted the concurrent-flow-count hypothesis. The
> bounded pilot with density-aware batching worked well, but surfaced a new
> finding (Infiltration payload flags) that needs resolving before scaling.

---

## 1. Timeout Hypothesis: Refuted, Correctly Not Acted On

`max_active_flows: 507`, with all 4,776 opened flows cleanly expired by scan
end. This does not support "too many concurrently-open flows" as the memory
driver. **Correct call not to change `active_timeout`/`idle_timeout`** on
this evidence — that would have been changing a setting that affects computed
flow features based on an unconfirmed cause.

---

## 2. Sharper Hypothesis: The Diagnostic Can't Rule Out a Cumulative Leak

The diagnostic is a lightweight packet-level approximation of NFStream's
open/expire bookkeeping — not real NFStream running its actual plugins
(`PacketCapture` retaining payload bytes per flow, `ActiveIdlePlugin`
accumulating statistics, full `statistical_analysis=True` computation). This
matters because a problem that scales with **cumulative flows processed**
rather than **concurrent flows held** would be invisible to this diagnostic
by construction — the lightweight simulation never runs the code path where
such a leak would exist.

This pattern fits the original failing runs better than the refuted
hypothesis does: memory floor exhaustion tracked with flows-scanned
(1,080 → 2,210 → 3,340 as the floor dropped from 8.0 → 7.5 → 6.5 GiB) —
consistent with something not being released as each flow is processed and
discarded, not with too much simultaneous state.

**Recommended next diagnostic:** run real NFStream, plugins included, on the
same problem PCAP (`capDESKTOP-AN3U28N-172.31.64.115`), without any
candidate-matching or graph-construction wrapper — just the raw extraction
call — and track process RSS at intervals over the scan.

```
IF RSS stays flat (like the lightweight diagnostic did):
    The leak is in the wrapper/candidate-matching/graph-construction code,
    not NFStream itself. Focus there.

IF RSS climbs with cumulative flows processed:
    The leak is in NFStream or its plugins — PacketCapture's payload
    retention is the most likely candidate, since it's the plugin that
    explicitly stores data (payload bytes) per flow rather than just
    computing statistics.
```

This isolates the actual leak location before any further fix is attempted,
rather than continuing to guess.

---

## 3. Bounded Pilot: Density-Aware Batching and Defer Handling Both Working

82 materialized vs. the prior run's 4 — a real, substantial improvement.
Evidence both fixes are working as intended:

- `UCAP172.31.69.15` and `UCAP172.31.69.7`: 40/40 candidates matched in under
  400 flows scanned each — density-aware batching is delivering exactly the
  efficiency gain it was designed for.
- Two PCAPs hit the memory floor and were **deferred**, not crashed — the
  scheduler continued and completed the requested PCAP budget regardless.
  This is the defer mechanism working correctly.

No further action needed on this part — continue using this approach for
subsequent bounded runs.

---

## 4. New Finding Requiring Investigation: Infiltration Payload Flags

**81 of 82 newly materialized graphs were flagged** for payload
nonzero-fraction outliers, overwhelmingly among the 79 new Infiltration
graphs. This is a very high flag rate and needs a specific look before
scaling further — "numerically finite" is not the same as "confirmed
correct," and this project has a direct precedent for why that distinction
matters (WebBased's `Attempted` rows).

### 4.1 A plausible, but unconfirmed, benign explanation

Infiltration's established mechanism (from the IP/time-window cross-check
investigation) is compromised-host reconnaissance — `172.31.69.13` scanning
other internal targets. Port scans and host-discovery probes are
characteristically low- or zero-payload by nature: a scan typically sends
minimal probe packets (e.g., bare SYN packets) without the kind of payload
content a WebBased or credential-based attack requires. If this is what's
happening, the established payload reference range (0.10–0.33 non-zero
fraction, calibrated on WebBased/IoT-model data) is simply the wrong
yardstick for a reconnaissance-heavy class — Infiltration may need its own,
lower reference range rather than being flagged against a threshold that
doesn't apply to it.

**This is a hypothesis, not a confirmed explanation, and should be checked
the same way WebBased's payload question was checked, not assumed.**

### 4.2 The check to run (same methodology as the WebBased payload audit)

- [ ] Inspect actual payload content (not just the nonzero-fraction number)
      for a sample of the flagged Infiltration graphs. Confirm whether these
      genuinely look like scanning/probe traffic (minimal packets, expected
      protocol behavior for a port scan or host discovery attempt) — the
      same content-level verification already applied to WebBased's
      `Attempted` rows, not just a byte-count check.
- [ ] Rule out an extraction or IP-matching artifact specific to
      Infiltration's "either endpoint is `172.31.69.13`" rule (established in
      the pretraining checklist implementation) — confirm the flagged graphs
      represent genuine flows involving that host during the attack window,
      not some kind of spurious empty-graph record produced by a matching
      edge case.
- [ ] If confirmed as genuine reconnaissance traffic: establish a
      class-specific payload reference range for Infiltration rather than
      applying the universal 0.10–0.33 threshold, and document this as an
      expected, legitimate characteristic of the class — not a data quality
      problem.
- [ ] If NOT confirmed (i.e., some flagged graphs don't represent real
      scanning traffic): investigate the extraction path for those specific
      cases before including them in the training pool.

---

## 5. Recommended Sequencing

```
1. Run the plugin-included NFStream RSS diagnostic (Section 2) to isolate
   the leak's actual location before attempting further memory fixes.
2. Investigate the Infiltration payload-flag pattern (Section 4) with the
   same content-level rigor applied to WebBased's Attempted rows.
3. Only after both are resolved: run a larger bounded pilot to confirm
   throughput improvements hold at scale.
4. Continue withholding the full run until 1-3 are complete — the full-run
   lock should stay in place.
```

---

## 6. What Must Not Happen

- Treating the open-flow diagnostic's low concurrent-flow-count finding as a
  complete refutation of a memory problem in NFStream/plugins — it only
  rules out one specific mechanism (concurrent state), not a cumulative one.
- Accepting the 81 flagged Infiltration graphs into the training pool without
  the content-level check in Section 4.2, based only on the values being
  numerically finite.
- Scaling to a larger bounded run or the full materialization before both
  open items above are resolved.
