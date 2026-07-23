# WebBased "Attempted" Exclusion — Payload Retention Check

> **Generated:** 2026-07-13
> **Context:** CIC-IDS2018's WebBased pool is confirmed critically small (157
> in the strict candidate manifest, out of 230 raw CSV-labeled rows on
> Friday-23-02-2018, 72 excluded as `Attempted`/contamination). Combined with
> CICIDS2017 augmentation, the honest total may still land under 1,000. This
> is the cheapest, highest-value check to run before leaning further on
> CICIDS2017 or explicitly lowering WebBased's target — it might recover real
> samples that are currently being excluded unnecessarily.

---

## 0. The Core Question

The `Attempted` exclusion rule was built and validated against **Wednesday-14-02-2018's
FTP/SSH BruteForce contamination**, where the documented rationale is
transport-layer failure: the target port was closed, so the attacker never
had the opportunity to send any credentials at all
(`Total length of Fwd Packets == 0`, verified empirically for that specific
contamination).

**That rationale does not automatically transfer to web-based attacks.** A
SQL injection or XSS attempt can be blocked, sanitized, or rejected entirely
at the *application* layer, but the malicious payload still has to travel
over the wire as part of the HTTP request before the server ever gets a
chance to reject it. If CIC-IDS2018's WebBased `Attempted` exclusions are
being applied using the same blanket rule as the FTP/SSH case, they may be
discarding rows that still carry a genuine, usable attack payload — samples
this project cannot currently afford to lose.

**This check settles the question with evidence instead of assumption.**

---

## 1. What To Check

For every one of the 72 excluded WebBased rows on Friday-23-02-2018 (and the
equivalent excluded rows on any other WebBased-relevant day, if applicable):

1. **Extract the actual forward-payload byte count** for each excluded row,
   the same way the FTP/SSH contamination was originally verified
   (`Total length of Fwd Packets` or equivalent field from the CSV, cross-checked
   against the real packet payload pulled from the matched endpoint PCAP).
2. **Split the 72 excluded rows into two groups:**
   - **Zero-payload group** — genuinely no forward payload, matching the same
     failure mode as the FTP/SSH case (e.g., connection reset before any HTTP
     request was ever sent). These should stay excluded — there's nothing to
     learn from them.
   - **Non-zero-payload group** — forward payload exists. These are the
     candidates for recovery.
3. **For the non-zero-payload group, inspect actual payload content**, not
   just the byte count. Confirm the payload contains recognizable attack
   syntax appropriate to the row's labeled subtype:
   - `SQL Injection` rows: look for SQL metacharacters/keywords (`' OR`,
     `UNION SELECT`, `--`, etc.)
   - `Brute Force-XSS` rows: look for script/tag injection patterns
     (`<script>`, `onerror=`, etc.)
   - `Brute Force-Web` rows: look for repeated login-attempt patterns
     (POST requests to a login endpoint, credential-like form fields)
   - This step matters because non-zero payload alone isn't sufficient
     justification for recovery — a flow could have non-zero payload for an
     unrelated reason (e.g., an incidental background packet sharing the same
     5-tuple/time window) without actually containing the attack signature
     itself. Recovering a flow requires confirming the payload is genuinely
     attack-relevant, not just non-empty.

---

## 2. Decision Rule

```
IF a row has zero forward payload:
    KEEP EXCLUDED — same rationale as the validated FTP/SSH case, nothing
    to learn from it.

IF a row has non-zero forward payload AND the payload contains recognizable
attack syntax matching its labeled subtype:
    RECOVER — add back into the WebBased candidate pool. Document this
    explicitly as a deliberate, evidence-based rule relaxation specific to
    WebBased, not a general loosening of the Attempted-exclusion logic used
    elsewhere (it stays strict for FTP/SSH BruteForce).

IF a row has non-zero forward payload but the content does NOT match the
expected attack signature for its labeled subtype:
    FLAG FOR MANUAL REVIEW — do not silently recover or silently exclude.
    This is a case the automated rule can't safely resolve on its own.
```

---

## 3. What This Recovers, Realistically

This check can only recover what already exists in the 72 currently-excluded
rows — it is not a new data source, just a more precise use of data already
downloaded. Expect a partial recovery, not a full one: some fraction of the
72 will genuinely be zero-payload (closed connections, aborted handshakes)
and should stay excluded. Report the exact before/after count once this runs
— do not assume a specific recovery number in advance.

---

## 4. Sequencing

This check does not block the other six classes, all of which are already
resolved and comfortably at or near their 20,000 target. It specifically
targets WebBased before the next decision point:

```
1. Run this payload-retention check on the 72 excluded rows (this document).
2. Re-run the strict candidate manifest for WebBased only, incorporating
   any recovered rows.
3. Report the new WebBased total.
4. Only then decide how much weight CICIDS2017 augmentation needs to carry,
   and whether WebBased's 20,000 target needs to be explicitly lowered and
   documented as a data-availability ceiling (matching how BruteForce/WebBased
   scarcity was handled honestly on the IoT model).
```

---

## 5. What Must Not Happen

- Do not relax the `Attempted` exclusion rule for FTP/SSH BruteForce based on
  this check — the zero-payload rationale there is already independently
  documented and verified. This check is scoped to WebBased specifically.
- Do not recover a row on non-zero-payload evidence alone without confirming
  the payload actually contains attack-relevant content — an incidental
  non-empty payload is not the same as a usable attack example.
- Do not treat a successful recovery here as a substitute for the
  proportional split-ratio discipline already established — whatever the
  final WebBased total ends up being, training still needs to get the large
  majority of it, not a fixed share eaten by val/test.
