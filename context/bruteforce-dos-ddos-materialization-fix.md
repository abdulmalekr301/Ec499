# Office Materialization — BruteForce/DoS/DDoS Structural Block: Diagnosis and Fix

> **Generated:** 2026-07-15
> **Context:** The full-run attempt confirmed a structural, reproducible
> failure specific to BruteForce, DoS, and DDoS — not a continuation of the
> earlier Bot-day leak investigation, which was cleared for that PCAP and is
> not representative of these three classes' PCAPs.

---

## 1. Current Status

```
Benign         10,764 / 24,000  (44.9%)
Bot            14,172 / 24,000  (59.1%)
Infiltration   23,509 / 24,000  (98.0%) -- essentially complete
WebBased          412 /    412  (100%)  -- native CIC-IDS2018 portion complete
                                          (CICIDS2017's 167-sample train-only
                                          augmentation is a separate pipeline —
                                          confirm its status separately)
BruteForce          0 / 24,000  (0.0%)  -- structurally blocked
DoS                 0 / 24,000  (0.0%)  -- structurally blocked
DDoS                 0 / 24,000  (0.0%)  -- structurally blocked
```

Four of seven classes are in good shape. Three are at zero, and the targeted
retest (one PCAP, no competing work, `--office-max-pcaps 1`) proves this is
reproducible, not a matter of the run not having reached them yet:

```
BruteForce: 182,990 flows scanned, 0 matched, memory floor hit
DoS:         86,270 flows scanned, 0 matched, memory floor hit
DDoS:         1,990 flows scanned, 0 matched, memory floor hit
```

---

## 2. Why This Is a Different Problem From the Bot-Day Leak Investigation

Every prior diagnostic (the open-flow diagnostic, the NFStream RSS
diagnostic) ran against `capDESKTOP-AN3U28N-172.31.64.115` from the Bot day.
Both cleared NFStream/plugins as a leak source **for that PCAP**. Neither was
ever run against BruteForce/DoS/DDoS's PCAPs, so their conclusions don't
necessarily transfer.

These three attack types are volumetric or high-repetition by nature:
- BruteForce means thousands of rapid, repeated connection attempts against
  one victim.
- DoS/DDoS mean sustained high-rate flooding against one victim.

Their victim-side PCAPs (`UCAP172.31.69.25` for BruteForce and DoS,
`UCAP172.31.69.28 part 1` for DDoS) are almost certainly enormous by the very
nature of what these attacks generate on the wire — this is far more likely a
genuine scale problem specific to these PCAPs than a generic code-level leak
of the kind investigated on the Bot day.

**Supporting evidence: the relative failure speeds.** DDoS hit the memory
floor after only 1,990 flows scanned — 42x faster than DoS's 86,270, despite
DDoS having the smaller flow count. This is consistent with flood traffic
carrying far more packets per flow than typical brute-force/DoS traffic —
pointing at raw packet/state volume, not flow count, as the driver.

**Why health-aware skipping can't fix this:** it worked for Bot/Infiltration/
Benign because those classes draw from many candidate-bearing PCAPs, so
skipping a bad one still leaves alternatives. BruteForce, DoS, and DDoS each
have their entire candidate pool concentrated in one specific victim PCAP —
there is no alternate source to fall back to. The fix has to make that PCAP
tractable, not avoid it.

---

## 3. Recommended Fix: Pre-Slice Before NFStream, Using Already-Known IP Pairs

This is the coding agent's own recommendation in the prior report, made more
concrete: the attacker/victim IP pairs for all three classes were already
established at the start of this project's office-model work, no
re-derivation needed.

```
BruteForce: attacker 172.31.70.4 / 172.31.70.6   <-> victim 172.31.69.25
DoS:        attacker 172.31.70.23 / 172.31.70.16 <-> victim 172.31.69.25
DDoS:       attacker (10 rotating IPs, see below) <-> victim 172.31.69.28
```

```
DDoS rotating attacker IPs: 18.218.115.60, 18.219.9.1, 18.219.32.43,
18.218.55.126, 52.14.136.135, 18.219.5.43, 18.216.200.189, 18.218.229.235,
18.218.11.51, 18.216.24.42
```

**Implementation:** a BPF-filtered packet-level pre-pass (`tcpdump` or
equivalent, filtering on `host <attacker_ip> and host <victim_ip>`) run
*before* NFStream ever touches the file. This requires no flow-state
tracking — pure packet-level IP matching — and should be fast and
lightweight relative to the full NFStream statistical extraction. The output
is a much smaller, attack-relevant PCAP slice that the existing NFStream +
candidate-matching + graph-construction pipeline can then process without
hitting the same memory wall, since it will be operating on a file scale
comparable to what's already worked cleanly for the other four classes.

```
1. For each of the three classes, build the known attacker/victim IP filter.
2. Pre-slice the relevant PCAP(s) into a temporary, attack-relevant-only file.
3. Run the existing compact materialization pipeline against the sliced file,
   using --office-target-class as already implemented.
4. Confirm candidate matches succeed and memory stays well under the floor.
5. Regenerate readable graph samples for the three previously-missing classes.
```

**Note on private vs. public IP:** confirm which IP variant (private
`172.31.70.x`-style or public `18.x.x.x`-style) actually appears in these
specific victim-side PCAPs before building the filter — this was established
per-day earlier in the project (private IP confirmed on-wire for the days
already verified), but hasn't been specifically re-confirmed for these three
PCAPs. A quick real-packet check avoids building a filter against the wrong
address family.

---

## 4. Separate Issue: Parent Process Hang After Worker Failure

Independent of the PCAP-size problem: after a worker raised `MemoryError`
inside `pad_payload`, the parent process stayed alive but stopped emitting
progress for several minutes, requiring a manual `SIGINT` (exit code 130) to
recover. This is a real gap in the recovery logic, not just a symptom of the
PCAP-size issue — subprocess isolation is supposed to let the parent detect a
failed worker and move on cleanly, and here it technically didn't crash but
also didn't self-recover.

**This needs its own fix, independent of Section 3.** Even after PCAP
pre-slicing resolves the BruteForce/DoS/DDoS block, an occasional worker
failure (transient issue, unexpected data, anything) could still happen on
any PCAP, and a full run shouldn't require someone watching it to intervene
manually when that occurs. Recommend adding an explicit timeout on parent-side
worker-result waiting, with a defined fallback (defer and move on) if a
worker doesn't report back within a bounded time — similar in spirit to the
existing `SECUREEDGE_PCAP_WORKER_TIMEOUT_SECONDS` setting already present in
the environment, but worth confirming it actually triggers correctly in this
specific hang scenario, since it apparently didn't prevent this one.

---

## 5. What Must Not Happen

- Re-attempting another full, unfiltered pass over the same full-size
  BruteForce/DoS/DDoS PCAPs — already shown low-value per the targeted
  retest; the file needs to be reduced first, not retried harder.
- Assuming the Bot-day diagnostics (open-flow, NFStream RSS) rule out a
  memory issue for these three classes — they were never tested against
  these specific PCAPs and the failure pattern here looks meaningfully
  different (much faster, much more severe).
- Treating the parent-hang issue as resolved by the PCAP-slicing fix — it's
  a separate reliability gap and needs independent verification.
- Starting another full run before both Section 3 (pre-slicing) and Section 4
  (hang recovery) are addressed and validated on a bounded/targeted basis.
