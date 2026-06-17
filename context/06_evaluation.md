# HGNN Evaluation

Generated: `2026-06-15T08:19:13+00:00`

## Action
- Evaluated checkpoint `/var/home/alucard-00/EC499/artifacts/best_hgnn.pt` on graph test files.
- Saved metrics to `/var/home/alucard-00/EC499/artifacts/metrics.json`.
- Macro F1: `0.873174`.

## Target
- Final methodology target is macro F1 >= 0.97.
- Each DDoS subtype should be predicted as DDoS at a rate >= 0.90.

## DDoS Subtype DDoS Recall
```json
{
  "DDoS-ACK_Fragmentation": 0.9584569732937686,
  "DDoS-HTTP_Flood": 0.9620253164556962,
  "DDoS-ICMP_Flood": 0.9787878787878788,
  "DDoS-ICMP_Fragmentation": 0.7439024390243902,
  "DDoS-PSHACK_Flood": 1.0,
  "DDoS-RSTFINFlood": 1.0,
  "DDoS-SYN_Flood": 0.9969512195121951,
  "DDoS-SlowLoris": 0.5718562874251497,
  "DDoS-SynonymousIP_Flood": 0.997134670487106,
  "DDoS-TCP_Flood": 0.993993993993994,
  "DDoS-UDP_Flood": 1.0,
  "DDoS-UDP_Fragmentation": 0.8547945205479452
}
```
