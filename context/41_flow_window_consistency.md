# Flow Window Consistency

Generated: `2026-07-04T17:02:30+00:00`

## Action
- Examined `1000` compact reservoir records under `/var/home/alucard-00/EC499/data/graphs/_reservoir`.
- Saved machine-readable output to `/var/home/alucard-00/EC499/artifacts/flow_window_consistency.json`.

## Result
```json
{
  "records_examined": 1000,
  "flow_packet_limit": 20,
  "mismatch_count": 0,
  "mismatch_fraction": 0.0,
  "max_flow_bidirectional_packets": 20.0,
  "max_packet_node_count": 20,
  "conclusion": "no_mismatch_observed_flowcapper_consistent"
}
```
