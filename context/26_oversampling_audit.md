# Oversampling Audit

Generated: `2026-06-16T17:45:09+00:00`

## Action
- Audited duplicate path usage from `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json`.
- Saved machine-readable report to `/var/home/alucard-00/EC499/artifacts/oversampling_audit.json`.

## Train Duplicate Fractions
| Class | Train Total | Unique Train | Duplicate Count | Duplicate Fraction |
|---|---:|---:|---:|---:|
| Benign | 20000 | 20000 | 0 | 0.00% |
| DDoS | 20000 | 20000 | 0 | 0.00% |
| DoS | 20000 | 20000 | 0 | 0.00% |
| Mirai | 20000 | 20000 | 0 | 0.00% |
| Recon | 20000 | 11882 | 8118 | 40.59% |
| Spoofing | 20000 | 20000 | 0 | 0.00% |
| WebBased | 20000 | 11691 | 8309 | 41.55% |
| BruteForce | 20000 | 6669 | 13331 | 66.66% |
