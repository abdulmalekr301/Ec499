# Office Attack Subtype Eligible Sample Inventory

Date: 2026-08-01

This report lists the attack subtypes present in the CIC-IDS-2018 office dataset and the number of samples that survived the current strict candidate eligibility gate. The gate is the same one used before reservoir capping and graph materialization:

- CSV label must be accepted as a real attack label, not an attempted/non-success label.
- CSV attack class must agree with the configured IP/time ground-truth attack window.
- Endpoint PCAP files must be available for the flow.
- The class/day must be part of the configured office candidate target set.

For WebBased, the recovered attempted-flow policy was included where the current pipeline recognizes those recovered hashes.

| Attack type | Subtype / attack window | Dataset attack windows | Eligible attack windows | Ground-truth rows | Eligible samples |
|---|---:|---:|---:|---:|---:|
| BruteForce | FTP-BruteForce | 1 | 0 | 190,294 | 0 |
| BruteForce | SSH-Bruteforce | 1 | 1 | 92,648 | 92,618 |
| DoS | DoS-Hulk | 1 | 1 | 1,803,246 | 1,803,160 |
| DoS | DoS-SlowHTTPTest | 1 | 0 | 105,550 | 0 |
| DDoS | DDOS-HOIC | 1 | 1 | 1,074,379 | 1,074,379 |
| DDoS | DDOS-LOIC-UDP | 1 | 1 | 1,864 | 1,697 |
| WebBased | Brute Force-Web | 2 | 1 | 260 | 122 |
| WebBased | Brute Force-XSS | 2 | 1 | 116 | 72 |
| WebBased | SQL Injection | 2 | 1 | 50 | 27 |
| Bot | Bot | 1 | 1 | 143,183 | 142,921 |
| Infiltration | Infiltration | 1 | 1 | 48,006 | 39,689 |

## Notes

- `Dataset attack windows` counts configured ground-truth attack windows that exist for that subtype in the dataset.
- `Eligible attack windows` counts windows that produced at least one strict eligible sample after label filtering, IP/time crosscheck, and endpoint PCAP availability checks.
- BruteForce and DoS each have a second subtype in the dataset, but those secondary subtypes currently produce no strict eligible samples.
- DDoS has a small eligible alternate subtype/window: `DDOS-LOIC-UDP` with `1,697` eligible samples.
- Bot remains a single-subtype, single-window class under the current dataset configuration.
- WebBased has two dataset windows per subtype, but only the Friday-23-02-2018 window produced strict eligible samples in this scan; Thursday-22-02-2018 had subtype rows but no endpoint PCAP-backed eligible candidates.
