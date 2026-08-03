# Office Final Robust Training Manifest

Date: 2026-08-03T03:39:41+00:00

- Manifest: `artifacts/office_model/office_final_robust_training_manifest.json`
- Train graphs: `36957`
- Validation graphs: `14399`
- Test graphs: `15747`
- Train groups: `1886`
- Validation groups: `423`
- Test groups: `785`
- Temporal features masked: `True`
- Train cap per group: `1000`

## Split Counts

| Class | Train | Val | Test |
| --- | ---: | ---: | ---: |
| Benign | 18723 | 2340 | 2340 |
| BruteForce | 1000 | 4013 | 1455 |
| DoS | 3000 | 559 | 402 |
| DDoS | 3000 | 772 | 5569 |
| WebBased | 234 | 138 | 40 |
| Bot | 7000 | 2536 | 3380 |
| Infiltration | 4000 | 4041 | 2561 |

## Subtype Counts

### Train

| Subtype | Graphs |
| --- | ---: |
| Benign|BENIGN | 18723 |
| Bot|Bot | 7000 |
| BruteForce|SSH-Bruteforce | 1000 |
| DDoS|DDOS-HOIC | 1000 |
| DDoS|DDOS-LOIC-HTTP | 1000 |
| DDoS|DDOS-LOIC-UDP | 1000 |
| DoS|DoS-GoldenEye | 1000 |
| DoS|DoS-Hulk | 1000 |
| DoS|DoS-Slowloris | 1000 |
| Infiltration|Infiltration | 4000 |
| WebBased|Brute Force-Web | 135 |
| WebBased|Brute Force-XSS | 72 |
| WebBased|SQL Injection | 27 |

### Val

| Subtype | Graphs |
| --- | ---: |
| Benign|BENIGN | 2340 |
| Bot|Bot | 2536 |
| BruteForce|SSH-Bruteforce | 4013 |
| DDoS|DDOS-LOIC-HTTP | 10 |
| DDoS|DDOS-LOIC-UDP | 762 |
| DoS|DoS-Hulk | 559 |
| Infiltration|Infiltration | 4041 |
| WebBased|Brute Force-Web | 122 |
| WebBased|SQL Injection | 16 |

### Test

| Subtype | Graphs |
| --- | ---: |
| Benign|BENIGN | 2340 |
| Bot|Bot | 3380 |
| BruteForce|SSH-Bruteforce | 1455 |
| DDoS|DDOS-HOIC | 4917 |
| DDoS|DDOS-LOIC-UDP | 652 |
| DoS|DoS-Hulk | 402 |
| Infiltration|Infiltration | 2561 |
| WebBased|Brute Force-XSS | 40 |

## Stress Sets

| Stress set | Graphs | Counts |
| --- | ---: | --- |
| dos_slowhttptest_attempted_stress_set | 3907 | `{'DoS|DoS-SlowHTTPTest': 3907}` |
| ftp_bruteforce_attempted_stress_set | 12000 | `{'BruteForce|FTP-BruteForce': 12000}` |
