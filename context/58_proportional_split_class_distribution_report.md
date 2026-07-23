# Proportional Split Class Distribution Report

## Source Artifacts

- compact: `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json`
- graph: `/var/home/alucard-00/EC499/artifacts/graph_dataset_manifest.json`
- shards: `/var/home/alucard-00/EC499/artifacts/graph_shard_manifest.json`
- leakage_audit: `/var/home/alucard-00/EC499/artifacts/training_runs/run_21_proportional_split_leakage_audit.md`

## Global Summary

- Split strategy: `split_first_then_oversample_train_only`
- Graph value mode: `raw`
- Raw derived flow transform: `log1p`
- Proportional split threshold: `24000`
- Compact total count: `183684`

| Split | Graph count | Shards |
|---|---:|---:|
| train | 160000 | 160 |
| val | 11843 | 12 |
| test | 11841 | 12 |

## Class-Level Split Distribution

| Class | Pool Before Split | Split Target Mode | Requested Train Real | Train Sampled | Train Unique | Train Duplicate Slots | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 28000 | fixed_targets | 24000 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| DDoS | 28008 | fixed_targets | 24008 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| DoS | 28000 | fixed_targets | 24000 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| Mirai | 28002 | fixed_targets | 24002 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| Recon | 23143 | proportional_targets | 19286 | 20000 | 19286 | 714 | 1929 | 1929 | 1928 | 1928 |
| Spoofing | 16151 | proportional_targets | 13459 | 20000 | 13459 | 6541 | 1346 | 1346 | 1346 | 1346 |
| WebBased | 4627 | proportional_targets | 3856 | 20000 | 3856 | 16144 | 386 | 386 | 385 | 385 |
| BruteForce | 2184 | proportional_targets | 1820 | 20000 | 1820 | 18180 | 182 | 182 | 182 | 182 |

## Scarce-Class Before/After Summary

| Class | Previous Train Unique | New Train Unique | Previous Val | New Val | Previous Test | New Test |
|---|---:|---:|---:|---:|---:|---:|
| Recon | 19143 | 19286 | 2000 | 1929 | 2000 | 1928 |
| Spoofing | 12151 | 13459 | 2000 | 1346 | 2000 | 1346 |
| WebBased | 627 | 3856 | 2000 | 386 | 2000 | 385 |
| BruteForce | 184 | 1820 | 1000 | 182 | 1000 | 182 |

## Per-Class Details

### Benign

- Pool before split: `28000`
- Split target mode: `fixed_targets`
- Requested train real count: `24000`
- Requested val/test counts: `2000` / `2000`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 20000 | 0 |
| val | 2000 | 2000 | 0 |
| test | 2000 | 2000 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| BenignTraffic | 20000 | 20000 | 2000 | 2000 | 2000 | 2000 |

### DDoS

- Pool before split: `28008`
- Split target mode: `fixed_targets`
- Requested train real count: `24008`
- Requested val/test counts: `2000` / `2000`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 20000 | 0 |
| val | 2000 | 2000 | 0 |
| test | 2000 | 2000 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| DDoS-ACK_Fragmentation | 1662 | 1662 | 168 | 168 | 166 | 166 |
| DDoS-HTTP_Flood | 1673 | 1673 | 164 | 164 | 173 | 173 |
| DDoS-ICMP_Flood | 1679 | 1679 | 179 | 179 | 158 | 158 |
| DDoS-ICMP_Fragmentation | 1647 | 1647 | 150 | 150 | 193 | 193 |
| DDoS-PSHACK_Flood | 1657 | 1657 | 180 | 180 | 170 | 170 |
| DDoS-RSTFINFlood | 1641 | 1641 | 160 | 160 | 177 | 177 |
| DDoS-SYN_Flood | 1668 | 1668 | 163 | 163 | 143 | 143 |
| DDoS-SlowLoris | 1651 | 1651 | 170 | 170 | 161 | 161 |
| DDoS-SynonymousIP_Flood | 1686 | 1686 | 180 | 180 | 152 | 152 |
| DDoS-TCP_Flood | 1704 | 1704 | 149 | 149 | 163 | 163 |
| DDoS-UDP_Flood | 1662 | 1662 | 165 | 165 | 175 | 175 |
| DDoS-UDP_Fragmentation | 1670 | 1670 | 172 | 172 | 169 | 169 |

### DoS

- Pool before split: `28000`
- Split target mode: `fixed_targets`
- Requested train real count: `24000`
- Requested val/test counts: `2000` / `2000`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 20000 | 0 |
| val | 2000 | 2000 | 0 |
| test | 2000 | 2000 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| DoS-HTTP_Flood | 4998 | 4998 | 504 | 504 | 492 | 492 |
| DoS-SYN_Flood | 5015 | 5015 | 495 | 495 | 498 | 498 |
| DoS-TCP_Flood | 4971 | 4971 | 519 | 519 | 479 | 479 |
| DoS-UDP_Flood | 5016 | 5016 | 482 | 482 | 531 | 531 |

### Mirai

- Pool before split: `28002`
- Split target mode: `fixed_targets`
- Requested train real count: `24002`
- Requested val/test counts: `2000` / `2000`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 20000 | 0 |
| val | 2000 | 2000 | 0 |
| test | 2000 | 2000 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| Mirai-greeth_flood | 6696 | 6696 | 655 | 655 | 658 | 658 |
| Mirai-greip_flood | 6634 | 6634 | 683 | 683 | 654 | 654 |
| Mirai-udpplain | 6670 | 6670 | 662 | 662 | 688 | 688 |

### Recon

- Pool before split: `23143`
- Split target mode: `proportional_targets`
- Requested train real count: `19286`
- Requested val/test counts: `1929` / `1928`
- Train oversampled fraction: `0.0357`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 19286 | 714 |
| val | 1929 | 1929 | 0 |
| test | 1928 | 1928 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| Recon-HostDiscovery | 4867 | 4692 | 461 | 461 | 447 | 447 |
| Recon-OSScan | 4821 | 4652 | 450 | 450 | 498 | 498 |
| Recon-PingSweep | 633 | 609 | 72 | 72 | 62 | 62 |
| Recon-PortScan | 4799 | 4625 | 497 | 497 | 478 | 478 |
| VulnerabilityScan | 4880 | 4708 | 449 | 449 | 443 | 443 |

### Spoofing

- Pool before split: `16151`
- Split target mode: `proportional_targets`
- Requested train real count: `13459`
- Requested val/test counts: `1346` / `1346`
- Train oversampled fraction: `0.32705`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 13459 | 6541 |
| val | 1346 | 1346 | 0 |
| test | 1346 | 1346 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| DNS_Spoofing | 17337 | 11667 | 1180 | 1180 | 1153 | 1153 |
| MITM-ArpSpoofing | 2663 | 1792 | 166 | 166 | 193 | 193 |

### WebBased

- Pool before split: `4627`
- Split target mode: `proportional_targets`
- Requested train real count: `3856`
- Requested val/test counts: `386` / `385`
- Train oversampled fraction: `0.8072`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 3856 | 16144 |
| val | 386 | 386 | 0 |
| test | 385 | 385 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| Backdoor_Malware | 2545 | 205 | 23 | 23 | 16 | 16 |
| BrowserHijacking | 4144 | 807 | 89 | 89 | 76 | 76 |
| CommandInjection | 2614 | 231 | 24 | 24 | 20 | 20 |
| SqlInjection | 6000 | 2351 | 228 | 228 | 251 | 251 |
| Uploading_Attack | 2197 | 74 | 4 | 4 | 6 | 6 |
| XSS | 2500 | 188 | 18 | 18 | 16 | 16 |

### BruteForce

- Pool before split: `2184`
- Split target mode: `proportional_targets`
- Requested train real count: `1820`
- Requested val/test counts: `182` / `182`
- Train oversampled fraction: `0.909`

| Split | Sampled Count | Unique Real Count | Duplicate Slots |
|---|---:|---:|---:|
| train | 20000 | 1820 | 18180 |
| val | 182 | 182 | 0 |
| test | 182 | 182 | 0 |

Subtype distribution by sampled and unique counts:

| Subtype | Train Sampled | Train Unique | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|
| DictionaryBruteForce | 20000 | 1820 | 182 | 182 | 182 | 182 |

## Leakage Audit Result

- Audit report: `artifacts/training_runs/run_21_proportional_split_leakage_audit.md`
- Result: passed with zero compact duplicates, zero graph hash duplicates, zero near-duplicate fingerprints, and no identity feature leakage.

## JSON Copy

- JSON copy: `/var/home/alucard-00/EC499/artifacts/class_distribution_report_proportional_split.json`
