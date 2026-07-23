# Class Distribution Report

## Source Artifacts

- compact: `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json`
- graph: `/var/home/alucard-00/EC499/artifacts/graph_dataset_manifest.json`
- shards: `/var/home/alucard-00/EC499/artifacts/graph_shard_manifest.json`

## Global Summary

- Split strategy: `split_first_then_oversample_train_only`
- Graph value mode: `raw`
- Raw derived flow transform: `log1p`
- Compact total count: `190000`

| Split | Graph count | Shards |
|---|---:|---:|
| train | 160000 | 160 |
| val | 15000 | 15 |
| test | 15000 | 15 |

## Class-Level Split Distribution

| Class | Pool Before Split | Train Sampled | Train Unique | Train Duplicate Slots | Val Sampled | Val Unique | Test Sampled | Test Unique |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 28000 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| DDoS | 28008 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| DoS | 28000 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| Mirai | 28002 | 20000 | 20000 | 0 | 2000 | 2000 | 2000 | 2000 |
| Recon | 23143 | 20000 | 19143 | 857 | 2000 | 2000 | 2000 | 2000 |
| Spoofing | 16151 | 20000 | 12151 | 7849 | 2000 | 2000 | 2000 | 2000 |
| WebBased | 4627 | 20000 | 627 | 19373 | 2000 | 2000 | 2000 | 2000 |
| BruteForce | 2184 | 20000 | 184 | 19816 | 1000 | 1000 | 1000 | 1000 |

## Per-Class Details

### Benign

- Pool before split: `28000`
- Train seed real available: `24000`
- Train target total: `20000`
- Train oversampled count: `0`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 20000 | 0 | 0.000000 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | BenignTraffic | 20000 | 20000 |
| val | BenignTraffic | 2000 | 2000 |
| test | BenignTraffic | 2000 | 2000 |

### DDoS

- Pool before split: `28008`
- Train seed real available: `24008`
- Train target total: `20000`
- Train oversampled count: `0`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 20000 | 0 | 0.000000 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | DDoS-ACK_Fragmentation | 1662 | 1662 |
| train | DDoS-HTTP_Flood | 1673 | 1673 |
| train | DDoS-ICMP_Flood | 1679 | 1679 |
| train | DDoS-ICMP_Fragmentation | 1647 | 1647 |
| train | DDoS-PSHACK_Flood | 1657 | 1657 |
| train | DDoS-RSTFINFlood | 1641 | 1641 |
| train | DDoS-SYN_Flood | 1668 | 1668 |
| train | DDoS-SlowLoris | 1651 | 1651 |
| train | DDoS-SynonymousIP_Flood | 1686 | 1686 |
| train | DDoS-TCP_Flood | 1704 | 1704 |
| train | DDoS-UDP_Flood | 1662 | 1662 |
| train | DDoS-UDP_Fragmentation | 1670 | 1670 |
| val | DDoS-ACK_Fragmentation | 168 | 168 |
| val | DDoS-HTTP_Flood | 164 | 164 |
| val | DDoS-ICMP_Flood | 179 | 179 |
| val | DDoS-ICMP_Fragmentation | 150 | 150 |
| val | DDoS-PSHACK_Flood | 180 | 180 |
| val | DDoS-RSTFINFlood | 160 | 160 |
| val | DDoS-SYN_Flood | 163 | 163 |
| val | DDoS-SlowLoris | 170 | 170 |
| val | DDoS-SynonymousIP_Flood | 180 | 180 |
| val | DDoS-TCP_Flood | 149 | 149 |
| val | DDoS-UDP_Flood | 165 | 165 |
| val | DDoS-UDP_Fragmentation | 172 | 172 |
| test | DDoS-ACK_Fragmentation | 166 | 166 |
| test | DDoS-HTTP_Flood | 173 | 173 |
| test | DDoS-ICMP_Flood | 158 | 158 |
| test | DDoS-ICMP_Fragmentation | 193 | 193 |
| test | DDoS-PSHACK_Flood | 170 | 170 |
| test | DDoS-RSTFINFlood | 177 | 177 |
| test | DDoS-SYN_Flood | 143 | 143 |
| test | DDoS-SlowLoris | 161 | 161 |
| test | DDoS-SynonymousIP_Flood | 152 | 152 |
| test | DDoS-TCP_Flood | 163 | 163 |
| test | DDoS-UDP_Flood | 175 | 175 |
| test | DDoS-UDP_Fragmentation | 169 | 169 |

### DoS

- Pool before split: `28000`
- Train seed real available: `24000`
- Train target total: `20000`
- Train oversampled count: `0`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 20000 | 0 | 0.000000 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | DoS-HTTP_Flood | 4998 | 4998 |
| train | DoS-SYN_Flood | 5015 | 5015 |
| train | DoS-TCP_Flood | 4971 | 4971 |
| train | DoS-UDP_Flood | 5016 | 5016 |
| val | DoS-HTTP_Flood | 504 | 504 |
| val | DoS-SYN_Flood | 495 | 495 |
| val | DoS-TCP_Flood | 519 | 519 |
| val | DoS-UDP_Flood | 482 | 482 |
| test | DoS-HTTP_Flood | 492 | 492 |
| test | DoS-SYN_Flood | 498 | 498 |
| test | DoS-TCP_Flood | 479 | 479 |
| test | DoS-UDP_Flood | 531 | 531 |

### Mirai

- Pool before split: `28002`
- Train seed real available: `24002`
- Train target total: `20000`
- Train oversampled count: `0`
- Train oversampled fraction: `0.0`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 20000 | 0 | 0.000000 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | Mirai-greeth_flood | 6696 | 6696 |
| train | Mirai-greip_flood | 6634 | 6634 |
| train | Mirai-udpplain | 6670 | 6670 |
| val | Mirai-greeth_flood | 655 | 655 |
| val | Mirai-greip_flood | 683 | 683 |
| val | Mirai-udpplain | 662 | 662 |
| test | Mirai-greeth_flood | 658 | 658 |
| test | Mirai-greip_flood | 654 | 654 |
| test | Mirai-udpplain | 688 | 688 |

### Recon

- Pool before split: `23143`
- Train seed real available: `19143`
- Train target total: `20000`
- Train oversampled count: `857`
- Train oversampled fraction: `0.04285`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 19143 | 857 | 0.042850 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | Recon-HostDiscovery | 4872 | 4660 |
| train | Recon-OSScan | 4831 | 4619 |
| train | Recon-PingSweep | 631 | 605 |
| train | Recon-PortScan | 4799 | 4595 |
| train | VulnerabilityScan | 4867 | 4664 |
| val | Recon-HostDiscovery | 470 | 470 |
| val | Recon-OSScan | 467 | 467 |
| val | Recon-PingSweep | 74 | 74 |
| val | Recon-PortScan | 514 | 514 |
| val | VulnerabilityScan | 475 | 475 |
| test | Recon-HostDiscovery | 470 | 470 |
| test | Recon-OSScan | 514 | 514 |
| test | Recon-PingSweep | 64 | 64 |
| test | Recon-PortScan | 491 | 491 |
| test | VulnerabilityScan | 461 | 461 |

### Spoofing

- Pool before split: `16151`
- Train seed real available: `12151`
- Train target total: `20000`
- Train oversampled count: `7849`
- Train oversampled fraction: `0.39245`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 12151 | 7849 | 0.392450 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | DNS_Spoofing | 17377 | 10525 |
| train | MITM-ArpSpoofing | 2623 | 1626 |
| val | DNS_Spoofing | 1739 | 1739 |
| val | MITM-ArpSpoofing | 261 | 261 |
| test | DNS_Spoofing | 1736 | 1736 |
| test | MITM-ArpSpoofing | 264 | 264 |

### WebBased

- Pool before split: `4627`
- Train seed real available: `627`
- Train target total: `20000`
- Train oversampled count: `19373`
- Train oversampled fraction: `0.96865`
- WebBased subtype balancing: `capped_floor`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 627 | 19373 | 0.968650 |
| val | 2000 | 2000 | 0 | 0.000000 |
| test | 2000 | 2000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | Backdoor_Malware | 2577 | 33 |
| train | BrowserHijacking | 4305 | 132 |
| train | CommandInjection | 2472 | 27 |
| train | SqlInjection | 6000 | 398 |
| train | Uploading_Attack | 2262 | 15 |
| train | XSS | 2384 | 22 |
| val | Backdoor_Malware | 116 | 116 |
| val | BrowserHijacking | 401 | 401 |
| val | CommandInjection | 111 | 111 |
| val | SqlInjection | 1239 | 1239 |
| val | Uploading_Attack | 31 | 31 |
| val | XSS | 102 | 102 |
| test | Backdoor_Malware | 95 | 95 |
| test | BrowserHijacking | 439 | 439 |
| test | CommandInjection | 137 | 137 |
| test | SqlInjection | 1193 | 1193 |
| test | Uploading_Attack | 38 | 38 |
| test | XSS | 98 | 98 |

### BruteForce

- Pool before split: `2184`
- Train seed real available: `184`
- Train target total: `20000`
- Train oversampled count: `19816`
- Train oversampled fraction: `0.9908`

| Split | Sampled Count | Unique Real Count | Duplicate Slots | Oversampled Fraction |
|---|---:|---:|---:|---:|
| train | 20000 | 184 | 19816 | 0.990800 |
| val | 1000 | 1000 | 0 | 0.000000 |
| test | 1000 | 1000 | 0 | 0.000000 |

Subtype distribution by sampled count:

| Split | Subtype | Sampled Count | Unique Real Count |
|---|---|---:|---:|
| train | DictionaryBruteForce | 20000 | 184 |
| val | DictionaryBruteForce | 1000 | 1000 |
| test | DictionaryBruteForce | 1000 | 1000 |

## Machine-Readable JSON

- JSON copy: `/var/home/alucard-00/EC499/artifacts/class_distribution_report.json`
