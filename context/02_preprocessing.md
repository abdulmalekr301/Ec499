# Compact Preprocessing

Generated: `2026-06-17T17:02:18+00:00`

## Action
- Reused existing compact reservoir under `/var/home/alucard-00/EC499/data/graphs/_reservoir`.
- Did not rerun NFStream extraction or modify raw compact records.
- Loaded `173324` compact records across `34` subtype directories.
- Applied XG-NID balanced-pool splitting: balance each class to train+test target first, then split 4,000 test and 20,000 train records.
- Saved compact reservoir manifest to `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json`.

## Counts
```json
{
  "seen_counts": {
    "Backdoor_Malware": 3236,
    "BenignTraffic": 24000,
    "BrowserHijacking": 4000,
    "CommandInjection": 4000,
    "DDoS-ACK_Fragmentation": 2000,
    "DDoS-HTTP_Flood": 2000,
    "DDoS-ICMP_Flood": 2000,
    "DDoS-ICMP_Fragmentation": 2000,
    "DDoS-PSHACK_Flood": 2000,
    "DDoS-RSTFINFlood": 2000,
    "DDoS-SYN_Flood": 2000,
    "DDoS-SlowLoris": 2000,
    "DDoS-SynonymousIP_Flood": 2000,
    "DDoS-TCP_Flood": 2000,
    "DDoS-UDP_Flood": 2000,
    "DDoS-UDP_Fragmentation": 2000,
    "DNS_Spoofing": 12000,
    "DictionaryBruteForce": 11043,
    "DoS-HTTP_Flood": 6000,
    "DoS-SYN_Flood": 6000,
    "DoS-TCP_Flood": 6000,
    "DoS-UDP_Flood": 6000,
    "MITM-ArpSpoofing": 12000,
    "Mirai-greeth_flood": 8000,
    "Mirai-greip_flood": 8000,
    "Mirai-udpplain": 8000,
    "Recon-HostDiscovery": 4800,
    "Recon-OSScan": 4800,
    "Recon-PingSweep": 2226,
    "Recon-PortScan": 4800,
    "SqlInjection": 4000,
    "Uploading_Attack": 1619,
    "VulnerabilityScan": 4800,
    "XSS": 4000
  },
  "stored_counts": {
    "Backdoor_Malware": 3236,
    "BenignTraffic": 24000,
    "BrowserHijacking": 4000,
    "CommandInjection": 4000,
    "DDoS-ACK_Fragmentation": 2000,
    "DDoS-HTTP_Flood": 2000,
    "DDoS-ICMP_Flood": 2000,
    "DDoS-ICMP_Fragmentation": 2000,
    "DDoS-PSHACK_Flood": 2000,
    "DDoS-RSTFINFlood": 2000,
    "DDoS-SYN_Flood": 2000,
    "DDoS-SlowLoris": 2000,
    "DDoS-SynonymousIP_Flood": 2000,
    "DDoS-TCP_Flood": 2000,
    "DDoS-UDP_Flood": 2000,
    "DDoS-UDP_Fragmentation": 2000,
    "DNS_Spoofing": 12000,
    "DictionaryBruteForce": 11043,
    "DoS-HTTP_Flood": 6000,
    "DoS-SYN_Flood": 6000,
    "DoS-TCP_Flood": 6000,
    "DoS-UDP_Flood": 6000,
    "MITM-ArpSpoofing": 12000,
    "Mirai-greeth_flood": 8000,
    "Mirai-greip_flood": 8000,
    "Mirai-udpplain": 8000,
    "Recon-HostDiscovery": 4800,
    "Recon-OSScan": 4800,
    "Recon-PingSweep": 2226,
    "Recon-PortScan": 4800,
    "SqlInjection": 4000,
    "Uploading_Attack": 1619,
    "VulnerabilityScan": 4800,
    "XSS": 4000
  },
  "class_pool_counts_before_split": {
    "Benign": 24000,
    "DDoS": 24000,
    "DoS": 24000,
    "Mirai": 24000,
    "Recon": 21426,
    "Spoofing": 24000,
    "WebBased": 20855,
    "BruteForce": 11043
  },
  "oversampling_summary": {
    "Benign": {
      "real_available": 24000,
      "target_total": 24000,
      "unique_in_balanced_pool": 24000,
      "oversampled_count": 0,
      "oversampled_fraction": 0.0,
      "train_count": 20000,
      "test_count": 4000
    },
    "DDoS": {
      "real_available": 24000,
      "target_total": 24000,
      "unique_in_balanced_pool": 24000,
      "oversampled_count": 0,
      "oversampled_fraction": 0.0,
      "train_count": 20000,
      "test_count": 4000
    },
    "DoS": {
      "real_available": 24000,
      "target_total": 24000,
      "unique_in_balanced_pool": 24000,
      "oversampled_count": 0,
      "oversampled_fraction": 0.0,
      "train_count": 20000,
      "test_count": 4000
    },
    "Mirai": {
      "real_available": 24000,
      "target_total": 24000,
      "unique_in_balanced_pool": 24000,
      "oversampled_count": 0,
      "oversampled_fraction": 0.0,
      "train_count": 20000,
      "test_count": 4000
    },
    "Recon": {
      "real_available": 21426,
      "target_total": 24000,
      "unique_in_balanced_pool": 21426,
      "oversampled_count": 2574,
      "oversampled_fraction": 0.10725,
      "train_count": 20000,
      "test_count": 4000
    },
    "Spoofing": {
      "real_available": 24000,
      "target_total": 24000,
      "unique_in_balanced_pool": 24000,
      "oversampled_count": 0,
      "oversampled_fraction": 0.0,
      "train_count": 20000,
      "test_count": 4000
    },
    "WebBased": {
      "real_available": 20855,
      "target_total": 24000,
      "unique_in_balanced_pool": 20855,
      "oversampled_count": 3145,
      "oversampled_fraction": 0.13104166666666667,
      "train_count": 20000,
      "test_count": 4000
    },
    "BruteForce": {
      "real_available": 11043,
      "target_total": 24000,
      "unique_in_balanced_pool": 11043,
      "oversampled_count": 12957,
      "oversampled_fraction": 0.539875,
      "train_count": 20000,
      "test_count": 4000
    }
  },
  "train_per_class": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 20000,
    "Spoofing": 20000,
    "WebBased": 20000,
    "BruteForce": 20000
  },
  "test_per_class": {
    "Benign": 4000,
    "DDoS": 4000,
    "DoS": 4000,
    "Mirai": 4000,
    "Recon": 4000,
    "Spoofing": 4000,
    "WebBased": 4000,
    "BruteForce": 4000
  },
  "skipped_zero_packet_flows": 0,
  "skipped_files_after_reservoir_fill_count": 0,
  "skipped_files_after_reservoir_fill_sample": []
}
```
