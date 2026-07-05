# Class-Conditional Filtering Regeneration

Generated: `2026-07-04T21:45:00+00:00`

## Action
- Applied class-conditional MAC filtering.
- MAC-filtered classes: `['DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing']`.
- WebBased and BruteForce bypass attacker-MAC filtering and use filename/subtype labels.
- Benign remains strict and drops flows involving known attacker MACs.
- Regenerated selected subtype reservoirs: `['Backdoor_Malware', 'BrowserHijacking', 'CommandInjection', 'SqlInjection', 'Uploading_Attack', 'XSS', 'DictionaryBruteForce']`.
- Rebuilt compact split manifest at `/var/home/alucard-00/EC499/artifacts/compact_reservoir_manifest.json` using split-first/train-only oversampling.

## Regeneration Summary
```json
{
  "Backdoor_Malware": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 3236,
    "stored": 3236,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 3236,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 3236
      },
      "first_flow_macs": [
        {
          "source_file": "Backdoor_Malware.pcap",
          "source_order": 0,
          "src_mac": "28:6d:97:7a:2b:2d",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "Backdoor_Malware.pcap",
          "source_order": 1,
          "src_mac": "dc:a6:32:dc:27:d5",
          "dst_mac": "dc:a6:32:c9:e6:f4"
        },
        {
          "source_file": "Backdoor_Malware.pcap",
          "source_order": 2,
          "src_mac": "cc:f4:11:9c:d0:00",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "Backdoor_Malware.pcap",
          "source_order": 3,
          "src_mac": "3c:18:a0:41:c3:a0",
          "dst_mac": "44:bb:3b:00:39:07"
        },
        {
          "source_file": "Backdoor_Malware.pcap",
          "source_order": 4,
          "src_mac": "3c:18:a0:41:c3:a0",
          "dst_mac": "44:bb:3b:00:39:07"
        }
      ]
    }
  },
  "BrowserHijacking": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 4667,
    "stored": 4667,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 4667,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 4667
      },
      "first_flow_macs": [
        {
          "source_file": "BrowserHijacking.pcap",
          "source_order": 0,
          "src_mac": "dc:a6:32:c9:e5:02",
          "dst_mac": "dc:a6:32:dc:27:d5"
        },
        {
          "source_file": "BrowserHijacking.pcap",
          "source_order": 1,
          "src_mac": "7c:78:b2:86:0d:81",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "BrowserHijacking.pcap",
          "source_order": 2,
          "src_mac": "28:6d:97:7a:2b:2d",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "BrowserHijacking.pcap",
          "source_order": 3,
          "src_mac": "7c:78:b2:86:0d:81",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "BrowserHijacking.pcap",
          "source_order": 4,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        }
      ]
    }
  },
  "CommandInjection": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 4667,
    "stored": 4667,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 4667,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 4667
      },
      "first_flow_macs": [
        {
          "source_file": "CommandInjection.pcap",
          "source_order": 0,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "CommandInjection.pcap",
          "source_order": 1,
          "src_mac": "7c:78:b2:86:0d:81",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "CommandInjection.pcap",
          "source_order": 2,
          "src_mac": "00:17:88:60:d6:4f",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "CommandInjection.pcap",
          "source_order": 3,
          "src_mac": "28:6d:97:7a:2b:2d",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "CommandInjection.pcap",
          "source_order": 4,
          "src_mac": "dc:a6:32:dc:27:d5",
          "dst_mac": "cc:f4:11:9c:d0:00"
        }
      ]
    }
  },
  "SqlInjection": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 4667,
    "stored": 4667,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 4667,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 4667
      },
      "first_flow_macs": [
        {
          "source_file": "SqlInjection.pcap",
          "source_order": 0,
          "src_mac": "a0:d0:dc:c4:08:ff",
          "dst_mac": "1c:12:b0:9b:0c:ec"
        },
        {
          "source_file": "SqlInjection.pcap",
          "source_order": 1,
          "src_mac": "a0:d0:dc:c4:08:ff",
          "dst_mac": "1c:12:b0:9b:0c:ec"
        },
        {
          "source_file": "SqlInjection.pcap",
          "source_order": 2,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "SqlInjection.pcap",
          "source_order": 3,
          "src_mac": "08:7c:39:ce:6e:2a",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "SqlInjection.pcap",
          "source_order": 4,
          "src_mac": "a0:d0:dc:c4:08:ff",
          "dst_mac": "1c:12:b0:9b:0c:ec"
        }
      ]
    }
  },
  "Uploading_Attack": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 1619,
    "stored": 1619,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 1619,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 1619
      },
      "first_flow_macs": [
        {
          "source_file": "Uploading_Attack.pcap",
          "source_order": 0,
          "src_mac": "3c:18:a0:41:c3:a0",
          "dst_mac": "e8:1b:69:f8:d6:e6"
        },
        {
          "source_file": "Uploading_Attack.pcap",
          "source_order": 1,
          "src_mac": "7c:78:b2:86:0d:81",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "Uploading_Attack.pcap",
          "source_order": 2,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "Uploading_Attack.pcap",
          "source_order": 3,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "Uploading_Attack.pcap",
          "source_order": 4,
          "src_mac": "28:6d:97:7a:2b:2d",
          "dst_mac": "3c:18:a0:41:c3:a0"
        }
      ]
    }
  },
  "XSS": {
    "class_name": "WebBased",
    "target": 4667,
    "seen": 4270,
    "stored": 4270,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 4270,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 4270
      },
      "first_flow_macs": [
        {
          "source_file": "XSS.pcap",
          "source_order": 0,
          "src_mac": "84:7a:b6:64:62:58",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "XSS.pcap",
          "source_order": 1,
          "src_mac": "00:17:88:60:d6:4f",
          "dst_mac": "dc:a6:32:dc:27:d5"
        },
        {
          "source_file": "XSS.pcap",
          "source_order": 2,
          "src_mac": "7c:78:b2:86:0d:81",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "XSS.pcap",
          "source_order": 3,
          "src_mac": "3c:18:a0:41:c3:a0",
          "dst_mac": "44:bb:3b:00:39:07"
        },
        {
          "source_file": "XSS.pcap",
          "source_order": 4,
          "src_mac": "84:7a:b6:62:3a:6c",
          "dst_mac": "3c:18:a0:41:c3:a0"
        }
      ]
    }
  },
  "DictionaryBruteForce": {
    "class_name": "BruteForce",
    "target": 28000,
    "seen": 11043,
    "stored": 11043,
    "mac_filter": {
      "enabled": true,
      "attacker_mac_count": 9,
      "kept": 11043,
      "dropped": 0,
      "missing_mac_kept": 0,
      "reasons": {
        "class_conditional_unfiltered": 11043
      },
      "first_flow_macs": [
        {
          "source_file": "DictionaryBruteForce.pcap",
          "source_order": 0,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "DictionaryBruteForce.pcap",
          "source_order": 1,
          "src_mac": "44:bb:3b:00:39:07",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "DictionaryBruteForce.pcap",
          "source_order": 2,
          "src_mac": "a0:d0:dc:c4:08:ff",
          "dst_mac": "1c:12:b0:9b:0c:ec"
        },
        {
          "source_file": "DictionaryBruteForce.pcap",
          "source_order": 3,
          "src_mac": "d4:a6:51:30:64:b7",
          "dst_mac": "3c:18:a0:41:c3:a0"
        },
        {
          "source_file": "DictionaryBruteForce.pcap",
          "source_order": 4,
          "src_mac": "94:39:e5:5d:27:a6",
          "dst_mac": "3c:18:a0:41:c3:a0"
        }
      ]
    }
  }
}
```
