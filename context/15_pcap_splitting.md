# Controlled PCAP Splitting

Generated: `2026-06-14T19:01:30+00:00`

## Action
- Split oversized PCAP files into smaller chunks under `/var/home/alucard-00/EC499/data/raw/pcap_chunks`.
- Used chunk size `16` MiB.
- Required at least `6.0` GiB available memory for the initial staged splits.
- Used a stricter `8.0` GiB available-memory floor for the near-1 GiB and 2 GiB continuation runs.
- Split one source PCAP at a time and wrote a per-PCAP `split_manifest.json`.

## Results
| Source PCAP | Status | Chunks | Size GiB | Stop reason |
| --- | --- | ---: | ---: | --- |
| BenignTraffic1.pcap | completed | 128 | 1.91 | completed |
| DDoS-ACK_Fragmentation1.pcap | completed | 128 | 1.91 | completed |
| DDoS-HTTP_Flood-.pcap | skipped_completed | 39 | 0.57 | completed |
| DDoS-ICMP_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-ICMP_Fragmentation1.pcap | completed | 128 | 1.91 | completed |
| DDoS-PSHACK_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-RSTFINFlood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-SYN_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-SlowLoris.pcap | skipped_completed | 43 | 0.63 | completed |
| DDoS-SynonymousIP_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-TCP_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-UDP_Flood1.pcap | completed | 128 | 1.91 | completed |
| DDoS-UDP_Fragmentation1.pcap | completed | 128 | 1.91 | completed |
| DNS_Spoofing.pcap | skipped_completed | 47 | 0.91 | completed |
| DoS-HTTP_Flood1.pcap | completed | 94 | 1.39 | completed |
| DoS-SYN_Flood1.pcap | completed | 128 | 1.91 | completed |
| DoS-TCP_Flood1.pcap | completed | 128 | 1.91 | completed |
| DoS-UDP_Flood1.pcap | completed | 128 | 1.91 | completed |
| MITM-ArpSpoofing1.pcap | skipped_completed | 40 | 0.59 | completed |
| Mirai-greeth_flood1.pcap | completed | 128 | 1.91 | completed |
| Mirai-greip_flood1.pcap | completed | 128 | 1.91 | completed |
| Mirai-udpplain1.pcap | completed | 128 | 1.91 | completed |
| Recon-HostDiscovery.pcap | skipped_completed | 15 | 0.21 | completed |
| Recon-OSScan.pcap | skipped_completed | 21 | 0.30 | completed |
| Recon-PortScan.pcap | skipped_completed | 13 | 0.19 | completed |
| VulnerabilityScan.pcap | skipped_completed | 65 | 0.96 | completed |

## Safety Note
This phase only prepares smaller PCAP chunks. It does not run NFStream extraction or graph materialization.

## Final Totals
- Completed split manifests: `26`
- Split chunks written: `2,553`
- Source PCAP volume split: `38.16 GiB`
- Split output directory size: approximately `38 GiB`
- Final available memory after splitting: approximately `10 GiB`
- Final swap usage after splitting: approximately `1.2 GiB`
