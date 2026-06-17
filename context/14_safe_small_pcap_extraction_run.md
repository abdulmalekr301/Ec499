# Safe Small-PCAP Extraction Run

## Purpose

This run was started after repeated system crashes during full CIC-IoT2023 PCAP extraction. To avoid another memory/swap exhaustion event, only PCAP files below the configured safe threshold of 64 MiB were processed.

The full 192,000-graph final-methodology extraction was not started.

## Safety Settings

- Processed only PCAPs smaller than `SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB=64`.
- Automatic large-PCAP splitting remained disabled.
- Worker memory controls were used:
  - `--max-rss-gb 2`
  - `--min-available-gb 4`
  - `--memory-check-interval 25`
  - `MALLOC_ARENA_MAX=2`
  - `OMP_NUM_THREADS=1`
  - `OPENBLAS_NUM_THREADS=1`
  - `MKL_NUM_THREADS=1`
- Each selected PCAP targeted 50 compact graph records.

## Processed PCAPs

| PCAP subtype | Class | Seen | Stored | Skipped zero-packet flows | Stop reason | Chunks |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| Backdoor_Malware | WebBased | 50 | 50 | 0 | target_reached | 1 |
| BrowserHijacking | WebBased | 50 | 50 | 0 | target_reached | 1 |
| CommandInjection | WebBased | 50 | 50 | 0 | target_reached | 1 |
| DictionaryBruteForce | BruteForce | 50 | 50 | 0 | target_reached | 1 |
| Recon-PingSweep | Recon | 50 | 50 | 0 | target_reached | 1 |
| SqlInjection | WebBased | 50 | 50 | 0 | target_reached | 1 |
| Uploading_Attack | WebBased | 50 | 50 | 0 | target_reached | 1 |
| XSS | WebBased | 50 | 50 | 0 | target_reached | 1 |

## Output

- Output directory: `data/graphs/_safe_small_run`
- Compact graph records written: `400`
- Output size: approximately `14 MiB`

## Memory Result

After the safe run completed, the system still had approximately `10 GiB` available memory. Swap usage remained around `1.4 GiB`, but did not grow during this bounded run.

## Remaining Limitation

This safe run covers only the small PCAP files and therefore does not produce the full eight-class balanced dataset required by the final methodology. The 26 larger PCAP files remain blocked by the oversized-PCAP guard. They should be handled only after pre-splitting into small chunks outside the interactive extraction path or on a larger batch machine.
