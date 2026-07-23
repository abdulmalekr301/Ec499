# Cyber Attack Evaluation CSV Features and Labels

## Source

- CSV: `/var/home/alucard-00/EC499/Cyber Attack Evaluation Dataset/Cap_1_10VM_1Apache/Cap_1_10VM_1Apache/L1_Cap_10PC_1S_dissec_complete.csv`
- Size: `589440683` bytes
- Data rows: `3962784`
- Parsed columns: `8`

## Important Finding

No explicit ground-truth label column was found. There is no `label`, `class`, `attack`, `attack_type`, `category`, or equivalent target column in this CSV header.

The `Protocol` column is categorical and label-like, but it is a packet protocol field rather than an attack-class label.

## Features

| # | Column | Interpreted role | Notes |
|---:|---|---|---|
| 1 | `No.` | feature | Packet/frame sequence number |
| 2 | `Time` | feature | Packet timestamp relative to capture start |
| 3 | `Source` | feature | Source address |
| 4 | `Destination` | feature | Destination address |
| 5 | `Protocol` | categorical feature | Protocol value; not an attack label |
| 6 | `Length` | feature | Packet length |
| 7 | `Time to Live` | feature | IP TTL value when present |
| 8 | `Info` | text feature | Wireshark-style packet summary text |

## Protocol Values

- Unique protocol values: `12`

| Protocol | Count |
|---|---:|
| `TCP` | 3953715 |
| `FTP` | 3792 |
| `SSHv2` | 3032 |
| `HTTP` | 1090 |
| `ARP` | 784 |
| `ICMP` | 200 |
| `DNS` | 149 |
| `FTP-DATA` | 6 |
| `UDP` | 6 |
| `ICMPv6` | 5 |
| `SSHv1` | 4 |
| `SSH` | 1 |

## Numeric Feature Ranges

| Column | Min | Max | Non-numeric count |
|---|---:|---:|---:|
| `No.` | 1.0 | 3962784.0 | 0 |
| `Time` | 0.0 | 84714.903277321 | 0 |
| `Length` | 42.0 | 64293.0 | 0 |
| `Time to Live` | 37.0 | 127.0 | 4 |

## Missing Values

| Column | Missing/blank count |
|---|---:|
| `No.` | 0 |
| `Time` | 0 |
| `Source` | 0 |
| `Destination` | 0 |
| `Protocol` | 0 |
| `Length` | 0 |
| `Time to Live` | 789 |
| `Info` | 0 |

## Address Cardinality

- Unique `Source` values: `3432675`
- Unique `Destination` values: `30`

Top source values:

| Source | Count |
|---|---:|
| `172.18.0.6` | 218152 |
| `172.18.0.2` | 217152 |
| `185.125.190.39` | 29787 |
| `185.125.190.36` | 18777 |
| `172.18.0.11` | 11256 |
| `172.18.0.10` | 8122 |
| `172.18.0.9` | 7675 |
| `172.18.0.8` | 6521 |
| `172.18.0.3` | 2729 |
| `172.18.0.4` | 2532 |
| `172.18.0.7` | 1638 |
| `172.18.0.5` | 635 |
| `02:42:ac:12:00:02` | 167 |
| `02:42:72:d9:1e:10` | 138 |
| `02:42:ac:12:00:06` | 125 |
| `172.16.49.2` | 73 |
| `02:42:ac:12:00:07` | 59 |
| `02:42:ac:12:00:0a` | 48 |
| `02:42:ac:12:00:04` | 45 |
| `02:42:ac:12:00:05` | 40 |
| `02:42:ac:12:00:0b` | 39 |
| `02:42:ac:12:00:09` | 38 |
| `02:42:ac:12:00:08` | 36 |
| `02:42:ac:12:00:03` | 33 |
| `02:42:ac:12:00:0c` | 16 |

Top destination values:

| Destination | Count |
|---|---:|
| `172.17.0.2` | 3454398 |
| `172.18.0.2` | 216430 |
| `172.18.0.6` | 203223 |
| `185.125.190.39` | 26002 |
| `185.125.190.36` | 17051 |
| `172.18.0.11` | 11695 |
| `172.18.0.10` | 9502 |
| `172.18.0.9` | 8414 |
| `172.18.0.8` | 7097 |
| `172.18.0.3` | 2923 |
| `172.18.0.4` | 2662 |
| `172.18.0.7` | 1849 |
| `172.18.0.5` | 663 |
| `02:42:ac:12:00:06` | 133 |
| `02:42:72:d9:1e:10` | 130 |
| `02:42:ac:12:00:04` | 95 |
| `Broadcast` | 92 |
| `02:42:ac:12:00:02` | 81 |
| `172.16.49.2` | 78 |
| `02:42:ac:12:00:07` | 51 |
| `02:42:ac:12:00:0a` | 39 |
| `02:42:ac:12:00:05` | 34 |
| `02:42:ac:12:00:0b` | 33 |
| `02:42:ac:12:00:09` | 32 |
| `02:42:ac:12:00:08` | 30 |

## Top Info Prefixes

The full `Info` column is free text, so this report lists the most common first-three-token prefixes instead of treating every unique sentence as a label.

| Info prefix | Count |
|---|---:|
| `80 > 60906` | 6263 |
| `80 > 39498` | 5928 |
| `60906 > 80` | 5608 |
| `39498 > 80` | 5238 |
| `80 > 43000` | 4847 |
| `80 > 52740` | 4783 |
| `43000 > 80` | 4306 |
| `52740 > 80` | 4266 |
| `80 > 44124` | 3244 |
| `80 > 48490` | 3183 |
| `48490 > 80` | 3002 |
| `44124 > 80` | 2897 |
| `80 > 55042` | 1769 |
| `80 > 41228` | 1553 |
| `41228 > 80` | 1517 |
| `80 > 35100` | 1508 |
| `35100 > 80` | 1435 |
| `80 > 42996` | 1420 |
| `80 > 48492` | 1409 |
| `80 > 49138` | 1389 |
| `80 > 35066` | 1360 |
| `80 > 55814` | 1360 |
| `49138 > 80` | 1355 |
| `42996 > 80` | 1329 |
| `80 > 55892` | 1306 |
| `55892 > 80` | 1290 |
| `55814 > 80` | 1281 |
| `48492 > 80` | 1267 |
| `35066 > 80` | 1165 |
| `55042 > 80` | 1010 |
| `Client: Encrypted packet` | 880 |
| `Response: 331 Please` | 789 |
| `Response: 530 Login` | 784 |
| `Server: Encrypted packet` | 753 |
| `43190 > 80` | 616 |
| `43122 > 80` | 547 |
| `39918 > 80` | 542 |
| `80 > 43122` | 519 |
| `43706 > 80` | 519 |
| `80 > 39918` | 508 |
| `HTTP/1.1 200 OK` | 499 |
| `59010 > 80` | 491 |
| `80 > 43706` | 481 |
| `80 > 43190` | 474 |
| `80 > 59010` | 470 |
| `59022 > 80` | 464 |
| `44364 > 80` | 456 |
| `59102 > 80` | 448 |
| `80 > 59022` | 440 |
| `80 > 44364` | 411 |

## JSON Copy

- `/var/home/alucard-00/EC499/artifacts/cyber_attack_eval_features_labels.json`
