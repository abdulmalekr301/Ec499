# CIC-IDS-2017 Thursday WebBased Attack IP Map

## Purpose

This document records the official IP/time-window map for the **CIC-IDS-2017 Thursday WebBased attacks**. These samples may be used as a supplementary WebBased source for the enterprise SecureEdge/XG-NID-style model.

## Dataset

| Field | Value |
|---|---|
| Dataset | CIC-IDS-2017 |
| Day | Thursday, July 6, 2017 |
| Target final class | WebBased |
| Attack group | Web Attack |
| Main attacks | Web Brute Force, XSS, SQL Injection |

## Official WebBased Attack Windows

| Day | Attack | Final class | Attacker | Attacker IP | Firewall public IP | Firewall internal IP | Victim | Victim public IP | Victim local IP | Time |
|---|---|---|---|---|---|---|---|---|---|---|
| Thursday, July 6, 2017 | Web Attack - Brute Force | WebBased | Kali | `205.174.165.73` | `205.174.165.80` | `172.16.0.1` | WebServer Ubuntu | `205.174.165.68` | `192.168.10.50` | `09:20-10:00` |
| Thursday, July 6, 2017 | Web Attack - XSS | WebBased | Kali | `205.174.165.73` | `205.174.165.80` | `172.16.0.1` | WebServer Ubuntu | `205.174.165.68` | `192.168.10.50` | `10:15-10:35` |
| Thursday, July 6, 2017 | Web Attack - SQL Injection | WebBased | Kali | `205.174.165.73` | `205.174.165.80` | `172.16.0.1` | WebServer Ubuntu | `205.174.165.68` | `192.168.10.50` | `10:40-10:42` |

## NAT Path

The Thursday WebBased attacks pass through the firewall/NAT path.

### Attack path

```text
205.174.165.73
→ 205.174.165.80
→ 172.16.0.1
→ 192.168.10.50
```

### Reply path

```text
192.168.10.50
→ 172.16.0.1
→ 205.174.165.80
→ 205.174.165.73
```

## YAML-Style Map for Coding Agent

```yaml
Thursday-06-07-2017:
  dataset: CIC-IDS-2017
  final_class: WebBased

  attacker:
    host: Kali
    ip: 205.174.165.73

  firewall:
    public_ip: 205.174.165.80
    internal_ip: 172.16.0.1

  victim:
    host: WebServer Ubuntu
    public_ip: 205.174.165.68
    local_ip: 192.168.10.50

  attacks:
    - attack: Web Attack - Brute Force
      class: WebBased
      start: "09:20"
      finish: "10:00"

    - attack: Web Attack - XSS
      class: WebBased
      start: "10:15"
      finish: "10:35"

    - attack: Web Attack - SQL Injection
      class: WebBased
      start: "10:40"
      finish: "10:42"

  nat_path:
    attack: "205.174.165.73 -> 205.174.165.80 -> 172.16.0.1 -> 192.168.10.50"
    reply: "192.168.10.50 -> 172.16.0.1 -> 205.174.165.80 -> 205.174.165.73"
```

## Labeling Rule for Graph Generation

For CIC-IDS-2017 Thursday WebBased traffic:

```text
time window + attacker/victim IP path match → WebBased
outside web attack windows + not involving attack path → Benign candidate
```

Recommended WebBased windows:

```text
09:20-10:00 → Web Attack - Brute Force
10:15-10:35 → Web Attack - XSS
10:40-10:42 → Web Attack - SQL Injection
```

## Important Note

Thursday afternoon in CIC-IDS-2017 contains **Infiltration**, not WebBased. For WebBased supplementation, only use the Thursday morning attack windows listed above.
