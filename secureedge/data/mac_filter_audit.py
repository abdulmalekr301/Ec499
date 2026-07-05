from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from secureedge import config
from secureedge.data.extract_worker import mac_filter_decision
from secureedge.data.pcap_flows import iter_flow_records
from secureedge.data.preprocess import canonical_label, discover_pcap_groups
from secureedge.features.temporal import TemporalFeatureExtractor
from secureedge.utils import ensure_directories, write_context


DEFAULT_SUBTYPES = [
    "Backdoor_Malware",
    "BrowserHijacking",
    "CommandInjection",
    "SqlInjection",
    "Uploading_Attack",
    "XSS",
    "DictionaryBruteForce",
    "DDoS-HTTP_Flood",
    "DDoS-SYN_Flood",
    "DDoS-UDP_Flood",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit attacker-MAC filtering attrition by subtype.")
    parser.add_argument("--subtype", action="append", dest="subtypes", help="Subtype to audit. Repeatable.")
    parser.add_argument("--max-flows-per-subtype", type=int, default=20000)
    parser.add_argument("--max-files-per-subtype", type=int, default=4)
    parser.add_argument("--top-pairs", type=int, default=12)
    parser.add_argument("--report", type=Path, default=config.ARTIFACTS_DIR / "mac_filter_audit.json")
    return parser.parse_args()


def mac_pair(flow_record: dict[str, object]) -> tuple[str, str]:
    return (
        config.normalize_mac_address(flow_record.get("src_mac", "")),
        config.normalize_mac_address(flow_record.get("dst_mac", "")),
    )


def pair_label(pair: tuple[str, str]) -> str:
    return f"{pair[0] or '<missing>'} -> {pair[1] or '<missing>'}"


def audit_subtype(subtype: str, paths: list[Path], max_flows: int, max_files: int, top_pairs: int) -> dict[str, object]:
    class_name = canonical_label(subtype)
    if class_name is None:
        return {"subtype": subtype, "skipped": "unknown_class"}

    extractor = TemporalFeatureExtractor(window_size=config.TEMPORAL_WINDOW_SIZE)
    reasons: Counter[str] = Counter()
    pair_counts: Counter[tuple[str, str]] = Counter()
    kept_pair_counts: Counter[tuple[str, str]] = Counter()
    dropped_pair_counts: Counter[tuple[str, str]] = Counter()
    attacker_mac_hits: Counter[str] = Counter()
    files_processed: list[str] = []
    total = 0
    kept = 0
    dropped = 0
    missing = 0

    for pcap_path in paths[:max_files]:
        files_processed.append(str(pcap_path))
        for flow_record in iter_flow_records(pcap_path, subtype, extractor):
            pair = mac_pair(flow_record)
            pair_counts[pair] += 1
            total += 1
            if not pair[0] and not pair[1]:
                missing += 1
            for mac in pair:
                if mac in config.ATTACKER_MACS:
                    attacker_mac_hits[mac] += 1
            keep_flow, reason = mac_filter_decision(flow_record, class_name)
            reasons[reason] += 1
            if keep_flow:
                kept += 1
                kept_pair_counts[pair] += 1
            else:
                dropped += 1
                dropped_pair_counts[pair] += 1
            if total >= max_flows:
                break
        if total >= max_flows:
            break

    return {
        "subtype": subtype,
        "class_name": class_name,
        "files_processed": files_processed,
        "flows_examined": total,
        "kept_by_current_filter": kept,
        "dropped_by_current_filter": dropped,
        "missing_mac_flows": missing,
        "kept_fraction": kept / max(total, 1),
        "reasons": dict(reasons),
        "attacker_mac_hits": dict(attacker_mac_hits),
        "top_mac_pairs": [
            {"pair": pair_label(pair), "count": count}
            for pair, count in pair_counts.most_common(top_pairs)
        ],
        "top_kept_pairs": [
            {"pair": pair_label(pair), "count": count}
            for pair, count in kept_pair_counts.most_common(top_pairs)
        ],
        "top_dropped_pairs": [
            {"pair": pair_label(pair), "count": count}
            for pair, count in dropped_pair_counts.most_common(top_pairs)
        ],
    }


def summarize_by_class(subtype_results: list[dict[str, object]]) -> dict[str, object]:
    class_summary: dict[str, dict[str, object]] = defaultdict(
        lambda: {"flows_examined": 0, "kept": 0, "dropped": 0, "reasons": Counter()}
    )
    for result in subtype_results:
        if result.get("skipped"):
            continue
        class_name = str(result["class_name"])
        item = class_summary[class_name]
        item["flows_examined"] = int(item["flows_examined"]) + int(result["flows_examined"])
        item["kept"] = int(item["kept"]) + int(result["kept_by_current_filter"])
        item["dropped"] = int(item["dropped"]) + int(result["dropped_by_current_filter"])
        item["reasons"].update(result["reasons"])

    output = {}
    for class_name, item in sorted(class_summary.items()):
        total = int(item["flows_examined"])
        output[class_name] = {
            "flows_examined": total,
            "kept": int(item["kept"]),
            "dropped": int(item["dropped"]),
            "kept_fraction": int(item["kept"]) / max(total, 1),
            "reasons": dict(item["reasons"]),
        }
    return output


def write_markdown_report(payload: dict[str, object]) -> None:
    lines = [
        "## Action",
        "- Streamed selected PCAP flows to audit attacker-MAC filtering attrition.",
        "- Counted current filter keep/drop decisions by subtype and class.",
        "- Compared WebBased/BruteForce against representative DDoS subtypes.",
        f"- JSON report: `{payload['report']}`.",
        "",
        "## Class Summary",
        "```json",
        json.dumps(payload["class_summary"], indent=2),
        "```",
        "",
        "## Interpretation",
        str(payload["interpretation"]),
    ]
    write_context("46_data_strategy_mac_filter_audit.md", "Data Strategy MAC Filter Audit", lines)


def interpret(class_summary: dict[str, object]) -> str:
    web = class_summary.get("WebBased", {})
    brute = class_summary.get("BruteForce", {})
    ddos = class_summary.get("DDoS", {})
    web_keep = float(web.get("kept_fraction", 0.0) or 0.0)
    brute_keep = float(brute.get("kept_fraction", 0.0) or 0.0)
    ddos_keep = float(ddos.get("kept_fraction", 0.0) or 0.0)
    if web_keep >= 0.95 and brute_keep >= 0.95 and ddos_keep >= 0.5:
        return (
            "Class-conditional filtering is active: WebBased/BruteForce are being retained by "
            "filename/subtype labeling while DDoS remains validated by attacker-MAC filtering."
        )
    if (web_keep < 0.5 or brute_keep < 0.5) and ddos_keep >= 0.5:
        return (
            "WebBased/BruteForce have substantially lower attacker-MAC match rates than the DDoS control. "
            "This supports the data-strategy concern that the current universal attacker-MAC filter may be "
            "discarding valid WebBased/BruteForce flows, or that these classes use different attacker devices "
            "than the current attacker MAC list."
        )
    return (
        "The sampled attacker-MAC match rates do not show a clear WebBased/BruteForce-specific attrition pattern. "
        "If scarcity remains, it is more likely genuine for the audited PCAPs or caused by another preprocessing limit."
    )


def main() -> None:
    args = parse_args()
    ensure_directories()
    if config.ENABLE_ATTACKER_MAC_FILTER and not config.ATTACKER_MACS:
        raise ValueError("MAC filter audit requires attacker MACs when SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1.")
    pcap_groups = discover_pcap_groups()
    requested = args.subtypes or DEFAULT_SUBTYPES
    results = []
    for subtype in requested:
        paths = pcap_groups.get(subtype, [])
        if not paths:
            results.append({"subtype": subtype, "skipped": "no_pcap_files"})
            continue
        print(f"[mac_filter_audit] {subtype}: files={len(paths)}", flush=True)
        results.append(audit_subtype(subtype, paths, args.max_flows_per_subtype, args.max_files_per_subtype, args.top_pairs))

    class_summary = summarize_by_class(results)
    payload = {
        "attacker_mac_count": len(config.ATTACKER_MACS),
        "attacker_macs": sorted(config.ATTACKER_MACS),
        "max_flows_per_subtype": args.max_flows_per_subtype,
        "max_files_per_subtype": args.max_files_per_subtype,
        "subtype_results": results,
        "class_summary": class_summary,
        "interpretation": interpret(class_summary),
        "report": str(args.report),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_markdown_report(payload)
    print(json.dumps({"report": str(args.report), "class_summary": class_summary}, indent=2))


if __name__ == "__main__":
    main()
