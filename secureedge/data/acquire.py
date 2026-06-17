from __future__ import annotations

import pandas as pd

from secureedge import config
from secureedge.data.preprocess import discover_pcap_files, validate_pcap_class_coverage
from secureedge.utils import ensure_directories, write_context


def ensure_raw_data() -> list:
    ensure_directories()
    pcap_files = discover_pcap_files()
    if not pcap_files:
        raise FileNotFoundError(f"No .pcap files found under {config.PCAP_DIR}")
    coverage = validate_pcap_class_coverage(pcap_files)
    total_bytes = sum(path.stat().st_size for path in pcap_files)
    write_context(
        "01_dataset_acquisition.md",
        "PCAP Dataset Acquisition",
        [
            "## Action",
            f"- Using `{config.PCAP_DIR}` as the raw dataset source.",
            f"- Found `{len(pcap_files)}` PCAP files.",
            f"- Total PCAP size: `{total_bytes / (1024 ** 3):.2f} GiB`.",
            "- The CSV export is ignored by the active NFStream PCAP pipeline.",
            "",
            "## Class Coverage",
            "```text",
            pd.Series({class_name: len(files) for class_name, files in coverage.items()}).to_string(),
            "```",
        ],
    )
    return pcap_files


def main() -> None:
    pcap_files = ensure_raw_data()
    print(f"Raw PCAP directory: {config.PCAP_DIR}")
    print(f"PCAP files: {len(pcap_files)}")


if __name__ == "__main__":
    main()
