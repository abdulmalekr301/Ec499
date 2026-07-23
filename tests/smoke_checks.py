from __future__ import annotations

import sys
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secureedge import config
from secureedge.data.graph_builder import build_hetero_graph
from secureedge.data.extract_worker import mac_filter_decision
from secureedge.data.office_pipeline import (
    ground_truth_window_for_row,
    is_attempted_or_non_success,
    office_candidate_requires_preslice,
    office_label_to_class,
    office_preslice_bpf_for_pairs,
    office_preslice_ip_pairs_for_pcap,
    pcap_ip_from_name,
    stratified_day_targets,
)
from secureedge.data.pcap_flows import FlowCapper, PacketCapture, nfstream_to_temporal_dict
from secureedge.data.preprocess import canonical_label
from secureedge.features.temporal import TemporalFeatureExtractor


def main() -> None:
    assert config.MAC_FILTERED_CLASSES == {name for name in config.CLASS_NAMES if name != "Benign"}

    assert canonical_label("BenignTraffic") == "Benign"
    assert canonical_label("Benign_Final") == "Benign"
    assert canonical_label("DDoS-UDP_Flood") == "DDoS"
    assert canonical_label("DictionaryBruteForce") == "BruteForce"
    assert canonical_label("SqlInjection") == "WebBased"
    assert canonical_label("VulnerabilityScan") == "Recon"
    assert canonical_label("DNS_Spoofing") == "Spoofing"
    assert office_label_to_class("BENIGN") == "Benign"
    assert office_label_to_class("FTP-BruteForce") == "BruteForce"
    assert office_label_to_class("DoS attacks-Hulk") == "DoS"
    assert office_label_to_class("DoS Hulk") == "DoS"
    assert office_label_to_class("DDOS attack-HOIC") == "DDoS"
    assert office_label_to_class("DDoS-LOIC-UDP") == "DDoS"
    assert office_label_to_class("Web Attack - SQL") == "WebBased"
    assert office_label_to_class("Bot") == "Bot"
    assert office_label_to_class("Infiltration") == "Infiltration"
    assert office_label_to_class("Infiltration - NMAP Portscan") == "Infiltration"
    assert is_attempted_or_non_success("Web Attack - Brute Force - Attempted")
    assert pcap_ip_from_name(Path("UCAP172.31.69.25-part1.pcap")) == "172.31.69.25"
    assert sum(stratified_day_targets(20000).values()) == 20000
    dos_candidate = {"day": "Friday-16-02-2018", "class_name": "DoS"}
    assert office_candidate_requires_preslice(dos_candidate)
    dos_pairs = office_preslice_ip_pairs_for_pcap("UCAP172.31.69.25-part1.pcap", [dos_candidate])
    assert ("18.219.193.20", "172.31.69.25") in dos_pairs
    assert ("172.31.70.16", "172.31.69.25") in dos_pairs
    assert "host 18.219.193.20 and host 172.31.69.25" in office_preslice_bpf_for_pairs(dos_pairs)
    assert (
        ground_truth_window_for_row(
            {
                "Src IP": "18.219.193.20",
                "Dst IP": "172.31.69.25",
                "Timestamp": "2018-02-16 17:45:27.826666",
            },
            "Friday-16-02-2018",
        ).class_name
        == "DoS"
    )
    assert (
        ground_truth_window_for_row(
            {
                "Src IP": "172.31.69.28",
                "Dst IP": "18.219.5.43",
                "Timestamp": "2018-02-21 14:08:51.251350",
            },
            "Wednesday-21-02-2018",
        )
        is None
    )
    assert (
        ground_truth_window_for_row(
            {
                "Src IP": "18.218.115.60",
                "Dst IP": "172.31.69.28",
                "Timestamp": "2018-02-22 14:17:51.336902",
            },
            "Thursday-22-02-2018",
        ).subtype
        == "Brute Force-Web"
    )

    mapped = nfstream_to_temporal_dict(
        {
            "dst_ip": "10.0.0.5",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": 6,
            "bidirectional_syn_packets": 3,
            "bidirectional_duration_ms": 2,
            "src2dst_packets": 4,
            "dst2src_packets": 5,
        }
    )
    temporal = TemporalFeatureExtractor(window_size=1).transform_row(mapped)
    assert list(temporal) == config.TEMPORAL_FEATURES
    assert mapped["SYN Flag Cnt"] == 3
    assert mapped["Flow Duration"] == 2000.0

    class Udps:
        pass

    class Flow:
        bidirectional_packets = config.FLOW_PACKET_LIMIT
        expiration_id = 0
        udps = Udps()

    class Packet:
        ip_payload_bytes = bytes(range(32))
        direction = 1
        ip_size = 64
        transport_size = 40
        payload_size = 32
        time = 1000.0

    flow = Flow()
    PacketCapture().on_init(Packet(), flow)
    assert len(flow.udps.packet_records) == 1
    assert len(flow.udps.packet_records[0]["payload"]) == config.N_PACKET_FEATURES
    FlowCapper().on_update(None, flow)
    assert flow.expiration_id == -1

    if config.ENABLE_ATTACKER_MAC_FILTER and config.ATTACKER_MACS:
        attacker_mac = next(iter(config.ATTACKER_MACS))
        assert mac_filter_decision({"src_mac": attacker_mac, "dst_mac": ""}, "WebBased")[0] is True
        assert mac_filter_decision({"src_mac": "00:00:00:00:00:01", "dst_mac": ""}, "WebBased")[0] is False

    try:
        import torch_geometric  # noqa: F401
    except ModuleNotFoundError:
        print("PyG not installed; graph/model smoke checks skipped")
        print("smoke checks passed")
        return

    flow_features = {f"feature_{index:02d}": float(index) for index in range(config.N_FLOW_FEATURES)}
    temporal_features = {name: 0.0 for name in config.TEMPORAL_FEATURES}
    graph = build_hetero_graph(
        flow_features,
        temporal_features,
        flow.udps.packet_records,
        label=0,
        subtype_label="BenignTraffic",
        class_name="Benign",
        source_file="smoke.pcap",
        source_order=0,
    )
    assert graph is not None
    assert tuple(graph["flow"].x.shape) == (1, config.N_FLOW_NODE_FEATURES)
    assert tuple(graph["packet"].x.shape) == (1, config.N_PACKET_FEATURES)

    from secureedge.models.hgnn import SecureEdgeHGNN
    from torch_geometric.loader import DataLoader

    batch = next(iter(DataLoader([graph, graph], batch_size=2)))
    model = SecureEdgeHGNN()
    assert model.bn_flow_1.eps == config.HGNN_BATCHNORM_EPS
    assert model.bn_packet_2.eps == config.HGNN_BATCHNORM_EPS
    with torch.no_grad():
        output = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
    assert tuple(output.shape) == (2, config.N_CLASSES)
    assert not torch.isnan(output).any()
    print("smoke checks passed")


if __name__ == "__main__":
    main()
