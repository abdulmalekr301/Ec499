from __future__ import annotations

import sys
from pathlib import Path

import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secureedge import config
from secureedge.data.graph_builder import build_hetero_graph
from secureedge.data.pcap_flows import FlowCapper, PacketCapture, nfstream_to_temporal_dict
from secureedge.data.preprocess import canonical_label
from secureedge.features.temporal import TemporalFeatureExtractor


def main() -> None:
    assert canonical_label("BenignTraffic") == "Benign"
    assert canonical_label("Benign_Final") == "Benign"
    assert canonical_label("DDoS-UDP_Flood") == "DDoS"
    assert canonical_label("DictionaryBruteForce") == "BruteForce"
    assert canonical_label("SqlInjection") == "WebBased"
    assert canonical_label("VulnerabilityScan") == "Recon"
    assert canonical_label("DNS_Spoofing") == "Spoofing"

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
    with torch.no_grad():
        output = model(batch.x_dict, batch.edge_index_dict, batch.edge_attr_dict, batch.batch_dict)
    assert tuple(output.shape) == (2, config.N_CLASSES)
    assert not torch.isnan(output).any()
    print("smoke checks passed")


if __name__ == "__main__":
    main()
