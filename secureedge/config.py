from __future__ import annotations

import os
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

ZIP_PATH = ROOT_DIR / "CSV.zip"
PCAP_DIR = ROOT_DIR / "PCAPs"
RAW_DATA_DIR = ROOT_DIR / "data" / "raw"
RAW_CSV_DIR = RAW_DATA_DIR / "CSV"
PROCESSED_DIR = ROOT_DIR / "data" / "processed"
GRAPH_DIR = ROOT_DIR / "data" / "graphs"
GRAPH_TRAIN_DIR = GRAPH_DIR / "train"
GRAPH_VAL_DIR = GRAPH_DIR / "val"
GRAPH_TEST_DIR = GRAPH_DIR / "test"
GRAPH_TRAIN_SHARD_DIR = GRAPH_DIR / "train_shards"
GRAPH_VAL_SHARD_DIR = GRAPH_DIR / "val_shards"
GRAPH_TEST_SHARD_DIR = GRAPH_DIR / "test_shards"
GRAPH_RESERVOIR_DIR = GRAPH_DIR / "_reservoir"
PCAP_CHUNK_DIR = RAW_DATA_DIR / "pcap_chunks"
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
CONTEXT_DIR = ROOT_DIR / "context"

STANDARD_TRAIN_PATH = PROCESSED_DIR / "train_standard.csv"
STANDARD_TEST_PATH = PROCESSED_DIR / "test_standard.csv"
FEATURE_TRAIN_PATH = PROCESSED_DIR / "train_features.csv"
FEATURE_TEST_PATH = PROCESSED_DIR / "test_features.csv"

STANDARD_SCALER_PATH = ARTIFACTS_DIR / "standard_scaler.joblib"
FEATURE_SCALER_PATH = ARTIFACTS_DIR / "feature_scaler.joblib"
FEATURE_COLUMNS_PATH = ARTIFACTS_DIR / "feature_columns.json"
BEST_CHECKPOINT_PATH = ARTIFACTS_DIR / "best_model.pt"
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
OOD_THRESHOLD_PATH = ARTIFACTS_DIR / "ood_threshold.json"
TORCHSCRIPT_PATH = ARTIFACTS_DIR / "secureedge_model.ts"
FLOW_NODE_SCALER_PATH = ARTIFACTS_DIR / "flow_node_scaler.joblib"
CONTAIN_EDGE_SCALER_PATH = ARTIFACTS_DIR / "contain_edge_scaler.joblib"
LINK_EDGE_NORM_PATH = ARTIFACTS_DIR / "link_edge_norm_p99.json"
FLOW_FEATURE_ORDER_PATH = ARTIFACTS_DIR / "flow_feature_order.json"
COMPACT_RESERVOIR_MANIFEST_PATH = ARTIFACTS_DIR / "compact_reservoir_manifest.json"
GRAPH_MANIFEST_PATH = ARTIFACTS_DIR / "graph_dataset_manifest.json"
GRAPH_SHARD_MANIFEST_PATH = ARTIFACTS_DIR / "graph_shard_manifest.json"
HGNN_CHECKPOINT_PATH = ARTIFACTS_DIR / "best_hgnn.pt"
HGNN_TORCHSCRIPT_PATH = ARTIFACTS_DIR / "secureedge_hgnn.ts"
TRAINING_RUNS_DIR = ARTIFACTS_DIR / "training_runs"
RESUME_CHECKPOINT_PATH = Path(os.getenv("SECUREEDGE_RESUME_CHECKPOINT_PATH", str(HGNN_CHECKPOINT_PATH)))


def normalize_mac_address(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", ":").replace(".", "")
    if not text:
        return ""
    if ":" in text:
        parts = [part.zfill(2) for part in text.split(":") if part]
        if len(parts) == 6 and all(len(part) == 2 for part in parts):
            return ":".join(parts)
    hex_only = "".join(char for char in text if char in "0123456789abcdef")
    if len(hex_only) == 12:
        return ":".join(hex_only[index : index + 2] for index in range(0, 12, 2))
    return text


def parse_mac_set(raw: str) -> set[str]:
    values = re.split(r"[\s,;]+", raw.strip()) if raw.strip() else []
    return {normalized for value in values if (normalized := normalize_mac_address(value))}


def parse_mac_file(path_value: str) -> set[str]:
    if not path_value.strip():
        return set()
    path = Path(path_value)
    if not path.is_absolute():
        path = ROOT_DIR / path
    if not path.exists():
        raise FileNotFoundError(f"Attacker MAC file not found: {path}")
    return parse_mac_set(path.read_text(encoding="utf-8"))

LABEL_COLUMNS = ("Attack_type", "label", "Label")
LABEL_COLUMN = "label"
SUBTYPE_COLUMN = "subtype_label"
CLASS_COLUMN = "class_name"
TARGET_COLUMN = "class_index"
SOURCE_FILE_COLUMN = "source_file"
SOURCE_ORDER_COLUMN = "source_order"

NFSTREAM_METADATA_COLUMNS = {
    "id",
    "expiration_id",
    "src_ip",
    "src_mac",
    "src_oui",
    "dst_ip",
    "dst_mac",
    "dst_oui",
    "ip_version",
    "vlan_id",
    "tunnel_id",
    "application_name",
    "application_category_name",
    "application_is_guessed",
    "application_confidence",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type",
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms",
    "src2dst_last_seen_ms",
    "dst2src_first_seen_ms",
    "dst2src_last_seen_ms",
}

CLASS_NAMES = [
    "Benign",
    "DDoS",
    "DoS",
    "Mirai",
    "Recon",
    "Spoofing",
    "WebBased",
    "BruteForce",
]
CLASS_TO_INDEX = {name: idx for idx, name in enumerate(CLASS_NAMES)}
MAC_FILTERED_CLASSES = {name for name in CLASS_NAMES if name != "Benign"}

SUBTYPE_TO_CLASS = {
    "DDoS-ACK_Fragmentation": "DDoS",
    "DDoS-HTTP_Flood": "DDoS",
    "DDoS-ICMP_Flood": "DDoS",
    "DDoS-ICMP_Fragmentation": "DDoS",
    "DDoS-PSHACK_Flood": "DDoS",
    "DDoS-RSTFINFlood": "DDoS",
    "DDoS-SYN_Flood": "DDoS",
    "DDoS-SlowLoris": "DDoS",
    "DDoS-SynonymousIP_Flood": "DDoS",
    "DDoS-TCP_Flood": "DDoS",
    "DDoS-UDP_Flood": "DDoS",
    "DDoS-UDP_Fragmentation": "DDoS",
    "DoS-HTTP_Flood": "DoS",
    "DoS-SYN_Flood": "DoS",
    "DoS-TCP_Flood": "DoS",
    "DoS-UDP_Flood": "DoS",
    "Mirai-greeth_flood": "Mirai",
    "Mirai-greip_flood": "Mirai",
    "Mirai-udpplain": "Mirai",
    "Recon-HostDiscovery": "Recon",
    "Recon-OSScan": "Recon",
    "Recon-PingSweep": "Recon",
    "Recon-PortScan": "Recon",
    "VulnerabilityScan": "Recon",
    "DNS_Spoofing": "Spoofing",
    "MITM-ArpSpoofing": "Spoofing",
    "SqlInjection": "WebBased",
    "XSS": "WebBased",
    "BrowserHijacking": "WebBased",
    "CommandInjection": "WebBased",
    "Uploading_Attack": "WebBased",
    "Backdoor_Malware": "WebBased",
    "DictionaryBruteForce": "BruteForce",
    "Benign_Final": "Benign",
    "BenignTraffic": "Benign",
}

WEB_BASED_LABELS = {
    "sqlinjection",
    "xss",
    "mqtt-publish",
    "commandinjection",
    "uploading_attack",
    "backdoor_malware",
    "browserhijacking",
    "browser hijacking",
}

RANDOM_SEED = 42
TEST_SAMPLES_PER_CLASS = int(os.getenv("SECUREEDGE_TEST_SAMPLES_PER_CLASS", "2000"))
VAL_SAMPLES_PER_CLASS = int(os.getenv("SECUREEDGE_VAL_SAMPLES_PER_CLASS", "2000"))
TRAIN_SAMPLES_PER_CLASS = int(os.getenv("SECUREEDGE_TRAIN_SAMPLES_PER_CLASS", "20000"))
PROPORTIONAL_SPLIT_THRESHOLD = int(
    os.getenv(
        "SECUREEDGE_PROPORTIONAL_SPLIT_THRESHOLD",
        str(TRAIN_SAMPLES_PER_CLASS + VAL_SAMPLES_PER_CLASS + TEST_SAMPLES_PER_CLASS),
    )
)
TEMPORAL_WINDOW_SIZE = 375

VULNERABLE_PORTS = {
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    1433,
    1521,
    3306,
    3389,
    5900,
    8080,
    8443,
}

HTTP_PORTS = {80, 443, 8080, 8443}

TEMPORAL_FEATURES = [
    "Rolling_UDP_Sum",
    "Rolling_TCP_Sum",
    "Rolling_ACK_Sum",
    "Rolling_FIN_Sum",
    "Rolling_RST_Sum",
    "Rolling_fin_Sum",
    "Rolling_psh_Sum",
    "Rolling_SYN_Sum",
    "Rolling_ICMP_Sum",
    "Rolling_http_port",
    "Rolling_Average_Duration",
    "Rolling_DNS_Sum",
    "Rolling_vulnerable_port",
    "Rolling_packets_Sum",
    "Rolling_bipackets_Sum",
    "Unique_Ports_In_SourceDestination",
]

NFSTREAM_STAT_FEATURES = [
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    "dst2src_max_ps",
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_max_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_cwr_packets",
    "bidirectional_ece_packets",
    "bidirectional_urg_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "src2dst_syn_packets",
    "src2dst_cwr_packets",
    "src2dst_ece_packets",
    "src2dst_urg_packets",
    "src2dst_ack_packets",
    "src2dst_psh_packets",
    "src2dst_rst_packets",
    "src2dst_fin_packets",
    "dst2src_syn_packets",
    "dst2src_cwr_packets",
    "dst2src_ece_packets",
    "dst2src_urg_packets",
    "dst2src_ack_packets",
    "dst2src_psh_packets",
    "dst2src_rst_packets",
    "dst2src_fin_packets",
]
FLOW_CORE_FEATURES = [
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_duration_ms",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_duration_ms",
    "dst2src_packets",
    "dst2src_bytes",
]
FLOW_ID_FEATURES = ["src_port", "dst_port", "protocol"]
ACTIVE_IDLE_FEATURES = [
    "bidirectional_mean_active_ms",
    "bidirectional_std_active_ms",
    "bidirectional_max_active_ms",
    "bidirectional_min_active_ms",
    "bidirectional_mean_idle_ms",
    "bidirectional_std_idle_ms",
    "bidirectional_max_idle_ms",
    "bidirectional_min_idle_ms",
]
DERIVED_FLOW_FEATURES = [
    "bidirectional_bytes_per_second",
    "bidirectional_packets_per_second",
    "src2dst_bytes_per_second",
    "src2dst_packets_per_second",
    "dst2src_bytes_per_second",
    "dst2src_packets_per_second",
    "down_up_bytes_ratio",
    "average_packet_size",
]
BASE_FLOW_FEATURES = NFSTREAM_STAT_FEATURES + FLOW_CORE_FEATURES + FLOW_ID_FEATURES + ACTIVE_IDLE_FEATURES
FLOW_FEATURE_ORDER = BASE_FLOW_FEATURES + DERIVED_FLOW_FEATURES
N_ACTIVE_IDLE_FEATURES = len(ACTIVE_IDLE_FEATURES)
N_DERIVED_FEATURES = len(DERIVED_FLOW_FEATURES)
N_FLOW_FEATURES = len(FLOW_FEATURE_ORDER)
N_TEMPORAL_FEATURES = len(TEMPORAL_FEATURES)
N_FLOW_NODE_FEATURES = N_FLOW_FEATURES + N_TEMPORAL_FEATURES
N_PACKET_FEATURES = 1500
N_CONTAIN_EDGE_FEATS = 4
N_LINK_EDGE_FEATS = 1
N_CLASSES = len(CLASS_NAMES)
FLOW_FEATURE_COLS: list[str] = []
INPUT_DIM = N_FLOW_NODE_FEATURES

MLP_HIDDEN_DIMS = (256, 128, 64)
DROPOUT_RATE = 0.4
BATCH_SIZE = int(os.getenv("SECUREEDGE_BATCH_SIZE", "512"))
GRAD_ACCUM_STEPS = int(os.getenv("SECUREEDGE_GRAD_ACCUM_STEPS", "1"))
EVAL_BATCH_SIZE = int(os.getenv("SECUREEDGE_EVAL_BATCH_SIZE", str(BATCH_SIZE)))
USE_AMP = os.getenv("SECUREEDGE_USE_AMP", "1") == "1"
HGNN_HIDDEN_SIZE = 64
HGNN_ATTN_SIZE = 32
HGNN_LEAKY_RELU_SLOPE = 0.01
HGNN_BATCHNORM_EPS = float(os.getenv("SECUREEDGE_HGNN_BATCHNORM_EPS", "1.0"))
USE_PAYLOAD_ENCODER = os.getenv("SECUREEDGE_USE_PAYLOAD_ENCODER", "0") == "1"
PAYLOAD_ENCODER_CHANNELS = 32
PAYLOAD_ENCODER_KERNEL_SIZE = 7
PAYLOAD_ENCODER_DROPOUT = 0.1
HGNN_READOUT_MODE = os.getenv("SECUREEDGE_HGNN_READOUT_MODE", "concat").lower()
WARMUP_START_LR = float(os.getenv("SECUREEDGE_LR_START", "3e-4"))
LEARNING_RATE = float(os.getenv("SECUREEDGE_LR_TARGET", "3e-3"))
MIN_LEARNING_RATE = float(os.getenv("SECUREEDGE_LR_MIN", "1e-5"))
WARMUP_EPOCHS = int(os.getenv("SECUREEDGE_WARMUP_EPOCHS", "5"))
WEIGHT_DECAY = 1e-5
MAX_EPOCHS = int(os.getenv("SECUREEDGE_MAX_EPOCHS", "300"))
EARLY_STOPPING_PATIENCE = int(os.getenv("SECUREEDGE_EARLY_STOP", os.getenv("SECUREEDGE_EARLY_STOPPING_PATIENCE", "50")))
LR_SCHEDULER_PATIENCE = int(os.getenv("SECUREEDGE_LR_SCHEDULER_PATIENCE", "5"))
LR_SCHEDULER = os.getenv("SECUREEDGE_SCHEDULER", "cosine").lower()
PLATEAU_THRESHOLD = float(os.getenv("SECUREEDGE_LR_PLATEAU_THRESHOLD", "0.01"))
PLATEAU_MONITOR = os.getenv("SECUREEDGE_PLATEAU_MONITOR", "val_macro_f1").lower()
COSINE_T0 = int(os.getenv("SECUREEDGE_COSINE_T0", "50"))
COSINE_T_MULT = int(os.getenv("SECUREEDGE_COSINE_T_MULT", "2"))
LABEL_SMOOTHING = float(os.getenv("SECUREEDGE_LABEL_SMOOTHING", "0.0"))
GRAD_CLIP_MAX_NORM = 1.0
PRINT_CLASS_EVERY = int(os.getenv("SECUREEDGE_PRINT_CLASS_EVERY", "10"))
NUM_WORKERS = int(os.getenv("SECUREEDGE_NUM_WORKERS", "0"))
PREFETCH_FACTOR = int(os.getenv("SECUREEDGE_PREFETCH_FACTOR", "2"))
TRAIN_LIMIT_PER_CLASS = int(os.getenv("SECUREEDGE_TRAIN_LIMIT_PER_CLASS", "0"))
EVAL_LIMIT_PER_CLASS = int(os.getenv("SECUREEDGE_EVAL_LIMIT_PER_CLASS", "0"))
DEVICE = os.getenv("SECUREEDGE_DEVICE", "auto").lower()
USE_GRAPH_SHARDS = os.getenv("SECUREEDGE_USE_GRAPH_SHARDS", "1") == "1"
GRAPH_SHARD_SIZE = int(os.getenv("SECUREEDGE_GRAPH_SHARD_SIZE", "1000"))
GRAPH_VALUE_MODE = os.getenv("SECUREEDGE_GRAPH_VALUE_MODE", "scaled").lower()
RAW_DERIVED_FLOW_TRANSFORM = os.getenv("SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM", "log1p").lower()
WEBBASED_SUBTYPE_BALANCING = os.getenv("SECUREEDGE_WEBBASED_SUBTYPE_BALANCING", "capped_floor").lower()
WEBBASED_SUBTYPE_FLOOR_FRACTION = float(os.getenv("SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION", "0.10"))
WEBBASED_SUBTYPE_CEILING_FRACTION = float(os.getenv("SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION", "0.30"))
RESUME_FROM_CHECKPOINT = os.getenv("SECUREEDGE_RESUME_FROM_CHECKPOINT", "0") == "1"
RESUME_LOAD_OPTIMIZER = os.getenv("SECUREEDGE_RESUME_LOAD_OPTIMIZER", "1") == "1"
RESUME_LOAD_SCHEDULER = os.getenv("SECUREEDGE_RESUME_LOAD_SCHEDULER", "1") == "1"
ENABLE_ATTACKER_MAC_FILTER = os.getenv("SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER", "0") == "1"
BENIGN_ONLY_ENFORCE = os.getenv("SECUREEDGE_BENIGN_ONLY_ENFORCE", "1") == "1"
ATTACKER_MACS_FILE = os.getenv("SECUREEDGE_ATTACKER_MACS_FILE", "")
ATTACKER_MACS = parse_mac_set(os.getenv("SECUREEDGE_ATTACKER_MACS", "")) | parse_mac_file(ATTACKER_MACS_FILE)

FLOW_PACKET_LIMIT = 20
FLOW_SEGMENT_PACKET_LIMIT = int(os.getenv("SECUREEDGE_FLOW_SEGMENT_PACKET_LIMIT", "0"))
FLOW_IDLE_TIMEOUT_SECONDS = 120.0
MAX_ACTIVE_FLOWS = int(os.getenv("SECUREEDGE_MAX_ACTIVE_FLOWS", "200000"))
PCAP_RECORD_BUFFER_SIZE = int(os.getenv("SECUREEDGE_PCAP_RECORD_BUFFER_SIZE", "10000"))
ALLOW_FULL_PREPROCESS = os.getenv("SECUREEDGE_ALLOW_FULL_PREPROCESS", "0") == "1"
ALLOW_UNSAFE_PREPROCESS = os.getenv("SECUREEDGE_ALLOW_UNSAFE_PREPROCESS", "0") == "1"
ALLOW_AUTOMATIC_PCAP_SPLITTING = os.getenv("SECUREEDGE_ALLOW_AUTOMATIC_PCAP_SPLITTING", "0") == "1"
USE_SPLIT_PCAP_CHUNKS = os.getenv("SECUREEDGE_USE_SPLIT_PCAP_CHUNKS", "1") == "1"
MIN_AVAILABLE_MEMORY_GB = float(os.getenv("SECUREEDGE_MIN_AVAILABLE_MEMORY_GB", "2.0"))
MAX_PROCESS_RSS_GB = float(os.getenv("SECUREEDGE_MAX_PROCESS_RSS_GB", "2.0"))
PCAP_CHUNK_THRESHOLD_MB = int(os.getenv("SECUREEDGE_PCAP_CHUNK_THRESHOLD_MB", "64"))
PCAP_CHUNK_SIZE_MB = int(os.getenv("SECUREEDGE_PCAP_CHUNK_SIZE_MB", "16"))
PCAP_MEMORY_CHECK_INTERVAL = int(os.getenv("SECUREEDGE_PCAP_MEMORY_CHECK_INTERVAL", "50"))
PCAP_WORKER_TIMEOUT_SECONDS = int(os.getenv("SECUREEDGE_PCAP_WORKER_TIMEOUT_SECONDS", "1800"))
PCAP_SPLIT_MIN_AVAILABLE_MEMORY_GB = float(os.getenv("SECUREEDGE_PCAP_SPLIT_MIN_AVAILABLE_MEMORY_GB", "6.0"))
PCAP_SPLIT_POLL_SECONDS = float(os.getenv("SECUREEDGE_PCAP_SPLIT_POLL_SECONDS", "2.0"))
PCAP_SPLIT_PAUSE_SECONDS = float(os.getenv("SECUREEDGE_PCAP_SPLIT_PAUSE_SECONDS", "10.0"))

PCAP_FEATURE_COLUMNS = [
    "Header_Length",
    "Protocol Type",
    "Time_To_Live",
    "Rate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IGMP",
    "IPv",
    "LLC",
    "Tot sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot size",
    "IAT",
    "Number",
    "Variance",
    "Flow_Duration",
    "Src_Port",
    "Dst_Port",
    "Src_IP_Int",
    "Dst_IP_Int",
    "Fwd_Packet_Count",
    "Bwd_Packet_Count",
    "Fwd_Byte_Count",
    "Bwd_Byte_Count",
    "Fwd_Header_Length",
    "Bwd_Header_Length",
    "Fwd_Min",
    "Fwd_Max",
    "Fwd_AVG",
    "Fwd_Std",
    "Bwd_Min",
    "Bwd_Max",
    "Bwd_AVG",
    "Bwd_Std",
    "Packet_Length_Mean",
    "Packet_Length_Std",
    "Packet_Length_Variance",
    "Packet_Length_Median",
    "Packet_Length_Q1",
    "Packet_Length_Q3",
    "IAT_Min",
    "IAT_Max",
    "IAT_Mean",
    "IAT_Std",
    "Fwd_IAT_Mean",
    "Bwd_IAT_Mean",
    "Bytes_Per_Second",
    "Packets_Per_Second",
    "Down_Up_Ratio",
    "Average_Packet_Size",
    "Active_Time",
    "Idle_Time",
    "Unique_Src_Ports",
    "Unique_Dst_Ports",
    "Src_To_Dst_Byte_Ratio",
    "Dst_To_Src_Byte_Ratio",
]
