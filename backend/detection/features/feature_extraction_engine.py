"""
Feature Extraction Engine — final version.
Computes the full CICIDS2017 feature set from raw packet-level data
retained by FlowManager. Feature NAMES match the exact training column
strings (including known dataset quirks like "Fwd Header Length.1").
"""

from backend.config import PROTOCOL_NUMERIC_MAP
from backend.detection.features.features_metadata import feature_metadata, FeatureMetadataError
from backend.core.logger import get_logger

logger = get_logger(__name__)


def _stats(values: list) -> dict:
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "variance": 0.0}
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    return {"mean": mean, "std": variance ** 0.5, "max": max(values), "min": min(values), "variance": variance}


def _iat_stats(timestamps: list) -> dict:
    ts = sorted(timestamps)
    if len(ts) < 2:
        return {"total": 0.0, "mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
    diffs_us = [(ts[i + 1] - ts[i]) * 1_000_000 for i in range(len(ts) - 1)]
    s = _stats(diffs_us)
    return {"total": sum(diffs_us), "mean": s["mean"], "std": s["std"], "max": s["max"], "min": s["min"]}


class FeatureExtractionEngine:

    def compute(self, flow: dict) -> dict:
        # ... (unchanged from previous message — full CICIDS2017 computation) ...
        fwd_lengths = flow.get("fwd_packet_lengths", [])
        bwd_lengths = flow.get("bwd_packet_lengths", [])
        all_lengths = flow.get("packet_lengths", [])

        fwd_ts = flow.get("fwd_timestamps", [])
        bwd_ts = flow.get("bwd_timestamps", [])
        all_ts = flow.get("packet_timestamps", [])

        total_fwd_packets = len(fwd_lengths)
        total_bwd_packets = len(bwd_lengths)
        total_fwd_bytes = sum(fwd_lengths)
        total_bwd_bytes = sum(bwd_lengths)
        total_packets = total_fwd_packets + total_bwd_packets
        total_bytes = total_fwd_bytes + total_bwd_bytes

        if len(all_ts) >= 2:
            duration_seconds = max(max(all_ts) - min(all_ts), 1e-6)
        else:
            duration_seconds = 1e-6

        pkt_len_stats = _stats(all_lengths)
        fwd_len_stats = _stats(fwd_lengths)
        bwd_len_stats = _stats(bwd_lengths)

        flow_iat = _iat_stats(all_ts)
        fwd_iat = _iat_stats(fwd_ts)
        bwd_iat = _iat_stats(bwd_ts)

        active_us = [t * 1_000_000 for t in flow.get("active_times", [])]
        idle_us = [t * 1_000_000 for t in flow.get("idle_times", [])]
        active_stats = _stats(active_us)
        idle_stats = _stats(idle_us)

        flags = flow.get("flag_counts", {})
        fwd_psh = flow.get("fwd_psh_count", 0)
        bwd_psh = flow.get("bwd_psh_count", 0)
        fwd_urg = flow.get("fwd_urg_count", 0)
        bwd_urg = flow.get("bwd_urg_count", 0)

        fwd_header_lengths = flow.get("fwd_header_lengths", [])
        bwd_header_lengths = flow.get("bwd_header_lengths", [])
        fwd_header_total = sum(fwd_header_lengths)
        bwd_header_total = sum(bwd_header_lengths)

        fwd_bulk_bytes = flow.get("fwd_bulk_total_bytes", 0)
        fwd_bulk_packets = flow.get("fwd_bulk_total_packets", 0)
        fwd_bulk_count = flow.get("fwd_bulk_count", 0)
        fwd_bulk_duration = flow.get("fwd_bulk_total_duration", 0.0)

        bwd_bulk_bytes = flow.get("bwd_bulk_total_bytes", 0)
        bwd_bulk_packets = flow.get("bwd_bulk_total_packets", 0)
        bwd_bulk_count = flow.get("bwd_bulk_count", 0)
        bwd_bulk_duration = flow.get("bwd_bulk_total_duration", 0.0)

        computed = {
            "Flow Duration": duration_seconds * 1_000_000,
            "Total Fwd Packets": total_fwd_packets,
            "Total Backward Packets": total_bwd_packets,
            "Total Length of Fwd Packets": total_fwd_bytes,
            "Total Length of Bwd Packets": total_bwd_bytes,

            "Fwd Packet Length Max": fwd_len_stats["max"],
            "Fwd Packet Length Min": fwd_len_stats["min"],
            "Fwd Packet Length Mean": fwd_len_stats["mean"],
            "Fwd Packet Length Std": fwd_len_stats["std"],

            "Bwd Packet Length Max": bwd_len_stats["max"],
            "Bwd Packet Length Min": bwd_len_stats["min"],
            "Bwd Packet Length Mean": bwd_len_stats["mean"],
            "Bwd Packet Length Std": bwd_len_stats["std"],

            "Flow Bytes/s": total_bytes / duration_seconds,
            "Flow Packets/s": total_packets / duration_seconds,

            "Flow IAT Mean": flow_iat["mean"],
            "Flow IAT Std": flow_iat["std"],
            "Flow IAT Max": flow_iat["max"],
            "Flow IAT Min": flow_iat["min"],

            "Fwd IAT Total": fwd_iat["total"],
            "Fwd IAT Mean": fwd_iat["mean"],
            "Fwd IAT Std": fwd_iat["std"],
            "Fwd IAT Max": fwd_iat["max"],
            "Fwd IAT Min": fwd_iat["min"],

            "Bwd IAT Total": bwd_iat["total"],
            "Bwd IAT Mean": bwd_iat["mean"],
            "Bwd IAT Std": bwd_iat["std"],
            "Bwd IAT Max": bwd_iat["max"],
            "Bwd IAT Min": bwd_iat["min"],

            "Fwd PSH Flags": fwd_psh,
            "Bwd PSH Flags": bwd_psh,
            "Fwd URG Flags": fwd_urg,
            "Bwd URG Flags": bwd_urg,

            "Fwd Header Length": fwd_header_total,
            "Bwd Header Length": bwd_header_total,
            "Fwd Header Length.1": fwd_header_total,

            "Fwd Packets/s": total_fwd_packets / duration_seconds,
            "Bwd Packets/s": total_bwd_packets / duration_seconds,

            "Min Packet Length": pkt_len_stats["min"],
            "Max Packet Length": pkt_len_stats["max"],
            "Packet Length Mean": pkt_len_stats["mean"],
            "Packet Length Std": pkt_len_stats["std"],
            "Packet Length Variance": pkt_len_stats["variance"],

            "SYN Flag Count": flags.get("SYN", 0),
            "ACK Flag Count": flags.get("ACK", 0),
            "FIN Flag Count": flags.get("FIN", 0),
            "RST Flag Count": flags.get("RST", 0),
            "PSH Flag Count": fwd_psh + bwd_psh,
            "URG Flag Count": fwd_urg + bwd_urg,
            "ECE Flag Count": flags.get("ECE", 0),
            "CWE Flag Count": flags.get("CWE", 0),

            "Down/Up Ratio": (total_bwd_packets / total_fwd_packets) if total_fwd_packets else 0.0,
            "Average Packet Size": (total_bytes / total_packets) if total_packets else 0.0,
            "Avg Fwd Segment Size": fwd_len_stats["mean"],
            "Avg Bwd Segment Size": bwd_len_stats["mean"],

            "Fwd Avg Bytes/Bulk": (fwd_bulk_bytes / fwd_bulk_count) if fwd_bulk_count else 0.0,
            "Fwd Avg Packets/Bulk": (fwd_bulk_packets / fwd_bulk_count) if fwd_bulk_count else 0.0,
            "Fwd Avg Bulk Rate": (fwd_bulk_bytes / fwd_bulk_duration) if fwd_bulk_duration > 0 else 0.0,
            "Bwd Avg Bytes/Bulk": (bwd_bulk_bytes / bwd_bulk_count) if bwd_bulk_count else 0.0,
            "Bwd Avg Packets/Bulk": (bwd_bulk_packets / bwd_bulk_count) if bwd_bulk_count else 0.0,
            "Bwd Avg Bulk Rate": (bwd_bulk_bytes / bwd_bulk_duration) if bwd_bulk_duration > 0 else 0.0,

            "Subflow Fwd Packets": total_fwd_packets,
            "Subflow Fwd Bytes": total_fwd_bytes,
            "Subflow Bwd Packets": total_bwd_packets,
            "Subflow Bwd Bytes": total_bwd_bytes,

            "Init_Win_bytes_forward": flow.get("init_win_fwd") or 0,
            "Init_Win_bytes_backward": flow.get("init_win_bwd") or 0,
            "act_data_pkt_fwd": flow.get("fwd_data_pkt_count", 0),
            "min_seg_size_forward": min(fwd_header_lengths) if fwd_header_lengths else 0,

            "Active Mean": active_stats["mean"],
            "Active Std": active_stats["std"],
            "Active Max": active_stats["max"],
            "Active Min": active_stats["min"],

            "Idle Mean": idle_stats["mean"],
            "Idle Std": idle_stats["std"],
            "Idle Max": idle_stats["max"],
            "Idle Min": idle_stats["min"],

            "Destination Port": flow.get("dst_port", 0) or 0,
            "Protocol": PROTOCOL_NUMERIC_MAP.get(flow.get("protocol", "OTHER"), -1),
        }

        return computed

    def to_vector(self, computed: dict, feature_columns: list = None) -> list:
        """
        Orders `computed` according to feature_columns. If feature_columns
        is not provided, defaults to feature_metadata.feature_columns —
        the trained order loaded from network_feature_columns.pkl. This
        keeps the method callable with a single argument (as the test does)
        while still allowing an explicit override (as the pipeline worker
        does, to avoid repeated metadata lookups per flow).
        """
        if feature_columns is None:
            try:
                feature_columns = feature_metadata.feature_columns
            except FeatureMetadataError as e:
                raise FeatureMetadataError(f"Cannot build feature vector: {e}")

        vector = []
        missing = []
        for name in feature_columns:
            if name not in computed:
                missing.append(name)
                vector.append(0.0)
            else:
                vector.append(float(computed[name]))

        if missing:
            logger.warning(f"Feature extraction missing {len(missing)} trained columns: {missing}")

        return vector


feature_extraction_engine = FeatureExtractionEngine()