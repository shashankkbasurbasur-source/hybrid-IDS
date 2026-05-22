class NetworkFeatureExtractor:
    """
    Converts network packet events into feature vector for NIDS model
    """

    def extract(self, events):
        features = [0] * 78  # match your model input size

        if not events:
            return features

        total_packets = len(events)

        lengths = [e["length"] for e in events]
        ttls = [e["ttl"] for e in events]

        tcp_count = sum(1 for e in events if e["protocol"] == "TCP")
        udp_count = sum(1 for e in events if e["protocol"] == "UDP")

        src_ports = [e["src_port"] for e in events if e["src_port"] > 0]
        dst_ports = [e["dst_port"] for e in events if e["dst_port"] > 0]

        # --- Basic statistical features ---
        features[0] = total_packets
        features[1] = sum(lengths) / total_packets if lengths else 0
        features[2] = max(lengths) if lengths else 0
        features[3] = min(lengths) if lengths else 0

        features[4] = sum(ttls) / total_packets if ttls else 0

        # --- Protocol distribution ---
        features[5] = tcp_count
        features[6] = udp_count
        features[7] = tcp_count / total_packets if total_packets else 0

        # --- Port behavior ---
        features[8] = len(set(src_ports))
        features[9] = len(set(dst_ports))

        # --- Suspicious indicators ---
        high_ports = sum(1 for p in dst_ports if p > 1024)
        features[10] = high_ports

        # --- Flags behavior (TCP) ---
        flags = [e["flags"] for e in events]
        features[11] = sum(flags) / total_packets if flags else 0

        # Remaining features stay 0 (padding for model compatibility)
        return features