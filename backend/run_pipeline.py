import requests
import time

from backend.ingestions.network_ingest import NetworkIngestor
from backend.ingestions.log_ingest import LogIngestor

from backend.features.network_features import NetworkFeatureExtractor
from backend.features.log_features import LogFeatureExtractor


API_URL = "http://127.0.0.1:8000/detect/"


class HybridIDSPipeline:
    """
    End-to-end Hybrid IDS pipeline:
    Ingestion → Feature Extraction → API → Alert
    """

    def __init__(self, packet_count=10):
        self.net_ingestor = NetworkIngestor(packet_count=packet_count)
        self.log_ingestor = LogIngestor()

        self.net_extractor = NetworkFeatureExtractor()
        self.log_extractor = LogFeatureExtractor()

    # -----------------------------
    # SINGLE RUN
    # -----------------------------
    def run_once(self, log_file="sample_logs.txt"):
        print("\n==============================")
        print("🚀 Hybrid IDS Execution Started")
        print("==============================\n")

        # 1️⃣ Network ingestion
        network_events = self.net_ingestor.ingest()
        print(f"[INFO] Network events: {len(network_events)}")

        # 2️⃣ Log ingestion
        log_events = self.log_ingestor.ingest_file(log_file)
        print(f"[INFO] Log events: {len(log_events)}")

        # 3️⃣ Feature extraction
        network_features = self.net_extractor.extract(network_events)
        host_features = self.log_extractor.extract(log_events)

        # Validation (VERY IMPORTANT)
        if len(network_features) != 78:
            print("❌ ERROR: Network feature size mismatch")
            return

        if len(host_features) != 100:
            print("❌ ERROR: Host feature size mismatch")
            return

        # 4️⃣ Send request to API
        payload = {
            "network_features": network_features,
            "host_features": host_features
        }

        try:
            response = requests.post(API_URL, json=payload)
        except requests.exceptions.RequestException as e:
            print("❌ API connection failed:", e)
            return

        # 5️⃣ Handle response
        if response.status_code == 200:
            result = response.json()

            print("\n========== HYBRID IDS RESULT ==========")
            print(f"Decision       : {result.get('decision')}")
            print(f"Confidence     : {result.get('final_score'):.4f}")
            print(f"NIDS Score     : {result.get('network_score'):.4f}")
            print(f"HIDS Score     : {result.get('host_score'):.4f}")

            alert = result.get("alert", {})

            print("\n🚨 ALERT DETAILS")
            print(f"Type       : {alert.get('type')}")
            print(f"Severity   : {alert.get('severity')}")
            print(f"Confidence : {alert.get('confidence')}")
            print(f"Timestamp  : {alert.get('timestamp')}")
            print("=======================================\n")

        else:
            print("❌ API Error:", response.text)

    # -----------------------------
    # CONTINUOUS MODE (REAL-TIME DEMO)
    # -----------------------------
    def run_continuous(self, interval=5, log_file="sample_logs.txt"):
        print("🔁 Starting real-time monitoring...\n")

        try:
            while True:
                self.run_once(log_file=log_file)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Stopped monitoring.")


# -----------------------------
# ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    pipeline = HybridIDSPipeline(packet_count=10)

    # 🔹 Run once (default)
    pipeline.run_once(log_file="sample_logs.txt")

    # 🔹 Uncomment for continuous monitoring
    # pipeline.run_continuous(interval=5)