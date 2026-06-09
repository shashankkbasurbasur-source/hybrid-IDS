# Add this debug script to test features
# File: debug_features.py

from backend.scenarios.attack_generators import generate_port_scan, analyze_scenario
from backend.features.network_features import NetworkFeatureExtractor

# Generate port scan
events = generate_port_scan(100)

# Analyze it
analysis = analyze_scenario("port_scan", events)
print("\nPort Scan Characteristics:")
print(f"  Unique ports: {analysis['unique_dst_ports']}")
print(f"  Port entropy: {analysis['port_entropy']:.3f}")  # Should be 0.8-1.0
print(f"  SYN count: {analysis['syn_count']}")           # Should be ~100
print(f"  ACK count: {analysis['ack_count']}")           # Should be 0
print(f"  SYN/ACK ratio: {analysis['syn_to_ack_ratio']:.1f}")  # Should be very high

# Extract features
extractor = NetworkFeatureExtractor()
features = extractor.extract(events)

print("\nExtracted Features:")
print(f"  Total features: {len(features)}")
print(f"  Non-zero features: {sum(1 for f in features if f != 0.0)}")
print(f"  Min: {min(features):.4f}, Max: {max(features):.4f}")
print(f"  Sum: {sum(features):.2f}")

# Run through NIDS
from backend.detection.ml.network_model import predict_network

score, attack_type = predict_network(features)
print(f"\nNIDS Result:")
print(f"  Score: {score:.4f}")
print(f"  Attack Type: {attack_type}")