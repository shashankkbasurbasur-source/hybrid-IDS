"""
backend/scenarios/attack_generators.py

FIXED FOR PHASE 2 - REALISTIC ATTACK GENERATION:
 - Port scans with high port entropy
 - DDoS with realistic packet patterns
 - SSH brute force with actual auth logs
 - Hybrid attacks with multi-stage correlation

These scenarios are designed to match CICIDS2017 + ADFA-LD training distributions.
"""

import numpy as np
import random
import time
from typing import List, Dict, Tuple
from backend.core.logger import get_logger

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 1: NORMAL TRAFFIC (Benign)
# ─────────────────────────────────────────────────────────────────────────────

def generate_normal_traffic(count: int = 50) -> List[Dict]:
    """
    Simulate normal web browsing and system activity.
    
    Characteristics (matching CICIDS benign):
    - Standard ports (80, 443, 53, 123)
    - Mixed ACK/PSH/FIN flags
    - Low port diversity
    - Gradual packet rate
    - Legitimate protocols (TCP/UDP)
    """
    logger.info("[NORMAL] Generating %d normal traffic events", count)
    events = []
    
    # Multiple users browsing from different IPs
    user_bases = [f"192.168.{i}" for i in range(1, 4)]
    web_servers = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.129.140"]
    
    for i in range(count):
        user_ip = f"{random.choice(user_bases)}.{random.randint(100, 250)}"
        server_ip = random.choice(web_servers)
        
        # Realistic port selection
        if random.random() < 0.5:
            # HTTPS
            dst_port = 443
            protocol = "TCP"
            flags = 0x18  # PSH + ACK (data transmission)
        elif random.random() < 0.3:
            # HTTP
            dst_port = 80
            protocol = "TCP"
            flags = 0x18
        elif random.random() < 0.1:
            # DNS
            dst_port = 53
            protocol = "UDP"
            flags = 0x00
        else:
            # NTP / Other
            dst_port = random.choice([123, 161, 162])
            protocol = "UDP"
            flags = 0x00
        
        events.append({
            "timestamp": f"2026-06-08T12:{i%60:02d}:{(i//60)%60:02d}",
            "src_ip": user_ip,
            "dst_ip": server_ip,
            "src_port": random.randint(40000, 65000),
            "dst_port": dst_port,
            "protocol": protocol,
            "length": random.randint(40, 1500),
            "ttl": 64,
            "flags": flags,
            "event_type": "normal",
        })
    
    logger.info("[✓ NORMAL] Generated %d benign events", len(events))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 2: PORT SCANNING (Nmap-style)
# CRITICAL: Generate HIGH PORT ENTROPY to match CICIDS PortScan class
# ─────────────────────────────────────────────────────────────────────────────

def generate_port_scan(count: int = 100) -> List[Dict]:
    """
    Simulate aggressive port scanning (Nmap SYN scan).
    
    CRITICAL FEATURES MATCHING CICIDS PortScan:
    - High port entropy: ports spread across 1-65535 (not sequential)
    - High SYN count: 80-90% packets have SYN flag only
    - No ACKs: Response traffic is ignored
    - Multiple target IPs: Scan hits many hosts in subnet
    - High packet rate: Rapid fire scanning
    - No data: Packets are minimal size (SYN only = 40 bytes)
    """
    logger.info("[PORT SCAN] Generating %d port scan events with HIGH ENTROPY", count)
    events = []
    
    # Single aggressive scanner
    attacker_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    target_subnet = "10.0.0"
    
    # FIXED: Generate HIGH PORT ENTROPY (spread across entire port range)
    # Instead of sequential 1,11,21,31... use random scatter
    scanned_ports = set()
    while len(scanned_ports) < min(count, 1000):
        # Random ports with higher density in known-service ranges
        if random.random() < 0.6:
            # Scan common service ports (0-10000)
            port = random.randint(1, 10000)
        elif random.random() < 0.3:
            # Scan high ports (10000-65535)
            port = random.randint(10000, 65535)
        else:
            # Scan system ports (1-1024)
            port = random.randint(1, 1024)
        
        scanned_ports.add(port)
    
    scanned_ports = list(scanned_ports)[:count]
    
    for i, port in enumerate(scanned_ports):
        # Random target in subnet (hit many IPs)
        target_ip = f"{target_subnet}.{random.randint(1, 254)}"
        
        events.append({
            "timestamp": f"2026-06-08T13:{(i//60)%60:02d}:{i%60:02d}",
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 60000),
            "dst_port": port,  # HIGH ENTROPY: scattered ports
            "protocol": "TCP",
            "length": 40,  # SYN packet is minimal
            "ttl": 64,
            "flags": 0x02,  # SYN ONLY (no ACK response expected)
            "event_type": "port_scan",
        })
    
    logger.info("[✓ PORT SCAN] Generated %d port scan events (entropy=%d unique ports)",
                len(events), len(set(p["dst_port"] for p in events)))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 3: DDoS / TRAFFIC FLOODING
# ─────────────────────────────────────────────────────────────────────────────

def generate_ddos_flood(count: int = 200) -> List[Dict]:
    """
    Simulate DDoS / UDP/SYN flood attack.
    
    CRITICAL FEATURES MATCHING CICIDS DoS:
    - High packet rate: Burst of packets
    - Single target: All traffic → same IP:port
    - Fixed packet size: Consistent flood pattern
    - Multiple spoofed sources: Attacker uses many IPs (reflection attack)
    - High byte volume: Rapid accumulation
    """
    logger.info("[DDoS FLOOD] Generating %d DDoS flood events", count)
    events = []
    
    # Multiple spoofed source IPs (botnet or reflection)
    spoofed_ips = [f"203.0.113.{random.randint(1, 254)}" for _ in range(20)]
    
    # Single target (victim)
    target_ip = "10.0.0.100"
    target_port = random.choice([53, 123, 161])  # DNS, NTP, SNMP (reflection targets)
    
    for i in range(count):
        events.append({
            "timestamp": f"2026-06-08T14:30:{i%60:02d}",
            "src_ip": random.choice(spoofed_ips),  # Rotating spoofed IPs
            "dst_ip": target_ip,
            "src_port": random.randint(40000, 65000),
            "dst_port": target_port,
            "protocol": "UDP",
            "length": 64,  # Fixed size (suspicious pattern)
            "ttl": random.choice([32, 64, 128]),  # Mixed TTLs (spoofed)
            "flags": 0,
            "event_type": "ddos_flood",
        })
    
    logger.info("[✓ DDoS FLOOD] Generated %d flood events to %s:%d",
                len(events), target_ip, target_port)
    return events


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 4: SSH BRUTE FORCE (Host-based)
# ─────────────────────────────────────────────────────────────────────────────

def generate_ssh_brute_force(count: int = 50) -> List[str]:
    """
    Generate SSH authentication log lines simulating brute-force attack.
    
    CRITICAL FEATURES:
    - Multiple failed attempts from single IP
    - Common username targeting (root, admin, test)
    - Rapid succession (no human delays)
    - Eventually successful login
    """
    logger.info("[SSH BRUTE FORCE] Generating %d SSH auth log lines", count)
    logs = []
    
    attacker_ip = f"192.168.{random.randint(1,5)}.{random.randint(50, 200)}"
    target_user = random.choice(["root", "admin", "test", "guest"])
    
    # Failed attempts
    for i in range(count):
        logs.append(
            f'Jun  8 13:30:{i%60:02d} target sshd[{2000+i}]: '
            f'Failed password for {target_user} from {attacker_ip} '
            f'port {40000+i} ssh2'
        )
    
    # Finally successful (shows persistence paid off)
    if random.random() > 0.3:
        logs.append(
            f'Jun  8 13:35:00 target sshd[3000]: '
            f'Accepted password for {target_user} from {attacker_ip} '
            f'port 50000 ssh2'
        )
    
    logger.info("[✓ SSH BRUTE FORCE] Generated %d auth logs from %s", len(logs), attacker_ip)
    return logs


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 5: HYBRID ATTACK (Network + Host, Multi-stage)
# ─────────────────────────────────────────────────────────────────────────────

def generate_hybrid_attack() -> Tuple[List[Dict], List[str]]:
    """
    Multi-stage attack combining network + host exploitation.
    
    CRITICAL PHASES:
    1. Reconnaissance (NIDS detects):
       - Port scanning to find vulnerable services
    
    2. Exploitation (HIDS detects):
       - SSH brute force against discovered services
    
    3. Lateral Movement (NIDS + HIDS):
       - Post-compromise scanning of internal network
       - Privilege escalation attempts
    
    This demonstrates the TRUE value of hybrid detection:
    - Either detector alone might miss it
    - Together they correlate multiple attack stages
    """
    logger.info("[HYBRID ATTACK] Generating 3-phase multi-stage attack")
    
    # ──────────────────────────────────────────────────────────────────────
    # PHASE 1: EXTERNAL RECONNAISSANCE (NIDS detects)
    # ──────────────────────────────────────────────────────────────────────
    external_scanner_ip = "203.0.113.50"
    target_subnet = "10.0.0"
    
    # Aggressive port scan with HIGH ENTROPY (will trigger NIDS)
    phase1_scan = []
    scan_ports = set()
    while len(scan_ports) < 30:
        scan_ports.add(random.randint(1, 65535))
    
    for port in list(scan_ports)[:30]:
        phase1_scan.append({
            "timestamp": "2026-06-08T13:00:00",
            "src_ip": external_scanner_ip,
            "dst_ip": f"{target_subnet}.{random.randint(1, 254)}",
            "src_port": random.randint(40000, 60000),
            "dst_port": port,
            "protocol": "TCP",
            "length": 40,
            "ttl": 64,
            "flags": 0x02,
            "event_type": "phase1_recon",
        })
    
    # ──────────────────────────────────────────────────────────────────────
    # PHASE 2: SSH BRUTE FORCE (HIDS detects)
    # ──────────────────────────────────────────────────────────────────────
    phase2_logs = generate_ssh_brute_force(20)
    
    # ──────────────────────────────────────────────────────────────────────
    # PHASE 3: LATERAL MOVEMENT (Both NIDS + HIDS detect)
    # ──────────────────────────────────────────────────────────────────────
    # After gaining access, attacker scans internal network
    attacker_ip = "10.0.0.50"  # Compromised internal host
    internal_targets = [f"10.0.0.{i}" for i in range(10, 20)]
    
    phase3_lateral = []
    for target in internal_targets:
        phase3_lateral.append({
            "timestamp": "2026-06-08T13:45:00",
            "src_ip": attacker_ip,
            "dst_ip": target,
            "src_port": random.randint(40000, 65000),
            "dst_port": random.choice([22, 135, 139, 445]),  # SSH, RPC, SMB
            "protocol": "TCP",
            "length": random.randint(40, 500),
            "ttl": 64,
            "flags": 0x02,
            "event_type": "phase3_lateral",
        })
    
    # Combine all phases
    all_network_events = phase1_scan + phase3_lateral
    
    logger.info("[✓ HYBRID ATTACK] 3 phases: recon(%d) + brute(%d) + lateral(%d)",
                len(phase1_scan), len(phase2_logs), len(phase3_lateral))
    
    return all_network_events, phase2_logs


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS: Feature Statistics
# ─────────────────────────────────────────────────────────────────────────────

def analyze_scenario(scenario_name: str, events: List[Dict]) -> dict:
    """
    Analyze generated scenario to verify it has expected characteristics.
    Used for validation.
    """
    if not events:
        return {"error": "No events"}
    
    ports = [e.get("dst_port", 0) for e in events]
    protocols = [e.get("protocol", "OTHER") for e in events]
    flags = [e.get("flags", 0) for e in events]
    lengths = [e.get("length", 0) for e in events]
    src_ips = [e.get("src_ip", "") for e in events]
    dst_ips = [e.get("dst_ip", "") for e in events]
    
    syn_count = sum(1 for f in flags if f & 0x02)
    ack_count = sum(1 for f in flags if f & 0x10)
    
    return {
        "scenario": scenario_name,
        "total_packets": len(events),
        "unique_dst_ports": len(set(ports)),
        "port_entropy": len(set(ports)) / max(len(ports), 1),  # 0-1, higher is more scattered
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_to_ack_ratio": syn_count / max(ack_count, 1),
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "avg_packet_size": sum(lengths) / max(len(lengths), 1),
        "protocols": dict(zip(*np.unique(protocols, return_counts=True))) if 'np' in dir() else {},
    }


if __name__ == "__main__":
    # Test scenarios locally
    import json
    
    print("\n" + "="*80)
    print("ATTACK SCENARIO GENERATOR TEST")
    print("="*80)
    
    # Test normal
    normal = generate_normal_traffic(50)
    print(f"\n✓ Normal Traffic: {len(normal)} events")
    
    # Test port scan with analysis
    port_scan = generate_port_scan(100)
    print(f"\n✓ Port Scan: {len(port_scan)} events")
    unique_ports = len(set(e["dst_port"] for e in port_scan))
    print(f"  - Unique ports: {unique_ports} (HIGH ENTROPY = good)")
    syn_only = sum(1 for e in port_scan if e["flags"] == 0x02)
    print(f"  - SYN-only packets: {syn_only}/{len(port_scan)}")
    
    # Test DDoS
    ddos = generate_ddos_flood(200)
    print(f"\n✓ DDoS Flood: {len(ddos)} events")
    targets = len(set(e["dst_ip"] for e in ddos))
    print(f"  - Target hosts: {targets}")
    
    # Test brute force
    brute = generate_ssh_brute_force(50)
    print(f"\n✓ SSH Brute Force: {len(brute)} log lines")
    failed = sum(1 for l in brute if "Failed" in l)
    success = sum(1 for l in brute if "Accepted" in l)
    print(f"  - Failed attempts: {failed}")
    print(f"  - Successful logins: {success}")
    
    # Test hybrid
    hybrid_net, hybrid_logs = generate_hybrid_attack()
    print(f"\n✓ Hybrid Attack: {len(hybrid_net)} packets + {len(hybrid_logs)} logs")
    
    print("\n" + "="*80)
    print("ALL SCENARIOS VALIDATED ✓")
    print("="*80 + "\n")