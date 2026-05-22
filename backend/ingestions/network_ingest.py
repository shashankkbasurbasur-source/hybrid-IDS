from scapy.all import sniff, IP, TCP, UDP


class NetworkIngestor:
    """
    Handles live network packet ingestion (NIDS)
    """

    def __init__(self, packet_count=10, interface=None):
        """
        packet_count: number of packets to capture (demo purpose)
        interface: network interface (e.g., 'eth0', 'wlan0')
        """
        self.packet_count = packet_count
        self.interface = interface

    def _parse_packet(self, packet):
        """
        Convert raw packet → structured event (NOT features)
        """
        event = {
            "length": 0,
            "ttl": 0,
            "protocol": "OTHER",
            "src_port": 0,
            "dst_port": 0,
            "flags": 0
        }

        if IP in packet:
            event["length"] = packet[IP].len
            event["ttl"] = packet[IP].ttl

        if TCP in packet:
            event["protocol"] = "TCP"
            event["src_port"] = packet[TCP].sport
            event["dst_port"] = packet[TCP].dport
            event["flags"] = int(packet[TCP].flags)

        elif UDP in packet:
            event["protocol"] = "UDP"
            event["src_port"] = packet[UDP].sport
            event["dst_port"] = packet[UDP].dport

        return event

    def ingest(self):
        """
        Capture packets and return list of structured events
        """
        events = []

        def process(packet):
            parsed = self._parse_packet(packet)
            events.append(parsed)

        print(f"[NIDS] Capturing {self.packet_count} packets...")
        sniff(prn=process, count=self.packet_count, iface=self.interface)

        print(f"[NIDS] Captured {len(events)} packets.")
        return events