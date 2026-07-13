"""
Packet Parser
Parses raw Scapy packets into a normalized event dict covering every
protocol the pipeline needs, now and later (Ethernet, IPv4/IPv6, TCP/UDP/
ICMP/ARP, DNS, DHCP, HTTP/HTTPS metadata).
"""

from datetime import datetime, timezone

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTPRequest

from backend.core.logger import get_logger

logger = get_logger(__name__)


class PacketParseError(Exception):
    pass


class PacketParser:
    """
    Stateless — takes a raw packet + context, returns a normalized dict.
    Never raises for "packet not interesting"; only raises PacketParseError
    for genuinely unreadable/corrupt input, which the caller should catch
    and count (never let it stop the sniffer).
    """

    def parse(self, packet, interface: str, session_id: str) -> dict:
        event = {
            "session_id": session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "interface": interface,
            "eth_src": None,
            "eth_dst": None,
            "ip_version": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "OTHER",
            "length": len(packet) if packet else 0,
            "ttl": 0,
            "flags": 0,
            "dns_query": None,
            "http_host": None,
            "is_fragmented": False,
            "parse_error": False,
            "direction": None,  # filled in after we know src_ip (set by caller or here if we have local IP context)
        }

        try:
            if Ether in packet:
                event["eth_src"] = packet[Ether].src
                event["eth_dst"] = packet[Ether].dst

            if IP in packet:
                self._parse_ipv4(packet, event)
            elif IPv6 in packet:
                self._parse_ipv6(packet, event)
            elif ARP in packet:
                self._parse_arp(packet, event)
            else:
                event["protocol"] = "OTHER"

            # Transport layer (only meaningful once we have an IP layer)
            if TCP in packet:
                self._parse_tcp(packet, event)
            elif UDP in packet:
                self._parse_udp(packet, event)
            elif ICMP in packet:
                event["protocol"] = "ICMP"

            # Application layer metadata only — never payload bodies
            if DNS in packet and packet.haslayer(DNSQR):
                try:
                    event["dns_query"] = packet[DNSQR].qname.decode(errors="ignore")
                    event["protocol"] = "DNS"
                except Exception:
                    pass

            if DHCP in packet:
                event["protocol"] = "DHCP"

            if packet.haslayer(HTTPRequest):
                try:
                    host = packet[HTTPRequest].Host
                    event["http_host"] = host.decode(errors="ignore") if host else None
                    event["protocol"] = "HTTP"
                except Exception:
                    pass

        except Exception as e:
            # Never propagate — flag and let caller count it as a parse error
            logger.warning(f"Packet parse error: {e}")
            event["parse_error"] = True

        return event

    def _parse_ipv4(self, packet, event):
        ip_layer = packet[IP]
        event["ip_version"] = 4
        event["src_ip"] = ip_layer.src
        event["dst_ip"] = ip_layer.dst
        event["length"] = ip_layer.len
        event["ttl"] = ip_layer.ttl
        event["protocol"] = "IPv4"
        # MF flag set or fragment offset nonzero => fragmented
        event["is_fragmented"] = bool(ip_layer.flags.MF) or ip_layer.frag > 0

    def _parse_ipv6(self, packet, event):
        ip6_layer = packet[IPv6]
        event["ip_version"] = 6
        event["src_ip"] = ip6_layer.src
        event["dst_ip"] = ip6_layer.dst
        event["ttl"] = ip6_layer.hlim
        event["protocol"] = "IPv6"

    def _parse_arp(self, packet, event):
        arp_layer = packet[ARP]
        event["protocol"] = "ARP"
        event["src_ip"] = arp_layer.psrc
        event["dst_ip"] = arp_layer.pdst
        event["eth_src"] = arp_layer.hwsrc

    def _parse_tcp(self, packet, event):
        tcp_layer = packet[TCP]
        event["protocol"] = "TCP"
        event["src_port"] = tcp_layer.sport
        event["dst_port"] = tcp_layer.dport
        event["flags"] = int(tcp_layer.flags)  # includes ECE/CWR bits already
        event["window_size"] = tcp_layer.window
        event["tcp_header_length"] = tcp_layer.dataofs * 4 if hasattr(tcp_layer, "dataofs") else 20

    def _parse_udp(self, packet, event):
        udp_layer = packet[UDP]
        event["protocol"] = "UDP"
        event["src_port"] = udp_layer.sport
        event["dst_port"] = udp_layer.dport