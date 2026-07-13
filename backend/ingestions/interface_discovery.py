"""
Network Interface Discovery
Detects all available network interfaces with IP, MAC, stats, and type.
"""

import socket
import psutil


class InterfaceDiscovery:
    """
    Detects and reports available network interfaces (like Wireshark's interface list).
    """

    TYPE_RULES = [
        (("lo",), "Loopback"),
        (("docker", "br-", "virbr", "veth"), "Virtual"),
        (("wlan", "wifi", "wl"), "Wireless"),
        (("eth", "enp", "eno", "ens"), "Ethernet"),
        (("tun", "tap", "ppp"), "VPN"),
    ]

    def _classify(self, name: str) -> str:
        lname = name.lower()
        for prefixes, iface_type in self.TYPE_RULES:
            if any(lname.startswith(p) for p in prefixes):
                return iface_type
        return "Unknown"

    def _read_default_gateway(self):
        """
        Reads the default gateway from /proc/net/route (Linux only).
        Returns (gateway_ip, iface_name) or (None, None).
        """
        try:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) < 3:
                        continue
                    iface, destination, gateway = fields[0], fields[1], fields[2]
                    if destination == "00000000":  # default route
                        gw_ip = socket.inet_ntoa(
                            int(gateway, 16).to_bytes(4, "little")
                        )
                        return gw_ip, iface
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        return None, None

    def list_interfaces(self):
        """
        Returns a list of interfaces with full metadata:
        identity, addressing, link stats, traffic counters, and routing info.
        """
        interfaces = []

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
        gateway_ip, gateway_iface = self._read_default_gateway()

        for iface_name, iface_addrs in addrs.items():
            ipv4 = None
            ipv6 = None
            mac_addr = None
            netmask = None
            broadcast = None

            for addr in iface_addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                    netmask = addr.netmask
                    broadcast = addr.broadcast
                elif addr.family == socket.AF_INET6:
                    ipv6 = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac_addr = addr.address

            subnet = self._compute_subnet(ipv4, netmask)

            iface_stats = stats.get(iface_name)
            is_up = iface_stats.isup if iface_stats else False
            speed = iface_stats.speed if iface_stats else 0
            mtu = iface_stats.mtu if iface_stats else 0
            duplex = str(iface_stats.duplex) if iface_stats else "UNKNOWN"

            io = io_counters.get(iface_name)

            interfaces.append({
                "name": iface_name,
                "type": self._classify(iface_name),
                "ipv4": ipv4 or "N/A",
                "ipv6": ipv6 or "N/A",
                "mac": mac_addr or "N/A",
                "netmask": netmask or "N/A",
                "broadcast": broadcast or "N/A",
                "subnet": subnet or "N/A",
                "gateway": gateway_ip if iface_name == gateway_iface else "N/A",
                "status": "UP" if is_up else "DOWN",
                "speed_mbps": speed,
                "mtu": mtu,
                "duplex": duplex,
                "packets_sent": io.packets_sent if io else 0,
                "packets_received": io.packets_recv if io else 0,
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_received": io.bytes_recv if io else 0,
                "errors_in": io.errin if io else 0,
                "errors_out": io.errout if io else 0,
            })

        return interfaces

    def _compute_subnet(self, ipv4, netmask):
        if not ipv4 or not netmask:
            return None
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ipv4}/{netmask}", strict=False)
            return str(network)
        except (ValueError, ImportError):
            return None