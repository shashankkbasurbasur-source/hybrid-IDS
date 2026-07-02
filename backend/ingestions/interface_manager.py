"""
Network Interface Detection and Management
"""

import psutil
import subprocess
from typing import List, Dict, Optional
import platform


class InterfaceManager:
    """Detect and manage network interfaces"""
    
    @staticmethod
    def get_available_interfaces() -> List[Dict]:
        """Get list of available network interfaces"""
        interfaces = []
        
        try:
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            
            for interface_name, stats_data in stats.items():
                # Skip loopback and virtual interfaces
                if interface_name.startswith(("lo", "docker", "virt", "vbox")):
                    continue
                
                if_addrs = addrs.get(interface_name, [])
                
                # Get IP addresses
                ipv4 = None
                ipv6 = None
                mac = None
                
                for addr in if_addrs:
                    if addr.family == psutil.AF_LINK:
                        mac = addr.address
                    elif addr.family == psutil.AF_INET:
                        ipv4 = addr.address
                    elif addr.family == psutil.AF_INET6:
                        ipv6 = addr.address
                
                interfaces.append({
                    "name": interface_name,
                    "is_up": stats_data.isup,
                    "mtu": stats_data.mtu,
                    "speed": stats_data.speed,
                    "ip_v4": ipv4,
                    "ip_v6": ipv6,
                    "mac": mac,
                    "bytes_sent": stats_data.bytes_sent,
                    "bytes_recv": stats_data.bytes_recv,
                    "packets_sent": stats_data.packets_sent,
                    "packets_recv": stats_data.packets_recv,
                    "drop_in": stats_data.dropin,
                    "drop_out": stats_data.dropout
                })
        
        except Exception as e:
            print(f"Error detecting interfaces: {e}")
        
        return interfaces
    
    @staticmethod
    def get_default_interface() -> Optional[str]:
        """Get the primary active network interface"""
        try:
            interfaces = InterfaceManager.get_available_interfaces()
            
            # Prefer connected interfaces with IP
            for iface in interfaces:
                if iface["is_up"] and iface["ip_v4"]:
                    return iface["name"]
            
            # Fallback to first active interface
            for iface in interfaces:
                if iface["is_up"]:
                    return iface["name"]
        
        except:
            pass
        
        return None
    
    @staticmethod
    def check_capture_permission() -> bool:
        """Check if user has permission to capture packets"""
        try:
            if platform.system() == "Windows":
                return True  # Windows handles this differently
            else:
                # Unix/Linux: check for root or CAP_NET_RAW
                result = subprocess.run(
                    ["sudo", "-n", "true"],
                    capture_output=True,
                    timeout=1
                )
                return result.returncode == 0
        except:
            return False