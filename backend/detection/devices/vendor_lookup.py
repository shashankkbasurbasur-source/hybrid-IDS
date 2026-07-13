"""
MAC Vendor Lookup (OUI-based)
Small built-in prefix table — offline, no external API dependency.
Falls back to 'Unknown' rather than guessing (per spec: never fake data).
"""

OUI_TABLE = {
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:1B:63": "Apple",
    "AC:DE:48": "Apple",
    "F0:18:98": "Apple",
    "28:CF:E9": "Apple",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "00:1D:D8": "Microsoft",
    "7C:D1:C3": "TP-Link",
    "50:D4:F7": "TP-Link",
    "00:23:69": "Cisco",
    "00:1E:C7": "Dell",
    "D4:BE:D9": "Dell",
    "40:B0:76": "Intel",
    "3C:97:0E": "Intel",
    "E4:5F:01": "Samsung",
    "5C:0A:5B": "Samsung",
}


def lookup_vendor(mac: str) -> str:
    if not mac or mac == "N/A":
        return "Unknown"

    prefix = mac.upper()[:8]  # first 3 octets, e.g. "AC:DE:48"
    return OUI_TABLE.get(prefix, "Unknown")