import socket
import subprocess
import ipaddress
import platform
import re

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def derive_subnet(ip: str) -> str:
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"


def resolve_hostname(ip: str) -> str:
    # Try regular DNS first
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # Try mDNS (.local) via ping -a on Windows
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["ping", "-a", "-n", "1", "-w", "500", ip],
                capture_output=True, text=True
            )
            # Output has "Pinging hostname [ip]" on the first line
            match = re.search(r"Pinging ([^\s\[]+)", result.stdout)
            if match and match.group(1) != ip:
                return match.group(1)
        except Exception:
            pass

    return "—"


def vendor_from_mac(mac: str) -> str:
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    oui = {
        "DCFB48": "Apple",    "F0D1A9": "Apple",   "A8BB50": "Apple",
        "88A29E": "Apple",    "F0DCE2": "Apple",    "BC9FEF": "Apple",
        "E0D4E8": "Intel",    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
        "001A11": "Google",   "94EB2C": "Google",
        "00E04C": "Realtek",  "4CCC6A": "Intel",
        "00155D": "Microsoft (Hyper-V)", "000C29": "VMware",
        "080027": "VirtualBox",
        "18D6C7": "Amazon Echo", "FC65DE": "Amazon",
        "606BBD": "Samsung",  "A0B4A5": "Samsung",
    }
    return oui.get(prefix, "Unknown")
