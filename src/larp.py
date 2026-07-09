from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box
import platform
import ipaddress
import subprocess

from .misc import *
import re

console = Console()
IS_WINDOWS = platform.system() == "Windows"

# ── ARP cache reader ──────────────────────────────────────────────────────────

def read_arp_cache(subnet: str) -> list[dict]:
    """Read ARP cache from the OS — works on Windows, Linux, macOS."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    devices = []
    seen = set()

    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        output = result.stdout
    except Exception as e:
        console.print(f"[red]Failed to run arp -a: {e}[/]")
        return []

    # Windows format:  10.42.0.59    88-a2-9e-4b-52-cb     dynamic
    # Linux format:    10.42.0.59 ether 88:a2:9e:4b:52:cb  C  wlan0
    # macOS format:    10.42.0.59 (10.42.0.59) at 88:a2:9e:4b:52:cb on en0
    ip_mac_pattern = re.compile(
        r'(\d{1,3}(?:\.\d{1,3}){3})\s+.*?([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}'
        r'[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})'
    )

    for match in ip_mac_pattern.finditer(output):
        ip  = match.group(1)
        mac = match.group(2).replace("-", ":").lower()

        # Skip broadcast/multicast MACs
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        if ip in seen:
            continue

        try:
            ip_obj = ipaddress.IPv4Address(ip)
        except ValueError:
            continue

        if ip_obj in network:
            seen.add(ip)
            devices.append({
                "ip":       ip,
                "mac":      mac,
                "hostname": resolve_hostname(ip),
                "vendor":   vendor_from_mac(mac),
            })

    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices


# ── Scapy fallback (Linux/macOS) ──────────────────────────────────────────────

def scapy_scan(subnet: str, timeout: int) -> list[dict]:
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        arp_req   = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(broadcast / arp_req, timeout=timeout, retry=2)
        devices = []
        for _, rcv in answered:
            ip  = rcv.psrc
            mac = rcv.hwsrc
            devices.append({
                "ip":       ip,
                "mac":      mac,
                "hostname": resolve_hostname(ip),
                "vendor":   vendor_from_mac(mac),
            })
        devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        return devices
    except Exception:
        return []
