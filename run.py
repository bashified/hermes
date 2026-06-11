import argparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from src.arp import *
from src.misc import *
from src.ps import *

console = Console()
IS_WINDOWS = platform.system() == "Windows"

def render_results(devices: list[dict], subnet: str, elapsed: float):
    if not devices:
        console.print("\n[bold red]No devices found.[/] Try increasing --timeout.\n")
        return

    table = Table(
        title=f"[bold cyan]Devices on {subnet}[/]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="bright_black",
        padding=(0, 1),
    )
    table.add_column("#",           style="dim",         width=4,  justify="right")
    table.add_column("IP Address",  style="bold green",  width=16)
    table.add_column("MAC Address", style="yellow",      width=20)
    table.add_column("Hostname",    style="cyan",        min_width=20)
    table.add_column("Vendor",      style="white",       min_width=14)

    for i, d in enumerate(devices, 1):
        table.add_row(str(i), d["ip"], d["mac"], d["hostname"], d["vendor"])

    console.print()
    console.print(table)
    console.print(
        f"\n  [bold white]{len(devices)}[/] device(s) found  •  "
        f"scan took [bold]{elapsed:.1f}s[/]  •  "
        f"{datetime.now().strftime('%H:%M:%S')}\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Local network scanner")
    parser.add_argument("--target", "-t", default=None,
                        help="Subnet to scan e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", "-T", type=int, default=2,
                        help="Ping timeout in seconds (default: 2)")
    args = parser.parse_args()

    local_ip = get_local_ip()
    target   = args.target or derive_subnet(local_ip)

    console.print(Panel(
        f"[bold]Local Network Scanner[/]\n"
        f"Your IP : [green]{local_ip}[/]\n"
        f"Target  : [cyan]{target}[/]\n"
        f"Timeout : {args.timeout}s per host\n"
        f"Method  : {'Ping sweep + ARP cache (Windows)' if IS_WINDOWS else 'ARP broadcast + ARP cache'}",
        border_style="bright_cyan",
        expand=False,
    ))

    t0 = time.time()

    console.print("[dim]Step 1/2 — Ping sweep to wake up devices…[/]")
    ping_sweep(target, args.timeout)

    console.print("[dim]Step 2/2 — Reading ARP cache…[/]\n")
    devices = read_arp_cache(target)

    if not IS_WINDOWS:
        scapy_devices = scapy_scan(target, args.timeout)
        existing_ips = {d["ip"] for d in devices}
        for d in scapy_devices:
            if d["ip"] not in existing_ips:
                devices.append(d)
        devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))

    elapsed = time.time() - t0
    render_results(devices, target, elapsed)


if __name__ == "__main__":
    main()