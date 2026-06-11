import subprocess
import ipaddress
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box
import threading
import time

console = Console()
IS_WINDOWS = platform.system() == "Windows"

def ping_one(ip: str, timeout_ms: int = 300):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ping_sweep(subnet: str, timeout: int):
    """Ping every host in subnet concurrently to populate ARP cache."""
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]Pinging {len(hosts)} hosts…", total=len(hosts))

        threads = []
        lock = threading.Lock()

        def worker(ip):
            ping_one(ip, timeout_ms=timeout * 1000)
            with lock:
                progress.advance(task)

        # Batch into groups of 50 to avoid spawning thousands of threads
        batch = 50
        for i in range(0, len(hosts), batch):
            chunk = hosts[i:i+batch]
            threads = [threading.Thread(target=worker, args=(ip,), daemon=True) for ip in chunk]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

    # Give ARP cache a moment to settle
    time.sleep(0.5)