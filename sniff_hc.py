from scapy.all import sniff, TCP, Raw
from rich.console import Console
from rich.table import Table
import re

console = Console()

def extract_http_custom_config(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")

        # Regex sederhana untuk mengekstrak informasi dari payload
        proxy_match = re.search(r"proxy\s*:\s*(\S+)", payload)
        ssl_match = re.search(r"ssl\s*:\s*(\S+)", payload)
        ssh_match = re.search(r"ssh\s*:\s*(\S+)", payload)
        host_match = re.search(r"Host:\s*(\S+)", payload)

        if proxy_match or ssl_match or ssh_match or host_match:
            table = Table(title="HTTP Custom Config Sniffed")

            table.add_column("Field", style="bold cyan")
            table.add_column("Value", style="bold yellow")

            table.add_row("Host", host_match.group(1) if host_match else "N/A")
            table.add_row("Proxy", proxy_match.group(1) if proxy_match else "N/A")
            table.add_row("SSL", ssl_match.group(1) if ssl_match else "N/A")
            table.add_row("SSH", ssh_match.group(1) if ssh_match else "N/A")

            console.print(table)

def start_sniffing(interface="eth0"):
    console.print(f"[bold green]Sniffing on interface {interface}...[/bold green]")
    sniff(filter="tcp port 80 or tcp port 443", prn=extract_http_custom_config, store=0)

if __name__ == "__main__":
    start_sniffing()
