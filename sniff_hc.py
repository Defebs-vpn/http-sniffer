from scapy.all import sniff, TCP, Raw
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import re

console = Console()

def extract_http_custom_config(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")

        # Regex untuk mengekstrak informasi dari payload
        proxy_match = re.search(r"proxy\s*:\s*(\S+)", payload)
        ssl_match = re.search(r"ssl\s*:\s*(\S+)", payload)
        ssh_match = re.search(r"ssh\s*:\s*(\S+)", payload)
        host_match = re.search(r"Host:\s*(\S+)", payload)

        # Menampilkan informasi terkait konfigurasi HTTP Custom
        if proxy_match or ssl_match or ssh_match or host_match or payload:
            # Membuat Tabel untuk menampilkan data
            table = Table(title="HTTP Custom Config Sniffed", show_header=True, header_style="bold magenta")

            table.add_column("Field", justify="left", style="cyan", width=15)
            table.add_column("Value", justify="left", style="yellow", width=50)

            table.add_row("Host", host_match.group(1) if host_match else "N/A")
            table.add_row("Proxy", proxy_match.group(1) if proxy_match else "N/A")
            table.add_row("SSL", ssl_match.group(1) if ssl_match else "N/A")
            table.add_row("SSH", ssh_match.group(1) if ssh_match else "N/A")
            
            # Menambahkan Payload yang ditemukan dalam data
            table.add_row("Payload", payload[:100] + '...' if len(payload) > 100 else payload)  # Menampilkan hanya 100 karakter pertama dari payload

            # Menampilkan tabel dalam Panel untuk memberikan kesan lebih rapi
            panel = Panel(table, title="Captured HTTP Custom Config", border_style="green")
            console.print(panel)

def start_sniffing(interface="eth0"):
    console.print(f"[bold green]Sniffing on interface {interface}...[/bold green]")
    sniff(filter="tcp port 80 or tcp port 443", prn=extract_http_custom_config, store=0)

if __name__ == "__main__":
    start_sniffing()
