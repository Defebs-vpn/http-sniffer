import os
import re
import json
import subprocess

# Fungsi untuk menangkap lalu lintas menggunakan tcpdump
def sniff_traffic(interface="any", filter_expr="tcp port 8080", output_file="hc_sniff.log"):
    cmd = f"tcpdump -i {interface} -A -nn {filter_expr}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    with open(output_file, "w") as log_file:
        for line in iter(process.stdout.readline, ''):
            log_file.write(line)
            log_file.flush()
            parse_http_custom(line)

# Fungsi untuk parsing data HTTP Custom
def parse_http_custom(packet_data):
    # Regex untuk mencari pola payload, proxy, SSH, dll.
    payload_pattern = r"(GET|POST|CONNECT) (.*?) HTTP/1.1"
    host_pattern = r"Host: ([^\s]+)"
    proxy_pattern = r"X-Online-Host: ([^\s]+)"
    ssh_pattern = r"(ssh:\/\/[^\s]+)"
    ssl_pattern = r"(CONNECT [^\s]+:443)"

    parsed_data = {}

    # Cek payload
    payload_match = re.search(payload_pattern, packet_data)
    if payload_match:
        parsed_data["Payload"] = payload_match.group(2)

    # Cek Host
    host_match = re.search(host_pattern, packet_data)
    if host_match:
        parsed_data["Host"] = host_match.group(1)

    # Cek Proxy
    proxy_match = re.search(proxy_pattern, packet_data)
    if proxy_match:
        parsed_data["Proxy"] = proxy_match.group(1)

    # Cek SSH
    ssh_match = re.search(ssh_pattern, packet_data)
    if ssh_match:
        parsed_data["SSH"] = ssh_match.group(1)

    # Cek SSL
    ssl_match = re.search(ssl_pattern, packet_data)
    if ssl_match:
        parsed_data["SSL"] = ssl_match.group(1)

    # Jika ada data yang ditemukan, cetak dengan format rapi
    if parsed_data:
        print(json.dumps(parsed_data, indent=4))

# Jalankan sniffing
if __name__ == "__main__":
    interface = "any"  # Bisa diganti dengan eth0, wlan0, dll.
    filter_expr = "port 8080 or port 3128 or port 443"  # Sesuaikan dengan trafik yang ingin disaring
    sniff_traffic(interface, filter_expr)
