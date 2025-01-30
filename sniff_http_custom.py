from scapy.all import sniff, TCP, Raw
from datetime import datetime

# Konfigurasi
LOG_FILE = "log_http_custom.txt"
FILTER_PORTS = "tcp port 80 or tcp port 443 or tcp port 8080 or tcp port 3128"  # Sniff beberapa port sekaligus

# Daftar User-Agent aplikasi HTTP Custom (tambahkan jika perlu)
HTTP_CUSTOM_USER_AGENTS = ["HTTPCustom", "HTTP Injector", "NapsternetV", "KPN Tunnel", "Psiphon"]

def log_to_file(data):
    """Simpan hasil sniffing ke file log"""
    with open(LOG_FILE, "a") as file:
        file.write(data + "\n" + "="*50 + "\n")

def analyze_http_payload(payload):
    """Analisis payload untuk menemukan konfigurasi HTTP Custom"""
    config = {}

    # Deteksi mode koneksi
    if "CONNECT" in payload:
        config["Mode"] = "CONNECT (Direct SSL/TLS)"
    elif "GET" in payload or "POST" in payload:
        config["Mode"] = "GET/POST (SSH/WebSocket)"

    # Cari header penting
    for line in payload.split("\n"):
        if line.startswith("Host:"):
            config["Host"] = line.split(": ")[1].strip()
        elif line.startswith("X-Online-Host:"):
            config["X-Online-Host"] = line.split(": ")[1].strip()
        elif line.startswith("User-Agent:"):
            ua = line.split(": ")[1].strip()
            config["User-Agent"] = ua

            # Cek apakah User-Agent berasal dari HTTP Custom
            for custom_agent in HTTP_CUSTOM_USER_AGENTS:
                if custom_agent in ua:
                    config["App"] = custom_agent

    return config

def packet_callback(packet):
    """Callback untuk menangkap paket HTTP Custom"""
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')

        # Filter paket HTTP Custom
        if "CONNECT" in payload or "Host:" in payload or "GET" in payload:
            config = analyze_http_payload(payload)

            # Pastikan hanya menangkap paket dari aplikasi HTTP Custom
            if "App" in config:
                print("="*50)
                print("[+] Paket HTTP Custom Terdeteksi:")
                print(payload.strip())
                print("="*50)

                # Simpan ke file log
                log_data = f"\n[Timestamp: {datetime.now()}]\nPayload:\n{payload.strip()}\n\nConfig Detected:\n{config}\n"
                log_to_file(log_data)

# Jalankan sniffing di beberapa port (80, 443, 8080, 3128)
print("[*] Sniffing HTTP Custom... (Tekan CTRL+C untuk berhenti)")
sniff(filter=FILTER_PORTS, prn=packet_callback, store=0)
