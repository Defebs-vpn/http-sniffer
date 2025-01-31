import os
import re
import json
import time

# Path ke direktori tempat file konfigurasi disimpan
config_directory = "/storage/emulated/0/Download/HTTPCustom/kontol.hc"

# Fungsi untuk membaca file konfigurasi
def read_config_file(file_path):
    with open(file_path, "r") as file:
        return file.read()

# Fungsi untuk mengekstrak informasi dari konfigurasi HTTP Custom
def extract_info(config_content):
    data = {
        "payload": None,
        "proxy": None,
        "ssl": None,
        "ssh": None
    }

    # Regular expression untuk menemukan informasi dalam konfigurasi
    payload_match = re.search(r"(?<=payload\s*=\s*).*", config_content)
    if payload_match:
        data["payload"] = payload_match.group(0).strip()

    proxy_match = re.search(r"(?<=proxy\s*=\s*).*", config_content)
    if proxy_match:
        data["proxy"] = proxy_match.group(0).strip()

    ssl_match = re.search(r"(?<=ssl\s*=\s*).*", config_content)
    if ssl_match:
        data["ssl"] = ssl_match.group(0).strip()

    ssh_match = re.search(r"(?<=ssh\s*=\s*).*", config_content)
    if ssh_match:
        data["ssh"] = ssh_match.group(0).strip()

    return data

# Fungsi untuk menyimpan log dalam format JSON
def save_log(data, log_file="sniff_log.json"):
    with open(log_file, "a") as json_file:
        json.dump(data, json_file, indent=4)
        json_file.write("\n")

# Fungsi untuk memindai direktori dan memproses file konfigurasi baru
def scan_configs():
    files = [f for f in os.listdir(config_directory) if f.endswith('.conf')]
    for file_name in files:
        file_path = os.path.join(config_directory, file_name)
        config_content = read_config_file(file_path)
        config_info = extract_info(config_content)
        
        # Menampilkan hasil sniffing
        print(f"Sniffing {file_name}:")
        print(json.dumps(config_info, indent=4))

        # Menyimpan log ke file JSON
        save_log(config_info)

# Fungsi untuk memonitor perubahan file baru
def auto_watch():
    print("Monitoring new configuration files...")
    while True:
        scan_configs()
        time.sleep(5)  # Cek setiap 5 detik

if __name__ == "__main__":
    auto_watch()
