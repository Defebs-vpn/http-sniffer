import scapy.all as scapy
import logging
import json
import datetime
import argparse
import os
import threading
import queue

class HTTPConfigSniffer:
    def __init__(self, interface, port=80, log_file=None):
        self.interface = interface
        self.port = port
        self.log_file = log_file
        self.packet_queue = queue.Queue()
        self.stop_flag = threading.Event()
        
        # Konfigurasi logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file) if log_file else logging.StreamHandler()
            ]
        )

    def packet_handler(self, packet):
        if scapy.TCP in packet and packet[scapy.TCP].dport == self.port:
            try:
                payload = packet[scapy.TCP].payload.load.decode('utf-8', errors='ignore')
                
                # Filter konfigurasi spesifik
                config_data = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'source_ip': packet[scapy.IP].src,
                    'dest_ip': packet[scapy.IP].dst,
                    'payload': payload
                }
                
                # Tambahkan ke queue untuk pemrosesan lebih lanjut
                self.packet_queue.put(config_data)
            
            except Exception as e:
                logging.error(f"Error processing packet: {e}")

    def process_queue(self):
        while not self.stop_flag.is_set():
            try:
                config_data = self.packet_queue.get(timeout=1)
                
                # Analisis payload
                if self._is_interesting_config(config_data['payload']):
                    self._log_config(config_data)
                    self._alert_config(config_data)
            
            except queue.Empty:
                continue

    def _is_interesting_config(self, payload):
        # Filter konfigurasi berdasarkan kriteria tertentu
        interesting_keywords = [
            'Host:', 
            'Content-Type:', 
            'Authorization:', 
            'Cookie:'
        ]
        return any(keyword in payload for keyword in interesting_keywords)

    def _log_config(self, config_data):
        # Logging dalam format JSON
        log_entry = json.dumps(config_data)
        logging.info(log_entry)

    def _alert_config(self, config_data):
        # Mekanisme alert kustom
        if 'sensitive' in config_data['payload'].lower():
            # Kirim notifikasi, misalnya email atau webhook
            self._send_alert(config_data)

    def _send_alert(self, config_data):
        # Implementasi mekanisme alert
        print(f"ALERT: Sensitive config detected from {config_data['source_ip']}")

    def start_sniffing(self):
        # Jalankan sniffing di thread terpisah
        sniffer_thread = threading.Thread(
            target=scapy.sniff, 
            kwargs={
                'iface': self.interface, 
                'prn': self.packet_handler, 
                'store': 0
            }
        )
        
        # Thread untuk memproses queue
        processor_thread = threading.Thread(target=self.process_queue)
        
        sniffer_thread.start()
        processor_thread.start()

        try:
            sniffer_thread.join()
            processor_thread.join()
        except KeyboardInterrupt:
            self.stop_flag.set()

def main():
    parser = argparse.ArgumentParser(description='Advanced HTTP Config Sniffer')
    parser.add_argument('-i', '--interface', required=True, help='Network interface')
    parser.add_argument('-p', '--port', type=int, default=80, help='Port to sniff')
    parser.add_argument('-l', '--log', help='Log file path')
    
    args = parser.parse_args()

    # Validasi akses root
    if os.geteuid() != 0:
        print("Jalankan dengan sudo/root")
        return

    sniffer = HTTPConfigSniffer(
        interface=args.interface, 
        port=args.port, 
        log_file=args.log
    )
    
    sniffer.start_sniffing()

if __name__ == "__main__":
    main()
