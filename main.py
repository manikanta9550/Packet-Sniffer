from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import datetime
import os

# Ensure log directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Define list of suspicious IPs (example)
suspicious_ips = ["192.168.1.100", "10.0.0.200"]

# Define packet handling function
def packet_callback(packet):
    # Check if packet has an IP and TCP layer
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        packet_info = f"[{datetime.datetime.now()}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"

        # Log packet info
        with open("logs/network_traffic_log.txt", "a") as log_file:
            log_file.write(packet_info)
        
        # Check for suspicious activity
        if src_ip in suspicious_ips or dst_port in [22, 23, 3389]:  # Example ports: SSH, Telnet, RDP
            alert = f"[ALERT] Suspicious activity detected from {src_ip} to {dst_ip}:{dst_port}\n"
            print(alert)
            with open("logs/security_alerts.txt", "a") as alert_file:
                alert_file.write(alert)

# Start packet sniffing with a filter for TCP traffic
print("Starting packet capture for security monitoring...")
sniff(prn=packet_callback, filter="tcp", store=0)

