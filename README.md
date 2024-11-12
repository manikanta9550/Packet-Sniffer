# Packet Sniffing and Monitoring Tool

A packet sniffing tool built with Python and Scapy designed for network traffic monitoring and cybersecurity analysis. This tool captures network packets, filters for specific conditions, logs network traffic, and generates alerts for suspicious activity.

## Features
- **Packet Capture**: Captures TCP packets on the network.
- **Suspicious Activity Detection**: Monitors for connections from known suspicious IPs and access to sensitive ports.
- **Logging**: Saves all traffic data to `network_traffic_log.txt`.
- **Alerting**: Generates alerts for flagged IPs or ports and saves them in `security_alerts.txt`.

## Technologies Used
- Python3
- Scapy library for packet sniffing

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/Packet-Sniffer.git
    cd Packet-Sniffer
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the script with administrative privileges:
    ```bash
    sudo python main.py
    ```

## Example Output

- **Traffic Log**: Saved in `logs/network_traffic_log.txt`.
- **Alerts**: Saved in `logs/security_alerts.txt`.

