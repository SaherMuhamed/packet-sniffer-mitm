# Network Packet Sniffer

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)  ![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)  ![Windows](https://img.shields.io/badge/Windows-0078D4.svg?style=for-the-badge&logo=Windows&logoColor=white)  ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)

- This Python script is a network packet sniffer that captures and analyzes network packets on a specified network interface. It detects HTTP requests and searches for potential credentials within the captured packets.
- The script utilizes the scapy library for packet capturing and parsing. It specifically focuses on capturing HTTP packets and extracting useful information such as server IP, URLs, and potential credentials. The captured packets are processed in real-time, and relevant details are displayed on the console.

## Prerequisites
- Python 3.x
- `scapy` library
- `argparse` library
- `colorama` library
- `logging` library

## Installation
- Clone the repository or download the script:
   ```commandline
   git clone https://github.com/SaherMuhamed/packet-sniffer-mitm.git
   ```
- Install the required libraries using the following command:
   ```commandline
   pip install scapy colorama scapy_http
   ```


## Usage
1. Make sure you have the necessary prerequisites installed first.
2. Run the script using the following command:
    ```commandline
    sudo python3 packet_sniffer.py -i <interface> [-f <filter>] [-c <count>] [-q] [-v]
    ```
   Replace `<interface_name>` with the name of the network interface card you want to use for packet capturing. You can find the available interfaces by running `ifconfig` command in linux OS.

### Arguments
| Option | Description |
|--------|-------------|
| `-i`, `--interface` | Specify the network interface (e.g., wlan0, eth0) **(Required)** |
| `-f`, `--filter` | Filter packets (default: `tcp port 80`) |
| `-c`, `--count` | Number of packets to capture (0 for unlimited) |
| `-q`, `--quiet` | Enable quiet mode (suppress console output) |
| `-v`, `--verbose` | Enable verbose mode (show detailed output) |

### Example
```bash
sudo python3 packet_sniffer.py -i wlan0 -f "tcp port 80" -v
```

## Logging
Captured packet details are stored in `Sniffing.log`. The log includes:
- Source IP
- HTTP request details
- Detected sensitive data (e.g., passwords, usernames)

## Features
1. Captures network packets in real-time on a specified network interface.
2. Detects HTTP requests.
3. Searches for potential credentials within the captured packets.
4. Extracts server IP and URLs from HTTP packets.
5. Identifies potential credentials based on specific keywords in packet payload.
6. Supports quiet mode and verbose mode.

## Screenshots
![](https://github.com/SaherMuhamed/packet-sniffer-mitm/blob/master/screenshots/Annotation%202025-03-13%20174858.png)

## Disclaimer
This script is intended for educational and research purposes only. Please use it responsibly. Iam assume no responsibility for any misuse or damages caused by this script.

### Updates
- `v1.1.0 - 16/6/2023` adding yellow color to **possible creds** output
- `v1.1.1 - 28/12/2023` adding new outputs like **Methods**, and **device IP**
- `v1.1.2 - 14/12/2024` adding **Access.log** for analyzing requests, adding **responses** and refine outputs
- `v2.1.0 - 13/03/2025` add verbose and quiet mode with logging functionality
