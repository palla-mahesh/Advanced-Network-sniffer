# Advanced-Network-sniffer
An advanced Python-based network sniffer that captures and analyzes network packets in real time for monitoring and cybersecurity learning. 👉 Features packet inspection, protocol analysis, and traffic monitoring to understand network communication and security concepts.
# 🌐 Advanced Network Packet Sniffer (Python + Scapy)

## 📌 Overview

This project is an advanced implementation of a **Network Packet Sniffer** using **Python** with **Scapy** library. It features both a **command-line interface** and an **interactive menu system** for capturing, analyzing, and logging network traffic in real-time.

It allows users to capture packets from live network interfaces, analyze protocols (TCP, UDP, ICMP, ARP, DNS), reconstruct HTTP requests, extract DNS queries, and save captured data to **PCAP** (Wireshark-compatible) and **JSON** formats for further analysis.

---

## 🚀 Features

* 🔍 **Real-time packet capture** from any network interface
* 📊 **Live statistics dashboard** with protocol breakdown
* 🌐 **Multi-protocol support** (TCP, UDP, ICMP, ARP, DNS)
* 📡 **HTTP request/response reconstruction**
* 🔎 **DNS query extraction** (see domains being looked up)
* 🎨 **Color-coded terminal output** for easy reading
* 💾 **Save packets to PCAP** (open with Wireshark)
* 📋 **Export to JSON** for programmatic analysis
* 🔧 **BPF filter support** (capture specific traffic only)
* 📁 **Load and analyze existing PCAP files**
* ⚙️ **Configurable settings** (toggle display options)
* 🔄 **Live statistics thread** (background updates)
* 🧹 **Interactive menu system** for easy navigation

---

## 🛠️ Technologies Used

* **Python 3.7+**
* **Scapy** (Packet manipulation library)
* **Colorama** (Terminal color support)
* **Npcap** (Windows packet capture driver)
* **libpcap** (Linux/macOS packet capture)

---

## 📂 Project Structure
network-sniffer/
│
├── advanced_network_sniffer.py # Main application with all features
├── test_sniffer.py # Quick test script
├── requirements.txt # Python dependencies
├── README.md # Project documentation
├── LICENSE # MIT License
├── .gitignore # Git ignore rules
│
├── captured_traffic.pcap # Default PCAP output (auto-generated)
├── packet_log.json # JSON log of captures (auto-generated)
│
└── captures/ # Folder for test captures
└── test_capture.pcap # Example capture (auto-generated)

---

## ▶️ How to Run the Project

### 1️⃣ Install Python

Download and install Python 3.7+ from: https://www.python.org

**Important**: Make sure to enable **"Add Python to PATH"** during installation.

---

### 2️⃣ Install Npcap (Windows Only)

1. Download Npcap from: https://npcap.com
2. **Right-click** installer → **Run as Administrator**
3. **CRITICAL**: Check ✅ **"Install Npcap in WinPcap API-compatible Mode"**
4. Complete installation and restart if prompted

**For Linux/macOS**: libpcap is usually pre-installed or available via package manager.

---

### 3️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/network-sniffer.git
cd network-sniffer
Install Dependencies
bash

pip install -r requirements.txt

Or manually:
bash

pip install scapy colorama
Run the Application

Windows (as Administrator):
bash

python advanced_network_sniffer.py

Linux/macOS (with sudo):
bash

sudo python3 advanced_network_sniffer.py

6️⃣ Quick Test (Optional)
bash

# Windows
python test_sniffer.py

# Linux/macOS
sudo python3 test_sniffer.py

This captures 10 packets and saves them to captures/test_capture.pcap.
🧠 How It Works

The packet sniffer captures network traffic at the data link layer (Ethernet) and dissects each packet to extract:
Packet Dissection Process
text

Ethernet Frame → IP Packet → TCP/UDP/ICMP Segment → Payload Data

Example: TCP Packet Analysis
text

1. Capture raw packet from network interface
2. Check for Ethernet layer (MAC addresses)
3. Extract IP layer (source/destination IPs, protocol, TTL)
4. Parse TCP layer (ports, flags, sequence numbers)
5. Extract payload data (if present)
6. Display formatted output with colors
7. Log to JSON and save to PCAP

Caesar Cipher vs Network Sniffer Analogy
Caesar Cipher	Network Sniffer
Shifts letters by a key	Captures packets from network
Encrypts/decrypts text	Analyzes protocol headers
Brute-force all 26 shifts	Filters traffic by protocol/port
Preserves case and symbols	Preserves packet structure
🎯 Interactive Menu Options

When you run the program, you'll see:
text

================================================================================
📡 ADVANCED NETWORK SNIFFER - MENU
================================================================================
1. Basic Capture (All Packets)
2. Capture HTTP Traffic (Port 80)
3. Capture HTTPS Traffic (Port 443)
4. Capture DNS Traffic (Port 53)
5. Capture Specific IP
6. Capture Specific Protocol
7. Load & Analyze PCAP File
8. Configure Settings
9. Exit
================================================================================

Option	Description	Use Case
1	All packets	General monitoring
2	HTTP only	Web traffic analysis
3	HTTPS only	SSL/TLS monitoring
4	DNS only	Domain lookup tracking
5	Specific IP	Monitor single device
6	TCP/UDP/ICMP/ARP	Protocol-specific analysis
7	Load PCAP	Offline analysis
8	Settings	Customize display
🔍 BPF Filter Examples

Berkeley Packet Filter (BPF) syntax for advanced filtering:
Filter	                Description
tcp	                  TCP packets only
udp	                  UDP packets only
icmp	                Ping packets only
port 80	              HTTP traffic
port 443	            HTTPS traffic
port 53	              DNS traffic
host 192.168.1.1	    Specific IP address
src host 192.168.1.1	Source IP only
tcp port 22	          SSH traffic
not port 443	        Exclude HTTPS
Combining Filters
python

# TCP on port 80 or 443
start_sniffing(bpf_filter="tcp and (port 80 or port 443)")

# Exclude ARP and ICMP
start_sniffing(bpf_filter="not arp and not icmp")

📊 Sample Output
Live Packet Capture
text

================================================================================
[2026-05-06 22:03:52.603] Packet #1
--------------------------------------------------------------------------------
🌐 IP Layer:
  Source     : 192.168.0.102
  Destination: 163.70.140.60
  Protocol   : TCP
  TTL        : 64
  Length     : 116 bytes
🔌 TCP Segment:
  Source Port : 56394
  Dest Port   : 443
  Flags       : PA
📦 Payload:
  Length: 76 bytes
  HEX   : 17030300476bd4399e5112f0c41b2e9d...
================================================================================

Live Statistics (Every 10 seconds)
text

======================================================================
📊 LIVE STATISTICS (Running: 30s)
======================================================================
Total Packets: 156

Protocol Breakdown:
  TCP       : 142 ██████████████████████████████
  UDP       : 10  ██
  ARP       : 4   █

Top IP Addresses (by bytes):
  192.168.0.102   : 45,234 bytes
  104.18.11.243   : 12,456 bytes
======================================================================

🎯 Use Cases

    Learning network protocols - Understand TCP/IP, HTTP, DNS

    Network debugging - Troubleshoot connectivity issues

    Security analysis - Detect suspicious traffic patterns

    Educational projects - Cybersecurity assignments

    Network monitoring - Track bandwidth usage by IP

    Malware analysis - Observe malicious domain lookups

    Hackathon submissions - Impress with real-time packet analysis

    Wireshark alternative - Lightweight CLI-based sniffer

🔧 Configuration

Edit the CONFIG dictionary in advanced_network_sniffer.py:
python

CONFIG = {
    "save_packets": True,                    # Auto-save to PCAP
    "pcap_file": "captured_traffic.pcap",    # Output filename
    "log_file": "packet_log.json",           # JSON log filename
    "max_payload_display": 100,              # Max payload bytes to show
    "show_hex": False,                       # Display hex dump
    "show_ascii": True,                      # Display ASCII text
    "show_mac": True,                        # Display MAC addresses
    "statistics_interval": 10                # Stats update interval (seconds)
}

📁 Analyzing Captured Data
With Wireshark (Recommended)

    Install Wireshark from: https://wireshark.org

    Open the generated PCAP file:
    bash

    wireshark captured_traffic.pcap

    Use Wireshark filters like tcp, http, or ip.src == 192.168.1.1

With Python (Scapy)
python

from scapy.all import rdpcap

packets = rdpcap("captured_traffic.pcap")
print(f"Total packets: {len(packets)}")

for pkt in packets[:5]:
    print(pkt.summary())

With JSON (Python)
python

import json

with open("packet_log.json", "r") as f:
    packets = json.load(f)

for pkt in packets[:5]:
    print(f"{pkt['src_ip']} → {pkt['dst_ip']} ({pkt['protocol']})")

🐛 Troubleshooting
Issue	Solution
Permission denied	Run as Administrator (Windows) or with sudo (Linux/macOS)
No packets captured	Check network connection, disable firewall temporarily
Npcap not found	Reinstall with "WinPcap API-compatible Mode" checked
ModuleNotFoundError: scapy	Run pip install scapy
PCAP file won't open	File may be empty. Capture at least 10 packets
Colorama not working	Run pip install colorama --upgrade
🚧 Future Enhancements

    Add GUI using Tkinter/PyQt

    Implement packet reassembly (TCP streams)

    Add GeoIP location mapping

    Export to CSV/Excel formats

    Real-time bandwidth graph

    Email/Slack alerts for suspicious traffic

    Packet capture scheduling

    Remote packet capture via SSH

🤝 Contribution

Contributions are welcome!

Feel free to:

    Fork this repository

    Create a feature branch

    Submit pull requests

    Report bugs via Issues

Development Setup
bash

# Clone your fork
git clone https://github.com/your-username/network-sniffer.git
cd network-sniffer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Make your changes and test
python test_sniffer.py

📜 License

This project is open-source and available under the MIT License.

See the LICENSE file for details.

🙏 Acknowledgments

    Scapy - Amazing packet manipulation library

    Wireshark - PCAP format and analysis tools

    Npcap - Windows packet capture driver

    Colorama - Terminal color support

⚠️ Disclaimer

This tool is for educational purposes only. Network packet sniffing can capture sensitive information and may be illegal without proper authorization.

Only use this tool on:

    Your own personal network

    Networks where you have explicit written permission

    Lab environments you control

Do NOT use on:

    Public Wi-Fi without authorization

    Corporate networks without permission

    Any network you don't own or manage

⭐ Show Your Support

If you like this project, please consider:

    ⭐ Starring the repository on GitHub

    🔄 Forking it for your own use

    📢 Sharing it with others

    🐛 Reporting issues
