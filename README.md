# NETWORK-_SNIFFER_CODE_ALPHA_PROJECT
#🔍 Network Sniffer
A Python-based network packet sniffer built with Scapy and Colorama, now featuring a modern, premium CustomTkinter Graphical User Interface. It captures live network traffic, analyzes each packet, and displays results in either a clean, color-coded terminal table or a rich dark-theme dashboard — with options for real-time statistics, file export, and packet detail breakdown.

#📋 Features
Premium Dark Mode GUI built with CustomTkinter
Live packet capture using Scapy (run on non-blocking background thread)
Protocol filtering — TCP, UDP, ICMP, or all
Color-coded output — TCP (Blue), UDP (Green), ICMP (Yellow)
Packet details — IPs, ports, payload (UTF-8 or hex), size, timestamp
Summary report — protocol breakdown, top source & destination IPs
File export — save results as .txt or .json
Graceful exit — Ctrl+C prints a summary before quitting in CLI mode

#🗂️ Project Structure
network_sniffer/
├── main.py           # CLI entry point (supports -g / --gui flag)
├── gui.py            # Modern CustomTkinter GUI dashboard
├── sniffer.py        # Packet capture module (Scapy)
├── analyzer.py       # Packet parsing & data extraction
├── display.py        # Terminal display with color formatting
├── requirements.txt  # Python dependencies (now includes customtkinter)
├── test_analyzer.py  # Unit tests (no root required)
└── README.md
#⚙️ Requirements
Python 3.8+
Windows: Run terminal as Administrator
Linux/macOS: Run with sudo
Install dependencies:

pip install -r requirements.txt
Windows users: You may also need to install Npcap for Scapy to capture packets.
