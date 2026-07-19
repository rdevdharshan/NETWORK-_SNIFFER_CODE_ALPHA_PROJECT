# NETWORK-_SNIFFER_CODE_ALPHA_PROJECT
# Network Sniffer

A real-time network packet sniffer built with **Python**, **Flask**, **Flask-SocketIO**, and **Scapy**. This project captures live network traffic, extracts useful packet information, and displays it through a clean web-based dashboard.

## Features

* 📡 Capture live network packets in real time
* 🌐 Display source and destination IP addresses
* 🔌 Detect TCP, UDP, and ICMP protocols
* 📊 Monitor packet size and timestamps
* ⚡ Real-time updates using WebSockets (Flask-SocketIO)
* 🖥️ User-friendly web interface
* 🔍 Filter and inspect captured packets
* 📈 Lightweight and easy to extend

## Technologies Used

* Python 3.x
* Flask
* Flask-SocketIO
* Scapy
* HTML, CSS, JavaScript

## How It Works

The application uses **Scapy** to capture packets from the selected network interface. Each captured packet is processed to extract important information such as:

* Timestamp
* Source IP
* Destination IP
* Protocol
* Packet Length

The processed data is then sent to the web interface using **Flask-SocketIO**, allowing packets to appear instantly without refreshing the page.

## Project Structure

```
Network-Sniffer/
│
├── app.py                 # Main Flask application
├── templates/
│   └── index.html         # Web dashboard
├── static/
│   ├── css/
│   └── js/
├── requirements.txt
└── README.md
```

## Installation

1. Clone the repository.

```bash
git clone https://github.com/devdharshan/network-sniffer.git
```

2. Navigate to the project folder.

```bash
cd network-sniffer
```

3. Install the required packages.

```bash
pip install -r requirements.txt
```

4. Install **Npcap** (Windows users) and enable **WinPcap Compatibility Mode** during installation.

5. Run the application.

```bash
python app.py
```

6. Open your browser and visit:

```
http://127.0.0.1:5000
```

## Requirements

* Python 3.9+
* Flask
* Flask-SocketIO
* Scapy
* Npcap (Windows)

## Future Improvements

* Packet filtering
* Search functionality
* Export captured packets to PCAP/CSV
* Packet statistics dashboard
* Protocol charts
* Network traffic visualization
* Dark mode
* User authentication

## Educational Purpose

This project is intended for **learning network protocols, packet analysis, and cybersecurity concepts**. It demonstrates how packet sniffing works using Python and Scapy in a controlled environment.

## Disclaimer

This tool is designed **only for educational and authorized network monitoring**. Use it only on networks and systems that you own or have explicit permission to analyze. Unauthorized packet capture may violate privacy laws and organizational policies.

## Author

**Devdharshan R**

Cybersecurity Student | Python Developer | SOC & Network Security Enthusiast
