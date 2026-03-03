# Network Reconnaissance Tool 

A lightweight network reconnaissance tool developed using Python for discovering active devices and scanning open ports in a local network.

This tool uses ARP requests for host discovery and multi-threaded TCP socket scanning for port detection.

---

## Features

- ARP-based Host Discovery
- Multi-threaded TCP Port Scanning
- MAC Vendor Identification (Basic)
- JSON Output Reporting
- Logging Support
- Command-line Interface

---

## Technologies Used

- Python
- Scapy
- Socket Programming
- Threading
- JSON
- Logging

---

## How It Works

1. Sends ARP broadcast packets to identify active hosts.
2. Extracts IP and MAC addresses from responses.
3. Performs TCP connect scan on specified port range.
4. Uses multi-threading to speed up port scanning.
5. Stores results in JSON format.

---

## Project Structure
network-recon-tool/
│
├── scanner.py          # Main script for ARP and Port Scanning
├── requirements.txt    # Project dependencies
├── README.md           # Project documentation
└── .gitignore          # Ignored files
