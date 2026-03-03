import scapy.all as scapy
import argparse
import socket
import json
import threading
import logging
from datetime import datetime

#  Logging Setup #

logging.basicConfig(
    filename="scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Argument Parser #

parser = argparse.ArgumentParser(description="Network Reconnaissance Tool")
parser.add_argument("-t", "--target", required=True, help="Target IP Range")
parser.add_argument("-p", "--ports", default="1-100", help="Port Range (ex: 1-100)")
parser.add_argument("-o", "--output", default="result.json", help="Output File")

args = parser.parse_args()

target_ip = args.target
port_range = args.ports
output_file = args.output

start_port, end_port = port_range.split("-")
start_port = int(start_port)
end_port = int(end_port)

# Vendor Lookup (Basic) #

vendor_map = {
    "3C:55:76": "Cloud Network Technology",
    "00:1A:2B": "Cisco",
    "F4:F5:E8": "Samsung"
}

def get_vendor(mac):
    prefix = mac.upper()[0:8]
    return vendor_map.get(prefix, "Unknown")

# ARP Scan #

def arp_scan(ip):
    logging.info("Starting ARP Scan")

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    request = broadcast / arp_request

    answered = scapy.srp(request, timeout=2, verbose=False)[0]

    devices = []

    for element in answered:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "vendor": get_vendor(element[1].hwsrc),
            "open_ports": []
        }

        print("\nDevice Found:", device_info["ip"])
        print("Vendor:", device_info["vendor"])
        print("Scanning Ports...")
        print("---------------------------")

        logging.info(f"Device Found: {device_info['ip']} {device_info['mac']}")

        devices.append(device_info)

    return devices

#Port Scan#

def scan_port(ip, port, result):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        if sock.connect_ex((ip, port)) == 0:
            result.append(port)

        sock.close()

    except:
        pass


def port_scan(ip, device):
    threads = []
    open_ports = []

    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    device["open_ports"] = open_ports

#  Main  #

print("\n==============================")
print("   Network Reconnaissance Tool")
print("==============================\n")

logging.info("Scan Started")

devices = arp_scan(target_ip)

for device in devices:
    port_scan(device["ip"], device)

# Save Output #

with open(output_file, "w") as file:
    json.dump(devices, file, indent=4)

print("\nScan Complete")
print("Output saved in:", output_file)
print("Time:", datetime.now())

logging.info("Scan Completed")
