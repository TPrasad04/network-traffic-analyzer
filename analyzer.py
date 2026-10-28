
import csv
from collections import Counter
from pathlib import Path

from scapy.all import (
    rdpcap, Ether, IP, IPv6, TCP, UDP, DNS
)

BASE_DIR = Path(__file__).resolve().parent
PCAP_FILE = BASE_DIR / "dns.cap"
CSV_FILE = BASE_DIR / "report.csv"

if not PCAP_FILE.exists():
    raise FileNotFoundError(
        f"Capture not found: {PCAP_FILE}\n"
        "Place dns.cap beside analyzer.py."
    )

packets = rdpcap(str(PCAP_FILE))

layer_counts = Counter()
source_ips = Counter()
destination_ips = Counter()
packet_rows = []

for number, packet in enumerate(packets, start=1):
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    layers = []

    # Identify link-layer and network-layer protocols
    if Ether in packet:
        layers.append("Ethernet")

    if IP in packet:
        layers.append("IPv4")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        layers.append("IPv6")
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    # Identify transport and application layers independently
    if TCP in packet:
        layers.append("TCP")
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    if UDP in packet:
        layers.append("UDP")
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if DNS in packet:
        layers.append("DNS")

    # Count every recognized layer present in this packet
    layer_counts.update(layers)

    if src_ip:
        source_ips[src_ip] += 1
        destination_ips[dst_ip] += 1

    packet_rows.append({
        "packet_number": number,
        "timestamp": float(packet.time),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol_layers": "+".join(layers) if layers else "Other",
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_size_bytes": len(packet),
    })

# Export packet-level information
fieldnames = [
    "packet_number",
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol_layers",
    "source_port",
    "destination_port",
    "packet_size_bytes",
]

with CSV_FILE.open(
    "w", newline="", encoding="utf-8"
) as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(packet_rows)

print("\n=== NETWORK TRAFFIC ANALYZER ===")
print(f"Capture: {PCAP_FILE.name}")
print(f"Total packets: {len(packets)}")
print(f"Total captured bytes: {sum(len(p) for p in packets)}")

print("\nProtocol-layer packet counts:")
for layer, count in layer_counts.most_common():
    print(f"  {layer}: {count} packets")

print("\nTop source IP addresses:")
for ip, count in source_ips.most_common(5):
    print(f"  {ip}: {count} packets")

print("\nTop destination IP addresses:")
for ip, count in destination_ips.most_common(5):
    print(f"  {ip}: {count} packets")

print(f"\nCSV report saved to: {CSV_FILE}")
