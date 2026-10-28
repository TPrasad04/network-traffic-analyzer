# Network Traffic Analyzer

A Python-based network traffic analysis tool that reads saved PCAP files, identifies selected protocol layers, extracts packet metadata, and exports results to CSV using Scapy.

## Overview

Network traffic analysis helps security analysts understand communication between hosts, investigate network activity, and collect evidence for further investigation.

This project demonstrates foundational packet analysis and data-processing skills relevant to entry-level cybersecurity and SOC Analyst roles.

## Project Objectives

- Read packets from a saved PCAP capture.
- Extract source and destination IP addresses.
- Identify selected Ethernet, IPv4, IPv6, TCP, UDP, and DNS layers.
- Examine transport-layer port numbers.
- Calculate packet sizes and preserve capture timestamps.
- Summarize protocol-layer counts and frequently observed IP addresses.
- Export packet-level metadata into a CSV report.

## Technologies Used

- **Python** — programming and data processing
- **Scapy** — packet parsing and protocol-layer inspection
- **CSV** — structured report generation
- **Wireshark** — optional independent packet inspection
- **Windows** — development environment

## Project Structure

```text
network-traffic-analyzer/
├── analyzer.py
├── README.md
├── dns.cap       # Local sample capture; not included in this repository
└── report.csv    # Generated when the analyzer runs
```

The `.venv` directory is a local Python virtual environment and should not be uploaded.

## Features

### 1. PCAP Analysis
Reads a saved packet capture and processes its packets using Scapy.

### 2. Protocol-Layer Statistics
Counts selected layers, including Ethernet, IPv4, IPv6, TCP, UDP, and DNS. A packet can contain multiple layers, so these counts may overlap.

### 3. IP Address Statistics
Displays the most frequently observed source and destination IP addresses in the capture.

### 4. Packet Metadata Extraction
Records packet numbers, timestamps, source and destination IP addresses, recognized protocol layers, available TCP/UDP ports, and packet sizes.

### 5. CSV Reporting
Exports packet-level records to `report.csv` for review using spreadsheet software or other analysis tools.

## Requirements

- Python 3.12 or another compatible Python 3 version
- Internet access to install Scapy and obtain a sample capture
- A Windows Command Prompt or terminal

## Installation and Usage

### 1. Obtain the project files

Download `analyzer.py` from this repository and place it in a local project folder.

Obtain a suitable sample capture from the [Wireshark Sample Captures collection](https://wiki.wireshark.org/SampleCaptures). Place the file named `dns.cap` beside `analyzer.py`.

### 2. Open the project folder

Open Command Prompt in the folder containing `analyzer.py`.

### 3. Create a virtual environment

```bat
python -m venv .venv
```

### 4. Activate the environment

```bat
.venv\Scripts\activate
```

### 5. Install Scapy

```bat
python -m pip install scapy
```

### 6. Run the analyzer

```bat
python analyzer.py
```

The program prints packet statistics and generates `report.csv` in the project directory.

## Test Results and Validation

The analyzer was tested using the local sample capture `dns.cap`.

| Validation metric | Observed result |
|---|---:|
| Packets read from PCAP | 38 |
| CSV data rows | 38 |
| Total captured packet bytes | 3,706 |
| Total packet bytes represented in CSV | 3,706 |
| Packet-count comparison | PASS |
| Packet-size-total comparison | PASS |

### Interpretation

The analyzer processed 38 packets and generated 38 CSV data rows. The sum of packet sizes recorded in the CSV matched the total calculated from the original capture.

These checks validate packet-record coverage and packet-size preservation for this test. They do not independently establish that every extracted field or protocol classification is correct.

## Relevance to SOC Analysis

This project demonstrates foundational skills used in network investigations:

- Understanding network and transport protocols
- Examining source and destination addresses
- Reviewing port-level communication
- Working with packet-capture evidence
- Producing structured investigation data
- Validating program output against an original data source

## Limitations

- Recognizes only selected protocol layers.
- Uses basic metadata analysis rather than comprehensive protocol dissection.
- Does not establish whether traffic is malicious.
- Does not perform advanced threat detection or behavioral anomaly detection.
- Does not provide a graphical interface or automated alerting.

## Future Improvements

- Add protocol and IP-address filtering.
- Generate a separate protocol-summary report.
- Add automated unit tests for packet parsing and CSV export.
- Improve handling of additional protocols and link-layer formats.
- Add evidence-based traffic observations and configurable detection rules.

## Author

**Tumati Lakshmi Prasad**

Aspiring Cybersecurity / SOC Analyst

[GitHub Profile](https://github.com/TPrasad04)
