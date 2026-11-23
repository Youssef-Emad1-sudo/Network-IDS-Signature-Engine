# Network IDS Signature Engine

A Suricata-based Network Intrusion Detection System (NIDS) project.

## Features
- 15 custom Suricata detection rules.
- 23 synthetic PCAP files for testing.
- Automated rule testing using Python and Suricata.
- JSON and text test reports.
- Flask web dashboard to browse detection alerts and rules.
- Rule tuning changelog.

## Project Structure
- `rules/`: Suricata detection rules.
- `pcaps/benign/`: Benign test traffic.
- `pcaps/malicious/`: Synthetic suspicious traffic.
- `scripts/`: PCAP generation and test harness scripts.
- `reports/`: Test results and tuning reports.
- `web/`: Flask dashboard.

## Requirements
- Python 3
- Scapy
- Flask
- Suricata 7

## Run the Test Harness
Activate the virtual environment:

    source venv/bin/activate

Run:

    sudo -E /home/youssef/Network-IDS/venv/bin/python scripts/test_rules.py

## Run the Web Dashboard

    python web/app.py

Open in your browser:

    http://127.0.0.1:5000

## Dataset
All PCAP files were synthetically generated using Scapy for controlled testing. They do not represent real-world traffic.

## Disclaimer
This project is for educational and defensive network security testing.
