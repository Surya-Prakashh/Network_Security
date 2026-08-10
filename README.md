# Network Security Assessment & MAC Spoofing Suite

An end-to-end cybersecurity assessment application built with **Python (Nmap, Scapy, PyShark)** and an interactive **Web Application Dashboard (Flask)**. The repository is organized into **3 distinct module folders** for collaborative team development, topped by a central web application dashboard.

---

## 📋 Table of Contents
- [Tools Required](#tools-required)
- [Project Architecture](#project-architecture)
- [Phases & Features](#phases--features)
  - [Phase 1: Real Network Discovery (Nmap CLI Integration)](#phase-1-real-network-discovery-nmap-cli-integration)
  - [Phase 2: Packet Capture & Protocol Analysis (Wireshark/PyShark)](#phase-2-packet-capture--protocol-analysis-wiresharkpyshark)
  - [Phase 3: MAC Address Spoofing (SMAC)](#phase-3-mac-address-spoofing-smac)
  - [Phase 4: Security Audit & Firewall Rules](#phase-4-security-audit--firewall-rules)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Walkthrough Documentation](#walkthrough-documentation)

---

## 🛠️ Tools Required
- **Programming Language**: Python 3.12+
- **Network Scanner**: Nmap & `python-nmap`
- **Packet Capture**: Wireshark / TShark / `scapy` / `pyshark`
- **MAC Address Changer**: Windows PowerShell / `netsh` / SMAC
- **Libraries**: `flask`, `pandas`, `matplotlib`, `openpyxl`, `scapy`, `python-nmap`, `pyshark`

---

## 📁 Project Architecture

The project is structured into three dedicated module folders for team collaboration:

```
Network_Security/
├── module1_network_discovery/        <-- Team Member 1 (Nmap Network Scanner)
│   ├── scanner.py                    <-- Pure live Nmap execution & XML parser
│   ├── nmap_terminal_output.txt      <-- Captured raw Nmap CLI terminal logs
│   ├── scan_results.json             <-- Phase 1 JSON scan findings
│   └── scan_results.csv              <-- Phase 1 CSV report
├── module2_packet_capture/           <-- Team Member 2 (Packet Sniffer & Dissector)
│   ├── sniffer.py                    <-- Packet capture & protocol dissector
│   ├── packet_analysis.json          <-- Phase 2 JSON packet log
│   └── packet_analysis.csv           <-- Phase 2 CSV report
├── module3_mac_spoofing/             <-- Team Member 3 (MAC Address Changer)
│   ├── mac_changer.py                <-- MAC spoofing & adapter control script
│   └── mac_spoofing_log.json         <-- Phase 3 audit & verification log
├── security_analyzer.py              <-- Phase 4 Security Assessment Engine
├── app.py                            <-- Central Flask Web Application Server
├── walkthrough.md                    <-- Comprehensive Project Walkthrough & Screenshots
├── requirements.txt                  <-- Python Dependencies
├── templates/
│   └── index.html                    <-- Web Dashboard Interface with Live Console
└── static/
    ├── style.css                     <-- Styling System
    └── dashboard.js                  <-- Client Interactive Logic
```

---

## 🚀 Phases & Features

### Phase 1: Real Network Discovery (`module1_network_discovery/`)
- Executes **pure, live Nmap commands** (`nmap -sV -O -F --open <target>` or `nmap -sV -O -p- --open <target>`).
- Completely free of mock or synthetic data.
- Captures raw Nmap stdout into a live terminal console (`#nmapTerminalConsole`) inside the Dashboard UI.
- Identifies active host IP addresses, hostnames, MAC addresses, vendor information, operating system details, open TCP ports, running services, and service versions.
- Exports results to `scan_results.json` and `scan_results.csv`.

### Phase 2: Packet Capture & Analysis (`module2_packet_capture/`)
- Captures live network traffic and dissects PCAP files.
- Analyzes TCP, UDP, DNS, HTTP/HTTPS, and ICMP ping packets.
- Identifies Source IP, Destination IP, Protocol, Packet Length, TCP 3-way handshake steps (SYN -> SYN-ACK -> ACK), and DNS queries.

### Phase 3: MAC Address Spoofing (`module3_mac_spoofing/`)
- Views current network hardware MAC address.
- Generates random MAC addresses and changes adapter MAC.
- Restarts network adapter via PowerShell.
- Verifies new MAC and provides 1-click restoration to original hardware MAC.

### Phase 4: Security Audit & Firewall Rules (`security_analyzer.py`)
- Evaluates unnecessary open ports (21 FTP, 23 Telnet, 80 HTTP, 135/139/445 SMB, 3389 RDP).
- Identifies unencrypted plain-text protocols.
- Generates specific Windows Defender Firewall (`netsh`) and Linux (`ufw`) rules.
- Provides actionable security hardening recommendations.

---

## 💻 Installation & Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Surya-Prakashh/Network_Security.git
   cd Network_Security
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🏃 Running the Application

Launch the Flask Dashboard Server:
```bash
python app.py
```

Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📄 Walkthrough Documentation

See [`walkthrough.md`](walkthrough.md) for detailed phase breakdowns, component architecture, and dashboard visual walkthroughs.
