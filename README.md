# Secure Online Examination Monitoring System

An end-to-end network security monitoring suite adapted for **Online Examination Security**, built with **Python (Nmap, Scapy, PyShark, Flask, Flask-SocketIO)** and an interactive **Web Application Dashboard**. The repository is organized into **3 core module folders** topped by a central web monitoring dashboard.

---

## 📋 Table of Contents
- [Use Case Overview](#use-case-overview)
- [Tools Required](#tools-required)
- [Project Architecture](#project-architecture)
- [Phases & Domain Mapping](#phases--domain-mapping)
  - [Phase 1: Exam Environment Verification (Nmap Scanner & SSE Stream)](#phase-1-exam-environment-verification-nmap-scanner--sse-stream)
  - [Phase 2: Examination Network Traffic Monitoring (Real-Time Scapy & SocketIO Engine)](#phase-2-examination-network-traffic-monitoring-real-time-scapy--socketio-engine)
  - [Phase 3: Candidate Device Verification (MAC Identity Audit)](#phase-3-candidate-device-verification-mac-identity-audit)
  - [Phase 4: Exam Security Assessment & Firewall Enforcement](#phase-4-exam-security-assessment--firewall-enforcement)
- [Installation & Setup](#installation--setup)
- [Running the Application](#running-the-application)
- [Walkthrough Documentation](#walkthrough-documentation)

---

## 🎓 Use Case Overview

> **Scenario**: A student is attending an online examination. The existing network security modules are used to check the examination environment, monitor live network traffic during the test, verify candidate device hardware identity, identify cheating-risk network behaviors (such as unauthorized remote desktop access or background file sharing), and enforce security warnings and firewall rules.

---

## 🛠️ Tools Required
- **Programming Language**: Python 3.12+
- **Network Scanner**: Nmap & `python-nmap`
- **Real-Time Traffic Engine**: Scapy & `flask-socketio`
- **Packet Dissector**: Wireshark / TShark / `scapy` / `pyshark`
- **Candidate Device Audit**: Windows PowerShell / `netsh` / `ipconfig`
- **Libraries**: `flask`, `flask-socketio`, `pandas`, `matplotlib`, `openpyxl`, `scapy`, `python-nmap`, `pyshark`

---

## 📁 Project Architecture

The project maintains the modular structure and adapts it to exam security monitoring:

```
Network_Security/
├── module1_network_discovery/        <-- Phase 1: Exam Environment Verification
│   ├── scanner.py                    <-- Nmap execution, XML parsing, SSE stream, command history
│   ├── nmap_terminal_output.txt      <-- Raw Nmap CLI terminal logs
│   ├── scan_results.json             <-- Phase 1 JSON scan findings
│   └── scan_results.csv              <-- Phase 1 CSV report
├── module2_packet_capture/           <-- Phase 2: Exam Network Traffic Monitoring
│   ├── sniffer.py                    <-- SocketIO real-time capture engine & packet dissector
│   ├── packet_analysis.json          <-- Phase 2 JSON packet log
│   └── packet_analysis.csv           <-- Phase 2 CSV report
├── module3_mac_spoofing/             <-- Phase 3: Candidate Device Verification
│   ├── mac_changer.py                <-- MAC identity baseline check & spoofing audit script
│   └── mac_spoofing_log.json         <-- Phase 3 device verification log
├── security_analyzer.py              <-- Phase 4 Exam Security Assessment & Firewall Engine
├── app.py                            <-- Central Flask & SocketIO Exam Monitoring Server
├── walkthrough.md                    <-- Project Architecture & Exam Domain Walkthrough
├── test_exam_security_suite.py       <-- Automated Unit & Integration Test Suite
├── requirements.txt                  <-- Python Dependencies
├── templates/
│   └── index.html                    <-- Secure Exam Cyber HUD Dashboard Interface
└── static/
    ├── style.css                     <-- Styling System
    └── dashboard.js                  <-- Client SocketIO & Interactive Dashboard Logic
```

---

## 🚀 Phases & Domain Mapping

### Phase 1: Exam Environment Verification (`module1_network_discovery/`)
- Verifies candidate network environment via **live Nmap scans** (`nmap -sn -PR`, `nmap -sV`, `nmap -O`, `nmap -A`).
- Streams real-time CLI terminal output to dashboard using Server-Sent Events (SSE `/api/module1/stream-scan`).
- Maintains an archived audit log of all executed commands (`/api/module1/history`).
- Discovers active network hosts, open proxy ports, and unexpected secondary devices in the exam hall.

### Phase 2: Exam Network Traffic Monitoring (`module2_packet_capture/`)
- Captures live exam session network traffic in real-time using Socket.IO events (`m2_packet`, `m2_stats`, `m2_dns`, `m2_handshake`).
- Analyzes TCP 3-way handshakes, DNS domain lookups, HTTPS/TLS encryption, and ICMP ping sweeps.
- Identifies unencrypted exam content transmissions and unauthorized connection attempts.

### Phase 3: Candidate Device Verification (`module3_mac_spoofing/`)
- Audits network interface MAC address to verify candidate hardware identity.
- Evaluates baseline MAC addresses and flags suspicious hardware address changes or spoofing attempts.

### Phase 4: Exam Security Assessment & Firewall Rules (`security_analyzer.py`)
- Evaluates cheating-risk open ports (3389 RDP for remote assistance, 21 FTP for test paper leakage, 23 Telnet for cleartext shell access, 445 SMB for peer-to-peer answer sharing).
- Generates specific Windows Defender Firewall (`netsh`) and Linux (`ufw`) block rules to isolate the examination environment.
- Produces an actionable security posture score (0–100) and security hardening checklist.

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

Launch the Secure Online Examination Monitoring Dashboard:
```bash
python app.py
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 📄 Walkthrough Documentation

See [`walkthrough.md`](walkthrough.md) for full phase breakdowns, domain mappings, technical design details, and verification results.

