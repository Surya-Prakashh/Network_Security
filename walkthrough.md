# Secure Online Examination Monitoring System — Complete Walkthrough

An end-to-end network security monitoring suite transformed for **Online Examination Monitoring**. The application leverages real-time Nmap scanning, Scapy packet dissection, SocketIO streaming, and candidate device MAC verification to ensure a secure exam environment.

---

## 🎓 Domain & Use Case Mapping

| Existing Component / Folder | Online Examination Monitoring Domain Role | Key Functionality |
| :--- | :--- | :--- |
| **Module 1 (`module1_network_discovery/`)** | **Exam Environment Verification** | Scans candidate network for active hosts, open proxy/unnecessary ports, and unknown secondary devices. Streams live CLI output via SSE. |
| **Module 2 (`module2_packet_capture/`)** | **Exam Network Traffic Monitoring** | Monitors live exam traffic via Socket.IO events (`m2_packet`, `m2_stats`, `m2_dns`, `m2_handshake`). Dissects TCP 3-way handshakes & DNS lookups. |
| **Module 3 (`module3_mac_spoofing/`)** | **Candidate Device Verification** | Audits candidate hardware network MAC address. Detects identity tampering, unauthorized adapter changes, or MAC spoofing. |
| **Phase 4 (`security_analyzer.py`)** | **Exam Security Assessment & Firewall Enforcement** | Evaluates cheating-risk open ports (RDP 3389, FTP 21, Telnet 23, SMB 445). Formulates Windows Defender and Linux `ufw` block rules. |

---

## 📁 Modular Project Architecture

```
Network_Security/
├── module1_network_discovery/        <-- Phase 1: Exam Environment Verification
│   ├── scanner.py                    <-- Nmap scanner, SSE stream, command history
│   ├── scan_results.json             <-- Phase 1 JSON scan data
│   └── scan_results.csv              <-- Phase 1 CSV report
├── module2_packet_capture/           <-- Phase 2: Exam Traffic Monitoring
│   ├── sniffer.py                    <-- SocketIO real-time packet capture engine
│   ├── packet_analysis.json          <-- Phase 2 JSON packet log
│   └── packet_analysis.csv           <-- Phase 2 CSV report
├── module3_mac_spoofing/             <-- Phase 3: Candidate Device Verification
│   ├── mac_changer.py                <-- MAC identity baseline check & spoofing audit script
│   └── mac_spoofing_log.json         <-- Phase 3 device verification log
├── security_analyzer.py              <-- Phase 4 Exam Security Assessment & Firewall Engine
├── app.py                            <-- Flask & SocketIO Web Application Server
├── test_exam_security_suite.py       <-- Automated Unit & Integration Test Suite
├── requirements.txt                  <-- Python Dependencies
├── templates/
│   └── index.html                    <-- Responsive Glassmorphism Exam Dashboard
└── static/
    ├── style.css                     <-- Dark Theme Cyber HUD Design System
    └── dashboard.js                  <-- Client SocketIO & Interactive Dashboard Logic
```

---

## 🚀 Module Feature Breakdowns

### Module 1: Examination Environment Verification (`module1_network_discovery/`)
- **Subnet Auto-Discovery**: Auto-detects local IPv4, Gateway IP, Subnet Mask, and CIDR subnet from system network interfaces.
- **Nmap Sequence Pipeline**: Executes 6 distinct CLI command steps (Ping Sweep `-sn -PR`, Basic Scan, Service Versions `-sV`, OS Fingerprint `-O`, Aggressive Audit `-A`).
- **SSE Real-Time Stream**: Streams stdout directly into the web console without page refresh.
- **Audit Command Archive**: Retains an in-memory execution history log (`/api/module1/history`).

### Module 2: Examination Network Traffic Monitoring (`module2_packet_capture/`)
- **Real-Time Capture Engine**: Captures live exam traffic on selected network interface.
- **SocketIO Event Bus**: Pushes real-time packet data (`m2_packet`), protocol counters (`m2_stats`), DNS queries (`m2_dns`), and TCP 3-way handshakes (`m2_handshake`).
- **Traffic Export**: Exports packet captures to `packet_analysis.json` and `packet_analysis.csv`.

### Module 3: Candidate Device Verification (`module3_mac_spoofing/`)
- **MAC Baseline Audit**: Compares active network adapter MAC address against baseline identity.
- **Anti-Spoofing Verification**: Identifies hardware address changes or unauthorized adapter replacement during exam session.

### Phase 4: Exam Security Assessment (`security_analyzer.py`)
- **Cheating-Risk Port Detection**: Flags ports 3389 (RDP - remote assistance), 21 (FTP - test leakage), 23 (Telnet - cleartext shell), and 445 (SMB - file sharing).
- **Firewall Enforcement**: Generates automated Windows Defender `netsh` and Linux `ufw` block commands.

---

## 🏃 How to Run

1. Launch the server:
   ```bash
   python app.py
   ```
2. Open your web browser at: **`http://127.0.0.1:5000`**

