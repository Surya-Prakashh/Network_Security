# Network Security Assessment & MAC Spoofing Suite — Complete Walkthrough

An end-to-end cybersecurity assessment tool built for network discovery, packet capture, MAC address spoofing, and security analysis. The codebase is organized into **3 distinct module folders** for team collaboration, topped by a central **Web Application Dashboard**.

---

## 📁 Modular Project Structure

```
d:/Education/DPSA/
├── module1_network_discovery/        <-- Folder 1 (Team Member 1)
│   ├── scanner.py                    <-- Nmap network discovery & port scanner
│   ├── scan_results.json             <-- Phase 1 JSON scan data
│   └── scan_results.csv              <-- Phase 1 CSV report
├── module2_packet_capture/           <-- Folder 2 (Team Member 2)
│   ├── sniffer.py                    <-- Wireshark/PyShark/Scapy packet dissector
│   ├── packet_analysis.json          <-- Phase 2 JSON packet log
│   └── packet_analysis.csv           <-- Phase 2 CSV report
├── module3_mac_spoofing/             <-- Folder 3 (Team Member 3)
│   ├── mac_changer.py                <-- MAC spoofing & adapter control script
│   └── mac_spoofing_log.json         <-- Phase 3 audit & verification log
├── security_analyzer.py              <-- Phase 4 Security Assessment Engine
├── app.py                            <-- Flask Web Application Server
├── requirements.txt                  <-- Python Dependencies
├── templates/
│   └── index.html                    <-- Responsive Glassmorphism Dashboard UI
└── static/
    ├── style.css                     <-- Dark Theme Design System
    └── dashboard.js                  <-- Client-side AJAX & Chart.js logic
```

---

## 📸 Interactive Web Dashboard

![Executive Overview](file:///C:/Users/Surya_prakash/.gemini/antigravity-ide/brain/eeffb6ca-6838-4037-8727-6c7ab3a9657b/executive_overview_1786342965517.png)

### Features & Phase Accomplishments

#### Phase 1: Network Discovery (`module1_network_discovery/`)
- **Host Discovery**: Discovers active IP addresses across local network subnets (`/24`).
- **OS Fingerprinting**: Identifies operating system details (Windows, Linux, Embedded Router).
- **Service & Version Scanning**: Scans TCP ports (e.g. 21 FTP, 22 SSH, 23 Telnet, 80 HTTP, 445 SMB, 3389 RDP) and detects service products & versions.
- **Exporting**: Automatically updates `scan_results.json` and `scan_results.csv`.

![Module 1 Network Discovery](file:///C:/Users/Surya_prakash/.gemini/antigravity-ide/brain/eeffb6ca-6838-4037-8727-6c7ab3a9657b/module1_network_discovery_1786342988310.png)

---

#### Phase 2: Packet Capture & Protocol Analysis (`module2_packet_capture/`)
- **Traffic Capture**: Parses live network packets and PCAP files across standard activities (browsing, file downloads, DNS queries, ICMP pings).
- **Protocol Dissection**: Analyzes TCP, UDP, DNS, HTTP/HTTPS, and ICMP protocols.
- **Header Field Extraction**: Extracts Source IP, Destination IP, Protocol, Packet Length, TCP 3-Way Handshake step (SYN -> SYN-ACK -> ACK), and DNS queries.

![Module 2 Packet Capture](file:///C:/Users/Surya_prakash/.gemini/antigravity-ide/brain/eeffb6ca-6838-4037-8727-6c7ab3a9657b/module2_packet_capture_1786343006957.png)

---

#### Phase 3: MAC Address Spoofing (`module3_mac_spoofing/`)
- **Adapter Inspection**: Displays current active hardware MAC address and interface status.
- **MAC Address Changer**: Generates random locally administered MAC addresses or accepts custom inputs.
- **Adapter Control**: Restarts network adapters via PowerShell / Windows API.
- **Verification & Restore**: Verifies applied MAC address changes and provides 1-click restoration to original hardware MAC.

![Module 3 MAC Spoofing](file:///C:/Users/Surya_prakash/.gemini/antigravity-ide/brain/eeffb6ca-6838-4037-8727-6c7ab3a9657b/module3_mac_spoofing_1786343025813.png)

---

#### Phase 4: Security Analysis & Firewall Rule Generation
- **Vulnerability Assessment**: Identifies unnecessary open ports (21 FTP, 23 Telnet, 80 HTTP, 135/139/445 SMB, 3389 RDP).
- **Protocol Security**: Flags plain-text unencrypted protocols.
- **Firewall Rule Generator**: Formulates copy-paste Windows Defender Firewall (`netsh advfirewall`) and Linux (`ufw`) rules.
- **Actionable Checklist**: Recommends SFTP, HTTPS/TLS 1.3, 802.1X NAC, and network segmentation.

![Phase 4 Security Analysis](file:///C:/Users/Surya_prakash/.gemini/antigravity-ide/brain/eeffb6ca-6838-4037-8727-6c7ab3a9657b/phase4_security_analysis_1786343044409.png)

---

## 🚀 How to Run

1. Open PowerShell / Command Prompt in `d:\Education\DPSA`.
2. Start the web server:
   ```bash
   python app.py
   ```
3. Open your web browser at: **`http://127.0.0.1:5000`**
