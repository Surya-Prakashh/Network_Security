"""
Phase 4: Online Examination Security Assessment Engine
--------------------------------------------------------
Evaluates scan data and packet captures in an online examination environment to:
1. Identify unauthorized, unnecessary, or cheating-risk open ports (e.g. RDP 3389, FTP 21, Telnet 23).
2. Flag insecure / unencrypted network protocols that risk exam content leakage.
3. Formulate specific Windows Defender Firewall and Linux ufw rules to enforce exam network restrictions.
4. Provide comprehensive security hardening recommendations for secure online exam monitoring.
"""

import json
import os
import datetime

# Known insecure / high-risk ports database for Online Examination Environment
RISKY_PORTS_DB = {
    21: {"service": "FTP", "risk": "High", "reason": "Transmits exam credentials and test files in unencrypted cleartext; high risk of exam paper leakage."},
    23: {"service": "Telnet", "risk": "Critical", "reason": "Unencrypted remote command shell allowing unauthorized remote assistance or candidate computer manipulation during exams."},
    80: {"service": "HTTP", "risk": "Medium", "reason": "Plaintext web traffic susceptible to eavesdropping and unencrypted exam content transmission."},
    135: {"service": "MSRPC", "risk": "Medium", "reason": "Windows RPC endpoint mapper susceptible to network enumeration by secondary devices in the exam venue."},
    139: {"service": "NetBIOS", "risk": "High", "reason": "Legacy NetBIOS Session Service prone to local candidate machine discovery and unauthorized session hijacking."},
    445: {"service": "SMB", "risk": "Critical", "reason": "Direct file sharing port frequently targeted by network exploits or unauthorized peer-to-peer exam answer sharing."},
    3389: {"service": "RDP", "risk": "Critical", "reason": "Remote Desktop Protocol active; critical risk of candidate impersonation or unauthorized third-party remote assistance during the exam."}
}

INSECURE_PROTOCOLS_DB = {
    "HTTP": {"severity": "Medium", "mitigation": "Migrate exam client web traffic to HTTPS with TLS 1.3 encryption and HSTS headers."},
    "TELNET": {"severity": "Critical", "mitigation": "Disable Telnet daemon completely to prevent unauthorized remote shell access during exams."},
    "FTP": {"severity": "High", "mitigation": "Replace plain FTP with secure SFTP (SSH File Transfer Protocol) for exam question/answer uploads."},
    "DNS": {"severity": "Low", "mitigation": "Implement DNS-over-HTTPS (DoH) or DNSSEC to prevent DNS spoofing and unauthorized domain redirects."}
}


def analyze_security_posture(scan_file=None, packet_file=None):
    """Performs Phase 4 Security Assessment on candidate examination environment."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    if not scan_file:
        scan_file = os.path.join(script_dir, "module1_network_discovery", "scan_results.json")
    if not packet_file:
        packet_file = os.path.join(script_dir, "module2_packet_capture", "packet_analysis.json")

    scan_data = {}
    packet_data = {}

    if os.path.exists(scan_file):
        try:
            with open(scan_file, "r") as f:
                scan_data = json.load(f)
        except Exception:
            pass

    if os.path.exists(packet_file):
        try:
            with open(packet_file, "r") as f:
                packet_data = json.load(f)
        except Exception:
            pass

    unnecessary_ports = []
    insecure_protocols = set()
    recommended_firewall_rules = []
    security_recommendations = []

    # Analyze hosts and ports from Phase 1 (Exam Environment Verification)
    hosts = scan_data.get("hosts", [])
    for host in hosts:
        ip = host.get("ip", "Unknown")
        for port_info in host.get("ports", []):
            p = port_info.get("port")
            svc = port_info.get("service", "").lower()

            if p in RISKY_PORTS_DB:
                info = RISKY_PORTS_DB[p]
                unnecessary_ports.append({
                    "ip": ip,
                    "port": p,
                    "service": port_info.get("service"),
                    "version": port_info.get("version"),
                    "risk_level": info["risk"],
                    "reason": info["reason"]
                })
                insecure_protocols.add(info["service"].upper())

                # Generate specific firewall enforcement rules for exam security
                win_cmd = f'netsh advfirewall firewall add rule name="Exam Security Block Port {p} ({info["service"]})" dir=in action=block protocol=TCP localport={p}'
                linux_cmd = f'sudo ufw deny in proto tcp to any port {p} comment "Exam Security Block {info["service"]}"'
                recommended_firewall_rules.append({
                    "target_ip": ip,
                    "port": p,
                    "service": info["service"],
                    "windows_firewall_cmd": win_cmd,
                    "linux_ufw_cmd": linux_cmd,
                    "rationale": f"Block prohibited port {p} ({info['service']}) on {ip} to isolate the exam environment and prevent remote cheating/assistance."
                })

    # Analyze traffic from Phase 2 (Exam Network Traffic Monitoring)
    for p in packet_data.get("packets", []):
        proto = p.get("protocol", "").upper()
        if proto in INSECURE_PROTOCOLS_DB:
            insecure_protocols.add(proto)

    # Formulate security hardening recommendations for examination environment
    for proto in insecure_protocols:
        if proto in INSECURE_PROTOCOLS_DB:
            info = INSECURE_PROTOCOLS_DB[proto]
            security_recommendations.append({
                "category": f"Insecure Exam Protocol: {proto}",
                "severity": info["severity"],
                "finding": f"Detected unencrypted plain-text {proto} traffic during exam session.",
                "action_item": info["mitigation"]
            })

    # General exam security recommendations
    security_recommendations.extend([
        {
            "category": "Exam Environment Network Isolation",
            "severity": "High",
            "finding": "Candidate examination workstation shares the subnet with unmonitored local network devices.",
            "action_item": "Isolate candidate exam devices onto a dedicated Exam VLAN with strict inter-VLAN firewall routing during testing."
        },
        {
            "category": "Candidate Device Verification & MAC Anti-Spoofing",
            "severity": "Medium",
            "finding": "Static MAC identity checks are vulnerable to device impersonation via MAC address spoofing (Phase 3 audit).",
            "action_item": "Enforce 802.1X Port-Based Network Access Control (NAC) alongside candidate hardware MAC verification."
        }
    ])

    report = {
        "generated_at": datetime.datetime.now().isoformat(),
        "summary": {
            "total_hosts_evaluated": len(hosts),
            "unnecessary_open_ports_count": len(unnecessary_ports),
            "insecure_protocols_found": list(insecure_protocols),
            "recommended_firewall_rules_count": len(recommended_firewall_rules),
            "security_score": max(10, 100 - (len(unnecessary_ports) * 15 + len(insecure_protocols) * 10))
        },
        "unnecessary_ports": unnecessary_ports,
        "insecure_protocols": [
            {"protocol": p, "details": INSECURE_PROTOCOLS_DB.get(p, {"severity": "Medium", "mitigation": "Enforce encryption."})}
            for p in insecure_protocols
        ],
        "recommended_firewall_rules": recommended_firewall_rules,
        "security_improvements": security_recommendations
    }

    report_path = os.path.join(script_dir, "security_analysis_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] Online Examination Security Assessment Report generated: {report_path}")

    return report


if __name__ == "__main__":
    analyze_security_posture()

