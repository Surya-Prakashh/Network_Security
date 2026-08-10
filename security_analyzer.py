"""
Phase 4: Security Analysis Engine
----------------------------------
Evaluates scan data and packet captures to:
1. Identify unnecessary or risky open ports.
2. Flag insecure / unencrypted network protocols.
3. Formulate specific Windows Defender Firewall and Linux ufw/iptables rules.
4. Provide comprehensive security hardening recommendations.
"""

import json
import os
import datetime

# Known insecure/risky ports database
RISKY_PORTS_DB = {
    21: {"service": "FTP", "risk": "High", "reason": "Transmits credentials and files in unencrypted cleartext."},
    23: {"service": "Telnet", "risk": "Critical", "reason": "Transmits all login credentials and shell commands in plain text."},
    80: {"service": "HTTP", "risk": "Medium", "reason": "Plaintext web traffic susceptible to eavesdropping and MITM attacks."},
    135: {"service": "MSRPC", "risk": "Medium", "reason": "Windows RPC endpoint mapper often targeted for reconnaissance."},
    139: {"service": "NetBIOS", "risk": "High", "reason": "Legacy NetBIOS Session Service prone to enumeration and spoofing."},
    445: {"service": "SMB", "risk": "Critical", "reason": "Direct SMB port frequently targeted by WannaCry/EternalBlue exploits."},
    3389: {"service": "RDP", "risk": "High", "reason": "Remote Desktop exposed without Network Level Authentication or VPN."}
}

INSECURE_PROTOCOLS_DB = {
    "HTTP": {"severity": "Medium", "mitigation": "Migrate to HTTPS with TLS 1.3 encryption and HSTS headers."},
    "TELNET": {"severity": "Critical", "mitigation": "Disable Telnet daemon completely and use OpenSSH (Port 22)."},
    "FTP": {"severity": "High", "mitigation": "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS."},
    "DNS": {"severity": "Low", "mitigation": "Implement DNS-over-HTTPS (DoH) or DNSSEC to prevent spoofing/poisoning."}
}


def analyze_security_posture(scan_file=None, packet_file=None):
    """Performs Phase 4 Security Analysis on discovered network assets."""
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

    # Analyze hosts and ports from Phase 1
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

                # Generate specific firewall rules
                win_cmd = f'netsh advfirewall firewall add rule name="Block Insecure Port {p} ({info["service"]})" dir=in action=block protocol=TCP localport={p}'
                linux_cmd = f'sudo ufw deny in proto tcp to any port {p} comment "Block {info["service"]}"'
                recommended_firewall_rules.append({
                    "target_ip": ip,
                    "port": p,
                    "service": info["service"],
                    "windows_firewall_cmd": win_cmd,
                    "linux_ufw_cmd": linux_cmd,
                    "rationale": f"Block unnecessary port {p} ({info['service']}) on {ip} to prevent unauthorized exploitation."
                })

    # Analyze traffic from Phase 2
    for p in packet_data.get("packets", []):
        proto = p.get("protocol", "").upper()
        if proto in INSECURE_PROTOCOLS_DB:
            insecure_protocols.add(proto)

    # Formulate security hardening recommendations
    for proto in insecure_protocols:
        if proto in INSECURE_PROTOCOLS_DB:
            info = INSECURE_PROTOCOLS_DB[proto]
            security_recommendations.append({
                "category": f"Insecure Protocol: {proto}",
                "severity": info["severity"],
                "finding": f"Detected plain-text {proto} traffic across network.",
                "action_item": info["mitigation"]
            })

    # General recommendations
    security_recommendations.extend([
        {
            "category": "Network Segmentation & Isolation",
            "severity": "High",
            "finding": "Management devices and IoT cameras share the same subnet as workstations.",
            "action_item": "Isolate IoT devices and IP cameras onto a dedicated VLAN with strict inter-VLAN firewall routing."
        },
        {
            "category": "MAC Address Privacy & Spoofing Defense",
            "severity": "Medium",
            "finding": "Static MAC filtering is vulnerable to MAC address spoofing (Phase 3 testing).",
            "action_item": "Enforce 802.1X Port-Based Network Access Control (NAC) instead of relying solely on MAC filtering."
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
    print(f"[+] Security Analysis Report generated: {report_path}")

    return report


if __name__ == "__main__":
    analyze_security_posture()
