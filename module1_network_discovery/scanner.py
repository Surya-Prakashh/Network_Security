"""
Module 1: Real Network Discovery & Sequential Nmap Scanner (Phase 1)
---------------------------------------------------------------------
Executes dynamic native Nmap CLI commands in sequence:
1. Detect Default Gateway & Local IP (ipconfig logic)
2. Network Host Discovery Ping Sweep (-sn)
3. Basic TCP Port Scan (top ports / default ports)
4. Service Version Detection (-sV)
5. Operating System Fingerprinting (-O)
6. Aggressive Security Scan (-A)

Captures live stdout into nmap_terminal_output.txt and updates scan_results.json & scan_results.csv dynamically.
NO mock/synthetic data.
"""

import json
import csv
import os
import sys
import datetime
import subprocess
import socket
import re
import xml.etree.ElementTree as ET


def get_network_interfaces_info():
    """
    Executes ipconfig to get local IPv4 address, Subnet Mask, Default Gateway, 
    and auto-calculates the local CIDR subnet (e.g. 192.168.160.0/19).
    """
    local_ip = "127.0.0.1"
    gateway = None
    subnet_mask = "255.255.255.0"
    subnet_cidr = "192.168.1.0/24"

    try:
        cmd_out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
        
        # Regex find active Wi-Fi or Ethernet IPv4 and Gateway
        ipv4_matches = re.findall(r"IPv4 Address[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)
        mask_matches = re.findall(r"Subnet Mask[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)
        gw_matches = re.findall(r"Default Gateway[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)

        if ipv4_matches:
            # Pick first non-loopback IP
            for ip in ipv4_matches:
                if not ip.startswith("127."):
                    local_ip = ip
                    break
        
        if mask_matches:
            subnet_mask = mask_matches[0]
            
        if gw_matches:
            gateway = gw_matches[0]

        # Calculate CIDR subnet from IP and Subnet Mask
        if local_ip != "127.0.0.1":
            ip_parts = [int(p) for p in local_ip.split(".")]
            mask_parts = [int(p) for p in subnet_mask.split(".")]
            
            # Netmask bits to CIDR prefix
            cidr_bits = sum(bin(m).count('1') for m in mask_parts)
            
            # Calculate network base address
            net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            base_net = ".".join(str(p) for p in net_parts)
            subnet_cidr = f"{base_net}/{cidr_bits}"

    except Exception as e:
        print(f"[!] Exception discovering IP/Gateway via ipconfig: {e}")

    return {
        "local_ip": local_ip,
        "default_gateway": gateway,
        "subnet_mask": subnet_mask,
        "subnet_cidr": subnet_cidr,
        "raw_ipconfig": cmd_out if 'cmd_out' in locals() else "ipconfig command unavailable."
    }


def parse_nmap_xml(xml_content):
    """Parses Nmap XML output into structured python dictionary."""
    hosts_data = []
    if xml_content and "<nmaprun" in xml_content:
        try:
            root = ET.fromstring(xml_content)
            for host_elem in root.findall("host"):
                status_elem = host_elem.find("status")
                state = status_elem.get("state") if status_elem is not None else "down"

                if state != "up":
                    continue

                ip_addr = "Unknown"
                mac_addr = "N/A"
                vendor = "Unknown"
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype")
                    if addr_type in ["ipv4", "ipv6"]:
                        ip_addr = addr.get("addr")
                    elif addr_type == "mac":
                        mac_addr = addr.get("addr")
                        vendor = addr.get("vendor", "Unknown")

                hostname = ip_addr
                hostnames_elem = host_elem.find("hostnames")
                if hostnames_elem is not None:
                    hn_elem = hostnames_elem.find("hostname")
                    if hn_elem is not None:
                        hostname = hn_elem.get("name") or ip_addr

                os_details = "OS detection not available / restricted"
                os_elem = host_elem.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        os_name = osmatch.get("name")
                        accuracy = osmatch.get("accuracy")
                        os_details = f"{os_name} ({accuracy}% accuracy)"
                
                ports_list = []
                ports_elem = host_elem.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        port_num = int(port_elem.get("portid"))
                        protocol = port_elem.get("protocol")
                        
                        state_elem = port_elem.find("state")
                        port_state = state_elem.get("state") if state_elem is not None else "closed"

                        service_elem = port_elem.find("service")
                        svc_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                        product = service_elem.get("product", "") if service_elem is not None else ""
                        version = service_elem.get("version", "") if service_elem is not None else ""
                        extra = service_elem.get("extrainfo", "") if service_elem is not None else ""
                        
                        svc_version = f"{product} {version} {extra}".strip() or "Unknown Version"

                        if "restricted" in os_details and service_elem is not None:
                            ostype = service_elem.get("ostype")
                            if ostype:
                                os_details = f"OS Hint: {ostype}"

                        ports_list.append({
                            "port": port_num,
                            "protocol": protocol,
                            "service": svc_name,
                            "version": svc_version,
                            "state": port_state
                        })

                hosts_data.append({
                    "ip": ip_addr,
                    "status": state,
                    "hostname": hostname,
                    "mac_address": mac_addr,
                    "vendor": vendor,
                    "os_details": os_details,
                    "ports": ports_list
                })
        except Exception as e:
            print(f"[!] Nmap XML parsing error: {e}")

    return hosts_data


def parse_nmap_text_output(text):
    """Parses raw text stdout from Nmap CLI into hosts list."""
    hosts = []
    current_host = None

    for line in text.splitlines():
        line = line.strip()
        # Nmap scan report for 192.168.160.2 or localhost (127.0.0.1)
        report_match = re.search(r"Nmap scan report for (?:([^\s()]+)\s+\()?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?", line)
        if report_match:
            if current_host:
                hosts.append(current_host)
            hostname = report_match.group(1) or report_match.group(2)
            ip = report_match.group(2)
            current_host = {
                "ip": ip,
                "status": "up",
                "hostname": hostname,
                "mac_address": "N/A",
                "vendor": "Unknown",
                "os_details": "N/A",
                "ports": []
            }
            continue

        # MAC Address: 78:48:59:B7:66:A0 (Hewlett Packard)
        mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]+)\s*(?:\((.*?)\))?", line)
        if mac_match and current_host:
            current_host["mac_address"] = mac_match.group(1)
            current_host["vendor"] = mac_match.group(2) or "Unknown"

    if current_host:
        hosts.append(current_host)

    return hosts


def run_single_nmap_command(cmd_type, target):
    """
    Executes a specific Nmap command mode:
    - 'ping_sweep': nmap -sn <target>
    - 'basic_scan': nmap <target>
    - 'service_scan': nmap -sV <target>
    - 'os_scan': nmap -O <target>
    - 'aggressive_scan': nmap -A <target>
    """
    net_info = get_network_interfaces_info()
    if not target:
        target = net_info["subnet_cidr"] if cmd_type == "ping_sweep" else (net_info["default_gateway"] or net_info["local_ip"])

    # Build Nmap command array
    if cmd_type == "ping_sweep":
        base_cmd = ["nmap", "-sn", target]
        display_cmd = f"nmap -sn {target}"
    elif cmd_type == "basic_scan":
        base_cmd = ["nmap", target]
        display_cmd = f"nmap {target}"
    elif cmd_type == "service_scan":
        base_cmd = ["nmap", "-sV", target]
        display_cmd = f"nmap -sV {target}"
    elif cmd_type == "os_scan":
        base_cmd = ["nmap", "-O", target]
        display_cmd = f"nmap -O {target}"
    elif cmd_type == "aggressive_scan":
        base_cmd = ["nmap", "-A", target]
        display_cmd = f"nmap -A {target}"
    else:
        base_cmd = ["nmap", "-sV", "-O", "-F", "--open", target]
        display_cmd = f"nmap -sV -O -F --open {target}"

    print(f"[*] Executing Nmap Command: {display_cmd}")

    # Run for terminal output
    try:
        term_proc = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        terminal_out = f"$ {display_cmd}\n\n" + (term_proc.stdout or "")
        if term_proc.stderr:
            terminal_out += f"\n[Stderr Output]\n{term_proc.stderr}"
    except Exception as e:
        terminal_out = f"$ {display_cmd}\n\nError executing Nmap: {str(e)}"

    # Run with XML flag for structured JSON extraction
    xml_out = ""
    try:
        xml_cmd = base_cmd + ["-oX", "-"]
        xml_proc = subprocess.run(
            xml_cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        xml_out = xml_proc.stdout
    except Exception as e:
        print(f"[!] XML execution warning: {e}")

    hosts_data = parse_nmap_xml(xml_out)
    if not hosts_data:
        hosts_data = parse_nmap_text_output(terminal_out)

    # Save to terminal log
    script_dir = os.path.dirname(os.path.abspath(__file__))
    terminal_log_path = os.path.join(script_dir, "nmap_terminal_output.txt")
    json_path = os.path.join(script_dir, "scan_results.json")
    csv_path = os.path.join(script_dir, "scan_results.csv")

    with open(terminal_log_path, "w", encoding="utf-8") as f:
        f.write(terminal_out)

    scan_result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "command_executed": display_cmd,
        "cmd_type": cmd_type,
        "scan_mode": f"Live Nmap CLI ({cmd_type.replace('_', ' ').title()})",
        "network_interfaces": net_info,
        "total_hosts_found": len(hosts_data),
        "hosts": hosts_data,
        "terminal_output": terminal_out
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=4)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "Status", "MAC Address", "OS Details", "Port", "Protocol", "Service", "Version"])
        for host in hosts_data:
            if not host["ports"]:
                writer.writerow([host["ip"], host["hostname"], host["status"], host["mac_address"], host["os_details"], "None", "None", "None", "None"])
            else:
                for p in host["ports"]:
                    writer.writerow([
                        host["ip"], host["hostname"], host["status"], host["mac_address"], host["os_details"],
                        p["port"], p["protocol"], p["service"], p["version"]
                    ])

    return scan_result


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "service_scan"
    tgt = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    res = run_single_nmap_command(cmd, tgt)
    print(f"[*] Done executing {cmd} on {tgt}. Discovered {res['total_hosts_found']} hosts.")
