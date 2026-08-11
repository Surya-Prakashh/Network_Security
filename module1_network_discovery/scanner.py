"""
Module 1: Real Network Discovery & Sequential Nmap Scanner (Phase 1)
---------------------------------------------------------------------
Executes dynamic native Nmap CLI commands in sequence with live progress streaming:
1. Detect Default Gateway & Local IP (ipconfig logic)
2. Network Host Discovery Ping Sweep (-sn)
3. Basic TCP Port Scan (top ports / default ports)
4. Service Version Detection (-sV)
5. Operating System Fingerprinting (-O)
6. Aggressive Security Scan (-A)

Outputs real Nmap terminal logs, live progress percentage, scan_results.json, and scan_results.csv.
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
    cmd_out = ""

    try:
        cmd_out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
        
        # Regex find active Wi-Fi or Ethernet IPv4 and Gateway
        ipv4_matches = re.findall(r"IPv4 Address[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)
        mask_matches = re.findall(r"Subnet Mask[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)
        gw_matches = re.findall(r"Default Gateway[.\s]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", cmd_out)

        if ipv4_matches:
            for ip in ipv4_matches:
                if not ip.startswith("127."):
                    local_ip = ip
                    break
        
        if mask_matches:
            subnet_mask = mask_matches[0]
            
        if gw_matches:
            gateway = gw_matches[0]

        if local_ip != "127.0.0.1":
            ip_parts = [int(p) for p in local_ip.split(".")]
            mask_parts = [int(p) for p in subnet_mask.split(".")]
            cidr_bits = sum(bin(m).count('1') for m in mask_parts)
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
        "raw_ipconfig": cmd_out if cmd_out else "ipconfig command output unavailable."
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

        mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]+)\s*(?:\((.*?)\))?", line)
        if mac_match and current_host:
            current_host["mac_address"] = mac_match.group(1)
            current_host["vendor"] = mac_match.group(2) or "Unknown"

    if current_host:
        hosts.append(current_host)

    return hosts


def extract_progress_percentage(line, current_percent=0.0):
    """Extracts completion percentage from Nmap status line."""
    match = re.search(r"About\s+([0-9]+(?:\.[0-9]+)?)\%\s+done", line, re.IGNORECASE)
    if match:
        return float(match.group(1))
    
    # Stage heuristics fallback
    if "Initiating ARP Ping Scan" in line or "Initiating Ping Scan" in line:
        return max(current_percent, 5.0)
    elif "Initiating Parallel DNS resolution" in line:
        return max(current_percent, 15.0)
    elif "Initiating SYN Stealth Scan" in line or "Initiating Connect Scan" in line:
        return max(current_percent, 30.0)
    elif "Initiating Service scan" in line:
        return max(current_percent, 55.0)
    elif "Initiating OS detection" in line:
        return max(current_percent, 80.0)
    elif "Initiating NSE" in line:
        return max(current_percent, 90.0)
    elif "Nmap done:" in line:
        return 100.0
    return current_percent


def run_single_nmap_command(cmd_type, target):
    """
    Executes a specific Nmap command mode:
    - 'ping_sweep': nmap -sn --stats-every 1s --min-rate 300 <target>
    - 'basic_scan': nmap --stats-every 1s <target>
    - 'service_scan': nmap -sV --stats-every 1s <target>
    - 'os_scan': nmap -O --stats-every 1s <target>
    - 'aggressive_scan': nmap -A --stats-every 1s <target>
    """
    net_info = get_network_interfaces_info()
    if not target:
        target = net_info["subnet_cidr"] if cmd_type == "ping_sweep" else (net_info["default_gateway"] or net_info["local_ip"])

    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_xml_path = os.path.join(script_dir, "temp_scan.xml")

    # Build Nmap command array with --stats-every 1s
    if cmd_type == "ping_sweep":
        base_cmd = ["nmap", "-sn", "-PR", "--stats-every", "1s", "--min-rate", "300", target]
        display_cmd = f"nmap -sn -PR --stats-every 1s --min-rate 300 {target}"
    elif cmd_type == "basic_scan":
        base_cmd = ["nmap", "--stats-every", "1s", target]
        display_cmd = f"nmap --stats-every 1s {target}"
    elif cmd_type == "service_scan":
        base_cmd = ["nmap", "-sV", "--stats-every", "1s", target]
        display_cmd = f"nmap -sV --stats-every 1s {target}"
    elif cmd_type == "os_scan":
        base_cmd = ["nmap", "-O", "--stats-every", "1s", target]
        display_cmd = f"nmap -O --stats-every 1s {target}"
    elif cmd_type == "aggressive_scan":
        base_cmd = ["nmap", "-A", "--stats-every", "1s", target]
        display_cmd = f"nmap -A --stats-every 1s {target}"
    else:
        base_cmd = ["nmap", "-sV", "-O", "-F", "--open", "--stats-every", "1s", target]
        display_cmd = f"nmap -sV -O -F --open --stats-every 1s {target}"

    print(f"[*] Executing Nmap Command: {display_cmd}")

    terminal_out = ""
    xml_out = ""
    
    try:
        full_cmd = base_cmd + ["-oX", temp_xml_path]
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        terminal_out = f"$ {display_cmd}\n\n" + (proc.stdout or "")
        if proc.stderr:
            terminal_out += f"\n[Stderr Output]\n{proc.stderr}"

        if os.path.exists(temp_xml_path):
            with open(temp_xml_path, "r", encoding="utf-8", errors="ignore") as f:
                xml_out = f.read()
            try:
                os.remove(temp_xml_path)
            except Exception:
                pass
    except subprocess.TimeoutExpired as te:
        stdout_part = te.stdout or ""
        terminal_out = f"$ {display_cmd}\n\n[Timeout Warning: Scan exceeded 300 seconds]\n{stdout_part}"
    except Exception as e:
        terminal_out = f"$ {display_cmd}\n\nError executing Nmap: {str(e)}"

    hosts_data = parse_nmap_xml(xml_out)
    if not hosts_data:
        hosts_data = parse_nmap_text_output(terminal_out)

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

    append_command_to_history(cmd_type, display_cmd, target, len(hosts_data), terminal_out)

    return scan_result


def stream_nmap_command_events(cmd_type, target):
    """
    Generator streaming live lines & progress percentage via Server-Sent Events (SSE).
    """
    net_info = get_network_interfaces_info()
    if not target:
        target = net_info["subnet_cidr"] if cmd_type == "ping_sweep" else (net_info["default_gateway"] or net_info["local_ip"])

    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_xml_path = os.path.join(script_dir, "temp_stream_scan.xml")

    if cmd_type == "ping_sweep":
        base_cmd = ["nmap", "-sn", "-PR", "--stats-every", "1s", "--min-rate", "300", target]
        display_cmd = f"nmap -sn -PR --stats-every 1s --min-rate 300 {target}"
    elif cmd_type == "basic_scan":
        base_cmd = ["nmap", "--stats-every", "1s", target]
        display_cmd = f"nmap {target}"
    elif cmd_type == "service_scan":
        base_cmd = ["nmap", "-sV", "--stats-every", "1s", target]
        display_cmd = f"nmap -sV {target}"
    elif cmd_type == "os_scan":
        base_cmd = ["nmap", "-O", "--stats-every", "1s", target]
        display_cmd = f"nmap -O {target}"
    elif cmd_type == "aggressive_scan":
        base_cmd = ["nmap", "-A", "--stats-every", "1s", target]
        display_cmd = f"nmap -A {target}"
    else:
        base_cmd = ["nmap", "-sV", "-O", "-F", "--open", "--stats-every", "1s", target]
        display_cmd = f"nmap -sV -O -F --open {target}"

    full_cmd = base_cmd + ["-oX", temp_xml_path]
    
    yield f"data: {json.dumps({'type': 'start', 'cmd': display_cmd, 'percent': 0.0})}\n\n"

    collected_log = f"$ {display_cmd}\n\n"
    current_pct = 0.0

    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in iter(proc.stdout.readline, ''):
            collected_log += line
            current_pct = extract_progress_percentage(line, current_pct)
            event_data = {
                "type": "log",
                "line": line,
                "percent": round(current_pct, 1),
                "full_log": collected_log
            }
            yield f"data: {json.dumps(event_data)}\n\n"

        proc.wait()

    except Exception as e:
        err_msg = f"\nExecution error: {str(e)}\n"
        collected_log += err_msg
        yield f"data: {json.dumps({'type': 'log', 'line': err_msg, 'percent': current_pct, 'full_log': collected_log})}\n\n"

    xml_out = ""
    if os.path.exists(temp_xml_path):
        try:
            with open(temp_xml_path, "r", encoding="utf-8", errors="ignore") as f:
                xml_out = f.read()
            os.remove(temp_xml_path)
        except Exception:
            pass

    hosts_data = parse_nmap_xml(xml_out)
    if not hosts_data:
        hosts_data = parse_nmap_text_output(collected_log)

    terminal_log_path = os.path.join(script_dir, "nmap_terminal_output.txt")
    json_path = os.path.join(script_dir, "scan_results.json")
    csv_path = os.path.join(script_dir, "scan_results.csv")

    with open(terminal_log_path, "w", encoding="utf-8") as f:
        f.write(collected_log)

    scan_result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "command_executed": display_cmd,
        "cmd_type": cmd_type,
        "scan_mode": f"Live Nmap CLI ({cmd_type.replace('_', ' ').title()})",
        "network_interfaces": net_info,
        "total_hosts_found": len(hosts_data),
        "hosts": hosts_data,
        "terminal_output": collected_log
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

    append_command_to_history(cmd_type, display_cmd, target, len(hosts_data), collected_log)

    yield f"data: {json.dumps({'type': 'complete', 'percent': 100.0, 'result': scan_result})}\n\n"


def append_command_to_history(cmd_type, command_executed, target, total_hosts, terminal_output):
    """Appends an executed command entry to persistent command_history.json and execution_history.log."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    history_json_path = os.path.join(script_dir, "command_history.json")
    history_log_path = os.path.join(script_dir, "execution_history.log")

    history = []
    if os.path.exists(history_json_path):
        try:
            with open(history_json_path, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            history = []

    entry = {
        "id": len(history) + 1,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cmd_type": cmd_type,
        "command_executed": command_executed,
        "target": target,
        "total_hosts": total_hosts,
        "terminal_output": terminal_output
    }

    history.insert(0, entry)  # latest first
    history = history[:50]    # keep up to 50 entries

    try:
        with open(history_json_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4)
        
        with open(history_log_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n[{entry['timestamp']}] COMMAND: {command_executed} (Target: {target})\n{'='*70}\n{terminal_output}\n")
    except Exception as e:
        print(f"[!] Error saving command history: {e}")

    return entry


def get_command_history():
    """Returns the list of previously executed commands from command_history.json."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    history_json_path = os.path.join(script_dir, "command_history.json")
    if os.path.exists(history_json_path):
        try:
            with open(history_json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error reading command history: {e}")
    return []


def clear_command_history():
    """Clears persistent command history."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    history_json_path = os.path.join(script_dir, "command_history.json")
    try:
        with open(history_json_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return True
    except Exception as e:
        print(f"[!] Error clearing history: {e}")
        return False


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "service_scan"
    tgt = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    res = run_single_nmap_command(cmd, tgt)
    print(f"[*] Done executing {cmd} on {tgt}. Discovered {res['total_hosts_found']} hosts.")
