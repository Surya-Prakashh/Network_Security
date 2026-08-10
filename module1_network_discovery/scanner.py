"""
Module 1: Real Network Discovery & Nmap Port Scanner (Phase 1)
---------------------------------------------------------------
Executes native live Nmap scans for:
- Host discovery
- Operating system identification
- TCP port scanning
- Running services identification
- Service version detection

Outputs real Nmap terminal logs, scan_results.json, and scan_results.csv.
NO mock/synthetic data.
"""

import json
import csv
import os
import sys
import datetime
import subprocess
import socket
import xml.etree.ElementTree as ET

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


def get_default_target():
    """Detect local IP and return default target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def run_nmap_live_scan(target=None, scan_type="fast"):
    """
    Executes live Nmap binary against specified target(s).
    Captures raw stdout for terminal display and parses XML output.
    """
    if not target:
        target = get_default_target()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    terminal_log_path = os.path.join(script_dir, "nmap_terminal_output.txt")
    json_path = os.path.join(script_dir, "scan_results.json")
    csv_path = os.path.join(script_dir, "scan_results.csv")

    print(f"[*] Executing Live Nmap Scan on Target: {target}")

    # Build Nmap CLI command arguments
    # -sV: Service version detection
    # -O: Operating system detection
    # -F: Fast scan (top 100 ports)
    # -oX -: Output XML to stdout for precise parsing
    if scan_type == "full":
        nmap_args = ["nmap", "-sV", "-O", "-p-", "--open", "-oX", "-", target]
        cmd_display = f"nmap -sV -O -p- --open {target}"
    else:
        nmap_args = ["nmap", "-sV", "-O", "-F", "--open", "-oX", "-", target]
        cmd_display = f"nmap -sV -O -F --open {target}"

    raw_output = ""
    nmap_stdout = ""
    
    # Run Nmap CLI directly
    try:
        process = subprocess.run(
            nmap_args,
            capture_output=True,
            text=True,
            timeout=120
        )
        nmap_stdout = process.stdout
        nmap_stderr = process.stderr

        # Generate human-readable terminal log from raw Nmap execution
        # Also run non-XML version for clean terminal log view
        terminal_proc = subprocess.run(
            [arg for arg in nmap_args if arg not in ["-oX", "-"]],
            capture_output=True,
            text=True,
            timeout=120
        )
        raw_terminal_log = f"$ {cmd_display}\n\n" + (terminal_proc.stdout or nmap_stdout)
        if terminal_proc.stderr:
            raw_terminal_log += f"\n[Nmap Stderr]\n{terminal_proc.stderr}"
    except Exception as e:
        raw_terminal_log = f"$ {cmd_display}\n\nError executing Nmap CLI: {str(e)}"
        print(f"[!] Nmap execution error: {e}")
        nmap_stdout = ""

    # Save raw terminal output
    with open(terminal_log_path, "w", encoding="utf-8") as f:
        f.write(raw_terminal_log)
    print(f"[+] Live Nmap terminal output saved to: {terminal_log_path}")

    # Parse XML Output into structured JSON
    hosts_data = []
    if nmap_stdout and "<nmaprun" in nmap_stdout:
        try:
            root = ET.fromstring(nmap_stdout)
            for host_elem in root.findall("host"):
                status_elem = host_elem.find("status")
                state = status_elem.get("state") if status_elem is not None else "down"

                if state != "up":
                    continue

                # IP Address & MAC Address
                ip_addr = "Unknown"
                mac_addr = "N/A"
                vendor = "Unknown"
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype")
                    if addr_type == "ipv4" or addr_type == "ipv6":
                        ip_addr = addr.get("addr")
                    elif addr_type == "mac":
                        mac_addr = addr.get("addr")
                        vendor = addr.get("vendor", "Unknown")

                # Hostnames
                hostname = ip_addr
                hostnames_elem = host_elem.find("hostnames")
                if hostnames_elem is not None:
                    hn_elem = hostnames_elem.find("hostname")
                    if hn_elem is not None:
                        hostname = hn_elem.get("name") or ip_addr

                # Operating System Detection
                os_details = "OS detection not available / restricted"
                os_elem = host_elem.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        os_name = osmatch.get("name")
                        accuracy = osmatch.get("accuracy")
                        os_details = f"{os_name} ({accuracy}% accuracy)"
                
                # Ports and Services
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

                        # If OS not found in osmatch, check service info hints
                        if "restricted" in os_details and service_elem is not None:
                            devtype = service_elem.get("devicetype")
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
            print(f"[!] XML parsing error: {e}")

    # Build Scan Findings Dictionary
    scan_result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "target": target,
        "command_executed": cmd_display,
        "scan_mode": f"Live Real Nmap ({scan_type.upper()})",
        "total_hosts_found": len(hosts_data),
        "hosts": hosts_data,
        "terminal_output": raw_terminal_log
    }

    # Save to JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=4)
    print(f"[+] Saved JSON scan results to: {json_path}")

    # Save to CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Hostname", "Status", "MAC Address", "OS Details", "Port", "Protocol", "Service", "Version"])
        for host in hosts_data:
            if not host["ports"]:
                writer.writerow([host["ip"], host["hostname"], host["status"], host["mac_address"], host["os_details"], "None", "None", "None", "None"])
            else:
                for p in host["ports"]:
                    writer.writerow([
                        host["ip"], 
                        host["hostname"], 
                        host["status"], 
                        host["mac_address"], 
                        host["os_details"], 
                        p["port"], 
                        p["protocol"], 
                        p["service"], 
                        p["version"]
                    ])
    print(f"[+] Saved CSV scan results to: {csv_path}")

    return scan_result


if __name__ == "__main__":
    target_arg = sys.argv[1] if len(sys.argv) > 1 else get_default_target()
    scan_mode_arg = sys.argv[2] if len(sys.argv) > 2 else "fast"
    res = run_nmap_live_scan(target_arg, scan_mode_arg)
    print(f"[*] Scan finished. Discovered {res['total_hosts_found']} live host(s).")
