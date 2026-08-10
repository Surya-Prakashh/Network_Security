"""
Flask Server Dashboard for Network Analysis & MAC Spoofing Suite
------------------------------------------------------------------
Serves backend REST API routes and interactive web dashboard UI.
Interfacing with:
- Module 1 (module1_network_discovery/scanner.py)
- Module 2 (module2_packet_capture/sniffer.py)
- Module 3 (module3_mac_spoofing/mac_changer.py)
- Phase 4 (security_analyzer.py)
"""

import os
import json
from flask import Flask, render_template, jsonify, request, send_from_directory

# Import local modules
from module1_network_discovery.scanner import (
    run_single_nmap_command,
    get_network_interfaces_info
)
from module2_packet_capture.sniffer import analyze_pcap
from module3_mac_spoofing.mac_changer import (
    get_network_adapters, 
    view_current_mac, 
    change_mac_address, 
    restore_original_mac,
    load_log as load_mac_log
)
from security_analyzer import analyze_security_posture

app = Flask(__name__, template_folder="templates", static_folder="static")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/overview", methods=["GET"])
def get_overview():
    """Returns aggregated stats from all 3 module outputs and security analysis."""
    scan_file = os.path.join(BASE_DIR, "module1_network_discovery", "scan_results.json")
    packet_file = os.path.join(BASE_DIR, "module2_packet_capture", "packet_analysis.json")
    sec_file = os.path.join(BASE_DIR, "security_analysis_report.json")

    scan_data = {}
    packet_data = {}
    sec_data = {}

    if os.path.exists(scan_file):
        with open(scan_file, "r") as f:
            scan_data = json.load(f)

    if os.path.exists(packet_file):
        with open(packet_file, "r") as f:
            packet_data = json.load(f)

    if os.path.exists(sec_file):
        with open(sec_file, "r") as f:
            sec_data = json.load(f)

    mac_log = load_mac_log()

    return jsonify({
        "total_hosts": scan_data.get("total_hosts_found", 0),
        "total_packets": packet_data.get("total_packets_captured", 0),
        "protocol_summary": packet_data.get("protocol_summary", {}),
        "mac_status": {
            "current_mac": mac_log.get("current_mac", "N/A"),
            "original_mac": mac_log.get("original_mac", "N/A"),
            "is_spoofed": mac_log.get("is_spoofed", False),
            "adapter": mac_log.get("adapter_name", "Wi-Fi")
        },
        "security_summary": sec_data.get("summary", {
            "security_score": 85,
            "unnecessary_open_ports_count": 0,
            "recommended_firewall_rules_count": 0
        })
    })


@app.route("/api/network-info", methods=["GET"])
def get_network_info():
    """Returns local network interface details from ipconfig."""
    return jsonify(get_network_interfaces_info())


@app.route("/api/module1/scan", methods=["GET", "POST"])
def api_module1_scan():
    """Trigger dynamic Nmap command or fetch scan results."""
    scan_file = os.path.join(BASE_DIR, "module1_network_discovery", "scan_results.json")
    if request.method == "POST":
        data = request.json or {}
        cmd_type = data.get("cmd_type") or data.get("scan_type") or "service_scan"
        target = data.get("target") or data.get("target_subnet")
        
        res = run_single_nmap_command(cmd_type, target)
        analyze_security_posture()
        return jsonify(res)
    
    if os.path.exists(scan_file):
        with open(scan_file, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify(run_single_nmap_command("service_scan", "127.0.0.1"))


@app.route("/api/module1/terminal", methods=["GET"])
def api_module1_terminal():
    """Returns raw Nmap stdout terminal log."""
    term_file = os.path.join(BASE_DIR, "module1_network_discovery", "nmap_terminal_output.txt")
    if os.path.exists(term_file):
        with open(term_file, "r", encoding="utf-8") as f:
            return jsonify({"terminal_output": f.read()})
    return jsonify({"terminal_output": "No Nmap terminal log available yet."})


@app.route("/api/module2/packets", methods=["GET", "POST"])
def api_module2_packets():
    """Trigger or fetch Phase 2 Packet Capture results."""
    packet_file = os.path.join(BASE_DIR, "module2_packet_capture", "packet_analysis.json")
    if request.method == "POST":
        res = analyze_pcap()
        analyze_security_posture()
        return jsonify(res)
    
    if os.path.exists(packet_file):
        with open(packet_file, "r") as f:
            return jsonify(json.load(f))
    return jsonify(analyze_pcap())


@app.route("/api/module3/mac", methods=["GET", "POST"])
def api_module3_mac():
    """Manage Phase 3 MAC Address viewing, spoofing, and restoration."""
    if request.method == "POST":
        data = request.json or {}
        action = data.get("action")
        adapter = data.get("adapter", "Wi-Fi")
        new_mac = data.get("new_mac")

        if action == "change":
            res = change_mac_address(adapter, new_mac)
        elif action == "restore":
            res = restore_original_mac(adapter)
        else:
            res = view_current_mac(adapter)
        
        analyze_security_posture()
        return jsonify(res)

    adapters = get_network_adapters()
    mac_log = load_mac_log()
    return jsonify({
        "adapters": adapters,
        "mac_log": mac_log
    })


@app.route("/api/security-analysis", methods=["GET", "POST"])
def api_security_analysis():
    """Fetch or re-run Phase 4 Security Assessment."""
    if request.method == "POST":
        report = analyze_security_posture()
        return jsonify(report)

    sec_file = os.path.join(BASE_DIR, "security_analysis_report.json")
    if os.path.exists(sec_file):
        with open(sec_file, "r") as f:
            return jsonify(json.load(f))
    return jsonify(analyze_security_posture())


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    """Download generated CSV or JSON report files."""
    return send_from_directory(BASE_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    scan_file = os.path.join(BASE_DIR, "module1_network_discovery", "scan_results.json")
    if not os.path.exists(scan_file):
        run_single_nmap_command("service_scan", "127.0.0.1")
    
    packet_file = os.path.join(BASE_DIR, "module2_packet_capture", "packet_analysis.json")
    if not os.path.exists(packet_file):
        analyze_pcap()

    analyze_security_posture()
    
    print("\n=======================================================")
    print("[*] Network Analysis & MAC Spoofing Dashboard Started!")
    print("[*] Open Browser: http://127.0.0.1:5000")
    print("=======================================================\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
