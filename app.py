"""
Flask Server Dashboard for Network Analysis & MAC Spoofing Suite
------------------------------------------------------------------
Serves backend REST API routes and interactive web dashboard UI.
Interfacing with:
- Module 1 (module1_network_discovery/scanner.py)
- Module 2 (module2_packet_capture/sniffer.py)  [real-time via SocketIO]
- Module 3 (module3_mac_spoofing/mac_changer.py)
- Phase 4 (security_analyzer.py)
"""

import os
import json
from flask import Flask, render_template, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO

# Import local modules
from module1_network_discovery.scanner import (
    run_single_nmap_command,
    stream_nmap_command_events,
    get_network_interfaces_info,
    get_command_history,
    clear_command_history
)
from module2_packet_capture.sniffer import analyze_pcap, capture_engine, get_interfaces
from module3_mac_spoofing.mac_changer import (
    get_network_adapters, 
    view_current_mac, 
    change_mac_address, 
    restore_original_mac,
    load_log as load_mac_log
)
from security_analyzer import (
    analyze_security_posture,
    log_exam_violation,
    get_exam_violations,
    clear_exam_violations
)

app = Flask(__name__, template_folder="templates", static_folder="static")
# SocketIO in threading mode — works on Windows without eventlet/gevent
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/candidate")
def candidate_portal():
    """Renders the Candidate Online Examination Portal for System 2."""
    return render_template("candidate.html")


@app.route("/api/candidate/ping", methods=["POST"])
def candidate_ping():
    """Telemetry endpoint called when a candidate device connects to the exam."""
    data = request.json or {}
    client_ip = request.remote_addr
    return jsonify({
        "status": "connected",
        "candidate_ip": client_ip,
        "session_id": data.get("candidate_id", "CANDIDATE-8821"),
        "exam_subject": "Computer Networks & Security",
        "message": "Candidate device registered on Proctor Server."
    })


@app.route("/api/candidate/simulate-threat", methods=["POST"])
def candidate_simulate_threat():
    """Demonstration endpoint triggered from Candidate Portal to simulate cheating behavior."""
    data = request.json or {}
    threat_type = data.get("threat_type", "rdp")
    candidate_id = data.get("candidate_id", "CANDIDATE-8821")
    client_ip = request.remote_addr

    log_entry = {
        "candidate_id": candidate_id,
        "client_ip": client_ip,
        "threat_type": threat_type
    }

    dst_port = 3389 if threat_type == "rdp" else (21 if threat_type == "ftp" else (53 if threat_type == "dns" else 80))

    if threat_type == "rdp":
        log_entry["detail"] = f"Candidate {candidate_id} ({client_ip}) attempted Remote Desktop Connection (Port 3389 RDP)."
        log_entry["risk"] = "CRITICAL"
    elif threat_type == "ftp":
        log_entry["detail"] = f"Candidate {candidate_id} ({client_ip}) attempted Unencrypted File Transfer (Port 21 FTP)."
        log_entry["risk"] = "HIGH"
    elif threat_type == "dns":
        log_entry["detail"] = f"Candidate {candidate_id} ({client_ip}) attempted DNS lookup to prohibited domain: cheating-answers.com"
        log_entry["risk"] = "MEDIUM"
    else:
        log_entry["detail"] = f"Candidate {candidate_id} ({client_ip}) performed unexpected network probe."
        log_entry["risk"] = "INFO"

    # Save false attempt / security violation separately into exam_violations.json
    violation = log_exam_violation(
        candidate_id=candidate_id,
        client_ip=client_ip,
        threat_type=threat_type.upper(),
        detail=log_entry["detail"],
        risk=log_entry["risk"],
        port=dst_port,
        target_ip="192.168.1.1"
    )

    # Re-evaluate security posture
    analyze_security_posture()

    # Emit SocketIO real-time events for live Exam Security Assessment tab update
    socketio.emit("exam_violation", violation)
    socketio.emit("m2_packet", {
        "id": 9999,
        "timestamp": violation["timestamp"],
        "src_ip": client_ip,
        "dst_ip": "192.168.1.1",
        "protocol": threat_type.upper(),
        "source_port": 54321,
        "destination_port": dst_port,
        "length": 128,
        "details": log_entry["detail"]
    })

    return jsonify({"ok": True, "log": log_entry, "violation": violation})


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

    net_info = get_network_interfaces_info()

    return jsonify({
        "total_hosts": scan_data.get("total_hosts_found", 0),
        "total_packets": packet_data.get("total_packets_captured", 0),
        "protocol_summary": packet_data.get("protocol_summary", {}),
        "server_ip": net_info.get("local_ip", "127.0.0.1"),
        "candidate_url": f"http://{net_info.get('local_ip', '127.0.0.1')}:5000/candidate",
        "mac_status": {
            "current_mac": mac_log.get("current_mac", "N/A"),
            "original_mac": mac_log.get("original_mac", "N/A"),
            "is_spoofed": mac_log.get("is_spoofed", False),
            "adapter": mac_log.get("adapter_name", "Wi-Fi")
        },
        "security_summary": sec_data.get("summary", {
            "security_score": 85,
            "unnecessary_open_ports_count": 0,
            "recommended_firewall_rules_count": 0,
            "total_violations_count": 0,
            "critical_violations_count": 0
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


@app.route("/api/module1/stream-scan", methods=["GET"])
def api_module1_stream_scan():
    """Streams live Nmap CLI stdout lines and progress percentage using SSE."""
    cmd_type = request.args.get("cmd_type", "service_scan")
    target = request.args.get("target", "")
    return Response(stream_nmap_command_events(cmd_type, target), mimetype="text/event-stream")


@app.route("/api/module1/history", methods=["GET", "DELETE"])
def api_module1_history():
    """Fetch or clear command execution history log entries."""
    if request.method == "DELETE":
        clear_command_history()
        return jsonify({"status": "success", "message": "Command history cleared."})
    return jsonify(get_command_history())


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
    """Fetch saved packet analysis (from JSON) or analyze a PCAP file offline.
    The real-time live-capture path now uses /api/module2/start instead."""
    packet_file = os.path.join(BASE_DIR, "module2_packet_capture", "packet_analysis.json")
    if request.method == "POST":
        data = request.json or {}
        pcap_path = data.get("pcap")          # optional PCAP file path
        res = analyze_pcap(pcap_filepath=pcap_path)
        analyze_security_posture()
        return jsonify(res)

    if os.path.exists(packet_file):
        with open(packet_file, "r") as f:
            return jsonify(json.load(f))
    return jsonify(analyze_pcap())


# ---------------------------------------------------------------------------
# Module 2 Real-Time Capture Endpoints (Flask-SocketIO)
# ---------------------------------------------------------------------------

@app.route("/api/module2/interfaces", methods=["GET"])
def api_module2_interfaces():
    """Return list of available network interfaces for the interface selector."""
    return jsonify({"interfaces": get_interfaces()})


@app.route("/api/module2/start", methods=["POST"])
def api_module2_start():
    """Start real-time packet capture on the selected interface."""
    data = request.json or {}
    interface = data.get("interface", "").strip()
    if not interface:
        return jsonify({"ok": False, "error": "No interface specified."}), 400
    result = capture_engine.start(interface, socketio)
    if result["ok"]:
        return jsonify(result)
    return jsonify(result), 400


@app.route("/api/module2/stop", methods=["POST"])
def api_module2_stop():
    """Stop the running packet capture."""
    result = capture_engine.stop()
    return jsonify(result)


@app.route("/api/module2/clear", methods=["POST"])
def api_module2_clear():
    """Clear all real-time capture state (packets, counters, DNS, handshakes)."""
    capture_engine.clear()
    return jsonify({"ok": True})


@app.route("/api/module2/export", methods=["POST"])
def api_module2_export():
    """Export current in-memory capture to packet_analysis.json and .csv."""
    try:
        data = capture_engine.export_data()
        return jsonify({
            "ok": True,
            "total_packets": data.get("total_packets_captured", 0),
            "json_path": "module2_packet_capture/packet_analysis.json",
            "csv_path": "module2_packet_capture/packet_analysis.csv",
        })
    except Exception as exc:
        print(f"[!] Module 2 export failed: {exc}")
        return jsonify({"ok": False, "error": "Failed to export capture data."}), 500


@app.route("/api/module2/status", methods=["GET"])
def api_module2_status():
    """Return current capture engine status and statistics."""
    return jsonify(capture_engine.get_status())


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
            violation = log_exam_violation(
                candidate_id="CANDIDATE-8821",
                client_ip=request.remote_addr,
                threat_type="MAC_SPOOFING",
                detail=f"Candidate workstation MAC address changed on {adapter} to {new_mac} (Device impersonation attempt).",
                risk="HIGH"
            )
            socketio.emit("exam_violation", violation)
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


@app.route("/api/security-analysis/violations", methods=["GET", "DELETE"])
def api_security_violations():
    """Fetch or clear recorded candidate false attempts / security violations."""
    if request.method == "DELETE":
        clear_exam_violations()
        analyze_security_posture()
        return jsonify({"status": "success", "message": "Exam violations log cleared."})
    return jsonify(get_exam_violations())


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    """Download generated CSV or JSON report files."""
    return send_from_directory(BASE_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    scan_file = os.path.join(BASE_DIR, "module1_network_discovery", "scan_results.json")
    if not os.path.exists(scan_file):
        run_single_nmap_command("service_scan", "127.0.0.1")

    analyze_security_posture()
    net_info = get_network_interfaces_info()
    local_ip = net_info.get("local_ip", "127.0.0.1")

    print("\n=======================================================================")
    print("[*] SECURE ONLINE EXAMINATION MONITORING SERVER STARTED!")
    print(f"[*] Proctor Dashboard (System 1) : http://127.0.0.1:5000 or http://{local_ip}:5000")
    print(f"[*] Candidate Portal    (System 2) : http://{local_ip}:5000/candidate")
    print("[*] Listening on all Wi-Fi network interfaces (0.0.0.0:5000)")
    print("=======================================================================\n")
    # Use socketio.run() bound to 0.0.0.0 to allow candidate connection over Wi-Fi
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)

