"""
Test Suite for Secure Online Examination Monitoring System
------------------------------------------------------------
Contains 31 comprehensive Unit Tests and Edge Cases covering:
1. Module 1: Nmap scanner XML parser, CIDR subnet calculation, SSE streaming, and command history.
2. Module 2: Packet capture dissector, non-existent/corrupted PCAP handling, and SocketIO capture engine endpoints.
3. Module 3: Candidate device MAC identity verification, status checking, case normalization, and invalid format handling.
4. Phase 4: Exam security analyzer engine, prohibited port detection, firewall rule generator, and missing file edge cases.
5. Flask Web Server REST API, Streaming Endpoints, and Candidate Examination Portal routes.
"""

import unittest
import os
import json
import tempfile
from unittest.mock import patch, MagicMock

# Import modules to test
import security_analyzer
from module1_network_discovery.scanner import parse_nmap_xml, get_network_interfaces_info
from module2_packet_capture.sniffer import analyze_pcap, build_output
from module3_mac_spoofing.mac_changer import get_mac_status, change_mac_address
from app import app


class TestOnlineExamSecuritySuite(unittest.TestCase):

    def setUp(self):
        """Set up test environment and Flask test client."""
        self.app = app.test_client()
        self.app.testing = True

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 1 TESTS & EDGE CASES (Exam Environment Verification)
    # ─────────────────────────────────────────────────────────────────────────

    def test_01_parse_nmap_xml_valid(self):
        """Test 1: Parse valid Nmap XML with open exam ports."""
        sample_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.100" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Intel"/>
                <hostnames><hostname name="candidate-pc"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="3389">
                        <state state="open"/>
                        <service name="ms-wbt-server" product="Microsoft Remote Desktop"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""
        result = parse_nmap_xml(sample_xml)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ip"], "192.168.1.100")
        self.assertEqual(result[0]["mac_address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(len(result[0]["ports"]), 1)
        self.assertEqual(result[0]["ports"][0]["port"], 3389)

    def test_02_parse_nmap_xml_corrupted(self):
        """Test 2 [Edge Case]: Handle corrupted / malformed Nmap XML gracefully."""
        corrupted_xml = "<nmaprun><host><status state='up'/><address addr='192.168.1.1'</nmaprun>"
        result = parse_nmap_xml(corrupted_xml)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_03_parse_nmap_xml_empty(self):
        """Test 3 [Edge Case]: Handle empty Nmap XML input."""
        result = parse_nmap_xml("")
        self.assertEqual(result, [])

    def test_04_get_network_interfaces_info_structure(self):
        """Test 4: Verify network interface auto-detection returns valid CIDR keys."""
        net_info = get_network_interfaces_info()
        self.assertIn("local_ip", net_info)
        self.assertIn("subnet_cidr", net_info)
        self.assertIn("default_gateway", net_info)

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 2 TESTS & EDGE CASES (Exam Network Traffic Monitoring)
    # ─────────────────────────────────────────────────────────────────────────

    def test_05_build_output_structure(self):
        """Test 5: Verify exam traffic analysis dataset structure and fields."""
        data = build_output([], "test_source")
        self.assertIn("total_packets_captured", data)
        self.assertIn("packets", data)
        self.assertIn("protocol_summary", data)
        self.assertIn("dns_queries", data)

    def test_06_analyze_pcap_non_existent_file(self):
        """Test 6 [Edge Case]: Non-existent PCAP file returns valid packet dictionary."""
        res = analyze_pcap("non_existent_file_xyz_123.pcap")
        self.assertIsNotNone(res)
        self.assertIn("packets", res)
        self.assertIsInstance(res["packets"], list)

    def test_07_analyze_pcap_empty_filepath(self):
        """Test 7 [Edge Case]: Empty PCAP filepath handling."""
        res = analyze_pcap(None)
        self.assertIsNotNone(res)
        self.assertIn("total_packets_captured", res)

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 3 TESTS & EDGE CASES (Candidate Device Verification)
    # ─────────────────────────────────────────────────────────────────────────

    def test_08_mac_status_original(self):
        """Test 8: Baseline MAC matches active MAC -> returns ORIGINAL."""
        baseline = {"original_mac": "F4:6D:04:88:99:AA"}
        status = get_mac_status("F4:6D:04:88:99:AA", baseline)
        self.assertEqual(status, "ORIGINAL")

    def test_09_mac_status_spoofed(self):
        """Test 9: Baseline MAC differs from active MAC -> returns SPOOFED."""
        baseline = {"original_mac": "F4:6D:04:88:99:AA"}
        status = get_mac_status("02:11:22:33:44:55", baseline)
        self.assertEqual(status, "SPOOFED")

    def test_10_mac_status_case_insensitive(self):
        """Test 10 [Edge Case]: Mixed case & hyphen vs colon MAC normalization."""
        baseline = {"original_mac": "f4-6d-04-88-99-aa"}
        status = get_mac_status("F4:6D:04:88:99:AA", baseline)
        self.assertEqual(status, "ORIGINAL")

    def test_11_mac_status_none_mac(self):
        """Test 11 [Edge Case]: None or empty MAC address input -> returns ERROR."""
        baseline = {"original_mac": "F4:6D:04:88:99:AA"}
        self.assertEqual(get_mac_status(None, baseline), "ERROR")
        self.assertEqual(get_mac_status("", baseline), "ERROR")

    def test_12_change_mac_address_invalid_format(self):
        """Test 12 [Edge Case]: Invalid MAC string length/characters handling."""
        res = change_mac_address("Wi-Fi", "INVALID_MAC_STRING")
        self.assertIsNotNone(res)
        self.assertIn("current_mac", res)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 4 TESTS & EDGE CASES (Exam Security Assessment Engine)
    # ─────────────────────────────────────────────────────────────────────────

    def test_13_security_analyzer_risky_ports(self):
        """Test 13: Identifies prohibited exam ports (RDP 3389) and generates firewall rules."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp_scan:
            scan_data = {
                "hosts": [{
                    "ip": "192.168.1.50",
                    "ports": [{"port": 3389, "service": "ms-wbt-server", "version": "RDP"}]
                }]
            }
            json.dump(scan_data, tmp_scan)
            tmp_scan_path = tmp_scan.name

        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp_packet:
            json.dump({"packets": []}, tmp_packet)
            tmp_packet_path = tmp_packet.name

        report = security_analyzer.analyze_security_posture(tmp_scan_path, tmp_packet_path)
        
        # Cleanup
        os.remove(tmp_scan_path)
        os.remove(tmp_packet_path)

        self.assertEqual(report["summary"]["unnecessary_open_ports_count"], 1)
        self.assertEqual(report["unnecessary_ports"][0]["port"], 3389)
        self.assertIn("Exam Security Block Port 3389", report["recommended_firewall_rules"][0]["windows_firewall_cmd"])

    def test_14_security_analyzer_missing_files(self):
        """Test 14 [Edge Case]: Handles missing scan/packet JSON files gracefully."""
        report = security_analyzer.analyze_security_posture(
            "non_existent_scan.json", "non_existent_packet.json"
        )
        self.assertIsInstance(report, dict)
        self.assertIn("summary", report)

    def test_15_security_analyzer_empty_json(self):
        """Test 15 [Edge Case]: Handles empty JSON files ({}) without crashing."""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f1, tempfile.NamedTemporaryFile("w+", delete=False) as f2:
            f1.write("{}")
            f2.write("{}")
            f1_path, f2_path = f1.name, f2.name

        report = security_analyzer.analyze_security_posture(f1_path, f2_path)
        
        os.remove(f1_path)
        os.remove(f2_path)

        self.assertEqual(report["summary"]["total_hosts_evaluated"], 0)
        self.assertEqual(report["summary"]["security_score"], 100)

    def test_16_security_score_formula_bounds(self):
        """Test 16: Security score maintains bounds between 10 and 100."""
        # 10 risky ports -> 100 - (10 * 15) = -50 -> bounded to 10
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp_scan:
            scan_data = {
                "hosts": [{
                    "ip": "192.168.1.1",
                    "ports": [{"port": p, "service": "test"} for p in [21, 23, 80, 135, 139, 445, 3389]]
                }]
            }
            json.dump(scan_data, tmp_scan)
            tmp_scan_path = tmp_scan.name

        report = security_analyzer.analyze_security_posture(tmp_scan_path, None)
        os.remove(tmp_scan_path)

        self.assertGreaterEqual(report["summary"]["security_score"], 10)
        self.assertLessEqual(report["summary"]["security_score"], 100)

    # ─────────────────────────────────────────────────────────────────────────
    # FLASK REST API ENDPOINT INTEGRATION TESTS
    # ─────────────────────────────────────────────────────────────────────────

    def test_17_api_overview_endpoint(self):
        """Test 17: GET /api/overview returns HTTP 200 and required KPI keys."""
        response = self.app.get("/api/overview")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("total_hosts", data)
        self.assertIn("total_packets", data)
        self.assertIn("mac_status", data)
        self.assertIn("security_summary", data)

    def test_18_api_network_info_endpoint(self):
        """Test 18: GET /api/network-info returns HTTP 200 and local network IP."""
        response = self.app.get("/api/network-info")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("local_ip", data)

    def test_19_api_module1_scan_endpoint(self):
        """Test 19: GET /api/module1/scan returns HTTP 200 and host scan list."""
        response = self.app.get("/api/module1/scan")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("hosts", data)

    def test_20_api_module2_packets_endpoint(self):
        """Test 20: GET /api/module2/packets returns HTTP 200 and packet stream."""
        response = self.app.get("/api/module2/packets")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("packets", data)

    def test_21_api_security_analysis_endpoint(self):
        """Test 21: GET /api/security-analysis returns HTTP 200 and Phase 4 report."""
        response = self.app.get("/api/security-analysis")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("summary", data)
        self.assertIn("recommended_firewall_rules", data)

    def test_22_api_module1_history_endpoint(self):
        """Test 22: GET /api/module1/history returns command history array."""
        response = self.app.get("/api/module1/history")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data, list)

    def test_23_api_module1_stream_scan_endpoint(self):
        """Test 23: GET /api/module1/stream-scan initializes SSE text/event-stream response."""
        response = self.app.get("/api/module1/stream-scan?cmd_type=ping_sweep&target=127.0.0.1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")

    def test_24_api_module2_interfaces_endpoint(self):
        """Test 24: GET /api/module2/interfaces returns network interfaces list."""
        response = self.app.get("/api/module2/interfaces")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("interfaces", data)

    def test_25_api_module2_status_endpoint(self):
        """Test 25: GET /api/module2/status returns capture engine status."""
        response = self.app.get("/api/module2/status")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("status", data)

    def test_26_api_module2_start_stop_endpoints(self):
        """Test 26: POST /api/module2/start and /api/module2/stop controls capture engine."""
        # Start capture
        start_res = self.app.post(
            "/api/module2/start",
            data=json.dumps({"interface": "Loopback"}),
            content_type="application/json"
        )
        self.assertEqual(start_res.status_code, 200)
        start_data = json.loads(start_res.data)
        self.assertTrue(start_data.get("ok", False))

        # Stop capture
        stop_res = self.app.post("/api/module2/stop")
        self.assertEqual(stop_res.status_code, 200)
        stop_data = json.loads(stop_res.data)
        self.assertIn("packet_count", stop_data)

    def test_27_api_module2_clear_endpoint(self):
        """Test 27: POST /api/module2/clear resets real-time packet state."""
        response = self.app.post("/api/module2/clear")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get("ok", False))

    def test_28_api_module2_export_endpoint(self):
        """Test 28: POST /api/module2/export exports capture JSON and CSV files."""
        response = self.app.post("/api/module2/export")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get("ok", False))
        self.assertIn("total_packets", data)

    def test_29_candidate_portal_route(self):
        """Test 29: GET /candidate renders the candidate examination portal HTML."""
        response = self.app.get("/candidate")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Online Examination Portal", response.data)

    def test_30_api_candidate_ping_endpoint(self):
        """Test 30: POST /api/candidate/ping registers candidate telemetry."""
        response = self.app.post(
            "/api/candidate/ping",
            data=json.dumps({"candidate_id": "CANDIDATE-8821"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data.get("status"), "connected")
        self.assertIn("candidate_ip", data)

    def test_31_api_candidate_simulate_threat_endpoint(self):
        """Test 31: POST /api/candidate/simulate-threat emits demonstration cheating packets."""
        response = self.app.post(
            "/api/candidate/simulate-threat",
            data=json.dumps({"threat_type": "rdp", "candidate_id": "CANDIDATE-8821"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data.get("ok", False))
        self.assertEqual(data["log"]["threat_type"], "rdp")


if __name__ == "__main__":
    unittest.main(verbosity=2)


