"""
Module 2: Packet Capture & Protocol Analysis (Phase 2)
=======================================================
Captures and analyzes live/recorded network traffic. Supports:
  - Live capture via Scapy (requires Administrator/root + Npcap on Windows)
  - PCAP / PCAPNG file analysis via PyShark/TShark or Scapy
  - Protocol detection: TCP, UDP, DNS, HTTP, HTTPS/TLS, ICMP, QUIC
  - TCP three-way handshake detection (SYN -> SYN-ACK -> ACK)
  - DNS query & response extraction
  - ICMP echo request/reply identification
  - HTTP method/host/URI extraction
  - TLS version and SNI extraction
  - JSON and CSV export

Usage examples:
  python sniffer.py --interface "Wi-Fi" --count 100
  python sniffer.py --interface "Ethernet" --duration 30
  python sniffer.py --pcap capture.pcapng
  python sniffer.py --pcap capture.pcap --json-output out.json --csv-output out.csv
  python sniffer.py --help
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency detection
# ---------------------------------------------------------------------------

SCAPY_AVAILABLE = False
PYSHARK_AVAILABLE = False

try:
    from scapy.all import (
        DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Raw,
        conf as scapy_conf,
        rdpcap,
        sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    pass

try:
    import pyshark  # type: ignore
    PYSHARK_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
DNS_PORTS = {53}
QUIC_PORTS = {443}

ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}

DNS_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON_PATH = os.path.join(SCRIPT_DIR, "packet_analysis.json")
DEFAULT_CSV_PATH = os.path.join(SCRIPT_DIR, "packet_analysis.csv")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

def empty_record() -> Dict[str, Any]:
    """Return a packet record template with all fields as None."""
    return {
        "packet_number": None,
        "timestamp": None,
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "packet_length": None,
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "tcp_sequence": None,
        "tcp_acknowledgment": None,
        "dns_query": None,
        "dns_query_type": None,
        "dns_response": None,
        "icmp_type": None,
        "icmp_code": None,
        "http_host": None,
        "http_method": None,
        "http_uri": None,
        "tls_version": None,
        "info": "",
    }


# ---------------------------------------------------------------------------
# Protocol detection helpers (Scapy)
# ---------------------------------------------------------------------------

def _scapy_tcp_flags(flags_int: int) -> str:
    """Convert Scapy TCP flags integer to a human-readable string like 'SYN', 'SYN-ACK'."""
    flag_map = [
        (0x001, "FIN"),
        (0x002, "SYN"),
        (0x004, "RST"),
        (0x008, "PSH"),
        (0x010, "ACK"),
        (0x020, "URG"),
    ]
    active = [name for bit, name in flag_map if flags_int & bit]
    return "-".join(active) if active else str(flags_int)


def _detect_protocol_scapy(pkt) -> str:
    """Classify a Scapy packet into a named protocol string."""
    if not IP in pkt:
        return "OTHER"

    if ICMP in pkt:
        return "ICMP"

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        # DNS over TCP (rare but valid)
        if sport in DNS_PORTS or dport in DNS_PORTS:
            if DNS in pkt:
                return "DNS"
        if sport in HTTP_PORTS or dport in HTTP_PORTS:
            return "HTTP"
        if sport in HTTPS_PORTS or dport in HTTPS_PORTS:
            return "HTTPS/TLS"
        return "TCP"

    if UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport in DNS_PORTS or dport in DNS_PORTS:
            if DNS in pkt:
                return "DNS"
        # QUIC rides on UDP 443
        if sport in QUIC_PORTS or dport in QUIC_PORTS:
            return "QUIC"
        return "UDP"

    return "IP"


def _extract_dns_info_scapy(pkt) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (query_name, query_type, response_ip) from a Scapy DNS packet."""
    query_name = None
    query_type = None
    response_ip = None

    try:
        if pkt.haslayer(DNSQR):
            raw_name = pkt[DNSQR].qname
            if isinstance(raw_name, bytes):
                query_name = raw_name.decode("utf-8", errors="ignore").rstrip(".")
            else:
                query_name = str(raw_name).rstrip(".")
            qtype_int = pkt[DNSQR].qtype
            query_type = DNS_QTYPE_NAMES.get(qtype_int, str(qtype_int))

        if pkt.haslayer(DNSRR):
            rr = pkt[DNSRR]
            if hasattr(rr, "rdata"):
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    response_ip = rdata.decode("utf-8", errors="ignore").rstrip(".")
                else:
                    response_ip = str(rdata).rstrip(".")
    except Exception:
        pass

    return query_name, query_type, response_ip


def _extract_http_info_scapy(pkt) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (host, method, uri) from a Scapy packet carrying raw HTTP."""
    host = method = uri = None
    try:
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="ignore")
            lines = payload.split("\r\n")
            if lines:
                first_line = lines[0]
                parts = first_line.split(" ")
                if len(parts) >= 2 and parts[0] in (
                    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"
                ):
                    method = parts[0]
                    uri = parts[1] if len(parts) > 1 else None
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                    break
    except Exception:
        pass
    return host, method, uri


def _extract_tls_info_scapy(pkt) -> Optional[str]:
    """Attempt to identify TLS from raw payload (Client Hello starts with 0x16 0x03)."""
    try:
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load
            if isinstance(raw, (bytes, bytearray)) and len(raw) >= 3:
                if raw[0] == 0x16 and raw[1] == 0x03:
                    minor = raw[2]
                    tls_versions = {0: "TLS 1.0", 1: "TLS 1.1", 2: "TLS 1.2", 3: "TLS 1.3"}
                    return tls_versions.get(minor, f"TLS 1.{minor}")
    except Exception:
        pass
    return None


def normalize_scapy_packet(pkt, idx: int) -> Optional[Dict[str, Any]]:
    """
    Convert a single Scapy packet into a normalized packet record dict.
    Returns None if the packet has no IP layer.
    """
    if not SCAPY_AVAILABLE:
        return None
    try:
        if not IP in pkt:
            return None

        rec = empty_record()
        rec["packet_number"] = idx
        rec["source_ip"] = pkt[IP].src
        rec["destination_ip"] = pkt[IP].dst
        rec["packet_length"] = len(pkt)

        # Timestamp
        try:
            ts = float(pkt.time)
            rec["timestamp"] = datetime.datetime.fromtimestamp(ts).strftime(
                "%H:%M:%S.%f"
            )[:-3]
        except Exception:
            rec["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        proto = _detect_protocol_scapy(pkt)
        rec["protocol"] = proto

        # ── TCP ──────────────────────────────────────────────────────────────
        if TCP in pkt:
            tcp = pkt[TCP]
            rec["source_port"] = tcp.sport
            rec["destination_port"] = tcp.dport
            flags_int = int(tcp.flags)
            rec["tcp_flags"] = _scapy_tcp_flags(flags_int)
            rec["tcp_sequence"] = tcp.seq
            rec["tcp_acknowledgment"] = tcp.ack

            if proto == "HTTP":
                host, method, uri = _extract_http_info_scapy(pkt)
                rec["http_host"] = host
                rec["http_method"] = method
                rec["http_uri"] = uri
                info_parts = []
                if method and uri:
                    info_parts.append(f"{method} {uri}")
                if host:
                    info_parts.append(f"Host: {host}")
                rec["info"] = " | ".join(info_parts) if info_parts else f"HTTP {tcp.sport}->{tcp.dport}"

            elif proto == "HTTPS/TLS":
                tls_ver = _extract_tls_info_scapy(pkt)
                rec["tls_version"] = tls_ver
                rec["info"] = f"TLS {tls_ver or ''} {tcp.sport}->{tcp.dport} [{rec['tcp_flags']}]".strip()

            else:
                # DNS over TCP
                if DNS in pkt:
                    q, qt, resp = _extract_dns_info_scapy(pkt)
                    rec["dns_query"] = q
                    rec["dns_query_type"] = qt
                    rec["dns_response"] = resp
                    rec["info"] = f"DNS Query: {q} ({qt})" if q else "DNS"
                else:
                    rec["info"] = (
                        f"{tcp.sport}->{tcp.dport} [{rec['tcp_flags']}] "
                        f"Seq={tcp.seq} Ack={tcp.ack} Len={len(pkt)}"
                    )

        # ── UDP ──────────────────────────────────────────────────────────────
        elif UDP in pkt:
            udp = pkt[UDP]
            rec["source_port"] = udp.sport
            rec["destination_port"] = udp.dport

            if proto == "DNS":
                q, qt, resp = _extract_dns_info_scapy(pkt)
                rec["dns_query"] = q
                rec["dns_query_type"] = qt
                rec["dns_response"] = resp
                is_response = bool(pkt[DNS].qr) if DNS in pkt else False
                if is_response and resp:
                    rec["info"] = f"DNS Response: {q} -> {resp}"
                else:
                    rec["info"] = f"DNS Query: {q} ({qt})" if q else "DNS Query"
            elif proto == "QUIC":
                rec["info"] = f"QUIC {udp.sport}->{udp.dport} Len={len(pkt)}"
            else:
                rec["info"] = f"UDP {udp.sport}->{udp.dport} Len={len(pkt)}"

        # ── ICMP ─────────────────────────────────────────────────────────────
        elif ICMP in pkt:
            icmp = pkt[ICMP]
            rec["icmp_type"] = icmp.type
            rec["icmp_code"] = icmp.code
            type_name = ICMP_TYPE_NAMES.get(icmp.type, f"Type {icmp.type}")
            rec["info"] = f"ICMP {type_name} (type={icmp.type} code={icmp.code})"

        else:
            rec["info"] = f"IP {pkt[IP].src}->{pkt[IP].dst} Proto={pkt[IP].proto}"

        return rec

    except Exception as exc:
        # Skip corrupt/unusual packets without crashing
        print(f"  [!] Skipped packet #{idx}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Protocol detection helpers (PyShark)
# ---------------------------------------------------------------------------

def _detect_protocol_pyshark(pkt) -> str:
    """Classify a PyShark packet into a named protocol string."""
    try:
        layers = [layer.layer_name.upper() for layer in pkt.layers]

        if "ICMP" in layers:
            return "ICMP"
        if "DNS" in layers:
            return "DNS"

        transport = getattr(pkt, "transport_layer", None)

        if transport == "TCP":
            try:
                dport = int(pkt.tcp.dstport)
                sport = int(pkt.tcp.srcport)
            except Exception:
                return "TCP"
            if dport in HTTP_PORTS or sport in HTTP_PORTS:
                return "HTTP"
            if dport in HTTPS_PORTS or sport in HTTPS_PORTS:
                if "TLS" in layers:
                    return "HTTPS/TLS"
                return "HTTPS/TLS"
            return "TCP"

        if transport == "UDP":
            try:
                dport = int(pkt.udp.dstport)
                sport = int(pkt.udp.srcport)
            except Exception:
                return "UDP"
            if dport in DNS_PORTS or sport in DNS_PORTS:
                return "DNS"
            if dport in QUIC_PORTS or sport in QUIC_PORTS:
                return "QUIC"
            return "UDP"

    except Exception:
        pass
    return "OTHER"


def _safe_attr(obj, *attrs, default=None):
    """Safely traverse attributes on a PyShark layer object."""
    cur = obj
    for attr in attrs:
        try:
            cur = getattr(cur, attr)
        except AttributeError:
            return default
    return cur if cur is not None else default


def normalize_pyshark_packet(pkt, idx: int) -> Optional[Dict[str, Any]]:
    """
    Convert a single PyShark packet into a normalized packet record dict.
    Returns None if no IP layer is found.
    """
    try:
        # Require an IP layer
        ip_layer = None
        for layer in pkt.layers:
            if layer.layer_name.lower() in ("ip", "ipv6"):
                ip_layer = layer
                break
        if ip_layer is None:
            return None

        rec = empty_record()
        rec["packet_number"] = idx
        rec["source_ip"] = _safe_attr(ip_layer, "src", default="?")
        rec["destination_ip"] = _safe_attr(ip_layer, "dst", default="?")

        try:
            rec["packet_length"] = int(pkt.length)
        except Exception:
            rec["packet_length"] = 0

        # Timestamp
        try:
            rec["timestamp"] = str(pkt.sniff_time.strftime("%H:%M:%S.%f"))[:-3]
        except Exception:
            rec["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        proto = _detect_protocol_pyshark(pkt)
        rec["protocol"] = proto

        transport = getattr(pkt, "transport_layer", None)

        # ── TCP ──────────────────────────────────────────────────────────────
        if transport == "TCP":
            try:
                tcp = pkt.tcp
                rec["source_port"] = int(tcp.srcport)
                rec["destination_port"] = int(tcp.dstport)
                rec["tcp_sequence"] = int(tcp.seq)
                rec["tcp_acknowledgment"] = int(tcp.ack)

                # Build flags string
                flag_parts = []
                for fname, fattr in [
                    ("SYN", "flags_syn"), ("ACK", "flags_ack"), ("FIN", "flags_fin"),
                    ("RST", "flags_reset"), ("PSH", "flags_push"), ("URG", "flags_urg")
                ]:
                    val = _safe_attr(tcp, fattr, default="0")
                    if str(val) == "1":
                        flag_parts.append(fname)
                rec["tcp_flags"] = "-".join(flag_parts) if flag_parts else "NONE"
            except Exception:
                pass

        # ── UDP ──────────────────────────────────────────────────────────────
        if transport == "UDP":
            try:
                rec["source_port"] = int(pkt.udp.srcport)
                rec["destination_port"] = int(pkt.udp.dstport)
            except Exception:
                pass

        # ── DNS ──────────────────────────────────────────────────────────────
        if proto == "DNS":
            try:
                dns = pkt.dns
                qry = _safe_attr(dns, "qry_name", default=None)
                if qry:
                    rec["dns_query"] = str(qry).rstrip(".")
                qtype = _safe_attr(dns, "qry_type", default=None)
                if qtype:
                    try:
                        rec["dns_query_type"] = DNS_QTYPE_NAMES.get(int(qtype), str(qtype))
                    except Exception:
                        rec["dns_query_type"] = str(qtype)
                resp_a = _safe_attr(dns, "a", default=None)
                if resp_a:
                    rec["dns_response"] = str(resp_a)
                is_response = str(_safe_attr(dns, "flags_response", default="0")) == "1"
                if is_response and rec["dns_response"]:
                    rec["info"] = f"DNS Response: {rec['dns_query']} -> {rec['dns_response']}"
                else:
                    rec["info"] = (
                        f"DNS Query: {rec['dns_query']} ({rec['dns_query_type']})"
                        if rec["dns_query"] else "DNS"
                    )
            except Exception:
                rec["info"] = "DNS"

        # ── ICMP ─────────────────────────────────────────────────────────────
        elif proto == "ICMP":
            try:
                icmp = pkt.icmp
                icmp_type = int(_safe_attr(icmp, "type", default="-1"))
                icmp_code = int(_safe_attr(icmp, "code", default="0"))
                rec["icmp_type"] = icmp_type
                rec["icmp_code"] = icmp_code
                type_name = ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
                rec["info"] = f"ICMP {type_name} (type={icmp_type} code={icmp_code})"
            except Exception:
                rec["info"] = "ICMP"

        # ── HTTP ─────────────────────────────────────────────────────────────
        elif proto == "HTTP":
            try:
                http = pkt.http
                rec["http_method"] = _safe_attr(http, "request_method", default=None)
                rec["http_uri"] = _safe_attr(http, "request_uri", default=None)
                rec["http_host"] = _safe_attr(http, "host", default=None)
                parts = []
                if rec["http_method"] and rec["http_uri"]:
                    parts.append(f"{rec['http_method']} {rec['http_uri']}")
                if rec["http_host"]:
                    parts.append(f"Host: {rec['http_host']}")
                rec["info"] = " | ".join(parts) if parts else "HTTP"
            except Exception:
                rec["info"] = "HTTP"

        # ── HTTPS/TLS ────────────────────────────────────────────────────────
        elif proto == "HTTPS/TLS":
            try:
                tls = pkt.tls
                ver = _safe_attr(tls, "record_version", default=None)
                if ver:
                    tls_ver_map = {
                        "0x0301": "TLS 1.0", "0x0302": "TLS 1.1",
                        "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
                    }
                    rec["tls_version"] = tls_ver_map.get(str(ver).lower(), str(ver))
                sni = _safe_attr(tls, "handshake_extensions_server_name", default=None)
                rec["http_host"] = str(sni) if sni else None
                info_parts = [f"TLS {rec['tls_version'] or ''}".strip()]
                if rec["http_host"]:
                    info_parts.append(f"SNI={rec['http_host']}")
                port_info = f"{rec['source_port']}->{rec['destination_port']}" if rec["source_port"] else ""
                if port_info:
                    info_parts.append(port_info)
                rec["info"] = " ".join(filter(None, info_parts))
            except Exception:
                rec["info"] = f"HTTPS/TLS {rec['source_port'] or ''}->{rec['destination_port'] or ''}"

        # ── QUIC ─────────────────────────────────────────────────────────────
        elif proto == "QUIC":
            rec["info"] = (
                f"QUIC {rec['source_port'] or ''}->{rec['destination_port'] or ''}"
                f" Len={rec['packet_length']}"
            )

        # ── Generic TCP/UDP ──────────────────────────────────────────────────
        elif transport == "TCP" and not rec["info"]:
            rec["info"] = (
                f"TCP {rec['source_port']}->{rec['destination_port']}"
                f" [{rec['tcp_flags']}] Seq={rec['tcp_sequence']} Len={rec['packet_length']}"
            )
        elif transport == "UDP" and not rec["info"]:
            rec["info"] = f"UDP {rec['source_port']}->{rec['destination_port']} Len={rec['packet_length']}"

        return rec

    except Exception as exc:
        print(f"  [!] Skipped packet #{idx}: {exc}")
        return None


# ---------------------------------------------------------------------------
# TCP Handshake Correlator
# ---------------------------------------------------------------------------

def correlate_tcp_handshakes(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect TCP three-way handshakes across the packet list.
    Tracks per connection-tuple: (client_ip, client_port, server_ip, server_port)
    and looks for SYN -> SYN-ACK -> ACK sequences.

    Returns a list of handshake dicts.
    """
    # pending[conn_key] = {"syn_seq": int, "syn_ack_seq": int, "syn": True/False, ...}
    pending: Dict[Tuple, Dict[str, Any]] = {}
    completed: List[Dict[str, Any]] = []

    for p in packets:
        if p.get("protocol") not in ("TCP", "HTTPS/TLS", "HTTP"):
            continue
        flags = p.get("tcp_flags") or ""
        src_ip = p.get("source_ip")
        dst_ip = p.get("destination_ip")
        sport = p.get("source_port")
        dport = p.get("destination_port")
        seq = p.get("tcp_sequence")
        ack = p.get("tcp_acknowledgment")

        if None in (src_ip, dst_ip, sport, dport):
            continue

        flag_set = set(flags.split("-"))

        # Step 1: Pure SYN (no ACK)
        if "SYN" in flag_set and "ACK" not in flag_set:
            conn_key = (src_ip, sport, dst_ip, dport)
            pending[conn_key] = {
                "client": f"{src_ip}:{sport}",
                "server": f"{dst_ip}:{dport}",
                "syn": True,
                "syn_ack": False,
                "ack": False,
                "complete": False,
                "syn_seq": seq,
                "packet_numbers": [p["packet_number"]],
            }

        # Step 2: SYN-ACK
        elif "SYN" in flag_set and "ACK" in flag_set:
            # The "server" side responds — key is reversed
            conn_key = (dst_ip, dport, src_ip, sport)
            if conn_key in pending and pending[conn_key]["syn"] and not pending[conn_key]["syn_ack"]:
                pending[conn_key]["syn_ack"] = True
                pending[conn_key]["syn_ack_seq"] = seq
                pending[conn_key]["packet_numbers"].append(p["packet_number"])

        # Step 3: Pure ACK (no SYN, no FIN, no RST)
        elif "ACK" in flag_set and "SYN" not in flag_set and "FIN" not in flag_set and "RST" not in flag_set:
            conn_key = (src_ip, sport, dst_ip, dport)
            if conn_key in pending:
                entry = pending[conn_key]
                if entry["syn"] and entry["syn_ack"] and not entry["ack"]:
                    # Verify the ACK number corresponds to SYN-ACK sequence
                    syn_ack_seq = entry.get("syn_ack_seq")
                    if syn_ack_seq is None or (ack is not None and ack == syn_ack_seq + 1):
                        entry["ack"] = True
                        entry["complete"] = True
                        entry["packet_numbers"].append(p["packet_number"])
                        completed.append({
                            "client": entry["client"],
                            "server": entry["server"],
                            "syn": True,
                            "syn_ack": True,
                            "ack": True,
                            "complete": True,
                            "packet_numbers": entry["packet_numbers"],
                        })
                        del pending[conn_key]

    # Add incomplete handshakes (SYN seen, SYN-ACK seen, but no ACK yet)
    for key, entry in pending.items():
        completed.append({
            "client": entry["client"],
            "server": entry["server"],
            "syn": entry["syn"],
            "syn_ack": entry["syn_ack"],
            "ack": entry["ack"],
            "complete": False,
            "packet_numbers": entry.get("packet_numbers", []),
        })

    return completed


# ---------------------------------------------------------------------------
# Live Capture (Scapy)
# ---------------------------------------------------------------------------

def live_capture(
    interface: str,
    count: int = 100,
    duration: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Capture live packets using Scapy's sniff().

    Args:
        interface: Network interface name (e.g. "Wi-Fi", "Ethernet", "eth0").
        count:     Number of packets to capture (0 = unlimited, use duration).
        duration:  Capture duration in seconds (overrides count if set).

    Returns:
        List of normalized packet record dicts.
    """
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed. Cannot perform live capture.")
        print("    Install with: pip install scapy")
        sys.exit(1)

    packets: List[Dict[str, Any]] = []
    captured_count = [0]

    def process_packet(pkt):
        idx = captured_count[0] + 1
        rec = normalize_scapy_packet(pkt, idx)
        if rec is not None:
            packets.append(rec)
            captured_count[0] += 1
            if captured_count[0] % 10 == 0:
                print(f"  [*] Captured {captured_count[0]} packets...", flush=True)

    print(f"\n[*] Starting live capture on interface: '{interface}'")
    if duration:
        print(f"    Duration: {duration}s")
    else:
        print(f"    Packet count: {count}")
    print("    Press Ctrl+C to stop early.\n")

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=0 if duration else count,
            timeout=duration,
            store=False,
        )
    except PermissionError:
        print("\n[!] Permission denied. Please run as Administrator (Windows) or root (Linux).")
        sys.exit(1)
    except OSError as exc:
        print(f"\n[!] Cannot open interface '{interface}': {exc}")
        print("    Available interfaces:")
        try:
            from scapy.arch import get_if_list
            for iface in get_if_list():
                print(f"      - {iface}")
        except Exception:
            pass
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture interrupted by user.")

    print(f"\n[+] Live capture complete. Total packets captured: {len(packets)}")
    return packets


# ---------------------------------------------------------------------------
# PCAP / PCAPNG File Analysis
# ---------------------------------------------------------------------------

def analyze_pcap_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Analyze a PCAP or PCAPNG file using PyShark (preferred) or Scapy (fallback).

    Args:
        filepath: Path to the .pcap or .pcapng file.

    Returns:
        List of normalized packet record dicts.
    """
    if not os.path.exists(filepath):
        print(f"[!] PCAP file not found: {filepath}")
        sys.exit(1)

    print(f"[*] Analyzing PCAP/PCAPNG file: {filepath}")

    packets: List[Dict[str, Any]] = []

    # ── Try PyShark first (supports PCAPNG natively) ─────────────────────────
    if PYSHARK_AVAILABLE:
        print("[*] Using PyShark for file analysis...")
        try:
            cap = pyshark.FileCapture(
                filepath,
                keep_packets=False,
                use_json=True,
                include_raw=False,
            )
            idx = 1
            for pkt in cap:
                rec = normalize_pyshark_packet(pkt, idx)
                if rec is not None:
                    packets.append(rec)
                    idx += 1
                    if idx % 50 == 0:
                        print(f"  [*] Processed {idx - 1} packets...", flush=True)
            cap.close()
            print(f"[+] PyShark analysis complete. Packets parsed: {len(packets)}")
            return packets
        except Exception as exc:
            print(f"[!] PyShark failed ({exc}), falling back to Scapy...")

    # ── Fallback: Scapy ───────────────────────────────────────────────────────
    if SCAPY_AVAILABLE:
        print("[*] Using Scapy for file analysis...")
        try:
            raw_packets = rdpcap(filepath)
            for idx, pkt in enumerate(raw_packets, start=1):
                rec = normalize_scapy_packet(pkt, idx)
                if rec is not None:
                    packets.append(rec)
                if idx % 50 == 0:
                    print(f"  [*] Processed {idx} packets...", flush=True)
            print(f"[+] Scapy analysis complete. Packets parsed: {len(packets)}")
            return packets
        except Exception as exc:
            print(f"[!] Scapy PCAP parsing failed: {exc}")
            sys.exit(1)

    print("[!] Neither PyShark nor Scapy is available. Cannot analyze PCAP file.")
    print("    Install dependencies: pip install scapy pyshark")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def _build_protocol_counts(packets: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for p in packets:
        proto = p.get("protocol") or "OTHER"
        counts[proto] = counts.get(proto, 0) + 1
    return counts


def _extract_dns_queries(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set = set()
    queries: List[Dict[str, Any]] = []
    for p in packets:
        if p.get("dns_query"):
            key = (p["dns_query"], p.get("dns_query_type"))
            if key not in seen:
                seen.add(key)
            queries.append({
                "domain": p["dns_query"],
                "query_type": p.get("dns_query_type"),
                "source_ip": p.get("source_ip"),
                "destination_ip": p.get("destination_ip"),
                "response": p.get("dns_response"),
                "packet_number": p.get("packet_number"),
                "timestamp": p.get("timestamp"),
            })
    return queries


def build_output(
    packets: List[Dict[str, Any]],
    source_label: str = "live",
) -> Dict[str, Any]:
    """
    Build the complete output dict from a list of normalized packet records.
    Maintains backward compatibility with the Flask dashboard JSON format.
    """
    if not packets:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_packets_captured": 0,
            "protocol_summary": {},
            "capture_summary": {
                "total_packets": 0,
                "unique_source_ips": 0,
                "unique_destination_ips": 0,
                "dns_query_count": 0,
                "tcp_handshake_count": 0,
                "icmp_count": 0,
                "start_time": None,
                "end_time": None,
                "source": source_label,
            },
            "tcp_handshakes": [],
            "dns_queries": [],
            "packets": [],
        }

    proto_counts = _build_protocol_counts(packets)
    handshakes = correlate_tcp_handshakes(packets)
    dns_queries = _extract_dns_queries(packets)

    src_ips = {p["source_ip"] for p in packets if p.get("source_ip")}
    dst_ips = {p["destination_ip"] for p in packets if p.get("destination_ip")}
    icmp_count = sum(1 for p in packets if p.get("protocol") == "ICMP")
    timestamps = [p["timestamp"] for p in packets if p.get("timestamp")]

    # ── Dashboard-compatible packet list ─────────────────────────────────────
    # Map internal fields -> the field names expected by dashboard.js
    dash_packets = []
    for p in packets:
        flags = p.get("tcp_flags") or ""
        flag_set = set(flags.split("-")) if flags else set()

        # Determine tcp_handshake string (for the dashboard "TCP Handshake / DNS" column)
        tcp_handshake_str = None
        if "SYN" in flag_set and "ACK" not in flag_set:
            tcp_handshake_str = "SYN Sent (Step 1)"
        elif "SYN" in flag_set and "ACK" in flag_set:
            tcp_handshake_str = "SYN-ACK Received (Step 2)"
        elif "ACK" in flag_set and "SYN" not in flag_set and "FIN" not in flag_set:
            if p.get("protocol") in ("TCP", "HTTPS/TLS", "HTTP"):
                tcp_handshake_str = "ACK (Step 3 / Data)"

        # dns_lookup sub-object for dashboard
        dns_lookup = None
        if p.get("dns_query"):
            dns_lookup = {
                "query_name": p["dns_query"],
                "query_type": p.get("dns_query_type"),
                "response_ip": p.get("dns_response"),
            }

        dash_packets.append({
            # Dashboard-expected fields
            "id": p["packet_number"],
            "timestamp": p["timestamp"],
            "src_ip": p["source_ip"],
            "dst_ip": p["destination_ip"],
            "protocol": p["protocol"],
            "length": p["packet_length"],
            "details": p.get("info") or "",
            "packet_type": p["protocol"],
            "tcp_handshake": tcp_handshake_str,
            "dns_lookup": dns_lookup,
            # Extended fields
            "source_port": p.get("source_port"),
            "destination_port": p.get("destination_port"),
            "tcp_flags": p.get("tcp_flags"),
            "tcp_sequence": p.get("tcp_sequence"),
            "tcp_acknowledgment": p.get("tcp_acknowledgment"),
            "dns_query": p.get("dns_query"),
            "dns_query_type": p.get("dns_query_type"),
            "dns_response": p.get("dns_response"),
            "icmp_type": p.get("icmp_type"),
            "icmp_code": p.get("icmp_code"),
            "http_host": p.get("http_host"),
            "http_method": p.get("http_method"),
            "http_uri": p.get("http_uri"),
            "tls_version": p.get("tls_version"),
        })

    return {
        # Dashboard-required top-level keys
        "timestamp": datetime.datetime.now().isoformat(),
        "total_packets_captured": len(packets),
        "protocol_summary": proto_counts,
        # Extended summary
        "capture_summary": {
            "total_packets": len(packets),
            "unique_source_ips": len(src_ips),
            "unique_destination_ips": len(dst_ips),
            "dns_query_count": len(dns_queries),
            "tcp_handshake_count": sum(1 for h in handshakes if h["complete"]),
            "icmp_count": icmp_count,
            "start_time": timestamps[0] if timestamps else None,
            "end_time": timestamps[-1] if timestamps else None,
            "source": source_label,
        },
        "tcp_handshakes": handshakes,
        "dns_queries": dns_queries,
        "packets": dash_packets,
    }


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def save_json(data: Dict[str, Any], path: str) -> None:
    """Write analysis data to a JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4, default=str)
        print(f"[+] JSON saved -> {path}")
    except IOError as exc:
        print(f"[!] Failed to save JSON: {exc}")


CSV_COLUMNS = [
    "packet_number", "timestamp", "source_ip", "destination_ip",
    "protocol", "packet_length", "source_port", "destination_port",
    "tcp_flags", "dns_query", "dns_query_type", "dns_response",
    "icmp_type", "icmp_code", "http_host", "http_method", "http_uri",
    "tls_version", "info",
]

CSV_HEADERS = [
    "Packet #", "Timestamp", "Source IP", "Destination IP",
    "Protocol", "Length (B)", "Source Port", "Destination Port",
    "TCP Flags", "DNS Query", "DNS Query Type", "DNS Response",
    "ICMP Type", "ICMP Code", "HTTP Host", "HTTP Method", "HTTP URI",
    "TLS Version", "Info",
]


def save_csv(packets: List[Dict[str, Any]], path: str) -> None:
    """
    Write normalized packet records to a CSV file.
    Accepts either internal packet records or dashboard-compatible dicts.
    """
    # Detect whether we have raw records (source_ip) or dash records (src_ip)
    # and normalize accordingly
    def _get(p: dict, key: str, dash_key: str):
        return p.get(key) if key in p else p.get(dash_key)

    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(CSV_HEADERS)
            for p in packets:
                writer.writerow([
                    _get(p, "packet_number", "id") or "",
                    p.get("timestamp") or "",
                    _get(p, "source_ip", "src_ip") or "",
                    _get(p, "destination_ip", "dst_ip") or "",
                    p.get("protocol") or "",
                    _get(p, "packet_length", "length") or "",
                    p.get("source_port") or "",
                    p.get("destination_port") or "",
                    p.get("tcp_flags") or "",
                    p.get("dns_query") or (
                        (p.get("dns_lookup") or {}).get("query_name") or ""
                    ),
                    p.get("dns_query_type") or (
                        (p.get("dns_lookup") or {}).get("query_type") or ""
                    ),
                    p.get("dns_response") or (
                        (p.get("dns_lookup") or {}).get("response_ip") or ""
                    ),
                    p.get("icmp_type") if p.get("icmp_type") is not None else "",
                    p.get("icmp_code") if p.get("icmp_code") is not None else "",
                    p.get("http_host") or "",
                    p.get("http_method") or "",
                    p.get("http_uri") or "",
                    p.get("tls_version") or "",
                    _get(p, "info", "details") or "",
                ])
        print(f"[+] CSV saved  -> {path}")
    except IOError as exc:
        print(f"[!] Failed to save CSV: {exc}")


# ---------------------------------------------------------------------------
# Statistics printer
# ---------------------------------------------------------------------------

def print_statistics(data: Dict[str, Any]) -> None:
    """Print a summary of the capture results to stdout."""
    summary = data.get("capture_summary", {})
    handshakes = data.get("tcp_handshakes", [])
    dns_queries = data.get("dns_queries", [])
    proto_counts = data.get("protocol_summary", {})

    print("\n" + "=" * 60)
    print("  CAPTURE SUMMARY")
    print("=" * 60)
    print(f"  Total packets analyzed : {data.get('total_packets_captured', 0)}")
    print(f"  Unique source IPs      : {summary.get('unique_source_ips', 0)}")
    print(f"  Unique destination IPs : {summary.get('unique_destination_ips', 0)}")
    print(f"  Capture start          : {summary.get('start_time', 'N/A')}")
    print(f"  Capture end            : {summary.get('end_time', 'N/A')}")

    print("\n  PROTOCOL BREAKDOWN")
    print("  " + "-" * 40)
    for proto, cnt in sorted(proto_counts.items(), key=lambda x: -x[1]):
        print(f"  {proto:<20} {cnt:>6}")

    print(f"\n  DNS Queries            : {summary.get('dns_query_count', 0)}")
    if dns_queries:
        for q in dns_queries[:5]:
            print(f"    - {q['domain']} ({q['query_type']}) "
                  f"{q['source_ip']} -> {q['destination_ip']}")
        if len(dns_queries) > 5:
            print(f"    ... and {len(dns_queries) - 5} more")

    complete_hs = [h for h in handshakes if h["complete"]]
    print(f"\n  TCP Handshakes (complete) : {len(complete_hs)}")
    for hs in complete_hs[:3]:
        print(f"    Client {hs['client']} -> Server {hs['server']}")
        print(f"      SYN [OK]  SYN-ACK [OK]  ACK [OK]  Complete [OK]")
    if len(complete_hs) > 3:
        print(f"    ... and {len(complete_hs) - 3} more")

    print(f"\n  ICMP packets           : {summary.get('icmp_count', 0)}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Flask-compatible wrapper (keeps existing app.py import working)
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_filepath: Optional[str] = None) -> Dict[str, Any]:
    """
    Flask-compatible entry point called by app.py.

    If a valid PCAP filepath is provided, analyzes that file.
    Otherwise, attempts a short live capture on the default interface,
    and if that fails (permission / no interface), returns a minimal
    empty result rather than crashing the Flask server.

    Always saves packet_analysis.json and packet_analysis.csv.
    """
    packets: List[Dict[str, Any]] = []
    source_label = "unknown"

    if pcap_filepath and os.path.exists(pcap_filepath):
        print(f"[Module 2] Analyzing PCAP file: {pcap_filepath}")
        packets = analyze_pcap_file(pcap_filepath)
        source_label = f"pcap:{os.path.basename(pcap_filepath)}"
    else:
        # Try a short live capture; swallow errors so Flask doesn't crash
        if SCAPY_AVAILABLE:
            try:
                import platform
                # Determine a sensible default interface
                if platform.system() == "Windows":
                    default_iface = "Wi-Fi"
                else:
                    default_iface = "eth0"
                print(f"[Module 2] Attempting brief live capture on '{default_iface}'...")
                packets = live_capture(interface=default_iface, count=50)
                source_label = f"live:{default_iface}"
            except SystemExit:
                pass  # Permission denied or bad interface — return empty
            except Exception as exc:
                print(f"[Module 2] Live capture failed: {exc}")
        else:
            print("[Module 2] Scapy not available. No data to capture.")

    data = build_output(packets, source_label=source_label)
    save_json(data, DEFAULT_JSON_PATH)
    save_csv(data["packets"], DEFAULT_CSV_PATH)
    return data


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description=(
            "Module 2: Packet Capture & Protocol Analysis\n"
            "Captures live traffic or analyzes PCAP/PCAPNG files.\n\n"
            "Examples:\n"
            "  python sniffer.py --interface \"Wi-Fi\" --count 100\n"
            "  python sniffer.py --interface \"Ethernet\" --duration 30\n"
            "  python sniffer.py --pcap capture.pcapng\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--interface", "-i",
        metavar="IFACE",
        help='Network interface for live capture (e.g. "Wi-Fi", "Ethernet", "eth0").',
    )
    mode.add_argument(
        "--pcap", "-p",
        metavar="FILE",
        help="Path to a .pcap or .pcapng file for offline analysis.",
    )

    parser.add_argument(
        "--count", "-c",
        type=int,
        default=100,
        metavar="N",
        help="Number of packets to capture in live mode (default: 100).",
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Capture duration in seconds (overrides --count when set).",
    )
    parser.add_argument(
        "--json-output", "-j",
        metavar="PATH",
        default=DEFAULT_JSON_PATH,
        help=f"Output JSON file path (default: {DEFAULT_JSON_PATH}).",
    )
    parser.add_argument(
        "--csv-output", "-C",
        metavar="PATH",
        default=DEFAULT_CSV_PATH,
        help=f"Output CSV file path (default: {DEFAULT_CSV_PATH}).",
    )
    parser.add_argument(
        "--list-interfaces", "-l",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    # ── List interfaces ───────────────────────────────────────────────────────
    if args.list_interfaces:
        if SCAPY_AVAILABLE:
            try:
                from scapy.arch import get_if_list
                print("[*] Available network interfaces:")
                for iface in get_if_list():
                    print(f"    - {iface}")
            except Exception:
                print("[!] Could not enumerate interfaces.")
        else:
            print("[!] Scapy not installed. Cannot list interfaces.")
        return

    # ── Dependency check ─────────────────────────────────────────────────────
    if not SCAPY_AVAILABLE and not PYSHARK_AVAILABLE:
        print("[!] Neither Scapy nor PyShark is installed.")
        print("    Install with: pip install scapy pyshark")
        sys.exit(1)

    packets: List[Dict[str, Any]] = []
    source_label = "cli"

    # ── PCAP file mode ───────────────────────────────────────────────────────
    if args.pcap:
        packets = analyze_pcap_file(args.pcap)
        source_label = f"pcap:{os.path.basename(args.pcap)}"

    # ── Live capture mode ─────────────────────────────────────────────────────
    elif args.interface:
        packets = live_capture(
            interface=args.interface,
            count=args.count,
            duration=args.duration,
        )
        source_label = f"live:{args.interface}"

    else:
        parser.print_help()
        print("\n[!] Please specify --interface or --pcap.")
        sys.exit(1)

    if not packets:
        print("[!] No packets were captured or parsed. Nothing to export.")
        sys.exit(0)

    # ── Build output & save ───────────────────────────────────────────────────
    data = build_output(packets, source_label=source_label)
    save_json(data, args.json_output)
    save_csv(data["packets"], args.csv_output)

    # ── Print statistics ──────────────────────────────────────────────────────
    print_statistics(data)


if __name__ == "__main__":
    main()
