"""
Module 3: MAC Address Spoofing & Management (Phase 3)
------------------------------------------------------
Fully dynamic approach:
- Detects Wi-Fi adapter and original MAC via ipconfig /all at runtime (no hardcodes)
- Stores per-system baselines in baselines.json keyed by Windows hostname
- Spoofs MAC via Windows Registry NetworkAddress + PowerShell adapter restart
- Restores original MAC by deleting registry override + adapter restart
- Reports and logs all actions with timestamps
"""

import os
import json
import re
import socket
import subprocess
import time
import winreg
from datetime import datetime
import pandas as pd

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINES_FILE = os.path.join(MODULE_DIR, "baselines.json")
REPORTS_DIR = os.path.join(MODULE_DIR, "reports")
LOG_FILE = os.path.join(REPORTS_DIR, "experiment_log.csv")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: DYNAMIC ADAPTER & MAC DETECTION (ipconfig /all — no hardcodes)
# ─────────────────────────────────────────────────────────────────────────────

def get_wifi_adapter_info():
    """
    Dynamically detect the primary Wi-Fi adapter and its current live MAC address
    by running ipconfig /all. Prioritizes physical hardware Wi-Fi adapters over
    virtual adapters (e.g. Microsoft Wi-Fi Direct Virtual Adapter).
    Returns (adapter_description: str, mac_address: str | None).
    """
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        sections = re.split(r"\n(?=[A-Za-z0-9].*adapter)", output)

        physical_wifi = None
        virtual_wifi = None
        other_active = None

        for section in sections:
            if "Physical Address" not in section:
                continue

            mac_match = re.search(r"Physical Address[.\s:]*([0-9A-Fa-f-]{17})", section)
            desc_match = re.search(r"Description[.\s:]*(.+)", section)

            if not mac_match:
                continue

            mac = mac_match.group(1).upper().replace("-", ":")
            desc = desc_match.group(1).strip() if desc_match else "Network Adapter"

            # Classify: physical Wi-Fi section has "Wi-Fi:" header (not virtual)
            if "Wi-Fi:" in section or ("Wireless" in section and "Virtual" not in desc):
                physical_wifi = (desc, mac)
            elif ("Wireless" in section or "Wi-Fi" in section) and not virtual_wifi:
                virtual_wifi = (desc, mac)
            elif not other_active:
                other_active = (desc, mac)

        if physical_wifi:
            return physical_wifi
        if virtual_wifi:
            return virtual_wifi
        if other_active:
            return other_active

    except Exception as e:
        print(f"[!] ipconfig detection notice: {e}")

    return "Wi-Fi Adapter", None


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: HOSTNAME-KEYED BASELINE STORAGE (baselines.json)
# ─────────────────────────────────────────────────────────────────────────────

def load_baselines():
    """Load the full baselines.json dictionary."""
    if os.path.exists(BASELINES_FILE):
        try:
            with open(BASELINES_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Could not read baselines.json: {e}")
    return {}


def save_baselines(baselines):
    """Save the baselines dictionary to baselines.json."""
    with open(BASELINES_FILE, "w") as f:
        json.dump(baselines, f, indent=4)


def get_or_create_baseline():
    """
    Get baseline for the current system (keyed by hostname).
    On first run for a new system, automatically detects and saves the baseline.
    Returns the baseline dict for this system.

    baselines.json structure:
    {
        "MouliDharan": {
            "hostname": "MouliDharan",
            "adapter": "RZ616 Wi-Fi 6E 160MHz",
            "original_mac": "60:E9:AA:F0:A2:C1",
            "first_detected": "10-Aug-2026 15:24:00"
        },
        "Surya-PC": { ... }
    }
    """
    hostname = socket.gethostname()
    baselines = load_baselines()

    if hostname in baselines:
        baseline = baselines[hostname]
        # Ensure all keys are present
        if baseline.get("original_mac") and baseline.get("adapter"):
            return baseline

    # New system detected — run ipconfig /all and save baseline
    adapter_desc, current_mac = get_wifi_adapter_info()
    print(f"[+] New system detected: '{hostname}'. Saving baseline automatically.")
    print(f"    Adapter : {adapter_desc}")
    print(f"    MAC     : {current_mac}")

    baseline = {
        "hostname": hostname,
        "adapter": adapter_desc if adapter_desc else "Wi-Fi Adapter",
        "original_mac": current_mac if current_mac else "UNKNOWN",
        "first_detected": datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    }

    baselines[hostname] = baseline
    save_baselines(baselines)
    return baseline


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: MAC STATUS DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def get_mac_status(current_mac, baseline):
    """
    Determine MAC status by comparing live MAC against the stored original baseline.
    Returns "ORIGINAL" if MAC matches baseline, "SPOOFED" if different, "ERROR" if unknown.
    """
    if not current_mac:
        return "ERROR"

    orig = baseline.get("original_mac", "").upper().replace("-", ":")
    curr = current_mac.upper().replace("-", ":")

    if curr == orig:
        return "ORIGINAL"
    return "SPOOFED"


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: WINDOWS REGISTRY ADAPTER KEY LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

def find_adapter_registry_key(adapter_desc):
    """
    Dynamically find the Windows Registry subkey for the target network adapter
    under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}.
    Returns (subkey_id: str, driver_description: str) or (None, None).
    """
    net_class_key = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    search_terms = []
    if adapter_desc:
        search_terms.append(adapter_desc.lower())
    # Fallback generic keywords
    search_terms += ["wi-fi", "wireless", "wlan"]

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_class_key) as key:
            for i in range(200):
                try:
                    sub_key_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub_key_name) as sub_key:
                        try:
                            driver_desc, _ = winreg.QueryValueEx(sub_key, "DriverDesc")
                            for term in search_terms:
                                if term in driver_desc.lower():
                                    return sub_key_name, driver_desc
                        except FileNotFoundError:
                            pass
                except OSError:
                    break
    except Exception as e:
        print(f"[!] Registry query notice: {e}")

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: EXPERIMENT LOGGING
# ─────────────────────────────────────────────────────────────────────────────

def log_experiment(action, current_mac, status, baseline):
    """Append timestamped experiment step to experiment_log.csv."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    adapter = baseline.get("adapter", "Wi-Fi Adapter")
    hostname = baseline.get("hostname", socket.gethostname())
    mac_str = current_mac if current_mac else "N/A"

    is_new = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0
    with open(LOG_FILE, "a") as f:
        if is_new:
            f.write("Timestamp,Hostname,Adapter,MAC Address,Status,Action\n")
        f.write(f'"{timestamp}","{hostname}","{adapter}","{mac_str}","{status}","{action}"\n')


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: API DASHBOARD STATE — load_log()
# ─────────────────────────────────────────────────────────────────────────────

def load_log():
    """
    Load current system state for the web API dashboard.
    Reads live MAC dynamically, compares against hostname-keyed baseline.
    """
    baseline = get_or_create_baseline()
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, baseline)

    history = []
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        try:
            df = pd.read_csv(LOG_FILE, on_bad_lines="skip")
            for row in df.to_dict(orient="records"):
                ts_raw = str(row.get("Timestamp", ""))
                try:
                    dt_obj = datetime.strptime(ts_raw, "%d-%b-%Y %H:%M:%S")
                    iso_ts = dt_obj.isoformat()
                except Exception:
                    iso_ts = datetime.now().isoformat()

                history.append({
                    "timestamp": iso_ts,
                    "action": row.get("Action", "LOG"),
                    "adapter": row.get("Adapter", adapter_desc),
                    "new_mac": row.get("MAC Address", "N/A"),
                    "restored_mac": row.get("MAC Address", "N/A"),
                    "status": row.get("Status", "N/A"),
                    "verified": True
                })
        except Exception as e:
            print(f"[!] Error reading history log: {e}")

    return {
        "adapter_name": baseline.get("adapter", adapter_desc),
        "hostname": baseline.get("hostname"),
        "original_mac": baseline.get("original_mac"),
        "current_mac": current_mac if current_mac else baseline.get("original_mac"),
        "is_spoofed": (status == "SPOOFED"),
        "status": status,
        "history": history
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7: ADAPTER LIST (for API dropdown)
# ─────────────────────────────────────────────────────────────────────────────

def get_network_adapters():
    """Retrieve live network adapters dynamically for Web Dashboard dropdown."""
    adapter_name, mac = get_wifi_adapter_info()
    return [{
        "name": "Wi-Fi",
        "description": adapter_name if adapter_name else "Wi-Fi Adapter",
        "mac": mac if mac else "N/A",
        "status": "Up"
    }]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8: PHASE 3 STEP 1 — VIEW CURRENT MAC
# ─────────────────────────────────────────────────────────────────────────────

def view_current_mac(adapter_name="Wi-Fi"):
    """Phase 3 Step 1: View current live MAC address and log it."""
    baseline = get_or_create_baseline()
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, baseline)
    log_experiment("Check Current MAC", current_mac, status, baseline)
    print(f"[*] Host: {baseline['hostname']} | Adapter: {adapter_desc} | MAC: {current_mac} | Status: {status}")
    return {"adapter": adapter_desc, "mac": current_mac, "status": status}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 9: PHASE 3 STEP 2/3/4 — CHANGE MAC ADDRESS
# ─────────────────────────────────────────────────────────────────────────────

def change_mac_address(adapter_name="Wi-Fi", new_mac=None):
    """
    Phase 3 Step 2, 3 & 4:
    - Writes new MAC to Windows Registry (NetworkAddress)
    - Restarts network adapter via PowerShell
    - Waits for adapter to come back up
    - Re-reads live MAC via ipconfig so UI 'Current MAC' field updates
    Returns updated load_log() state for the dashboard.
    """
    baseline = get_or_create_baseline()

    if not new_mac:
        print("[!] No target MAC provided.")
        return load_log()

    # Normalize MAC format: strip separators, uppercase, re-join as AA:BB:CC:DD:EE:FF
    raw_hex = new_mac.replace(":", "").replace("-", "").upper()
    if len(raw_hex) != 12:
        print(f"[!] Invalid MAC address: {new_mac}")
        return load_log()

    formatted_mac = ":".join([raw_hex[i:i+2] for i in range(0, 12, 2)])
    registry_mac = raw_hex   # Windows Registry NetworkAddress = no separators

    adapter_desc, pre_mac = get_wifi_adapter_info()
    print(f"[*] Spoofing MAC on '{adapter_desc}': {pre_mac} -> {formatted_mac}")

    # Step A: Write NetworkAddress to Windows Registry
    key_id, _ = find_adapter_registry_key(adapter_desc)
    if key_id:
        try:
            reg_path = (
                rf"SYSTEM\CurrentControlSet\Control\Class"
                rf"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{key_id}"
            )
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, registry_mac)
            print(f"[+] Registry NetworkAddress set: {registry_mac} (key {key_id})")
        except PermissionError:
            print("[!] Registry write requires Admin. Run app.py as Administrator.")
        except Exception as e:
            print(f"[!] Registry update: {e}")
    else:
        print("[!] Could not locate adapter registry key.")

    # Step B: Restart network adapter via PowerShell
    try:
        ps_cmd = f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"
        res = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        if res.returncode == 0:
            print("[+] Adapter restarted via PowerShell.")
    except Exception as e:
        print(f"[!] PowerShell restart: {e}")

    # Step C: Wait for adapter to finish restarting, then re-read live MAC
    time.sleep(3)
    _, live_mac = get_wifi_adapter_info()
    effective_mac = live_mac if live_mac else formatted_mac
    status = get_mac_status(effective_mac, baseline)

    log_experiment("Spoof MAC", effective_mac, status, baseline)
    print(f"[+] Live MAC after change: {effective_mac} | Status: {status}")

    return load_log()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 10: PHASE 3 STEP 5 — RESTORE ORIGINAL MAC
# ─────────────────────────────────────────────────────────────────────────────

def restore_original_mac(adapter_name="Wi-Fi"):
    """
    Phase 3 Step 5:
    - Deletes the NetworkAddress override from Windows Registry
    - Restarts network adapter via PowerShell
    - Waits and re-reads live MAC via ipconfig for UI update
    Returns updated load_log() state for the dashboard.
    """
    baseline = get_or_create_baseline()
    orig_mac = baseline.get("original_mac")
    adapter_desc, pre_mac = get_wifi_adapter_info()

    print(f"[*] Restoring Original MAC on '{adapter_desc}': {pre_mac} -> {orig_mac}")

    # Step A: Delete NetworkAddress from Windows Registry
    key_id, _ = find_adapter_registry_key(adapter_desc)
    if key_id:
        try:
            reg_path = (
                rf"SYSTEM\CurrentControlSet\Control\Class"
                rf"\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{key_id}"
            )
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteValue(key, "NetworkAddress")
            print(f"[+] Registry NetworkAddress cleared (key {key_id})")
        except FileNotFoundError:
            print("[*] NetworkAddress key was already empty — adapter uses hardware MAC.")
        except PermissionError:
            print("[!] Registry clear requires Admin. Run app.py as Administrator.")
        except Exception as e:
            print(f"[!] Registry clear: {e}")

    # Step B: Restart network adapter via PowerShell
    try:
        ps_cmd = f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"
        subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        print("[+] Adapter restarted via PowerShell.")
    except Exception as e:
        print(f"[!] PowerShell restart: {e}")

    # Step C: Wait for adapter to come back, then re-read live MAC
    time.sleep(3)
    _, live_mac = get_wifi_adapter_info()
    effective_mac = live_mac if live_mac else orig_mac
    status = get_mac_status(effective_mac, baseline)

    log_experiment("Restore MAC", effective_mac, status, baseline)
    print(f"[+] Live MAC after restore: {effective_mac} | Status: {status}")

    return load_log()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 11: GENERATE REPORTS
# ─────────────────────────────────────────────────────────────────────────────

def generate_reports():
    """Generate Phase 3 summary CSV and multi-sheet Excel report."""
    baseline = get_or_create_baseline()
    os.makedirs(REPORTS_DIR, exist_ok=True)

    csv_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.csv")
    xlsx_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.xlsx")

    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, baseline)

    log_df = pd.read_csv(LOG_FILE, on_bad_lines="skip") if (
        os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0
    ) else pd.DataFrame(columns=["Timestamp", "Hostname", "Adapter", "MAC Address", "Status", "Action"])

    summary = [{
        "Project Phase": "Phase 3 - MAC Address Spoofing",
        "Hostname": baseline.get("hostname"),
        "Adapter": baseline.get("adapter"),
        "Original MAC (Baseline)": baseline.get("original_mac"),
        "First Detected": baseline.get("first_detected"),
        "Current Live MAC": current_mac,
        "Current Status": status,
        "Total Test Runs": len(log_df),
        "Report Generated At": datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    }]
    summary_df = pd.DataFrame(summary)

    summary_df.to_csv(csv_path, index=False)
    print(f"[+] CSV report: '{csv_path}'")

    try:
        with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:
            summary_df.to_excel(writer, sheet_name="Phase3_Summary", index=False)
            log_df.to_excel(writer, sheet_name="Experiment_Logs", index=False)
        print(f"[+] Excel report: '{xlsx_path}'")
    except Exception as e:
        print(f"[!] Excel generation error: {e}")

    log_experiment("Generate Final Report", current_mac, status, baseline)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 12: INTERACTIVE CLI MENU
# ─────────────────────────────────────────────────────────────────────────────

def display_status_header(baseline):
    """Display system banner with live MAC status."""
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, baseline)

    print("\n" + "=" * 58)
    print("        MAC ADDRESS SECURITY TOOL (PHASE 3)")
    print("=" * 58)
    print(f"Hostname      : {baseline.get('hostname')}")
    print(f"Adapter       : {adapter_desc}")
    print(f"Original MAC  : {baseline.get('original_mac')}")
    print(f"Current MAC   : {current_mac if current_mac else 'Detection Failed'}")
    print(f"Status        : {status}")
    print("=" * 58)
    return current_mac, status


def run_cli_menu():
    """Interactive CLI menu for Phase 3 demonstration."""
    baseline = get_or_create_baseline()

    while True:
        display_status_header(baseline)
        print("\nMenu Options:")
        print("1. Check Current MAC Address")
        print("2. Spoof MAC Address (enter custom MAC)")
        print("3. Restore Original MAC Address")
        print("4. View Experiment History Log")
        print("5. Generate Phase 3 Report (CSV & Excel)")
        print("6. Exit")
        print("-" * 58)

        choice = input("Enter choice (1-6): ").strip()

        if choice == "1":
            view_current_mac()
        elif choice == "2":
            new_mac = input("Enter new MAC address (e.g. 02:B1:56:BC:FA:7C): ").strip()
            change_mac_address("Wi-Fi", new_mac if new_mac else None)
        elif choice == "3":
            restore_original_mac()
        elif choice == "4":
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
                print("\n" + pd.read_csv(LOG_FILE, on_bad_lines="skip").to_string(index=False))
            else:
                print("\n[!] No experiment logs yet.")
        elif choice == "5":
            generate_reports()
        elif choice == "6":
            print("\nExiting Phase 3 MAC Security Suite.")
            break
        else:
            print("\n[!] Invalid selection.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    run_cli_menu()
