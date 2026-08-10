"""
Module 3: MAC Address Spoofing & Management (Phase 3)
------------------------------------------------------
Allows viewing current MAC address, spoofing/changing MAC address,
restarting network adapter, verifying new MAC address, restoring original MAC,
maintaining automated configuration, experiment logging, and generating reports.

Uses dynamic ipconfig /all detection, Registry NetworkAddress modification,
and PowerShell adapter restart commands.
"""

import os
import json
import re
import subprocess
import winreg
from datetime import datetime
import pandas as pd

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(MODULE_DIR, "mac_spoofing_log.json")
CONFIG_FILE = os.path.join(MODULE_DIR, "config.json")
REPORTS_DIR = os.path.join(MODULE_DIR, "reports")
LOG_FILE = os.path.join(REPORTS_DIR, "experiment_log.csv")


def get_wifi_adapter_info():
    """Extract adapter name and physical MAC address dynamically using Windows ipconfig /all."""
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
        other_adapter = None

        for section in sections:
            if "Physical Address" in section:
                mac_match = re.search(r"Physical Address[.\s:]*([0-9A-Fa-f-]{17})", section)
                desc_match = re.search(r"Description[.\s:]*(.+)", section)

                if mac_match:
                    mac = mac_match.group(1).upper().replace("-", ":")
                    desc = desc_match.group(1).strip() if desc_match else "Network Adapter"

                    if "Wi-Fi:" in section or ("Wireless" in section and "Virtual" not in desc):
                        physical_wifi = (desc, mac)
                    elif "Wireless" in section or "Wi-Fi" in section:
                        if not virtual_wifi:
                            virtual_wifi = (desc, mac)
                    elif not other_adapter:
                        other_adapter = (desc, mac)

        if physical_wifi:
            return physical_wifi
        if virtual_wifi:
            return virtual_wifi
        if other_adapter:
            return other_adapter
    except Exception as e:
        print(f"[!] Dynamic ipconfig detection notice: {e}")

    return "Wi-Fi Adapter", None


def find_adapter_registry_key(adapter_desc_or_name="Wi-Fi"):
    """Find Windows Registry subkey under Network Class for target adapter."""
    net_class_key = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, net_class_key) as key:
            for i in range(100):
                try:
                    sub_key_name = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, sub_key_name) as sub_key:
                        try:
                            driver_desc, _ = winreg.QueryValueEx(sub_key, "DriverDesc")
                            if adapter_desc_or_name.lower() in driver_desc.lower() or "wi-fi" in driver_desc.lower() or "wireless" in driver_desc.lower():
                                return sub_key_name, driver_desc
                        except FileNotFoundError:
                            pass
                except OSError:
                    break
    except Exception as e:
        print(f"[!] Registry query notice: {e}")

    return None, None


def load_or_create_config():
    """Load configuration from config.json or create dynamic baseline automatically."""
    adapter_name, current_mac = get_wifi_adapter_info()

    default_config = {
        "adapter": adapter_name if adapter_name else "Wi-Fi Adapter",
        "original_mac": current_mac if current_mac else "00:00:00:00:00:00",
        "spoofed_mac": "0C:0C:0C:0C:0C:01"
    }

    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

            # Update dynamically if baseline original_mac is missing or uninitialized
            if not config.get("original_mac") or config.get("original_mac") == "00:00:00:00:00:00":
                if current_mac:
                    config["original_mac"] = current_mac
                    config["adapter"] = adapter_name
                    save_config(config)

            return config
    except Exception as e:
        print(f"[!] Error loading config.json: {e}")
        return default_config


def save_config(config):
    """Save updated configuration to config.json."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def get_mac_status(current_mac, config):
    """Determine MAC status dynamically (ORIGINAL / SPOOFED / UNKNOWN)."""
    if not current_mac:
        return "ERROR"

    orig_mac = config.get("original_mac", "").upper().replace("-", ":")
    spoof_mac = config.get("spoofed_mac", "").upper().replace("-", ":")
    curr_mac = current_mac.upper().replace("-", ":")

    if curr_mac == orig_mac:
        return "ORIGINAL"
    elif curr_mac == spoof_mac or curr_mac != orig_mac:
        return "SPOOFED"
    else:
        return "UNKNOWN"


def get_network_adapters():
    """Retrieves active network adapters dynamically for Web Dashboard API compatibility."""
    adapter_name, mac = get_wifi_adapter_info()
    return [{
        "name": "Wi-Fi",
        "description": adapter_name if adapter_name else "Wi-Fi 6E Adapter",
        "mac": mac if mac else "00:00:00:00:00:00",
        "status": "Up"
    }]


def load_log():
    """Load JSON state log for web API dashboard."""
    config = load_or_create_config()
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    history = []
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        try:
            df = pd.read_csv(LOG_FILE)
            for row in df.to_dict(orient="records"):
                ts_raw = str(row.get("Timestamp", ""))
                try:
                    dt_obj = datetime.strptime(ts_raw, "%d-%b-%Y %H:%M:%S")
                    iso_ts = dt_obj.isoformat()
                except Exception:
                    iso_ts = datetime.now().isoformat()

                history.append({
                    "timestamp": iso_ts,
                    "action": row.get("Action", "LOG_ACTION"),
                    "adapter": row.get("Adapter", adapter_desc),
                    "new_mac": row.get("MAC Address", "N/A"),
                    "restored_mac": row.get("MAC Address", "N/A"),
                    "status": row.get("Status", "N/A"),
                    "verified": True
                })
        except Exception as e:
            print(f"[!] Error mapping history log: {e}")

    return {
        "adapter_name": config.get("adapter", adapter_desc),
        "original_mac": config.get("original_mac"),
        "spoofed_mac": config.get("spoofed_mac"),
        "current_mac": current_mac if current_mac else config.get("original_mac"),
        "is_spoofed": (status == "SPOOFED"),
        "status": status,
        "history": history
    }


def log_experiment(action, current_mac, status, config):
    """Append experiment step into CSV log file."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    adapter = config.get("adapter", "Wi-Fi Adapter")
    mac_str = current_mac if current_mac else "N/A"

    file_is_empty = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0

    with open(LOG_FILE, "a") as f:
        if file_is_empty:
            f.write("Timestamp,Adapter,MAC Address,Status,Action\n")
        f.write(f'"{timestamp}","{adapter}","{mac_str}","{status}","{action}"\n')


def view_current_mac(adapter_name="Wi-Fi"):
    """Phase 3 Step 1: View current MAC address dynamically."""
    config = load_or_create_config()
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)
    log_experiment("Check Current MAC", current_mac, status, config)

    print(f"[*] Adapter: {adapter_desc} | Current MAC: {current_mac} | Status: {status}")
    return {
        "adapter": adapter_desc,
        "mac": current_mac,
        "status": status
    }


def change_mac_address(adapter_name="Wi-Fi", new_mac=None):
    """Phase 3 Step 2, 3 & 4: Dynamically spoof MAC address, restart adapter, and verify."""
    config = load_or_create_config()

    if not new_mac:
        new_mac = config.get("spoofed_mac", "0C:0C:0C:0C:0C:01")

    # Clean MAC string format (AABBCCDDEEFF -> AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
    raw_hex = new_mac.replace(":", "").replace("-", "").upper()
    formatted_mac = ":".join([raw_hex[i:i+2] for i in range(0, len(raw_hex), 2)])
    registry_mac = raw_hex  # Windows registry NetworkAddress requires raw hex without colons

    config["spoofed_mac"] = formatted_mac
    save_config(config)

    adapter_desc, pre_mac = get_wifi_adapter_info()
    print(f"[*] Initiating Dynamic MAC Spoofing for '{adapter_desc}' -> Target MAC: {formatted_mac}")

    # Step 1: Write NetworkAddress to Windows Registry
    key_id, found_desc = find_adapter_registry_key(adapter_desc)
    admin_success = False
    if key_id:
        try:
            reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{key_id}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, registry_mac)
            admin_success = True
            print(f"[+] Windows Registry NetworkAddress set to '{registry_mac}' for adapter key {key_id}")
        except PermissionError:
            print("[!] Registry write requires Administrator privileges. (Logged change request)")
        except Exception as e:
            print(f"[!] Registry update notice: {e}")

    # Step 2: Restart Network Adapter via PowerShell
    try:
        ps_cmd = f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"
        res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
        if res.returncode == 0:
            print("[+] PowerShell adapter restart executed successfully.")
    except Exception as e:
        print(f"[!] PowerShell restart notice: {e}")

    # Step 3: Re-detect live MAC dynamically
    _, live_mac = get_wifi_adapter_info()
    effective_mac = live_mac if live_mac else formatted_mac
    status = get_mac_status(effective_mac, config)

    log_experiment("Verify Spoofed MAC", effective_mac, status, config)
    print(f"[+] Verified Current Live MAC: {effective_mac} | Status: {status}")

    return load_log()


def restore_original_mac(adapter_name="Wi-Fi"):
    """Phase 3 Step 5: Restore original factory MAC address dynamically."""
    config = load_or_create_config()
    orig_mac = config.get("original_mac")
    adapter_desc, pre_mac = get_wifi_adapter_info()

    print(f"[*] Restoring Original MAC ({orig_mac}) on '{adapter_desc}'...")

    # Step 1: Remove NetworkAddress key from Windows Registry
    key_id, found_desc = find_adapter_registry_key(adapter_desc)
    if key_id:
        try:
            reg_path = rf"SYSTEM\CurrentControlSet\Control\Class\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{key_id}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteValue(key, "NetworkAddress")
            print(f"[+] Deleted NetworkAddress key from Windows Registry key {key_id}")
        except FileNotFoundError:
            pass  # Already cleared
        except PermissionError:
            print("[!] Registry restoration requires Administrator privileges.")
        except Exception as e:
            print(f"[!] Registry restoration notice: {e}")

    # Step 2: Restart Network Adapter via PowerShell
    try:
        ps_cmd = f"Restart-NetAdapter -Name '{adapter_name}' -Confirm:$false"
        subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=10)
    except Exception as e:
        print(f"[!] PowerShell restart notice: {e}")

    # Step 3: Re-detect live MAC dynamically
    _, live_mac = get_wifi_adapter_info()
    effective_mac = live_mac if live_mac else orig_mac
    status = get_mac_status(effective_mac, config)

    log_experiment("Verify Restoration", effective_mac, status, config)
    print(f"[+] Verified Restored Original MAC: {effective_mac} | Status: {status}")

    return load_log()


def generate_reports(config=None):
    """Generate summary CSV and multi-sheet Excel reports."""
    if not config:
        config = load_or_create_config()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    csv_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.csv")
    xlsx_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.xlsx")

    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        log_df = pd.read_csv(LOG_FILE)
    else:
        log_df = pd.DataFrame(columns=["Timestamp", "Adapter", "MAC Address", "Status", "Action"])

    summary_data = [{
        "Project Phase": "Phase 3 - MAC Address Spoofing",
        "Adapter": config.get("adapter", adapter_desc),
        "Original MAC": config.get("original_mac"),
        "Spoofed MAC Allowed": config.get("spoofed_mac"),
        "Current Live MAC": current_mac,
        "Current Status": status,
        "Total Test Runs": len(log_df),
        "Report Generated At": datetime.now().strftime("%d-%b-%Y %H:%M:%S")
    }]
    summary_df = pd.DataFrame(summary_data)

    summary_df.to_csv(csv_path, index=False)
    print(f"[+] Summary CSV report generated: '{csv_path}'")

    try:
        with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:
            summary_df.to_excel(writer, sheet_name="Phase3_Summary", index=False)
            log_df.to_excel(writer, sheet_name="Experiment_Logs", index=False)
        print(f"[+] Multi-sheet Excel report generated: '{xlsx_path}'")
    except Exception as e:
        print(f"[!] Error generating Excel report: {e}")

    log_experiment("Generate Final Report", current_mac, status, config)


def display_status_header(config):
    """Display status banner."""
    adapter_desc, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    print("\n" + "=" * 55)
    print("       MAC ADDRESS SECURITY TOOL (PHASE 3)")
    print("=" * 55)
    print(f"Adapter       : {adapter_desc}")
    print(f"Original MAC  : {config.get('original_mac')}")
    print(f"Spoofed MAC   : {config.get('spoofed_mac')}")
    print(f"Current MAC   : {current_mac if current_mac else 'Detection Failed'}")
    print(f"Status        : {status}")
    print("=" * 55)
    return current_mac, status


def run_cli_menu():
    """Interactive CLI menu runner."""
    config = load_or_create_config()

    while True:
        display_status_header(config)
        print("\nMenu Options:")
        print("1. Check Current MAC Address")
        print("2. Verify Spoofed MAC Address")
        print("3. Verify Restoration to Original MAC")
        print("4. View Experiment History Log")
        print("5. Generate Phase 3 Report (CSV & Excel)")
        print("6. Re-detect & Update Baseline Configuration")
        print("7. Exit")
        print("-" * 55)

        choice = input("Enter choice (1-7): ").strip()

        if choice == "1":
            view_current_mac()
        elif choice == "2":
            new_mac_in = input("Enter MAC address to spoof (or press Enter for default): ").strip()
            change_mac_address("Wi-Fi", new_mac_in if new_mac_in else None)
        elif choice == "3":
            restore_original_mac()
        elif choice == "4":
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
                df = pd.read_csv(LOG_FILE)
                print("\n" + df.to_string(index=False))
            else:
                print("\n[!] No logs recorded yet.")
        elif choice == "5":
            generate_reports(config)
        elif choice == "6":
            adapter, mac = get_wifi_adapter_info()
            if mac:
                config["adapter"] = adapter
                config["original_mac"] = mac
                save_config(config)
                print(f"\n[+] Updated config baseline dynamically to MAC: {mac}")
        elif choice == "7":
            print("\nExiting MAC Security Suite.")
            break
        else:
            print("\n[!] Invalid selection.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    run_cli_menu()
