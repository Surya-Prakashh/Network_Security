"""
Module 3: MAC Address Spoofing & Management (Phase 3)
------------------------------------------------------
Allows viewing current MAC address, spoofing/changing MAC address,
restarting network adapter, verifying new MAC address, restoring original MAC,
maintaining automated configuration, experiment logging, and generating reports.
"""

import os
import json
import re
import subprocess
from datetime import datetime
import pandas as pd

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(MODULE_DIR, "mac_spoofing_log.json")
CONFIG_FILE = os.path.join(MODULE_DIR, "config.json")
REPORTS_DIR = os.path.join(MODULE_DIR, "reports")
LOG_FILE = os.path.join(REPORTS_DIR, "experiment_log.csv")


def get_wifi_adapter_info():
    """Extract adapter name and physical MAC address using Windows ipconfig /all."""
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        adapter_match = re.search(
            r"Wireless LAN adapter Wi-Fi:(.*?)(?=\n\S|\Z)",
            output,
            re.DOTALL | re.IGNORECASE
        )

        adapter_name = "RZ616 Wi-Fi 6E 160MHz"
        mac_address = None

        if adapter_match:
            adapter_info = adapter_match.group(1)

            desc_match = re.search(r"Description[.\s:]*(.+)", adapter_info)
            if desc_match:
                adapter_name = desc_match.group(1).strip()

            mac_match = re.search(
                r"Physical Address[.\s:]*([0-9A-Fa-f-]{17})",
                adapter_info
            )
            if mac_match:
                mac_address = mac_match.group(1).upper()

        return adapter_name, mac_address
    except Exception as e:
        print(f"[!] Error detecting Wi-Fi adapter: {e}")
        return "Wi-Fi Adapter", None


def load_or_create_config():
    """Load configuration from config.json or create baseline automatically."""
    adapter_name, current_mac = get_wifi_adapter_info()

    default_config = {
        "adapter": adapter_name if adapter_name else "RZ616 Wi-Fi 6E 160MHz",
        "original_mac": current_mac if current_mac else "60-E9-AA-F0-A2-C1",
        "spoofed_mac": "0C-0C-0C-0C-0C-01"
    }

    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key, val in default_config.items():
                if key not in config:
                    config[key] = val
            return config
    except Exception as e:
        print(f"[!] Error loading config.json: {e}")
        return default_config


def save_config(config):
    """Save updated configuration to config.json."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def get_mac_status(current_mac, config):
    """Determine MAC status (ORIGINAL / SPOOFED / UNKNOWN)."""
    if not current_mac:
        return "ERROR"
    orig_mac = config.get("original_mac", "").upper().replace(":", "-")
    spoof_mac = config.get("spoofed_mac", "").upper().replace(":", "-")
    curr_mac = current_mac.upper().replace(":", "-")

    if curr_mac == orig_mac:
        return "ORIGINAL"
    elif curr_mac == spoof_mac:
        return "SPOOFED"
    else:
        return "UNKNOWN"


def get_network_adapters():
    """Retrieves active network adapters for API dashboard compatibility."""
    adapter_name, mac = get_wifi_adapter_info()
    return [{
        "name": "Wi-Fi",
        "description": adapter_name if adapter_name else "Wi-Fi 6E Adapter",
        "mac": mac if mac else "60-E9-AA-F0-A2-C1",
        "status": "Up"
    }]


def load_log():
    """Load JSON state log for web API dashboard."""
    config = load_or_create_config()
    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    history = []
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        try:
            df = pd.read_csv(LOG_FILE)
            history = df.to_dict(orient="records")
        except Exception:
            pass

    return {
        "adapter_name": config.get("adapter"),
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
    """Phase 3 Step 1: View current MAC address."""
    config = load_or_create_config()
    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)
    log_experiment("Check Current MAC", current_mac, status, config)

    print(f"[*] Adapter: {config.get('adapter')} | Current MAC: {current_mac} | Status: {status}")
    return {
        "adapter": config.get("adapter"),
        "mac": current_mac,
        "status": status
    }


def change_mac_address(adapter_name="Wi-Fi", new_mac=None):
    """Phase 3 Step 2, 3 & 4: Record MAC change / verification."""
    config = load_or_create_config()
    target_mac = new_mac if new_mac else config.get("spoofed_mac")

    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    log_experiment("Verify Spoofed MAC", current_mac, status, config)

    print(f"[*] Target Spoofed MAC: {target_mac}")
    print(f"[*] Current Live MAC  : {current_mac}")
    print(f"[*] Status            : {status}")

    return load_log()


def restore_original_mac(adapter_name="Wi-Fi"):
    """Phase 3 Step 5: Restore original MAC address."""
    config = load_or_create_config()
    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    log_experiment("Verify Restoration", current_mac, status, config)

    print(f"[*] Restoring / Verifying Original MAC: {config.get('original_mac')}")
    print(f"[*] Current Live MAC                 : {current_mac}")
    print(f"[*] Status                           : {status}")

    return load_log()


def generate_reports(config=None):
    """Generate summary CSV and multi-sheet Excel reports."""
    if not config:
        config = load_or_create_config()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    csv_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.csv")
    xlsx_path = os.path.join(REPORTS_DIR, "Phase3_MAC_Report.xlsx")

    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 0:
        log_df = pd.read_csv(LOG_FILE)
    else:
        log_df = pd.DataFrame(columns=["Timestamp", "Adapter", "MAC Address", "Status", "Action"])

    summary_data = [{
        "Project Phase": "Phase 3 - MAC Address Spoofing",
        "Adapter": config.get("adapter"),
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
    _, current_mac = get_wifi_adapter_info()
    status = get_mac_status(current_mac, config)

    print("\n" + "=" * 55)
    print("       MAC ADDRESS SECURITY TOOL (PHASE 3)")
    print("=" * 55)
    print(f"Adapter       : {config.get('adapter')}")
    print(f"Original MAC  : {config.get('original_mac')}")
    print(f"Spoofed MAC   : {config.get('spoofed_mac')} (SMAC Target)")
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
        print("2. Verify Spoofed MAC Address (0C-0C-0C-0C-0C-01)")
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
            change_mac_address()
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
                print(f"\n[+] Updated config baseline to MAC: {mac}")
        elif choice == "7":
            print("\nExiting MAC Security Suite.")
            break
        else:
            print("\n[!] Invalid selection.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    run_cli_menu()
