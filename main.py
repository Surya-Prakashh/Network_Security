"""
Main entry point for Phase 3 MAC Address Security & Verification Suite.
Invokes the interactive CLI menu from module3_mac_spoofing.mac_changer.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from module3_mac_spoofing.mac_changer import run_cli_menu

if __name__ == "__main__":
    run_cli_menu()