"""
SentinelHoneypot Launcher
=========================
Starts all honeypot services and the dashboard simultaneously.

Usage:
    python main.py              # Start all services
    python main.py --ssh-only   # Start SSH only
    python main.py --http-only  # Start HTTP only
    python main.py --dashboard  # Start dashboard only
"""

import asyncio
import threading
import argparse
import sys
import os

# Add dashboard to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "dashboard"))

from ssh_honeypot import start_ssh_honeypot
from http_honeypot import start_http_honeypot
from dashboard.app import run_dashboard


def print_banner():
    """Print the SentinelHoneypot startup banner."""
    banner = r"""
    ____            _   _       _       _   _               _   
   / ___|  ___  ___| |_(_)_ __ | | __ _| |_(_) ___  _ __   | |_ 
   \___ \ / _ \/ __| __| | '_ \| |/ _` | __| |/ _ \| '_ \  | __|
    ___) |  __/ (__| |_| | | | | | (_| | |_| | (_) | | | | | |_ 
   |____/ \___|\___|\__|_|_| |_|_|\__,_|\__|_|\___/|_| |_|  \__|

   Defensive Security Honeypot System v1.0
   github.com/Khaled880099/SentinelHoneypot
    """
    print(banner)


async def run_all():
    """Start SSH, HTTP, and Dashboard concurrently."""
    print_banner()
    print("[+] Starting SentinelHoneypot services...\n")

    # Start dashboard in a separate thread (Flask blocks)
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()

    # Give dashboard time to start
    await asyncio.sleep(1)

    # Start SSH and HTTP honeypots concurrently
    await asyncio.gather(
        start_ssh_honeypot(),
        start_http_honeypot()
    )


def main():
    parser = argparse.ArgumentParser(description="SentinelHoneypot - Multi-Service Honeypot")
    parser.add_argument("--ssh-only", action="store_true", help="Start SSH honeypot only")
    parser.add_argument("--http-only", action="store_true", help="Start HTTP honeypot only")
    parser.add_argument("--dashboard", action="store_true", help="Start dashboard only")
    args = parser.parse_args()

    try:
        if args.ssh_only:
            print_banner()
            print("[+] Starting SSH honeypot only...\n")
            asyncio.run(start_ssh_honeypot())

        elif args.http_only:
            print_banner()
            print("[+] Starting HTTP honeypot only...\n")
            asyncio.run(start_http_honeypot())

        elif args.dashboard:
            print_banner()
            print("[+] Starting dashboard only...\n")
            run_dashboard()

        else:
            # Start everything
            asyncio.run(run_all())

    except KeyboardInterrupt:
        print("\n[!] SentinelHoneypot shutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
