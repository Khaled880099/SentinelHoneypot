"""
SentinelHoneypot Configuration
==============================
Edit these settings to customize your honeypot deployment.
"""

import os

# ── Network Settings ──────────────────────────────────────────
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))
FTP_PORT = 2121          # Fake FTP port
BIND_HOST = "0.0.0.0"    # Listen on all interfaces

# ── Logging ─────────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "honeypot.jsonl")
SESSION_TIMEOUT = 300    # Seconds before idle session is dropped

# ── Honeypot Behavior ───────────────────────────────────────────
FAKE_HOSTNAME = "prod-server-01"
FAKE_OS = "Linux 5.15.0-91-generic"
MAX_AUTH_ATTEMPTS = 3    # Fake auth attempts before "success" or lockout
INTERACTIVE_SHELL = True # Enable fake interactive shell for SSH

# ── Dashboard ───────────────────────────────────────────────────
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = 5000
DASHBOARD_SECRET_KEY = "sentinel-honeypot-secret-key-change-in-production"

# ── Alert Thresholds ────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5      # Attempts from same IP
BRUTE_FORCE_WINDOW = 300       # Seconds (5 minutes)
SUSPICIOUS_COMMANDS = [
    "wget", "curl", "nc", "netcat", "python", "perl",
    "bash -i", "/bin/sh", "rm -rf", "mkfs", "dd if=",
    "base64", "eval", "exec", "system(", "pty.spawn",
    "chmod 777", "chmod +x", ".sh", ".py", ".pl"
]
