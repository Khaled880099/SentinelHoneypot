"""
Log Collector Module
====================
Centralized JSONL logging with real-time event broadcasting.
All honeypot services write events through this collector.
"""

import json
import os
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

# Try to import SocketIO for real-time dashboard updates
try:
    from flask_socketio import SocketIO
    _socketio = None
except ImportError:
    SocketIO = None
    _socketio = None


class LogCollector:
    """Thread-safe JSONL log collector with in-memory stats."""

    def __init__(self, log_file="logs/honeypot.jsonl"):
        self.log_file = log_file
        self.lock = threading.Lock()
        self.stats = {
            "total_sessions": 0,
            "total_attacks": 0,
            "unique_ips": set(),
            "commands_captured": 0,
            "passwords_attempted": [],
            "usernames_attempted": [],
            "ip_activity": defaultdict(lambda: {"attempts": 0, "commands": [], "first_seen": None, "last_seen": None}),
            "recent_events": deque(maxlen=500)
        }
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def set_socketio(self, socketio_instance):
        """Attach SocketIO instance for real-time dashboard pushes."""
        global _socketio
        _socketio = socketio_instance

    def log_event(self, event_type, **data):
        """Write a structured event to the JSONL log."""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "type": event_type,
            **data
        }

        with self.lock:
            # Write to file
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")

            # Update in-memory stats
            self._update_stats(event)
            self.stats["recent_events"].append(event)

            # Broadcast to dashboard if connected
            if _socketio:
                try:
                    _socketio.emit("new_event", event)
                except Exception:
                    pass

        return event

    def _update_stats(self, event):
        """Update internal statistics from an event."""
        etype = event.get("type")
        ip = event.get("source_ip", "unknown")

        self.stats["unique_ips"].add(ip)
        now = time.time()

        if self.stats["ip_activity"][ip]["first_seen"] is None:
            self.stats["ip_activity"][ip]["first_seen"] = now
        self.stats["ip_activity"][ip]["last_seen"] = now

        if etype == "ssh_session":
            self.stats["total_sessions"] += 1
            self.stats["ip_activity"][ip]["attempts"] += 1
            if event.get("password"):
                self.stats["passwords_attempted"].append(event["password"])
            if event.get("username"):
                self.stats["usernames_attempted"].append(event["username"])

        elif etype == "command_captured":
            self.stats["commands_captured"] += 1
            self.stats["ip_activity"][ip]["commands"].append(event.get("command", ""))

        elif etype == "http_request":
            self.stats["total_attacks"] += 1
            self.stats["ip_activity"][ip]["attempts"] += 1

        elif etype == "ftp_attempt":
            self.stats["total_attacks"] += 1
            self.stats["ip_activity"][ip]["attempts"] += 1

    def get_stats(self):
        """Return current statistics snapshot."""
        with self.lock:
            return {
                "total_sessions": self.stats["total_sessions"],
                "total_attacks": self.stats["total_attacks"],
                "unique_ips": len(self.stats["unique_ips"]),
                "commands_captured": self.stats["commands_captured"],
                "top_passwords": self._top_n(self.stats["passwords_attempted"], 10),
                "top_usernames": self._top_n(self.stats["usernames_attempted"], 10),
                "top_ips": sorted(
                    [(ip, data["attempts"]) for ip, data in self.stats["ip_activity"].items()],
                    key=lambda x: x[1], reverse=True
                )[:10],
                "recent_events": list(self.stats["recent_events"])[-50:]
            }

    @staticmethod
    def _top_n(items, n):
        from collections import Counter
        return Counter(items).most_common(n)


# Global singleton instance
collector = LogCollector()
