<div align="center">

# LittleEye

<img src="littleye.png" alt="LittleEye" width="160">

**Configuration drift detection for Linux servers**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![SQLite](https://img.shields.io/badge/SQLite-aiosqlite-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![systemd](https://img.shields.io/badge/systemd-service-EE0000?style=flat-square&logo=linux&logoColor=white)](systemd/littleeye.service)

</div>

---

LittleEye is an agent-based configuration drift detection tool for Linux servers. Run the agent on any machine, point it at a central dashboard, and track every change that deviates from the known-good baseline: file contents, open ports, installed packages, running services, sudo users, and environment variables.

No SaaS. No cloud dependency. Self-hosted.

---

## What gets monitored

| Category | What is tracked |
|---|---|
| **Files** | Content diff of watched files (`/etc/ssh/sshd_config`, `/etc/passwd`, `/etc/sudoers`, ...) |
| **Ports** | Listening TCP/UDP ports appearing or disappearing |
| **Packages** | Installed packages added or removed |
| **Services** | systemd services starting or stopping |
| **Sudo Users** | Changes to sudoers membership |
| **Env Vars** | Process-level environment variable mutations |

Each finding is classified as `CRITICAL`, `WARNING`, or `INFO`, configurable per category.

---

## Stack

| Layer | Technology |
|---|---|
| Agent | Python 3.9+, `schedule`, `requests`, `PyYAML`, `Jinja2` |
| Dashboard | FastAPI, Uvicorn, Starlette |
| Database | SQLite via `aiosqlite` |
| Auth | HTTP Bearer Token per-agent |
| Alerting | Telegram Bot API, JSON Webhook (n8n compatible) |
| Deployment | Docker Compose, systemd |

---

## Quickstart

Spin up the dashboard and two simulated agents locally:

```bash
docker compose up -d
```

Dashboard available at **http://localhost:8000**.

Trigger an immediate check:

```bash
docker exec littleeye-agent-web python3 -m littleeye.agent.cli --config /app/config.yaml check
docker exec littleeye-agent-db  python3 -m littleeye.agent.cli --config /app/config.yaml check
```

---

## Installing the agent on a remote server

Create a token in **Settings -> Agent Access Tokens**, then run on the target machine:

```bash
curl -sSL https://raw.githubusercontent.com/synaps3s/littleeye/main/install_agent.sh | \
  sudo bash -s -- --url http://<dashboard>:8000 --token <token>
```

The script installs dependencies, clones the repo to `/opt/littleeye`, writes the config, takes the baseline snapshot, and registers the systemd service.

### Manual setup

```bash
git clone https://github.com/synaps3s/littleeye.git /opt/littleeye
cd /opt/littleeye
python3 -m venv venv
./venv/bin/pip install -r requirements.agent.txt

cp config.example.yaml /etc/littleeye/config.yaml
# set dashboard_url and agent_token

./venv/bin/python3 -m littleeye.agent.cli --config /etc/littleeye/config.yaml init
./venv/bin/python3 -m littleeye.agent.cli --config /etc/littleeye/config.yaml daemon

# or as a systemd service
cp systemd/littleeye.service /etc/systemd/system/
systemctl enable --now littleeye
```

---

## CLI

```
python3 -m littleeye.agent.cli [OPTIONS] COMMAND

  init    Take the initial baseline snapshot
  check   Run a drift check and push results to the dashboard
  report  Render the last diff as a standalone HTML file
  daemon  Start the background scheduler

Options:
  -c, --config PATH   Path to config.yaml
  -v, --verbose       Enable debug logging
```

---

## Configuration

```yaml
# /etc/littleeye/config.yaml

check_interval_minutes: 5
dashboard_url: "http://<dashboard>:8000"
agent_token:   "<token>"

baseline_dir: "data/baselines"
report_dir:   "data/reports"

severity_thresholds:
  files:      critical
  sudo_users: critical
  ports:      warning
  services:   warning
  packages:   info
  env_vars:   info

watched_files:
  - /etc/ssh/sshd_config
  - /etc/passwd
  - /etc/sudoers
  - /etc/hosts
  - /etc/fstab
  - /etc/crontab
```

Environment variables override config values with the prefix `LITTLEEYE_`:

```bash
LITTLEEYE_DASHBOARD_URL=http://10.0.0.1:8000
LITTLEEYE_AGENT_TOKEN=my-token
LITTLEEYE_CHECK_INTERVAL=10
```

---

## Networking

Agents and dashboard do not need to be on the same network. Any HTTP reachability works.

**Tailscale / WireGuard** - recommended for private deployments. Add both servers to the same network, set `dashboard_url` to the private IP. No open firewall ports needed.

**Nginx + Basic Auth** - if you protect the UI with HTTP Basic Auth, exclude the agent API path so agents can still push reports:

```nginx
location / {
    auth_basic "LittleEye";
    auth_basic_user_file /etc/nginx/.htpasswd;
    proxy_pass http://127.0.0.1:8000;
}

location /api/ {
    auth_basic off;
    proxy_pass http://127.0.0.1:8000;
}
```

**Cloudflare Tunnel + Access** - add a Bypass policy for `/api/agent/report` so agent payloads are not blocked by the SSO screen.

---

## Project layout

```
littleeye/
├── agent/
│   ├── cli.py           entrypoint
│   ├── config.py        configuration loader
│   ├── snapshot.py      system state collector
│   ├── diff.py          baseline comparison
│   ├── scheduler.py     background daemon
│   ├── notify.py        Telegram / Webhook alerts
│   ├── report.py        local HTML report writer
│   └── templates/
│       └── report.html.j2
├── dashboard/
│   ├── main.py          FastAPI application
│   ├── api.py           agent REST endpoint
│   ├── db.py            SQLite access layer
│   ├── auth.py          Bearer token middleware
│   ├── settings.py      dashboard configuration
│   ├── static/style.css
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── servers.html
│       ├── server.html
│       └── settings.html
├── tests/
├── systemd/littleeye.service
├── install_agent.sh
├── docker-compose.yml
└── config.example.yaml
```

---

## Tests

```bash
PYTHONPATH=. pytest
```
