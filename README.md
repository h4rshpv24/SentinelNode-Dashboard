# SentinelNode Dashboard

A lightweight SIEM-style dashboard for monitoring a **Suricata** IDS sensor. SentinelNode pulls alerts and network events from a Linux sensor over SSH, normalizes them into incidents stored in SQLite, and surfaces them through a FastAPI backend, a React web dashboard, and a PySide6 desktop client — with optional **Discord** notifications for high-severity alerts.

## Features
- Collects Suricata `eve.json` alerts, DNS, HTTP, TLS and flow events from a remote sensor via SSH
- Incident database with severity, status and per-incident telemetry (SQLite)
- REST API (FastAPI): `/api/summary`, `/api/incidents`, `/api/incidents/{id}/telemetry`, `/api/events`, `/api/server`, `/api/collect`
- React + Vite web dashboard (`frontend/`)
- PySide6 desktop dashboard (`main.py`)
- Discord webhook alerts for critical/high incidents

## Setup
```bash
pip install -r requirements.txt
cp .env.example .env        # then add your Discord webhook URL
```
Edit `SERVER_USERNAME` and `SERVER_HOST` in `main.py` to point to your Suricata sensor (SSH key auth required).

### Run the API
```bash
uvicorn api:app --reload
```
### Run the web UI
```bash
cd frontend && npm install && npm run dev
```
### Run the desktop client
```bash
python main.py
```

`rules/test-alert.rules` is a Suricata rule that triggers a test alert on requests to `/sentinelnode-test`.

## Security notes
Never commit `.env` or the `.db` files — they are git-ignored. Use only on networks you own or are authorized to monitor.
