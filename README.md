# ThreatShield — SOC Platform

Live portfolio demo (frontend-only, dummy data): **https://threatshield.anshulvairagade.dev**

Full-stack Security Operations Center: React SOC dashboard + FastAPI detection backend with threat-intel enrichment, zero-day ML anomaly detection, MITRE ATT&CK mapping, incident correlation, and guided response actions.

## What it does

| View | Description |
|---|---|
| Dashboard | SOC KPIs, alert activity, severity mix, active incidents, detection sources |
| Alerts | Triage queue with severity/source/status filters, alert drawer with signals + MITRE + recommended actions |
| Events | Telemetry explorer (Wazuh / Zeek / simulator) with structured event drawer |
| Assets | Monitored endpoints/servers with risk scores, per-asset alerts + events |
| Incidents | Correlated cases, click through to Investigation Workspace |
| Investigation | Overview / Timeline / Entities + attack graph / MITRE / Evidence / Response tabs, assign + status workflow |
| Threat Intel | IOC lookup (IP, domain, URL, hashes) with reputation, confidence, sources, live verdict on repo miss |
| MITRE ATT&CK | Technique coverage matrix across 12 tactics, per-technique detail |
| Response | Approval-gated containment actions (isolate / block / disable) + revert, simulation mode default |
| Audit | Every significant operation, actor, target, result |
| Digital Twin | Enterprise topology from live asset state |
| Attack Replay | `SCN-APT-01` simulation lab: Windows ingress → C2 beacon → Ubuntu lateral pivot, synced with twin |

Detection layers: **IOC** (threat-intel feeds) · **RULE** (behavioral) · **ZERODAY** (ML anomaly).

Threat-intel feeds: AbuseIPDB, AlienVault OTX, AbuseCH (URLhaus/MalwareBazaar), VirusTotal enrichment. Collectors degrade gracefully without API keys.

## Tech stack

- **Frontend:** React 19 + Vite 6, `frontend/src/{pages,components,services,hooks,context}`
- **Backend:** FastAPI + Uvicorn, SQLAlchemy ORM + Alembic migrations, Pydantic v2
- **Data:** PostgreSQL 16 (prod) / SQLite (local dev), OpenSearch (event search, with in-memory fallback via `THREATSHIELD_EVENT_STORE=memory`)
- **ML:** scikit-learn zero-day anomaly adapter (`zero_day_model_package/`)
- **Infra:** Docker + `docker-compose.yml` (local) / `docker-compose.prod.yml` (prod overlay), Nginx static frontend serving
- **Telemetry in:** Wazuh manager + Zeek + simulator (`backend/docs/wazuh.md`, `backend/docs/zeek.md`)

## Repo layout

```
frontend/            # Vite React app (portfolio-deployed)
backend/             # FastAPI app, Alembic, tests, seed.py
threat_intel/        # Standalone TI lookup API (legacy :8001 proxy)
zero_day_model_package/
docker-compose.yml       # local: postgres + opensearch + backend + frontend
docker-compose.prod.yml  # prod overlay: no exposed DB ports
DEPLOY.md            # cloud runbook (AWS EC2/RDS/OpenSearch, TLS, Wazuh)
netlify.toml / frontend/vercel.json  # static hosting configs
```

Backend code is untouched by the demo deploy — all portfolio changes are `frontend/` only.

## Run locally

```bash
# full stack (needs Docker)
cp backend/.env.example backend/.env
docker compose up --build
# API: http://localhost:8000/api/v1/health
# UI:  http://localhost:5173

# backend only, no docker
cd backend && pip install -r requirements.txt
DATABASE_URL="sqlite:///./local.db" uvicorn app.main:app --reload --port 8000

# frontend only (uses backend if set, demo data if not)
cd frontend && npm install && npm run dev
```

Tests: `cd backend && python -m pytest tests/ -v`
Migrations: `cd backend && alembic upgrade head`
Seed demo data: `DATABASE_URL=<url> THREATSHIELD_EVENT_STORE=memory python backend/seed.py`

Env (see `backend/.env.example`): `DATABASE_URL`, `OPENSEARCH_URL`, `CORS_ORIGINS`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `ABUSECH_AUTH_KEY`, `VT_API_KEY`, `VITE_API_BASE_URL` (baked at frontend build time).

## Demo mode (how the live site works)

If `VITE_API_BASE_URL` is **unset**, the UI runs on curated dummy data in `frontend/src/services/mockData/mockBackend.js` — 8 alerts, 8 events, 5 assets, 3 incidents with full investigations, MITRE matrix, IOC verdicts, audit log. TopBar shows `Demo data · DEMO`.

Set `VITE_API_BASE_URL=https://your-api...` at build time to connect the live backend — no code change needed. See `DEPLOY.md` for the production path (RDS Postgres, OpenSearch, ALB + ACM TLS, Wazuh intake).

## Deploy

**Portfolio (free, current live site):** Netlify, Base `frontend`, Build `npm run build`, Publish `dist`, no env vars. Custom domain via Name.com CNAME `threatshield → threatshieldsoc.netlify.app`, auto TLS. Vercel equivalent: Root `frontend`, Framework Vite.

**Production (full stack):** `docker compose -f docker-compose.prod.yml up --build -d` on EC2/ECS with RDS PostgreSQL 16 — full checklist in `DEPLOY.md`.

## License

MIT — © 2026 Anshul Vairagade. See `LICENSE`.
