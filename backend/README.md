# ThreatShield Backend — Phase 1

Modular monolithic FastAPI backend. Phase 1: skeleton + PostgreSQL + Alembic + health + Docker.

## Run (docker)

```bash
cp backend/.env.example backend/.env
docker compose up --build
# API: http://localhost:8000/api/v1/health
# Frontend: http://localhost:5173
```

## Run (local, no docker)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
DATABASE_URL="sqlite:///./local.db" uvicorn app.main:app --reload --port 8000
```

## Tests

```bash
cd backend
pip install -r requirements.txt
python3 -m pytest tests/ -v
```

## Migrations

```bash
cd backend
alembic upgrade head
alembic revision --autogenerate -m "describe change"
```
