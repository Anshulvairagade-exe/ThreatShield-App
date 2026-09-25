# ThreatShield — Cloud Deployment Runbook

## 0. Straight answer on SQLite vs PostgreSQL

- **Application code is already database-agnostic**: all access goes through
  SQLAlchemy ORM (no raw SQL anywhere), migrations via Alembic, JSON columns
  and constraints that behave the same on SQLite and PostgreSQL.
- **SQLite was only ever the local-dev stand-in** (`local.db`, test files).
  Both compose files run **PostgreSQL 16** as the real store.
- **Caveat**: no machine in this loop has run the stack against a live
  PostgreSQL yet (no Docker / PG server here). Before calling it production,
  run the validation in §4 — it exercises migrations, seed, and the full
  pipeline against the real database.

## 1. What you need in the cloud (AWS example)

| Piece | Choice |
|---|---|
| API + workers | EC2 (Docker) running `docker-compose.prod.yml`, or ECS service from `backend/Dockerfile` |
| Database | **RDS PostgreSQL 16** (preferred) or the compose `postgres` service with an EBS-backed volume + snapshots |
| Event search | Compose `opensearch` single node (fine to start); move to Amazon OpenSearch Service when EPS grows |
| Frontend | `frontend/Dockerfile.prod` static build (behind ALB + ACM TLS), or S3 + CloudFront |
| TLS | ALB / CloudFront with ACM certificate; backend stays HTTP behind the LB |
| Wazuh | Existing manager (`3.104.196.100`); agents already enrolled. Open backend SG **only** to the manager if it POSTs intake, or let the backend poll — no inbound agent ports needed on ThreatShield |

## 2. Environment (never commit secrets)

`backend/.env` on the host (same keys as `.env.example`):

```bash
ENVIRONMENT=prod
DATABASE_URL=postgresql+psycopg2://threatshield:<STRONG-PW>@<rds-or-postgres-host>:5432/threatshield
OPENSEARCH_URL=http://opensearch:9200
CORS_ORIGINS=https://soc.example.com          # exact dashboard origin, no localhost
LOG_LEVEL=INFO
UVICORN_WORKERS=2
ABUSEIPDB_API_KEY=<key>                        # optional; collectors degrade without keys
OTX_API_KEY=<key>
ABUSECH_AUTH_KEY=<key>
```

Compose-level (shell env or CI secrets):

```bash
POSTGRES_PASSWORD=<STRONG-PW>       # only for compose-managed postgres
VITE_API_BASE_URL=https://api.example.com   # baked into the frontend build
CORS_ORIGINS=https://soc.example.com
DATABASE_URL=...                    # RDS endpoint in real deployments
```

## 3. Deploy (single EC2, fastest path)

```bash
# 1. Instance: Amazon Linux 2023 / Ubuntu 22.04, Docker + compose plugin, SG: 80/443 in, 8000 only from LB
# 2. Copy repo, write backend/.env per §2
docker compose -f docker-compose.prod.yml up --build -d
# entrypoint waits for Postgres, runs `alembic upgrade head`, starts uvicorn (non-root user)

# 3. (Optional) seed demo data — skip for a clean SOC, or run once:
docker compose -f docker-compose.prod.yml exec backend python /code/../backend/seed.py
# simpler: DATABASE_URL=<prod-url> python backend/seed.py from any host that can reach the DB

# 4. Check health
curl https://api.example.com/api/v1/health
```

## 4. Validate against real PostgreSQL (required before prod sign-off)

From any host with Docker or Python + network access to the database:

```bash
# A. Migrations apply cleanly on PG
DATABASE_URL='postgresql+psycopg2://threatshield:<pw>@<host>:5432/threatshield' \
  alembic -c backend/alembic.ini upgrade head

# B. Seed + full pipeline through REAL Postgres (migrates nothing, uses live models + TI logic)
DATABASE_URL='postgresql+psycopg2://...' THREATSHIELD_EVENT_STORE=memory \
  python backend/seed.py
# expect: 3 seeded events → detections → ONE incident, risk recomputed

# C. API smoke
curl $API/api/v1/dashboard | head -c 300
curl -X POST $API/api/v1/scenarios/SCN-APT-01/start -H 'Content-Type: application/json' -d '{}'
```

Known PG-compat audit (code review, all clear):

- No raw SQL / no `LIKE` (SQLite `LIKE` is case-insensitive, PG is not — unused).
- `users`, `type`, `metadata` identifiers are non-reserved in PG.
- JSON defaults (`'[]'`, `'{}'`) are unknown-type literals, coerced by PG.
- Naive UTC datetimes used consistently; comparisons are exact-match/range on one column family.
- `db.merge()` upsert and UUID-string PKs are portable.

## 5. Production checklist

- [ ] §4 A–C green against the real database
- [ ] `CORS_ORIGINS` set to the dashboard origin only
- [ ] TLS on ALB/CloudFront; backend not directly exposed (SG: 8000 from LB only)
- [ ] `POSTGRES_PASSWORD` / API keys in Secrets Manager or instance env, never in git
- [ ] Backups: RDS automated snapshots (or EBS snapshots of `pgdata`); snapshot OpenSearch `osdata` before upgrades
- [ ] `UVICORN_WORKERS` sized to vCPU (2× vCPU + 1 rule of thumb, start with 2–4)
- [ ] Wazuh intake path tested end-to-end (agent event → manager → `/intake/wazuh` → incident)
- [ ] Frontend rebuilt with the public `VITE_API_BASE_URL` (it is baked at build time)
- [ ] `docker compose up` dev file left for local work; prod runs only `docker-compose.prod.yml`
