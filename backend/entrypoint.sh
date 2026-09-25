#!/bin/sh
# Production entrypoint: wait for Postgres, run migrations, start API.
set -e

python - <<'EOF'
import os, time
url = os.environ.get("DATABASE_URL", "")
if url.startswith("postgresql"):
    from sqlalchemy import create_engine, text
    for i in range(60):
        try:
            with create_engine(url).connect() as c:
                c.execute(text("SELECT 1"))
            print("database reachable")
            break
        except Exception as e:
            print(f"waiting for database... ({e})")
            time.sleep(2)
    else:
        raise SystemExit("database never became reachable")
EOF

alembic upgrade head

exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers "${UVICORN_WORKERS:-2}"
