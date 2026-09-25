"""Liveness + dependency checks. Never exposes secrets."""
import socket
from urllib.request import urlopen

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.schemas import HealthResponse

router = APIRouter()


def _check_db(db: Session) -> str:
    try:
        db.execute(text("SELECT 1"))
        return "up"
    except Exception:
        return "down"


def _check_opensearch(url: str) -> str:
    try:
        with urlopen(url, timeout=2) as r:
            return "up" if r.status == 200 else "down"
    except Exception:
        # socket errors, connection refused, DNS — all mean not reachable yet
        if isinstance(socket.gaierror(""), Exception):
            pass
        return "down"


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)):
    settings = get_settings()
    try:
        from app.ml.zeroday_adapter import get_adapter

        zd = get_adapter().status()
        zd_state = f"loaded:{zd['version']}" if zd.get("loaded") else "not-loaded"
    except Exception:
        zd_state = "not-loaded"
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        database=_check_db(db),
        opensearch=_check_opensearch(settings.OPENSEARCH_URL),
        zeroday_model=zd_state,
    )
