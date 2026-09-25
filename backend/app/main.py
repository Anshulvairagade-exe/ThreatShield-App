"""ThreatShield FastAPI entrypoint — modular monolith, versioned API."""
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.core import logger
from app.db import Base  # noqa: F401 — ensure metadata object exists
import app.models  # noqa: F401 — register all ORM tables
from app.routers import alerts, assets, dashboard, detections, events, health, incidents, intake, mitre, pipeline, response, scenarios, threat_intel, ws, zeroday


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the zero-day pickle ONCE at startup — never per event.
    from app.ml.zeroday_adapter import get_adapter

    ok = get_adapter().load()
    logger.info("startup: zeroday model loaded=%s", ok)
    try:
        from app.db import SessionLocal
        from app.services.mitre_catalog import seed_catalog

        db = SessionLocal()
        try:
            n = seed_catalog(db)
            logger.info("startup: mitre catalog seeded=%s", n)
        finally:
            db.close()
    except Exception as e:
        logger.warning("startup: mitre seed skipped (%s)", e)
    yield


settings = get_settings()

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    start = time.time()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled error %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error", "code": "INTERNAL"})
    elapsed_ms = int((time.time() - start) * 1000)
    logger.info("%s %s -> %s (%sms) rid=%s", request.method, request.url.path, response.status_code, elapsed_ms, request_id)
    response.headers["X-Request-ID"] = request_id
    return response


app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(events.router, prefix="/api/v1", tags=["events"])
app.include_router(threat_intel.router, prefix="/api/v1", tags=["threat-intel"])
app.include_router(zeroday.router, prefix="/api/v1", tags=["zeroday-model"])
app.include_router(detections.router, prefix="/api/v1", tags=["detection"])
app.include_router(pipeline.router, prefix="/api/v1", tags=["pipeline"])
app.include_router(incidents.router, prefix="/api/v1", tags=["incidents"])
app.include_router(mitre.router, prefix="/api/v1", tags=["mitre"])
app.include_router(response.router, prefix="/api/v1", tags=["response"])
app.include_router(alerts.router, prefix="/api/v1", tags=["alerts"])
app.include_router(assets.router, prefix="/api/v1", tags=["assets"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["dashboard"])
app.include_router(scenarios.router, prefix="/api/v1", tags=["scenarios"])
app.include_router(ws.router, prefix="/api/v1", tags=["websocket"])
app.include_router(intake.router, prefix="/api/v1", tags=["intake"])


@app.get("/", tags=["root"])
def root():
    return {"service": settings.APP_NAME, "version": settings.APP_VERSION}
