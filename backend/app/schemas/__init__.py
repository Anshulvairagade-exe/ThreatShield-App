"""Shared Pydantic schemas + consistent error envelope."""
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    opensearch: str
    zeroday_model: str


class ErrorResponse(BaseModel):
    detail: str
    code: str = "ERROR"
