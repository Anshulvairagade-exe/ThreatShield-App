"""ThreatShield global settings — env-driven, no hardcoded secrets."""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "ThreatShield"
    APP_VERSION: str = "0.1.0-phase1"
    ENVIRONMENT: str = "local"

    DATABASE_URL: str = "postgresql+psycopg2://threatshield:threatshield@localhost:5432/threatshield"
    OPENSEARCH_URL: str = "http://localhost:9200"

    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    LOG_LEVEL: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
