from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]
    API_V1_PREFIX: str = "/api/v1"
    # Unset by default (NVD's keyless public rate limit is what
    # NvdRateLimiter's defaults assume). When set, nvd_client.py adds it as
    # an `apiKey` request header, which raises NVD's rate limit -- not
    # wired up to anything higher yet this phase, just read defensively so
    # a future key just works.
    NVD_API_KEY: str | None = None

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
