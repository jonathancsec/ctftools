"""Application configuration.

Every value can be overridden with an environment variable so the same code
runs locally (inline job queue) and in Docker (Redis/RQ queue).
"""

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# Keep local runtime data at the repository root. Docker overrides this with
# DATA_DIR=/data.
DEFAULT_DATA_DIR = BASE_DIR.parent / "data"


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")

    DATA_DIR = Path(os.environ.get("DATA_DIR", DEFAULT_DATA_DIR))
    UPLOAD_DIR = DATA_DIR / "uploads"
    ARTIFACT_DIR = DATA_DIR / "artifacts"
    DATABASE = Path(os.environ.get("DATABASE_PATH", DATA_DIR / "forensics.db"))

    MAX_CONTENT_LENGTH = _env_int("MAX_UPLOAD_BYTES", 32 * 1024 * 1024)
    MAX_ARTIFACT_BYTES = _env_int("MAX_ARTIFACT_BYTES", 5 * 1024 * 1024)
    TOOL_TIMEOUT = _env_int("TOOL_TIMEOUT", 60)
    TOOL_OUTPUT_LIMIT = _env_int("TOOL_OUTPUT_LIMIT", 100_000)
    RETENTION_HOURS = _env_int("RETENTION_HOURS", 24)
    MAX_STRING_LINES = _env_int("MAX_STRING_LINES", 500)

    # Abuse controls for a shared or public instance.
    UPLOAD_LIMIT_PER_HOUR = _env_int("UPLOAD_LIMIT_PER_HOUR", 20)
    MAX_PENDING_JOBS = _env_int("MAX_PENDING_JOBS", 25)
    JOB_STALE_HOURS = _env_int("JOB_STALE_HOURS", 2)
    TRUST_PROXY = os.environ.get("TRUST_PROXY", "0").lower() in {"1", "true", "yes"}
    COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
    SESSION_COOKIE_SECURE = COOKIE_SECURE
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # inline: run jobs in a background thread (development, Windows-friendly)
    # sync:   run jobs inside the request (tests)
    # rq:     hand jobs to an RQ worker backed by Redis (Docker)
    QUEUE_MODE = os.environ.get("QUEUE_MODE", "inline")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    RQ_QUEUE = os.environ.get("RQ_QUEUE", "forensics")

    JSON_SORT_KEYS = False
