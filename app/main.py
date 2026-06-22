"""AegisScan application entrypoint: API + served single-page frontend."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import get_settings
from .database import init_db
from .engine.runner import ENGINE_VERSION, CATEGORIES
from .routers import auth, dashboard, domains, scans
from .scoring import CATEGORY_WEIGHTS, GRADE_BANDS, STATUS_CREDIT

settings = get_settings()

# Optional Sentry (no-op when AEGIS_SENTRY_DSN is empty). SDK pinned to a version
# that does not crash on Python 3.13 - one of PostureScan's documented bugs.
if settings.sentry_dsn:
    import sentry_sdk

    sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.env, traces_sample_rate=0.1)

app = FastAPI(
    title="AegisScan API",
    version=__version__,
    description=(
        "External web security posture scanner. Submit a hostname, receive a graded "
        "report with concrete fixes and OWASP mappings. Passive and read-only."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=settings.cors_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    # For SQLite / quick starts. Postgres deployments run Alembic via a pre-deploy hook.
    init_db()


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "version": __version__, "engine": ENGINE_VERSION, "env": settings.env}


@app.get("/api/meta", tags=["meta"])
def meta() -> dict:
    """Self-documenting scoring rubric and category list."""
    return {
        "engine_version": ENGINE_VERSION,
        "categories": [{"key": k, "label": label} for k, label, _ in CATEGORIES],
        "category_weights": CATEGORY_WEIGHTS,
        "status_credit": STATUS_CREDIT,
        "grade_bands": [{"min_score": s, "grade": g} for s, g in GRADE_BANDS],
    }


app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(dashboard.router)
app.include_router(domains.router)

# Serve the SPA last so explicit API routes and /docs take precedence.
_web_dir = Path(__file__).resolve().parent.parent / "web"
if _web_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_web_dir), html=True), name="web")
