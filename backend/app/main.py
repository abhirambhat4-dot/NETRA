from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.assets import router as assets_router
from app.api.authorizations import router as authorizations_router
from app.api.collector import router as collector_router
from app.api.cyber_memory import router as cyber_memory_router
from app.api.containments import router as containments_router
from app.api.decisions import router as decisions_router
from app.api.dashboard import router as dashboard_router
from app.api.events import router as events_router
from app.api.health import router as health_router
from app.api.incidents import router as incidents_router
from app.api.threat_intelligence import router as threat_intelligence_router
from app.core.config import get_settings
from app.db.session import engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()

    application = FastAPI(
        title=settings.app_name,
        description=settings.app_description,
        version=settings.app_version,
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(health_router, prefix="/api")
    application.include_router(auth_router, prefix="/api")
    application.include_router(dashboard_router, prefix="/api")
    application.include_router(events_router, prefix="/api")
    application.include_router(collector_router, prefix="/api")
    application.include_router(incidents_router, prefix="/api")
    application.include_router(decisions_router, prefix="/api")
    application.include_router(authorizations_router, prefix="/api")
    application.include_router(containments_router, prefix="/api")
    application.include_router(assets_router, prefix="/api")
    application.include_router(threat_intelligence_router, prefix="/api")
    application.include_router(cyber_memory_router, prefix="/api")

    return application


app = create_app()
