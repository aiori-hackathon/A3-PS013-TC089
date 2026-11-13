"""FastAPI application entrypoint for VIGILANCE digital forensics platform."""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.config import settings
from app.database import init_db
from app.api import (
    investigations,
    evidence,
    events,
    analysis,
    reports,
    triage,
    demo,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager: ensure storage directories and database initialization."""
    # 1. Create storage directories
    evidence_dir = Path(settings.EVIDENCE_STORAGE_PATH)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    reports_dir = Path(settings.REPORTS_PATH)
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 2. Initialize database tables
    init_db()

    print(f"[VIGILANCE] Forensic platform initialized.")
    print(f"[VIGILANCE] Evidence Storage : {evidence_dir.resolve()}")
    print(f"[VIGILANCE] Reports Directory: {reports_dir.resolve()}")
    print(f"[VIGILANCE] Database URL     : {settings.DATABASE_URL}")

    yield

    print("[VIGILANCE] Shutting down forensic platform.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Full-fidelity digital forensics triage and timeline correlation platform.",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",  # Permissive for local hackathon demo integrations
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers under /api prefix
app.include_router(investigations.router, prefix="/api")
app.include_router(evidence.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(triage.router, prefix="/api")
app.include_router(demo.router, prefix="/api")


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
def health_check():
    """Health check endpoint verifying backend service operation."""
    return {
        "status": "HEALTHY",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "storage_ready": Path(settings.EVIDENCE_STORAGE_PATH).exists(),
        "database_ready": True,
    }


FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"

if FRONTEND_DIST.is_dir():
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend(full_path: str):
        """Serve the built SPA and fall back to index.html for client-side routes."""
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not Found")

        dist_root = FRONTEND_DIST.resolve()
        requested = (dist_root / full_path).resolve()
        if requested == dist_root or dist_root in requested.parents:
            if requested.is_file():
                return FileResponse(requested)

        return FileResponse(dist_root / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
