"""
Main FastAPI Application Entrypoint
Password Strength Analyzer & Security Suggestion Tool

SECURITY POLICY:
1. No passwords logged in access logs or stdout.
2. In-memory transient analysis only.
3. CORS configured.
4. Security response headers applied (X-Frame-Options, X-Content-Type-Options, etc.).
"""

import logging
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database import init_db, seed_demo_analytics_if_empty
from backend.routes.analyzer_routes import router as analyzer_router
from backend.routes.generator_routes import router as generator_router
from backend.routes.dashboard_routes import router as dashboard_router
from backend.routes.policy_routes import router as policy_router
from backend.routes.hashing_routes import router as hashing_router

# Configure safe logging that explicitly suppresses payload logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("password_analyzer")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing privacy-safe SQLite database...")
    init_db()
    seed_demo_analytics_if_empty()
    logger.info("Password Strength Analyzer backend is ready.")
    yield

app = FastAPI(
    title="Password Strength Analyzer & Security Tool",
    description="Privacy-preserving defensive cybersecurity engine for evaluating password strength and hygiene.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Custom Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response

# Register API routers
app.include_router(analyzer_router)
app.include_router(generator_router)
app.include_router(dashboard_router)
app.include_router(policy_router)
app.include_router(hashing_router)

# Mount frontend static directory
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/")
    def serve_frontend_root():
        return FileResponse(str(frontend_dir / "index.html"))

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Password Strength Analyzer & Security Tool",
        "privacy": "Zero Plaintext Password Retention"
    }
