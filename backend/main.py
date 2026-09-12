from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.core.config import settings
from backend.api.v1.routes_health import router as health_router
from backend.api.v1.routes_dashboard import router as dashboard_router
from backend.api.v1.routes_investigations import router as investigations_router
from backend.api.v1.routes_analyze import router as analyze_router
from backend.api.v1.routes_ml import router as ml_router
from backend.api.v1.routes_geo import router as geo_router
from backend.api.v1.routes_intel import router as intel_router
from backend.api.v1.routes_mitre import router as mitre_router
from backend.api.v1.routes_forensics import router as forensics_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_SUBTITLE,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers under /api/v1
app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(investigations_router, prefix=settings.API_V1_STR)
app.include_router(analyze_router, prefix=settings.API_V1_STR)
app.include_router(ml_router, prefix=settings.API_V1_STR)
app.include_router(geo_router, prefix=settings.API_V1_STR)
app.include_router(intel_router, prefix=settings.API_V1_STR)
app.include_router(mitre_router, prefix=settings.API_V1_STR)
app.include_router(forensics_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "version": settings.VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_STR
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
