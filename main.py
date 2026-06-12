
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from config import settings
from upload import router as upload_router
from audit import router as audit_router
from logger import get_logger, RequestLogger

logger = get_logger(__name__)


app = FastAPI(title=settings.app_name, version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
    logger.info("Root endpoint accessed")
    RequestLogger.log_request("GET", "/", 200)
    return JSONResponse(
        {
            "message": "Welcome to Firewall Audit Backend API",
            "version": settings.app_version,
            "status": "running",
            "username": settings.username,
            "email": settings.email
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    logger.debug("Health check requested")
    RequestLogger.log_request("GET", "/health", 200)
    return JSONResponse({"status": "healthy"})

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Firewall Audit Backend")
    logger.info(f"App version: {settings.app_version}")
    logger.info("Running on http://0.0.0.0:8000")
    try:
        uvicorn.run(app, host="0.0.0.0", port=8000)
    except KeyboardInterrupt:
        logger.info("Application shutdown requested")
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        raise
