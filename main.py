
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from config import settings
from upload import router as upload_router
from audit import router as audit_router
from logger import get_logger, RequestLogger

logger = get_logger(__name__)


app = FastAPI(title=settings.app_name, version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")


# ---------------------------------------------------------------------------
# Global error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Return a consistent JSON body for all HTTP errors (404, 405, etc.)."""
    logger.warning(f"HTTP {exc.status_code} on {request.method} {request.url.path}: {exc.detail}")
    RequestLogger.log_error(request.method, str(request.url.path), str(exc.detail), exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "code": exc.status_code,
            "message": exc.detail,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return a structured 422 response for Pydantic / FastAPI validation failures."""
    errors = [
        {
            "field": " -> ".join(str(loc) for loc in err.get("loc", [])),
            "message": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]
    logger.warning(f"Validation error on {request.method} {request.url.path}: {errors}")
    RequestLogger.log_error(request.method, str(request.url.path), "Validation error", 422)
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "code": 422,
            "message": "Request validation failed.",
            "errors": errors,
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catch-all handler so unhandled exceptions return JSON instead of a plain 500 page."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    RequestLogger.log_error(request.method, str(request.url.path), str(exc), 500)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "code": 500,
            "message": "An internal server error occurred.",
        },
    )


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
