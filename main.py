
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from config import settings
from upload import router as upload_router
from audit import router as audit_router


app = FastAPI(title=settings.app_name, version=settings.app_version)
app.include_router(upload_router, prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
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
    return JSONResponse({"status": "healthy"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
