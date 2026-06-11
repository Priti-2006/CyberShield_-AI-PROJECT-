from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time

from app.config import settings
from app.models.schemas import ScanRequest, ScanResponse
from app.services.scan_service import run_scan
from app.utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="CyberShield AI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "online", "service": "CyberShield AI"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    try:
        return await run_scan(request)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error("Scan error: %s", e)
        raise HTTPException(status_code=500, detail="Scan failed. Please try again.")
