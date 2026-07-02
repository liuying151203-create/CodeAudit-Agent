from fastapi import FastAPI

from app.api.reports import router as reports_router
from app.api.scan import router as scan_router

app = FastAPI(title="CodeAudit-Agent", version="0.1.0")
app.include_router(scan_router)
app.include_router(reports_router)


@app.get("/health")
def health():
    return {"status": "ok"}
