from fastapi import APIRouter, HTTPException

from app.storage.db import get_report, list_reports

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def reports():
    return list_reports()


@router.get("/{report_id}")
def report(report_id: str):
    data = get_report(report_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return data
