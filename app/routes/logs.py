from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ScanRecord
from app.routes.stats import to_event
from app.schemas import LogItem, LogsResponse

router = APIRouter(prefix="/api", tags=["Security logs"])


@router.get("/logs", response_model=LogsResponse, summary="Scan history, newest first")
def get_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None, pattern="^(ALLOWED|SUSPICIOUS|BLOCKED)$"),
    db: Session = Depends(get_db),
):
    query = select(ScanRecord)
    count_query = select(func.count()).select_from(ScanRecord)
    if verdict:
        query = query.where(ScanRecord.verdict == verdict)
        count_query = count_query.where(ScanRecord.verdict == verdict)
    rows = db.execute(query.order_by(ScanRecord.id.desc()).offset(offset).limit(limit)).scalars().all()
    items = [LogItem(**to_event(r), explanation=r.explanation, prompt_length=r.prompt_length) for r in rows]
    return LogsResponse(total=db.execute(count_query).scalar_one(), items=items)


@router.delete("/logs", summary="Clear all scan history (useful before a demo)")
def clear_logs(db: Session = Depends(get_db)):
    result = db.execute(delete(ScanRecord))
    db.commit()
    return {"deleted": result.rowcount}
