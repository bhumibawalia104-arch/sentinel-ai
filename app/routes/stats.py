from datetime import date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends

from app.database import get_db
from app.detection.rules import CATEGORY_LABELS
from app.models import ScanRecord
from app.schemas import RecentEvent, StatsResponse

router = APIRouter(prefix="/api", tags=["Analytics"])

BUCKETS = [(0, 19), (20, 39), (40, 59), (60, 79), (80, 100)]


def to_event(r: ScanRecord) -> dict:
    return {"id": r.id, "created_at": r.created_at, "prompt_preview": r.prompt_preview,
            "risk_score": r.risk_score, "category_label": CATEGORY_LABELS.get(r.category, r.category),
            "verdict": r.verdict, "source": r.source}


@router.get("/stats", response_model=StatsResponse, summary="Dashboard statistics (computed from the database)")
def get_stats(db: Session = Depends(get_db)):
    verdict_counts = dict(db.execute(select(ScanRecord.verdict, func.count()).group_by(ScanRecord.verdict)).all())
    allowed, suspicious, blocked = (verdict_counts.get(v, 0) for v in ("ALLOWED", "SUSPICIOUS", "BLOCKED"))
    total = allowed + suspicious + blocked

    category_counts = dict(db.execute(select(ScanRecord.category, func.count()).group_by(ScanRecord.category)).all())
    categories = [{"key": k, "label": CATEGORY_LABELS[k], "count": category_counts.get(k, 0)} for k in CATEGORY_LABELS]

    scores = db.execute(select(ScanRecord.risk_score)).scalars().all()
    distribution = [{"range": f"{lo}-{hi}", "count": sum(lo <= s <= hi for s in scores)} for lo, hi in BUCKETS]

    # Last 7 days (local time)
    today = date.today()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    since = datetime.combine(days[0], datetime.min.time())
    rows = db.execute(select(ScanRecord.created_at, ScanRecord.verdict).where(ScanRecord.created_at >= since)).all()
    daily = {d: {"date": d.isoformat(), "allowed": 0, "suspicious": 0, "blocked": 0} for d in days}
    for created, verdict in rows:
        bucket = daily.get(created.date())
        if bucket:
            bucket[verdict.lower()] += 1

    recent = db.execute(select(ScanRecord).order_by(ScanRecord.id.desc()).limit(8)).scalars().all()
    return StatsResponse(
        total=total, allowed=allowed, suspicious=suspicious, blocked=blocked,
        block_rate=round(100 * blocked / total, 1) if total else 0.0,
        categories=categories, risk_distribution=distribution, daily=list(daily.values()),
        recent=[RecentEvent(**to_event(r)) for r in recent],
    )
