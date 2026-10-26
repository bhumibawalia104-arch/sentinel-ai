"""Glue between the detection engine and the database."""
import re

from sqlalchemy.orm import Session

from app import config
from app.detection import risk_engine
from app.models import ScanRecord
from app.schemas import ScanResult

# Privacy: strip things that look like secrets before storing a preview
_REDACTIONS = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "[email]"),
    (re.compile(r"https?://\S+"), "[url]"),
    (re.compile(r"\b[A-Za-z0-9+/_-]{24,}={0,2}"), "[long-token]"),
    (re.compile(r"\b\d{9,}\b"), "[number]"),
]


def make_preview(prompt: str) -> str:
    text = " ".join(prompt.split())
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text[:config.PREVIEW_LENGTH] + ("..." if len(text) > config.PREVIEW_LENGTH else "")


def scan_and_record(db: Session, prompt: str, source: str = "scanner") -> ScanResult:
    analysis = risk_engine.analyze(prompt)
    record = ScanRecord(
        prompt_preview=make_preview(prompt), prompt_length=len(prompt),
        risk_score=analysis["risk_score"], category=analysis["category"],
        verdict=analysis["verdict"], explanation=analysis["explanation"], source=source,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return ScanResult(scan_id=record.id, **analysis)
