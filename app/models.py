"""Database tables."""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now, index=True)
    prompt_preview: Mapped[str] = mapped_column(String(200))   # redacted + truncated, never the full prompt
    prompt_length: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(40))
    verdict: Mapped[str] = mapped_column(String(12), index=True)
    explanation: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(20), default="scanner")   # scanner / simulator / chatbot
