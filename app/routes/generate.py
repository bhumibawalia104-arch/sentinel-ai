from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.services import scan_service

router = APIRouter(prefix="/api", tags=["Media Prompt Security"])


class GenerateRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    mode: str


@router.post("/generate")
def check_media_prompt(
    payload: GenerateRequest,
    db: Session = Depends(get_db)
):
    if payload.mode not in ("image", "video"):
        raise HTTPException(
            status_code=400,
            detail="Mode must be image or video"
        )

    result = scan_service.scan_and_record(
        db,
        payload.prompt,
        source=f"{payload.mode}_prompt_scanner"
    )

    return {
        "mode": payload.mode,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "category": result.category,
        "category_label": result.category_label,
        "explanation": result.explanation,
        "scan": result.model_dump(),
        "message": (
            "Prompt accepted by SENTINEL AI."
            if result.verdict == "ALLOWED"
            else "Prompt requires review."
            if result.verdict == "SUSPICIOUS"
            else "Prompt blocked by SENTINEL AI."
        )
    }