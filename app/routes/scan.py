
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection import ml_classifier
from app.schemas import ScanRequest, ScanResult
from app.services import scan_service
from app.services.llm_service import generate_response
from app.services.output_scanner import scan_ai_output


router = APIRouter(prefix="/api", tags=["Scanner"])


class ScanWithAI(ScanResult):
    ai_answer: str | None = None
    output_scan: dict | None = None


@router.post(
    "/scan",
    response_model=ScanWithAI,
    summary="Scan one prompt"
)
def scan_prompt(
    payload: ScanRequest,
    db: Session = Depends(get_db)
):

    # STEP 1: Scan the user's prompt
    result = scan_service.scan_and_record(
        db,
        payload.prompt,
        source="scanner"
    )

    ai_answer = None
    output_scan = None

    # STEP 2: Send only ALLOWED prompts to Gemini
    if result.verdict == "ALLOWED":

        try:
            # Generate Gemini answer
            generated_answer = generate_response(payload.prompt)

            print(
                "[SENTINEL] Gemini answer generated successfully",
                flush=True
            )

            # STEP 3: Scan Gemini's answer
            output_scan = scan_ai_output(generated_answer)

            print(
                "[SENTINEL] Output scan result:",
                output_scan,
                flush=True
            )

            # STEP 4: Show answer only if output is ALLOWED
            if output_scan["verdict"] == "ALLOWED":
                ai_answer = generated_answer

        except Exception as e:
            print(
                f"[SENTINEL] AI output scan failed: "
                f"{type(e).__name__}: {e}",
                flush=True
            )

    # STEP 5: Return both scan results
    return ScanWithAI(
        **result.model_dump(),
        ai_answer=ai_answer,
        output_scan=output_scan
    )


@router.get(
    "/model/metrics",
    summary="ML evaluation on the held-out test set"
)
def model_metrics():

    metrics = ml_classifier.get_metrics()

    if metrics is None:
        raise HTTPException(
            status_code=404,
            detail="Model has not been trained yet"
        )

    return metrics
