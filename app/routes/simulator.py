from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import SimulatorRequest, SimulatorResponse
from app.services import chatbot, scan_service
from app.services.examples import BY_ID, EXAMPLES

router = APIRouter(prefix="/api/simulator", tags=["Attack simulator"])


@router.get("/examples", summary="Predefined demo prompts")
def list_examples():
    return EXAMPLES


@router.post("/test", response_model=SimulatorResponse, summary="Run one prompt against unprotected and protected agents")
def run_test(payload: SimulatorRequest, db: Session = Depends(get_db)):
    if payload.example_id:
        example = BY_ID.get(payload.example_id)
        if example is None:
            raise HTTPException(status_code=404, detail=f"Unknown example '{payload.example_id}'")
        title, prompt, expected = example["title"], example["prompt"], example["expected"]
    else:
        title, prompt, expected = "Custom prompt", payload.prompt, "custom"

    scan = scan_service.scan_and_record(db, prompt, source="simulator")
    scan_dict = scan.model_dump()
    matches = {"safe": scan.verdict == "ALLOWED", "attack": scan.verdict != "ALLOWED",
               "borderline": True, "custom": True}[expected]
    return SimulatorResponse(
        title=title, prompt=prompt, expected=expected, matches_expectation=matches, scan=scan,
        unprotected={"status": "replied", "reply": chatbot.vulnerable_agent(prompt)},
        protected=chatbot.protected_agent(scan_dict, prompt, confirm=False),
    )
