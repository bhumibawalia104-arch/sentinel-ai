from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import ChatRequest, ChatResponse
from app.services import chatbot, scan_service
from app.services.llm_service import generate_response

router = APIRouter(prefix="/api", tags=["Chatbot"])


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Chat with Gemini protected by SENTINEL AI"
)
def chat(payload: ChatRequest, db: Session = Depends(get_db)):

    # STEP 1: Unprotected mode (demo only)
    if not payload.protected:
        return ChatResponse(
            status="replied",
            reply=chatbot.vulnerable_agent(payload.message),
            protected=False
        )

    # STEP 2: Scan user's message using SENTINEL AI
    scan = scan_service.scan_and_record(
        db,
        payload.message,
        source="chatbot"
    )

    # STEP 3: Block dangerous prompts
    if scan.verdict == "BLOCKED":
        return ChatResponse(
            status="blocked",
            reply="Security warning: Your prompt has been blocked.",
            protected=True,
            scan=scan
        )

    # STEP 4: Require confirmation for suspicious prompts
    if scan.verdict == "SUSPICIOUS" and not payload.confirm:
        return ChatResponse(
            status="needs_confirmation",
            reply="Suspicious prompt detected. Please confirm before proceeding.",
            protected=True,
            scan=scan
        )

        # STEP 5: Send allowed prompt to Gemini
    try:
        answer = generate_response(payload.message)
        print("Gemini response generated successfully")

    except Exception as e:
        print("GEMINI ERROR:", type(e).__name__, str(e))

        raise HTTPException(
            status_code=502,
            detail="Gemini service is unavailable. Check terminal."
        ) from e

    # STEP 6: Return Gemini's answer
    return ChatResponse(
        status="replied",
        reply=answer,
        protected=True,
        scan=scan
    )