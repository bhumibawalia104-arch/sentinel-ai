from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.concurrency import run_in_threadpool

from app.services.document_scanner import extract_document_text
# from app.services.llm_service import explain_document_risk
from app.detection.risk_engine import analyze
from app.services.llm_service import (
    explain_document_risk,
    answer_document_question
)


router = APIRouter(prefix="/api", tags=["Documents"])

MAX_FILE_SIZE = MAX_FILE_SIZE = 50 * 1024 * 1024

@router.post("/scan-document")
async def scan_document(file: UploadFile = File(...)):

    filename = file.filename or ""

    # Step 1: Validate file type
    if not filename.lower().endswith((".pdf", ".docx", ".txt")):
        raise HTTPException(
            status_code=400,
            detail="Only PDF, DOCX and TXT files supported"
        )

    # Step 2: Read uploaded file
    content = await file.read(MAX_FILE_SIZE + 1)

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File too large"
        )

    # Step 3: Extract text
    try:
        text = await run_in_threadpool(
            extract_document_text,
            filename,
            content
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Document could not be processed"
        )

    if not text.strip():
        raise HTTPException(
            status_code=422,
            detail="No extractable text found"
        )

    # Step 4: Analyze document using Rules + ML
    result = await run_in_threadpool(analyze, text)

    # Step 5: Ask Gemini to explain the security findings
    try:
        ai_explanation = await run_in_threadpool(
            explain_document_risk,
            text,
            result
        )

    except Exception as e:
        print(
            f"[SENTINEL] Gemini explanation failed: "
            f"{type(e).__name__}: {e}"
        )
        ai_explanation = None

         # Step 6: Generate AI answer only for safe documents
    ai_answer = None

    if result.get("verdict") == "ALLOWED":
        try:
            ai_answer = await run_in_threadpool(
                answer_document_question,
                text
            )

        except Exception as e:
            print(
                f"[SENTINEL] AI document answer failed: "
                f"{type(e).__name__}: {e}"
            )

    # Step 7: Return scan results + Gemini responses
    return {
        "filename": filename,
        **result,
        "ai_explanation": ai_explanation,
        "ai_answer": ai_answer
    }