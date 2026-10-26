from app.detection.risk_engine import analyze


def scan_ai_output(ai_answer: str) -> dict:
    """
    Scan Gemini's generated response using
    SENTINEL AI's existing Rules + ML engine.
    """

    return analyze(ai_answer)