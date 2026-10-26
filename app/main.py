"""SENTINEL AI: entry point. Run with: uvicorn app.main:app --reload"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.database import init_db
from app.detection import ml_classifier

# Import all API routers, including documents
from app.routes import chat, logs, scan, simulator, stats, documents
from app.routes import generate


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ready = ml_classifier.load_or_train()

    print(
        "[SENTINEL] ML layer:",
        "ready" if ready else "unavailable (rules only)"
    )

    yield


app = FastAPI(
    title="SENTINEL AI",
    description=(
        "Hybrid prompt-injection firewall for AI agents "
        "(rules + ML + risk engine). "
        "A defense-in-depth layer, not a guarantee against every attack."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def friendly_validation_error(
    request: Request,
    exc: RequestValidationError
):
    """Turn Pydantic's long error list into one readable message."""

    first = exc.errors()[0]

    message = str(
        first.get("msg", "Invalid input")
    ).removeprefix("Value error, ")

    if first.get("type") == "string_too_long":
        message = "Prompt is too long (maximum 4000 characters)"

    elif first.get("type") == "missing":
        message = "A required field is missing"

    return JSONResponse(
        status_code=422,
        content={"detail": message}
    )


@app.get("/api/health", tags=["System"])
def health_check():
    return {
        "status": "ok",
        "service": "SENTINEL AI",
        "ml_ready": ml_classifier._model is not None
    }


# Register ALL API routes BEFORE mounting frontend
for module in (
    scan,
    stats,
    logs,
    simulator,
    chat,
    documents,
    generate
):
    app.include_router(module.router)


# IMPORTANT: Frontend mount must always be LAST
GENERATED_DIR = Path(__file__).resolve().parent.parent / "generated"

GENERATED_DIR.mkdir(parents=True, exist_ok=True)

app.mount(
    "/generated",
    StaticFiles(directory=GENERATED_DIR),
    name="generated"
)
app.mount(
    "/",
    StaticFiles(
        directory=FRONTEND_DIR,
        html=True
    ),
    name="frontend"
)