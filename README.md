# SENTINEL AI: Prompt Injection Firewall for AI Agents

A hybrid firewall that scans every prompt **before** it reaches an AI chatbot or agent.
Rules + machine learning + a risk decision engine produce a 0-100 risk score and an
**ALLOWED / SUSPICIOUS / BLOCKED** verdict with a plain-English explanation.

> **Honest limits:** this is a defense-in-depth layer, not complete protection. Regex rules can be
> evaded and the ML model learns from a small hand-written dataset. The risk score is a heuristic
> ranking, **not** a calibrated probability.

## Quick start (Windows PowerShell)

```powershell
cd sentinel-ai
python -m venv venv
.\venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File scripts\get_chartjs.ps1   # once, while online: lets charts work offline
uvicorn app.main:app --reload
```

Open **http://127.0.0.1:8000** (API docs: **/docs**). The database and ML model are created automatically on first start.
No API key and no internet are needed to run the demo.

Run the tests: `pytest -v`   ·   Retrain / re-evaluate the model: `python -m scripts.train_model`

## How it works

```
Browser ──fetch──> FastAPI routes ──> Detection pipeline ──> Risk decision ──> verdict
                         │               0 Normalizer  (decode base64/hex/rot13, leetspeak, spaced letters)
                         │               1 Rules       (weighted regex)
                         │               2 ML          (TF-IDF + Logistic Regression)
                         └─> SQLAlchemy ─> SQLite (redacted preview, score, category, verdict, explanation)
ALLOWED -> demo chatbot     SUSPICIOUS -> warning + confirmation     BLOCKED -> never forwarded
```

**Risk score.** `rule_score` = 1 − Π(1 − weight) over matched rules. `ml_score` = 100 × (1 − P(benign)).
`risk = max(0.6·rule + 0.4·ml, 0.8·rule)`, so strong rule evidence is never diluted.
Thresholds (in `app/config.py`): ≥ 35 SUSPICIOUS, ≥ 65 BLOCKED.
When the two layers disagree the result is marked **low confidence**.

## Project layout

| Path | Purpose |
|---|---|
| `app/main.py` | FastAPI app, start-up, serves the frontend |
| `app/routes/` | `scan`, `stats`, `logs`, `simulator`, `chat` endpoints |
| `app/detection/` | `normalizer`, `rules`, `ml_classifier`, `risk_engine` |
| `app/services/` | simulated agent, demo prompts, scan + database glue |
| `app/models.py`, `database.py`, `schemas.py` | SQLAlchemy tables, DB setup, Pydantic models |
| `app/data/training_data.csv` | our own labeled dataset (130 prompts, 6 classes) |
| `frontend/` | HTML, CSS, vanilla JS, Chart.js |
| `tests/` | detection + API tests |
| `docs/DEMO_GUIDE.md` | 3-minute demo script and judge Q&A |

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/scan` | scan a prompt, store the result |
| GET | `/api/stats` | dashboard numbers (all computed from the DB) |
| GET | `/api/logs?verdict=&limit=` · DELETE | history / clear history |
| GET | `/api/simulator/examples` · POST `/api/simulator/test` | attack simulator |
| POST | `/api/chat` | chatbot with `protected` and `confirm` flags |
| GET | `/api/model/metrics` | held-out accuracy, precision, recall, confusion matrix |

## Privacy

The full prompt is never stored. Only an 80-character preview is saved, with emails, URLs, long tokens and long numbers redacted.
