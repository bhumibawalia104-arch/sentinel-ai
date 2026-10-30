# SENTINEL AI — repaired project

## Run (Windows PowerShell)

1. Extract this ZIP to a **new folder** (do not overwrite your current work).
2. Open the extracted `sentinel-ai-master` folder in VS Code.
3. Activate your existing venv, or create one: `python -m venv .venv` then `.\.venv\Scripts\Activate.ps1`.
4. Install dependencies: `python -m pip install -r requirements.txt`.
5. For Gemini, set a key **in the current PowerShell session**, not in source code: `$env:GEMINI_API_KEY="YOUR_KEY"`. Do not share or commit it.
6. Optionally set `$env:GEMINI_MODEL="gemini-2.5-flash"` (default). Model availability depends on your account.
7. Run: `python -m uvicorn app.main:app --reload` and open http://127.0.0.1:8000.

## Changes
- One unified CSS stylesheet and horizontal command-center navigation.
- Compact responsive dashboard with charts, shield and live API statistics.
- Restored original Media Safety prompt scanner with verdict-specific alerts; it **does not generate or play media**.
- Kept original Documents scan UI with readable results and Gemini explanation/answer.
- Kept protected Gemini chatbot, simulator, logs, scanner.
- Added missing Python dependencies and configurable Gemini model.

Gemini requires a valid API key and access to the selected model; this package cannot guarantee third-party service availability.
