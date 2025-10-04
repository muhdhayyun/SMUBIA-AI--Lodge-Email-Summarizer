import os
from fastapi import FastAPI, HTTPException, Request
from auth.google_oauth import exchange_code_for_tokens
from store.db import init_db, save_tokens, save_state, pop_telegram_by_state
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()

@app.on_event("startup")
def _startup():
    init_db()

@app.get("/health")
def health():
    return {"ok": True}

# For local testing you can generate a state manually too.
@app.get("/debug/make_state/{tgid}")
def debug_make_state(tgid: str):
    st = f"{tgid}-debug"
    save_state(st, tgid)
    return {"state": st}

@app.get("/google/oauth2/callback")
async def google_callback(code: str | None = None, state: str | None = None, request: Request = None):
    print("DEBUG code:", code)
    print("DEBUG state:", state)

    if not code or not state:
        raise HTTPException(400, "Missing code/state")

    telegram_id = pop_telegram_by_state(state)
    print("DEBUG telegram_id:", telegram_id)

    if not telegram_id:
        raise HTTPException(400, "Invalid state")

    tokens = exchange_code_for_tokens(code)
    print("DEBUG tokens:", tokens)

    if not tokens.get("refresh_token"):
        raise HTTPException(400, "No refresh_token returned. Try again with prompt=consent.")

    save_tokens(telegram_id, tokens["refresh_token"], tokens.get("access_token"), tokens.get("expiry"))
    return {"ok": True, "telegram_id": telegram_id, "message": "Linked! Go back to Telegram and run /digest."}

