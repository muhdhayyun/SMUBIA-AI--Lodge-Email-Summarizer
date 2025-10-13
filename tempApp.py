# app.py
import os, secrets, re, logging
from typing import List, Optional

from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, JobQueue

from auth.google_oauth import build_auth_url, refresh_access_token
from store.db import init_db, save_state, get_refresh_token, update_access_token, unlink
from gmail.client import list_unread_ids, get_message_full, extract_text
from summarize.summarizer import summarize_digest

# ====== Setup ======
load_dotenv()
init_db()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
log = logging.getLogger("gmail-bot")

# ====== OTP helpers ======
SEEN_BY_USER = {}  # tg_id -> set(message_ids)
WATCH_INTERVAL_SEC = 10

# OTP patterns (add/remove as needed)
OTP_PATTERNS = [
    r"\b(\d{6})\b",                                   # bare 6-digit
    r"otp[:\s-]*([0-9]{4,8})",
    r"verification\s*code[:\s-]*([0-9]{4,8})",
    r"one[-\s]?time\s*password[:\s-]*([0-9]{4,8})",
    r"code[:\s-]*([0-9]{4,8})",
    r"\b(\d{3}[-\s]\d{3})\b",                         # 123-456 or 123 456
]
OTP_REGEX = re.compile("|".join(f"(?:{p})" for p in OTP_PATTERNS), re.IGNORECASE)


def _find_otps(text: str) -> List[str]:
    """Run regex and normalize digits (e.g., '123-456' -> '123456')."""
    if not text:
        return []
    matches = OTP_REGEX.findall(text)
    out = []
    for m in matches:
        parts = [g for g in (m if isinstance(m, tuple) else (m,)) if g]
        for p in parts:
            digits = "".join(ch for ch in p if ch.isdigit())
            if 4 <= len(digits) <= 8:
                out.append(digits)
    # de-dupe preserve order
    seen = set(); ordered = []
    for x in out:
        if x not in seen:
            seen.add(x); ordered.append(x)
    return ordered


def _to_text(obj) -> str:
    """Flatten dict/list/etc into a single text string for regex scanning."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (list, tuple)):
        return "\n".join(_to_text(x) for x in obj)
    if isinstance(obj, dict):
        keys = ["text", "plain", "body", "snippet", "html"]
        chunks = []
        for k in keys:
            v = obj.get(k)
            if isinstance(v, str):
                chunks.append(v)
            elif isinstance(v, (list, tuple)):
                chunks.append("\n".join(x for x in v if isinstance(x, str)))
        # include any other string values
        for v in obj.values():
            if isinstance(v, str) and v not in chunks:
                chunks.append(v)
        return "\n".join(chunks)
    return str(obj)


def _header(msg: dict, name: str) -> Optional[str]:
    headers = (msg.get("payload", {}) or {}).get("headers", []) or []
    for h in headers:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None

# ====== Commands ======
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Hi! I can summarize your Gmail.\n"
        "Use /link to connect, /digest for unread, /latest for recent, /unlink to disconnect.\n"
        "Use /watch_otp to auto-forward verification codes, /unwatch_otp to stop."
    )

async def link(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    state = tg_id + "-" + secrets.token_urlsafe(8)
    save_state(state, tg_id)
    url = build_auth_url(state)
    await update.message.reply_text(f"Sign in with Google:\n{url}")

async def digest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await _summarize(update, unread_only=True)

async def latest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Work in Progress :(")

async def _summarize(update: Update, unread_only: bool):
    tg_id = str(update.effective_user.id)
    refresh_token = get_refresh_token(tg_id)
    if not refresh_token:
        await update.message.reply_text("Please /link your Gmail first.")
        return

    try:
        new = refresh_access_token(refresh_token)
    except Exception as e:
        log.exception("Token refresh failed")
        await update.message.reply_text(f"Auth error while refreshing token: {e}")
        return

    if not new or not new.get("access_token"):
        await update.message.reply_text("Could not refresh access token. Try /link again.")
        return

    access = new["access_token"]
    update_access_token(tg_id, access, new.get("expiry"))

    try:
        ids = list_unread_ids(access, 10)
    except Exception as e:
        log.exception("Failed to list unread emails")
        await update.message.reply_text(f"Error listing emails: {e}")
        return

    if not ids:
        await update.message.reply_text("No emails found 🎉")
        return

    items = []
    for mid in ids[:10]:
        try:
            msg = get_message_full(access, mid)
            items.append(_to_text(extract_text(msg) or msg.get("snippet", "")))
        except Exception:
            log.exception("Failed to fetch/parse message %s", mid)

    summary = summarize_digest(items)
    await update.message.reply_text(summary if summary else "Couldn't summarize.")

async def unlink_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    unlink(tg_id)
    await update.message.reply_text("Disconnected. You can /link again anytime.")

# ====== OTP watcher ======
async def watch_otp(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if ctx.job_queue is None:
        await update.message.reply_text(
            "JobQueue isn't available. Install: pip install \"python-telegram-bot[job-queue]\""
        )
        return

    tg_id = str(update.effective_user.id)
    job_name = f"otp_watcher_{tg_id}"

    for j in ctx.job_queue.get_jobs_by_name(job_name):
        j.schedule_removal()

    ctx.job_queue.run_repeating(
        otp_poll_job,
        interval=WATCH_INTERVAL_SEC,
        first=0,
        name=job_name,
        data={"tg_id": tg_id}
    )
    await update.message.reply_text(
        f"OTP watcher started (every {WATCH_INTERVAL_SEC}s). I’ll ping you when a verification code arrives."
    )

async def unwatch_otp(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    job_name = f"otp_watcher_{tg_id}"
    jobs = [] if ctx.job_queue is None else ctx.job_queue.get_jobs_by_name(job_name)
    if not jobs:
        await update.message.reply_text("No OTP watcher running.")
        return
    for j in jobs:
        j.schedule_removal()
    await update.message.reply_text("OTP watcher stopped.")

async def otp_poll_job(ctx: ContextTypes.DEFAULT_TYPE):
    data = ctx.job.data or {}
    tg_id = data.get("tg_id")
    if not tg_id:
        return

    SEEN_BY_USER.setdefault(tg_id, set())

    refresh_token = get_refresh_token(tg_id)
    if not refresh_token:
        return

    try:
        new = refresh_access_token(refresh_token)
        if not new or not new.get("access_token"):
            log.warning("No access token after refresh for tg_id=%s", tg_id)
            return
        access = new["access_token"]
        update_access_token(tg_id, access, new.get("expiry"))
    except Exception:
        log.exception("Token refresh failed for tg_id=%s", tg_id)
        return

    try:
        ids = list_unread_ids(access, 10)
    except Exception:
        log.exception("Failed to list unread for tg_id=%s", tg_id)
        return
    if not ids:
        return

    unseen = [m for m in ids if m not in SEEN_BY_USER[tg_id]]
    if not unseen:
        return

    for mid in unseen:
        try:
            msg = get_message_full(access, mid)
            body_raw = extract_text(msg)
            if not body_raw:
                body_raw = {"snippet": msg.get("snippet", "")}
            body = _to_text(body_raw)

            subject = _header(msg, "Subject") or "(no subject)"
            from_hdr = _header(msg, "From") or "(unknown sender)"
            log.info("Scanning msg %s: subject=%r from=%r body_len=%d",
                     mid, subject, from_hdr, len(body))

            otps = _find_otps(body)
            if otps:
                await ctx.bot.send_message(
                    chat_id=int(tg_id),
                    text=f"🔐 New verification code(s): {', '.join(otps)}\nFrom: {from_hdr}\nSubject: {subject}"
                )
        except Exception:
            log.exception("Failed processing message %s for tg_id=%s", mid, tg_id)
        finally:
            SEEN_BY_USER[tg_id].add(mid)

# ====== Main ======
def main():
    app = Application.builder().token(BOT_TOKEN).build()

    # Ensure JobQueue exists even if PTB extra isn't installed
    if app.job_queue is None:
        jq = JobQueue()
        jq.set_application(app)
        jq.start()
        app.job_queue = jq

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("link", link))
    app.add_handler(CommandHandler("digest", digest))
    app.add_handler(CommandHandler("latest", latest))
    app.add_handler(CommandHandler("unlink", unlink_cmd))
    app.add_handler(CommandHandler("watch_otp", watch_otp))
    app.add_handler(CommandHandler("unwatch_otp", unwatch_otp))

    app.run_polling()

if __name__ == "__main__":
    main()
