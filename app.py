# app.py
import os, secrets, re, logging, time
from typing import List, Optional
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, JobQueue

from auth.google_oauth import build_auth_url, refresh_access_token
from store.db import init_db, save_state, get_refresh_token, update_access_token, unlink
from gmail.client import list_unread_ids, get_message_full, extract_text, list_lastTen_ids
from summarize.summarizer import summarize_digest
from social.social import social


# ====== Setup ======
load_dotenv()
init_db()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s"
)
log = logging.getLogger("gmail-bot")

WATCH_INTERVAL_SEC = 10
BOT_START_TIME_MS = int(time.time() * 1000)
SEEN_BY_USER = {}  # tg_id -> set(message_ids)

# ====== OTP Patterns ======
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
    """Extract and normalize OTP codes."""
    if not text:
        return []
    matches = OTP_REGEX.findall(text)
    otps, seen = [], set()
    for m in matches:
        parts = [g for g in (m if isinstance(m, tuple) else (m,)) if g]
        for p in parts:
            digits = "".join(ch for ch in p if ch.isdigit())
            if 4 <= len(digits) <= 8 and digits not in seen:
                seen.add(digits)
                otps.append(digits)
    return otps


def _to_text(obj) -> str:
    """Flatten dict/list/etc into a single string for regex scanning."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (list, tuple)):
        return "\n".join(_to_text(x) for x in obj)
    if isinstance(obj, dict):
        chunks = []
        for k in ["text", "plain", "body", "snippet", "html"]:
            v = obj.get(k)
            if isinstance(v, str):
                chunks.append(v)
            elif isinstance(v, (list, tuple)):
                chunks.extend(x for x in v if isinstance(x, str))
        for v in obj.values():
            if isinstance(v, str) and v not in chunks:
                chunks.append(v)
        return "\n".join(chunks)
    return str(obj)


def _header(msg: dict, name: str) -> Optional[str]:
    """Get a header value from Gmail message."""
    for h in msg.get("payload", {}).get("headers", []) or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None

# ====== Commands ======
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Start command — auto start OTP watcher."""
    await update.message.reply_text(
        "Hi! I can summarize your Gmail.\n"
        "Use /link to connect, /digest for unread, /unlink to disconnect.\n"
        "Auto OTP watcher has started — I’ll notify you when a new verification code arrives."
    )

    tg_id = str(update.effective_user.id)
    job_name = f"otp_watcher_{tg_id}"

    # Clear existing watcher
    for j in ctx.job_queue.get_jobs_by_name(job_name):
        j.schedule_removal()

    ctx.job_queue.run_repeating(
        otp_poll_job,
        interval=WATCH_INTERVAL_SEC,
        first=0,
        name=job_name,
        data={"tg_id": tg_id}
    )
    log.info("Auto-started OTP watcher for tg_id=%s", tg_id)


async def link(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    state = f"{tg_id}-{secrets.token_urlsafe(8)}"
    save_state(state, tg_id)
    url = build_auth_url(state)
    await update.message.reply_text(f"Sign in with Google:\n{url}")


async def digest(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await _summarize(update)


async def _summarize(update: Update):
    tg_id = str(update.effective_user.id)
    refresh_token = get_refresh_token(tg_id)
    if not refresh_token:
        await update.message.reply_text("Please /link your Gmail first.")
        return

    try:
        new = refresh_access_token(refresh_token)
        if not new or not new.get("access_token"):
            raise ValueError("Missing access token")
        access = new["access_token"]
        update_access_token(tg_id, access, new.get("expiry"))
        ids = list_lastTen_ids(access, 10)
    except Exception as e:
        log.exception("Failed Gmail access for tg_id=%s", tg_id)
        await update.message.reply_text(f"Error fetching emails: {e}")
        return

    if not ids:
        await update.message.reply_text("No unread emails 🎉")
        return

    texts = []
    for mid in ids:
        try:
            msg = get_message_full(access, mid)
            texts.append(_to_text(extract_text(msg) or msg.get("snippet", "")))
        except Exception:
            log.exception("Failed to parse message %s", mid)

    summary = summarize_digest(texts)
    await update.message.reply_text(summary or "Couldn't summarize.")


async def unlink_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    unlink(tg_id)
    await update.message.reply_text("Disconnected. You can /link again anytime.")

# ====== OTP Watcher ======
async def otp_poll_job(ctx: ContextTypes.DEFAULT_TYPE):
    """Poll Gmail for new OTP messages."""
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

    for mid in ids:
        if mid in SEEN_BY_USER[tg_id]:
            continue
        try:
            msg = get_message_full(access, mid)
            internal_date = int(msg.get("internalDate", "0"))

            # Ignore old emails
            if internal_date < BOT_START_TIME_MS:
                SEEN_BY_USER[tg_id].add(mid)
                continue

            body = _to_text(extract_text(msg) or msg.get("snippet", ""))
            otps = _find_otps(body)
            if otps:
                subject = _header(msg, "Subject") or "(no subject)"
                sender = _header(msg, "From") or "(unknown sender)"
                await ctx.bot.send_message(
                    chat_id=int(tg_id),
                    text=f"🔐 New OTP: {', '.join(otps)}\nFrom: {sender}\nSubject: {subject}"
                )
        except Exception:
            log.exception("Failed to process message %s for tg_id=%s", mid, tg_id)
        finally:
            SEEN_BY_USER[tg_id].add(mid)

# ====== Main ======
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    if app.job_queue is None:
        jq = JobQueue()
        jq.set_application(app)
        jq.start()
        app.job_queue = jq

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("link", link))
    app.add_handler(CommandHandler("digest", digest))
    app.add_handler(CommandHandler("unlink", unlink_cmd))
    app.add_handler(CommandHandler("social", social))

    app.run_polling()


if __name__ == "__main__":
    main()
