import re
import logging
from typing import Optional
from telegram import Update
from telegram.ext import ContextTypes

from auth.google_oauth import refresh_access_token
from store.db import get_refresh_token, update_access_token
from gmail.client import search_ids, get_message_full

log = logging.getLogger("gmail-social")

# ===== Helpers =====
def _header(msg: dict, name: str) -> Optional[str]:
    for h in msg.get("payload", {}).get("headers", []) or []:
        if h.get("name", "").lower() == name.lower():
            return h.get("value")
    return None


async def _safe_send(bot, chat_id: int, text: str):
    """Split long messages under Telegram's 4096-char limit."""
    MAX_LEN = 4000
    for i in range(0, len(text), MAX_LEN):
        await bot.send_message(
            chat_id=chat_id,
            text=text[i:i + MAX_LEN],
            parse_mode="Markdown",
            disable_web_page_preview=True
        )


# ===== /social command =====
async def social(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Summarize unread LinkedIn activity emails in structured multiline format."""
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

        # Only fetch unread LinkedIn emails
        ids = search_ids(access, "category:social from:linkedin.com is:unread", max_results=30)

    except Exception as e:
        log.exception("Failed to fetch social emails for tg_id=%s", tg_id)
        await update.message.reply_text(f"Error accessing Gmail: {e}")
        return

    if not ids:
        await update.message.reply_text("No unread LinkedIn activity 📭")
        return

    connection_requests, new_connections, reminders = [], [], []

    for mid in ids:
        try:
            msg = get_message_full(access, mid)
            subject = _header(msg, "Subject") or ""
            sender = _header(msg, "From") or ""
            sender_name_match = re.match(r"([^<]+)", sender)
            sender_name = sender_name_match.group(1).strip() if sender_name_match else sender
            s = subject.lower()

            if "want to connect" in s or "connection request" in s:
                connection_requests.append(sender_name)
            elif "start a conversation" in s or "new connection" in s:
                new_connections.append(sender_name)
            elif "response" in s or "waiting" in s:
                reminders.append(sender_name)

        except Exception:
            log.exception("Failed parsing message %s", mid)

    lines = ["Here’s your latest *LinkedIn Digest (Unread):*\n"]

    def format_list(title: str, names: list) -> str:
        """Return formatted multiline bullet list."""
        if not names:
            return ""
        unique = sorted(set(names))
        lines = [f"• {title}"]
        for name in unique:
            lines.append(f"   • {name}")
        return "\n".join(lines)

    bullets = []
    if connection_requests:
        count = len(set(connection_requests))
        bullets.append(format_list(f"{count} new connection requests from", connection_requests))
    if new_connections:
        bullets.append(format_list("New connections made with", new_connections))
    if reminders:
        bullets.append(format_list("Reminder from", reminders))

    if not bullets:
        bullets.append("• No new personal LinkedIn messages 📭")

    # Tighten spacing: only one newline after header, one newline between sections
    text = lines[0] + "\n" + "\n\n".join(bullets)
    await _safe_send(ctx.bot, int(tg_id), text)
