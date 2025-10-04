import os, secrets
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from auth.google_oauth import build_auth_url, refresh_access_token
from store.db import init_db, save_state, get_refresh_token, update_access_token, unlink
from gmail.client import list_unread_ids, get_message_full, extract_text
from summarize.summarizer import summarize_digest

load_dotenv()
init_db()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Hi! I can summarize your Gmail.\n"
        "Use /link to connect, /digest for unread, /latest for recent, /unlink to disconnect."
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
    await _summarize(update, unread_only=False)
    # tg_id = str(update.effective_user.id)
    # refresh_token = refresh_access_token(tg_id)
    # if not refresh_token:
    #     await update.message.reply_text("Please /link your Gmail first.")
    #     return
    # new = refresh_access_token(refresh_token)
    # access = new["access_token"]
    # update_access_token(tg_id, access, new.get("expiry"))
    # from gmail.client import search_ids
    # ids = search_ids(access, "category:primary", max_results=5)
    # items = []
    # for mid in ids[:10]:
    #     msg = get_message_full(access, mid)
    #     items.append(extract_text(msg))

    # summary = summarize_digest(items)
    # await update.message.reply_text(summary if summary else "Couldn't summarize.")

async def _summarize(update: Update, unread_only: bool):
    tg_id = str(update.effective_user.id)
    refresh_token = get_refresh_token(tg_id)
    if not refresh_token:
        await update.message.reply_text("Please /link your Gmail first.")
        return
    new = refresh_access_token(refresh_token)
    access = new["access_token"]
    update_access_token(tg_id, access, new.get("expiry"))

    ids = list_unread_ids(access, 10) if unread_only else \
          list_unread_ids(access, 10) or []  # change to a search if you want "latest any"
    if not ids:
        await update.message.reply_text("No emails found 🎉")
        return

    # For "latest", you might want: search_ids(access, "in:inbox", max_results=10)
    if not unread_only:
        from gmail.client import search_ids
        ids = search_ids(access, "category:primary", max_results=2)

    items = []
    for mid in ids[:10]:
        msg = get_message_full(access, mid)
        items.append(extract_text(msg))

    summary = summarize_digest(items)
    await update.message.reply_text(summary if summary else "Couldn't summarize.")

async def unlink_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = str(update.effective_user.id)
    unlink(tg_id)
    await update.message.reply_text("Disconnected. You can /link again anytime.")

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("link", link))
    app.add_handler(CommandHandler("digest", digest))
    app.add_handler(CommandHandler("latest", latest))
    app.add_handler(CommandHandler("unlink", unlink_cmd))
    app.run_polling()

if __name__ == "__main__":
    main()
