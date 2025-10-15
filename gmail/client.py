import base64
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .cleaners import html_to_text

def _svc(access_token: str):
    creds = Credentials(token=access_token)
    # cache_discovery=False avoids file writes
    return build("gmail", "v1", credentials=creds, cache_discovery=False)

def search_ids(access_token: str, q: str, max_results=10):
    service = _svc(access_token)
    res = service.users().messages().list(
        userId="me", q=q, maxResults=max_results, includeSpamTrash=False
    ).execute()
    return [m["id"] for m in res.get("messages", [])]

def list_unread_ids(access_token: str, max_results=10):
    return search_ids(access_token, "is:unread category:primary", max_results)

def list_lastTen_ids(access_token: str, max_results=10):
    return search_ids(access_token, "category:primary", max_results)

def get_message_full(access_token: str, msg_id: str):
    service = _svc(access_token)
    return service.users().messages().get(userId="me", id=msg_id, format="full").execute()

def extract_text(message):
    payload = message.get("payload", {})
    headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
    subject = headers.get("subject", "(no subject)")
    sender = headers.get("from", "(unknown)")
    snippet = message.get("snippet", "")

    def walk(part):
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        if data:
            raw = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            if mime == "text/plain":
                return raw
            if mime == "text/html":
                return html_to_text(raw)
        for p in part.get("parts", []) or []:
            t = walk(p)
            if t:
                return t
        return None

    text = walk(payload) or snippet
    return {"from": sender, "subject": subject, "text": text}
